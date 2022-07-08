//=== Data Structures =====
struct compat_ipt_entry;
struct xt_table_info;
struct xt_entry_target;
struct xt_target;
struct ipt_entry;
struct xt_entry_match;

/**
 * @brief  {
	* modified =>{
	* 	data-structures: {xt_table_info, xt_entry_target, xt_target, ipt_entry, xt_entry_match},
	* 	how-it-was-modified: {
	* 		"xt_table_info  :: the following elements {hook_entry, underflow} were modified by assignment",
	* 		"xt_entry_target:: modified via compat_ipt_get_target() operation using `compat_ipt_entry` as parameter",
	* 		"xt_entry_target:: modified via xt_compat_target_from_user() operation",
	* 		"xt_target      :: modified by assigning data `xt_entry_target` target element ",
	* 		"ipt_entry      :: modified by casting a void pointer ((struct ipt_entry *)*dstptr) & memcpy() operation",
	* 		"xt_entry_match :: modified via xt_ematch_foreach() operation using `compat_ipt_entry` as parameter",
	* 		}
	* }, 
	* read =>{
	*    data-structures: {compat_ipt_entry, xt_table_info, xt_entry_target, ipt_entry, xt_entry_match},
	*    how-it-was-read: {
	*		"compat_ipt_entry:: the value is copied to data `ipt_entry` via memcpy() operation", 
	*           "compat_ipt_entry:: used to iteratively set the value of data `xt_entry_match` via xt_ematch_foreach() operation", 
	*           "compat_ipt_entry:: used to get the value of  data `xt_entry_target` via compat_ipt_get_target() operation", 
	*           "xt_entry_target :: used to set the value of data `xt_target` by reading it's target element"
	*         } 		
	* 	}
 * }
 * 
 * @param e 
 * @param dstptr 
 * @param size 
 * @param name 
 * @param newinfo 
 * @param base 
 * @return int 
 */
static int compat_copy_entry_from_user(struct compat_ipt_entry *e, void **dstptr,
			    unsigned int *size, const char *name,
			    struct xt_table_info *newinfo, unsigned char *base)
{
	struct xt_entry_target *t;
	struct xt_target *target;
	struct ipt_entry *de;
	unsigned int origsize;
	int ret, h;
	struct xt_entry_match *ematch;

	ret = 0;
	origsize = *size;
	de = (struct ipt_entry *)*dstptr;
	memcpy(de, e, sizeof(struct ipt_entry));
	memcpy(&de->counters, &e->counters, sizeof(e->counters));

	*dstptr += sizeof(struct ipt_entry);
	*size += sizeof(struct ipt_entry) - sizeof(struct compat_ipt_entry);

	xt_ematch_foreach(ematch, e) {
		ret = xt_compat_match_from_user(ematch, dstptr, size);
		if (ret != 0)
			return ret;
	}
	de->target_offset = e->target_offset - (origsize - *size);
	t = compat_ipt_get_target(e);
	target = t->u.kernel.target;
	xt_compat_target_from_user(t, dstptr, size);

	de->next_offset = e->next_offset - (origsize - *size);
	for (h = 0; h < NF_INET_NUMHOOKS; h++) {
		if ((unsigned char *)de - base < newinfo->hook_entry[h])
			newinfo->hook_entry[h] -= origsize - *size;
		if ((unsigned char *)de - base < newinfo->underflow[h])
			newinfo->underflow[h] -= origsize - *size;
	}
	return ret;
}//compat_copy_entry_from_user


//=== Data Structures =====
struct compat_ipt_entry;
struct xt_table_info;
struct xt_entry_match;
struct xt_entry_target;
struct xt_target;
/**
 * @brief {
	* modified =>{
	*    data-structures: {compat_ipt_entry, xt_table_info, xt_entry_match, xt_entry_target, xt_target},
	*    how-it-was-modified: {
	* 		"compat_ipt_entry:: the elements (counter & comefrom) were modified by memset() operation & assignment respectively",
	* 		"xt_table_info   :: the following elements {hook_entry, underflow} were modified by assignment",
	* 		"xt_entry_match  :: modified via xt_ematch_foreach() operation using `compat_ipt_entry` as parameter",
	* 		"xt_entry_target :: modified via compat_ipt_get_target() operation using `compat_ipt_entry` as paramenter",
	* 		"xt_entry_target :: modified by assigning data `xt_target` to the target element",
	* 		} 
	* }, 
	* read =>{
	*     data-structures: {compat_ipt_entry, xt_entry_match, xt_entry_target, xt_target},
	* 	how-it-was-read: {
	*	      "compat_ipt_entry:: the value was casted to `ipt_entry` via the check_entry() operation", 
	*           "compat_ipt_entry:: used to get data `xt_entry_target` via compat_ipt_get_target() operation", 
	*           "compat_ipt_entry:: used to iteratively set the value of data `xt_entry_match` via xt_ematch_foreach() operation", 
	*           "xt_entry_match  :: used with data `compat_ipt_entry` as parameters to compat_find_calc_match() operation",
	*           "xt_entry_match  :: used as a parameter in module_put() operation",
	*           "xt_entry_target :: used to get data `xt_target` via xt_request_find_target() operation",
	*           "xt_entry_target :: used as a parameter in module_put() operation",
	*           "xt_target       :: used as a parameter to xt_compat_target_offset() operation"
	*           "xt_target       :: used to update the value of `xt_entry_target` element via assignment"
	*         } 
	* 	}
 * }
 * 
 * @param e 
 * @param newinfo 
 * @param size 
 * @param base 
 * @param limit 
 * @param hook_entries 
 * @param underflows 
 * @param name 
 * @return int 
 */
static int check_compat_entry_size_and_hooks(struct compat_ipt_entry *e,
				  struct xt_table_info *newinfo,
				  unsigned int *size,
				  const unsigned char *base,
				  const unsigned char *limit,
				  const unsigned int *hook_entries,
				  const unsigned int *underflows,
				  const char *name)
{
	struct xt_entry_match *ematch;
	struct xt_entry_target *t;
	struct xt_target *target;
	unsigned int entry_offset;
	unsigned int j;
	int ret, off, h;

	printf("check_compat_entry_size_and_hooks %p\n", e);
	if ((unsigned long)e % __alignof__(struct compat_ipt_entry) != 0 ||
	    (unsigned char *)e + sizeof(struct compat_ipt_entry) >= limit ||
	    (unsigned char *)e + e->next_offset > limit) {
		printf("Bad offset %p, limit = %p\n", e, limit);
		return -EINVAL;
	}

	if (e->next_offset < sizeof(struct compat_ipt_entry) +
			     sizeof(struct compat_xt_entry_target)) {
		printf("checking: element %p size %u\n",
			 e, e->next_offset);
		return -EINVAL;
	}

	/* For purposes of check_entry casting the compat entry is fine */
	ret = check_entry((struct ipt_entry *)e);
	if (ret)
		return ret;

	off = sizeof(struct ipt_entry) - sizeof(struct compat_ipt_entry);
	entry_offset = (void *)e - (void *)base;
	j = 0;
	xt_ematch_foreach(ematch, e) {
		ret = compat_find_calc_match(ematch, name, &e->ip, &off);
		if (ret != 0)
			goto release_matches;
		++j;
	}

	t = compat_ipt_get_target(e);
	target = xt_request_find_target(NFPROTO_IPV4, t->u.user.name,
					t->u.user.revision);
	if (IS_ERR(target)) {
		printf("check_compat_entry_size_and_hooks: `%s' not found\n",
			 t->u.user.name);
		ret = PTR_ERR(target);
		goto release_matches;
	}
	t->u.kernel.target = target;

	off += xt_compat_target_offset(target);
	*size += off;
	ret = xt_compat_add_offset(AF_INET, entry_offset, off);
	if (ret)
		goto out;

	/* Check hooks & underflows */
	for (h = 0; h < NF_INET_NUMHOOKS; h++) {
		if ((unsigned char *)e - base == hook_entries[h])
			newinfo->hook_entry[h] = hook_entries[h];
		if ((unsigned char *)e - base == underflows[h])
			newinfo->underflow[h] = underflows[h];
	}

	/* Clear counters and comefrom */
	memset(&e->counters, 0, sizeof(e->counters));
	e->comefrom = 0;
	return 0;

out:
	module_put(t->u.kernel.target->me);
release_matches:
	xt_ematch_foreach(ematch, e) {
		if (j-- == 0)
			break;
		module_put(ematch->u.kernel.match->me);
	}
	return ret;
}//check_compat_entry_size_and_hooks


//=== Data Structures =====
struct compat_ipt_entry;
struct xt_entry_target;
struct xt_entry_match;

/**
 * @brief {
	* modified =>{
	*    data-structures: {xt_entry_target, xt_entry_match},
	*    how-it-was-modified: {
	* 		"xt_entry_target:: modified via compat_ipt_get_target() operation using `compat_ipt_entry` as paramenter",
	* 		"xt_entry_match :: modified via xt_ematch_foreach() operation using `compat_ipt_entry` as parameter",
	* 		} 
	* }, 
	* read =>{
	*    data-structures: {compat_ipt_entry, xt_entry_target, xt_entry_match},
	*    how-it-was-read: {
	*          "compat_ipt_entry:: used to iteratively set the value of data `xt_entry_match` via xt_ematch_foreach() operation",
	*          "compat_ipt_entry:: used to get the value of  data `xt_entry_target` via compat_ipt_get_target() operation",  
	*          "xt_entry_target :: used as a parameter to module_put",
	*          "xt_entry_match  :: the value is used as a parameter to module_put() operation"
	*         } 
	* 	},
 * }
 * 
 * @param e 
 */
static void compat_release_entry(struct compat_ipt_entry *e)
{
	struct xt_entry_target *t;
	struct xt_entry_match *ematch;

	/* Cleanup all matches */
	xt_ematch_foreach(ematch, e)
		module_put(ematch->u.kernel.match->me);
	t = compat_ipt_get_target(e);
	module_put(t->u.kernel.target->me);
}//compat_release_entry


