//=== Data Structures =====
struct compat_ipt_entry;
struct xt_table_info;
struct xt_entry_target;
struct xt_target;
struct ipt_entry;
struct xt_entry_match;

/**
 * @brief  {
 * modified =>{xt_table_info, xt_entry_target, xt_target, ipt_entry, xt_entry_match}, 
 * read =>{compat_ipt_entry, xt_table_info, xt_entry_target, ipt_entry, xt_entry_match},
 * used =>{
 *          "compat_ipt_entry:: the value is copied to `xt_target` via memcpy operation", 
 *          "compat_ipt_entry:: used to iteratively set the value of data `xt_entry_match` via xt_ematch_foreach operation", 
 *          "compat_ipt_entry:: used to get the value of  data `xt_entry_target` via compat_ipt_get_target operation", 
 *          "xt_entry_target :: used to set the value of data `xt_target` by reading it's target element",
 *          "xt_entry_target :: the value was passed as a parameter to xt_compat_target_from_user operation",
 *          "xt_entry_match  :: the value is used as a parameter to xt_compat_match_from_user operation"
 *    }
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
struct xt_entry_target;
struct xt_entry_match;

/**
 * @brief {
 * modified =>{xt_entry_target, xt_entry_match}, 
 * read =>{compat_ipt_entry, xt_entry_target, xt_entry_match},
 * used =>{
 *          "compat_ipt_entry:: used to iteratively set the value of data `xt_entry_match` via xt_ematch_foreach operation",
 *          "compat_ipt_entry:: used to get the value of  data `xt_entry_target` via compat_ipt_get_target operation",  
 *          "xt_entry_target :: used as a parameter to module_put",
 *          "xt_entry_match  :: the value is used as a parameter to module_put operation"
 *    }
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