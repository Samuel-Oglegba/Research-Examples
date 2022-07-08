//=== Data Structures =====
struct net;
struct compat_ipt_replace;
struct xt_table;
struct xt_table_info; // xt_table_info is an element of xt_table
struct ipt_entry;

/**
 * @brief {
	* modified =>{
	* 	data-structures: {compat_ipt_replace, xt_table_info,ipt_entry},
	* 	how-it-was-modified: {
	* 		"compat_ipt_replace:: the user-space data is copied to data `compat_ipt_replace` via copy_from_user() operation",
	* 		"xt_table_info     :: memory size is allocated via xt_alloc_table_info() operation and data `compat_ipt_replace` element as parameter ",
	*		"ipt_entry         :: modified by xt_entry_foreach() operation using data `xt_table_info` as parameter"
	* 		}
	* 	}, 
	* read =>{
	* 	data-structures: {net, compat_ipt_replace, xt_table_info, ipt_entry},
	* 	how-it-was-read: {
	* 	     "net               :: used to get the value of data `xt_table` via __do_replace() operation. `xt_table` is parent to `xt_table_info`",
	*         "compat_ipt_replace:: used to set the size of data `xt_table_info` via xt_alloc_table_info() operation",
	*         "xt_table_info     :: the size element of `xt_table_info` is used to iterate over data `ipt_entry` and clean up data `net` via xt_entry_foreach() & cleanup_entry() operations" 
	*         } 		
	* 	}
 * }
 * 
 * @param net 
 * @param user 
 * @param len 
 * @return int 
 */
static int compat_do_replace(struct net *net, void __user *user, unsigned int len)
{
	int ret;
	struct compat_ipt_replace tmp;
	struct xt_table_info *newinfo;
	void *loc_cpu_entry;
	struct ipt_entry *iter;

	/* unable to fix the definition of copy_from_user */
	if (copy_from_user(&tmp, user, sizeof(tmp)) != 0)
		return -EFAULT;

	/* overflow check */
	if (tmp.size >= INT_MAX / num_possible_cpus())
		return -ENOMEM;
	if (tmp.num_counters >= INT_MAX / sizeof(struct xt_counters))
		return -ENOMEM;
	if (tmp.num_counters == 0)
		return -EINVAL;

	tmp.name[sizeof(tmp.name)-1] = 0;

	newinfo = xt_alloc_table_info(tmp.size);
	if (!newinfo)
		return -ENOMEM;

	loc_cpu_entry = newinfo->entries;
	if (copy_from_user(loc_cpu_entry, user + sizeof(tmp),
			   tmp.size) != 0) {
		ret = -EFAULT;
		goto free_newinfo;
	}

	ret = translate_compat_table(net, tmp.name, tmp.valid_hooks,
				     &newinfo, &loc_cpu_entry, tmp.size,
				     tmp.num_entries, tmp.hook_entry,
				     tmp.underflow);
	if (ret != 0)
		goto free_newinfo;

	printf("compat_do_replace: Translated table\n");

	ret = __do_replace(net, tmp.name, tmp.valid_hooks, newinfo,
			   tmp.num_counters, compat_ptr(tmp.counters));
	if (ret)
		goto free_newinfo_untrans;
	return 0;

 free_newinfo_untrans:
	xt_entry_foreach(iter, loc_cpu_entry, newinfo->size)
		cleanup_entry(iter, net);
 free_newinfo:
	xt_free_table_info(newinfo);
	return ret;
}//compat_do_replace


//== Data Structures ===== 
struct net;
struct xt_table_info;
struct compat_ipt_entry; // compat_ipt_entry is an element of compat_ipt_replace
struct ipt_entry;

/**
 * @brief {
	* modified =>{
	* 	data-structures: {xt_table_info, ipt_entry},
	* 	how-it-was-modified: {
	* 		"xt_table_info:: modified by assignments to parameters passed into the function ",
	*		"ipt_entry    :: modified by xt_entry_foreach() operation using data `xt_table_info` as parameter"
	* 		}
	* }, 
	* read =>{
	* 	data-structures: {net, xt_table_info, compat_ipt_entry, ipt_entry},
	* 	how-it-was-read: {
	* 		"net             :: used for matching data `xt_entry_target` via the compat_check_entry() operation",
	*          "xt_table_info   :: the size of `xt_table_info` is used to iterate over `ipt_entry` via xt_entry_foreach() operation", 
	*          "xt_table_info   :: the size of `xt_table_info` is used to iterate over `compat_ipt_entry` via xt_entry_foreach() operation", 
	* 		} 
	* 	},
 * }
 * 
 * @param net 
 * @param name 
 * @param valid_hooks 
 * @param pinfo 
 * @param pentry0 
 * @param total_size 
 * @param number 
 * @param hook_entries 
 * @param underflows 
 * @return int 
 */
static int translate_compat_table(struct net *net,
		       const char *name,
		       unsigned int valid_hooks,
		       struct xt_table_info **pinfo,
		       void **pentry0,
		       unsigned int total_size,
		       unsigned int number,
		       unsigned int *hook_entries,
		       unsigned int *underflows)
{
	unsigned int i, j;
	struct xt_table_info *newinfo, *info;
	void *pos, *entry0, *entry1;
	struct compat_ipt_entry *iter0;
	struct ipt_entry *iter1;
	unsigned int size;
	int ret;

	info = *pinfo;
	entry0 = *pentry0;
	size = total_size;
	info->number = number;

	/* Init all hooks to impossible value. */
	for (i = 0; i < NF_INET_NUMHOOKS; i++) {
		info->hook_entry[i] = 0xFFFFFFFF;
		info->underflow[i] = 0xFFFFFFFF;
	}

	printf("translate_compat_table: size %u\n", info->size);
	j = 0;
	xt_compat_lock(AF_INET);
	xt_compat_init_offsets(AF_INET, number);
	/* Walk through entries, checking offsets. */
	xt_entry_foreach(iter0, entry0, total_size) {
		ret = check_compat_entry_size_and_hooks(iter0, info, &size,
							entry0,
							entry0 + total_size,
							hook_entries,
							underflows,
							name);
		if (ret != 0)
			goto out_unlock;
		++j;
	}

	ret = -EINVAL;
	if (j != number) {
		printf("translate_compat_table: %u not %u entries\n",
			 j, number);
		goto out_unlock;
	}

	/* Check hooks all assigned */
	for (i = 0; i < NF_INET_NUMHOOKS; i++) {
		/* Only hooks which are valid */
		if (!(valid_hooks & (1 << i)))
			continue;
		if (info->hook_entry[i] == 0xFFFFFFFF) {
			printf("Invalid hook entry %u %u\n",
				 i, hook_entries[i]);
			goto out_unlock;
		}
		if (info->underflow[i] == 0xFFFFFFFF) {
			printf("Invalid underflow %u %u\n",
				 i, underflows[i]);
			goto out_unlock;
		}
	}

	ret = -ENOMEM;
	newinfo = xt_alloc_table_info(size);
	if (!newinfo)
		goto out_unlock;

	newinfo->number = number;
	for (i = 0; i < NF_INET_NUMHOOKS; i++) {
		newinfo->hook_entry[i] = info->hook_entry[i];
		newinfo->underflow[i] = info->underflow[i];
	}
	entry1 = newinfo->entries;
	pos = entry1;
	size = total_size;
	xt_entry_foreach(iter0, entry0, total_size) {
		ret = compat_copy_entry_from_user(iter0, &pos, &size,
						  name, newinfo, entry1);
		if (ret != 0)
			break;
	}
	xt_compat_flush_offsets(AF_INET);
	xt_compat_unlock(AF_INET);
	if (ret)
		goto free_newinfo;

	ret = -ELOOP;
	if (!mark_source_chains(newinfo, valid_hooks, entry1))
		goto free_newinfo;

	i = 0;
	xt_entry_foreach(iter1, entry1, newinfo->size) {
		ret = compat_check_entry(iter1, net, name);
		if (ret != 0)
			break;
		++i;
		if (strcmp(ipt_get_target(iter1)->u.user.name,
		    XT_ERROR_TARGET) == 0)
			++newinfo->stacksize;
	}
	if (ret) {
		/*
		 * The first i matches need cleanup_entry (calls ->destroy)
		 * because they had called ->check already. The other j-i
		 * entries need only release.
		 */
		int skip = i;
		j -= i;
		xt_entry_foreach(iter0, entry0, newinfo->size) {
			if (skip-- > 0)
				continue;
			if (j-- == 0)
				break;
			compat_release_entry(iter0);
		}
		xt_entry_foreach(iter1, entry1, newinfo->size) {
			if (i-- == 0)
				break;
			cleanup_entry(iter1, net);
		}
		xt_free_table_info(newinfo);
		return ret;
	}

	*pinfo = newinfo;
	*pentry0 = entry1;
	xt_free_table_info(info);
	return 0;

free_newinfo:
	xt_free_table_info(newinfo);
out:
	xt_entry_foreach(iter0, entry0, total_size) {
		if (j-- == 0)
			break;
		compat_release_entry(iter0);
	}
	return ret;
out_unlock:
	xt_compat_flush_offsets(AF_INET);
	xt_compat_unlock(AF_INET);
	goto out;

}//translate_compat_table