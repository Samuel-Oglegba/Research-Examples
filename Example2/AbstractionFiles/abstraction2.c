//=== Data Structures =====
struct net;
struct compat_ipt_replace;
struct xt_table_info;
struct ipt_entry;

/**
 * @brief {
 * modified =>{compat_ipt_replace, xt_table_info, xt_target}, 
 * read =>{net, compat_ipt_replace, xt_table_info},
 * used =>{"net               :: used to get the value of `xt_table` via __do_replace operation, `xt_table` is parent to `xt_table_info`",
 *         "compat_ipt_replace:: the user data is copied to `compat_ipt_replace` via copy_from_user operation",
 *         "compat_ipt_replace:: used to set the size of data `xt_table_info` via xt_alloc_table_info operation"
 *         "compat_ipt_replace:: used to make changes to the state of `xt_table_info` via translate_compat_table operation"
 *         "xt_table_info     :: it's size element is used to iterate over data `ipt_entry` and clean up data `net` via xt_entry_foreach & cleanup_entry" }
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