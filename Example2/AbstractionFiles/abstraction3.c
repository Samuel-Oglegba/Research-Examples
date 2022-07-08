//=== Data Structures =====
struct net *net;
struct xt_table_info;
struct xt_table;
struct xt_counters;
struct ipt_entry;

/**
 * @brief {
 * modified =>{
 * 	data-structures: {xt_table, xt_counters, ipt_entry},
 * 	how-it-was-modified: {
 * 		"xt_table   :: modified via try_then_request_module() operation using data `net` as paramenter ",
 * 		"xt_counters:: modified via vzalloc() & vfree() operation",
 * 		"ipt_entry  :: modified by xt_entry_foreach() operation"
 * 		} 
 * }, 
 * read =>{
 *     data-structures: {net, xt_table_info, xt_table, xt_counters, ipt_entry},
 * 	 how-it-was-read: {
 *	      "net          :: used to get data `xt_table` via try_then_request_module operation", 
 *          "xt_table_info:: ", 
 *          "xt_table     :: used to get data `xt_table_info` via xt_replace_table operation", 
 *          "xt_counters  :: ", 
 *          "ipt_entry    :: used for iteration with data `xt_table_info` via xt_entry_foreach operation"
 *         } 
 * 	}
 * }
 * unable to fix due to system calls
 * 
 * @param net 
 * @param name 
 * @param valid_hooks 
 * @param newinfo 
 * @param num_counters 
 * @param counters_ptr 
 * @return int 
 */
static int
__do_replace(struct net *net, const char *name, unsigned int valid_hooks,
	     struct xt_table_info *newinfo, unsigned int num_counters,
	     void __user *counters_ptr)
{
	int ret;
	struct xt_table *t;
	struct xt_table_info *oldinfo;
	struct xt_counters *counters;
	struct ipt_entry *iter;

	ret = 0;
	counters = vzalloc(num_counters * sizeof(struct xt_counters));
	if (!counters) {
		ret = -ENOMEM;
		goto out;
	}

	t = try_then_request_module(xt_find_table_lock(net, AF_INET, name),
				    "iptable_%s", name);
	if (IS_ERR_OR_NULL(t)) {
		ret = t ? PTR_ERR(t) : -ENOENT;
		goto free_newinfo_counters_untrans;
	}

	/* You lied! */
	if (valid_hooks != t->valid_hooks) {
		printf("Valid hook crap: %08X vs %08X\n",
			 valid_hooks, t->valid_hooks);
		ret = -EINVAL;
		goto put_module;
	}

	oldinfo = xt_replace_table(t, num_counters, newinfo, &ret);
	if (!oldinfo)
		goto put_module;

	/* Update module usage count based on number of rules */
	printf("do_replace: oldnum=%u, initnum=%u, newnum=%u\n",
		oldinfo->number, oldinfo->initial_entries, newinfo->number);
	if ((oldinfo->number > oldinfo->initial_entries) ||
	    (newinfo->number <= oldinfo->initial_entries))
		module_put(t->me);
	if ((oldinfo->number > oldinfo->initial_entries) &&
	    (newinfo->number <= oldinfo->initial_entries))
		module_put(t->me);

	/* Get the old counters, and synchronize with replace */
	get_counters(oldinfo, counters);

	/* Decrease module usage counts and free resource */
	xt_entry_foreach(iter, oldinfo->entries, oldinfo->size)
		cleanup_entry(iter, net);

	xt_free_table_info(oldinfo);
	if (copy_to_user(counters_ptr, counters,
			 sizeof(struct xt_counters) * num_counters) != 0) {
		/* Silent error, can't fail, new table is already in place */
		net_warn_ratelimited("iptables: counters copy to user failed while replacing table\n");
	}
	vfree(counters);
	xt_table_unlock(t);
	return ret;

 put_module:
	module_put(t->me);
	xt_table_unlock(t);
 free_newinfo_counters_untrans:
	vfree(counters);
 out:
	return ret;
}