//=== Data Structures =====
struct ipt_entry;
struct net;
struct xt_tgdtor_param;
struct xt_entry_target;
struct xt_entry_match;

/**
 * @brief could not find the definition of xt_tgdtor_param
 * {
 * modified =>{xt_tgdtor_param, xt_entry_target, xt_entry_match}, 
 * read =>{ipt_entry, net, xt_tgdtor_param, xt_entry_target, xt_entry_match},
 * used =>{
 *          "ipt_entry      :: used to iteratively set the value of data `xt_entry_match` via xt_ematch_foreach operation", 
 *          "net            :: used with data `xt_entry_match` in cleanup_match operation", 
 *          "net            :: used to set `xt_tgdtor_param` element via assignment par.net = net", 
 *          "xt_tgdtor_param:: used in the module_put operation",
 *          "xt_entry_target:: used to set `xt_tgdtor_param` elements (target & targinfo) via assignment",
 *          "xt_entry_match :: used to iterate over data `ipt_entry` via xt_ematch_foreach operation",
 *          "xt_entry_match :: used with data `net` in cleanup_match operation",
 *    } 
 * }
 * 
 * @param e 
 * @param net 
 */
static void
cleanup_entry(struct ipt_entry *e, struct net *net)
{
	struct xt_tgdtor_param par;
	struct xt_entry_target *t;
	struct xt_entry_match *ematch;

	/* Cleanup all matches */
	xt_ematch_foreach(ematch, e)
		cleanup_match(ematch, net);
	t = ipt_get_target(e);

	par.net      = net;
	par.target   = t->u.kernel.target;
	par.targinfo = t->data;
	par.family   = NFPROTO_IPV4;
	if (par.target->destroy != NULL)
		par.target->destroy(&par);
	module_put(par.target->me);
	xt_percpu_counter_free(e->counters.pcnt);
	
}//cleanup_entry
