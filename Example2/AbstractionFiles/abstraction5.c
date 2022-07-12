//=== Data Structures =====
struct ipt_entry;
struct net;
struct xt_tgdtor_param;
struct xt_entry_target;
struct xt_entry_match;

/**
 * @brief {
 * modified =>{
 *   	data-structures: {xt_tgdtor_param, xt_entry_target, xt_entry_match},
 * 	how-it-was-modified: {
 * 		"xt_tgdtor_param:: modified by assignment to data `net`, `xt_entry_target`, & a constant",
 * 		"xt_entry_target:: modified via ipt_get_target() operation using data `ipt_entry` as parameter",
 * 		"xt_entry_match :: modified by xt_ematch_foreach() operation using data `ipt_entry` as parameter"
 * 		},
 *	relationships:{
 *		xt_tgdtor_param & net ==> "`xt_tgdtor_param` has `net` as an element",
 *		xt_entry_target & ipt_entry ==> "`ipt_entry` was casted to `xt_entry_target` in addition to it's offset {(void *)e + e->target_offset} in ipt_get_target() operation",
 *		xt_entry_match & ipt_entry ==> "`ipt_entry` has an element {char elems[]} which was casted to `xt_entry_match` via xt_ematch_foreach() operation",
 *		},  
 * }, 
 * read =>{
 *    data-structures: {ipt_entry, net, xt_tgdtor_param, xt_entry_target, xt_entry_match},
 * 	how-it-was-read: {
 *	      "ipt_entry      :: used to iteratively set the value of data `xt_entry_match` via xt_ematch_foreach operation", 
 *          "net            :: used with data `xt_entry_match` in cleanup_match operation", 
 *          "net            :: used to set `xt_tgdtor_param` element via assignment (par.net = net)", 
 *          "xt_entry_target:: used to set `xt_tgdtor_param` elements (target & targinfo) via assignment",
 *          "xt_entry_match :: used to iterate over data `ipt_entry` via xt_ematch_foreach operation",
 *          "xt_entry_match :: used with data `net` in the cleanup_match operation",
 *         } 
 * 	},
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
