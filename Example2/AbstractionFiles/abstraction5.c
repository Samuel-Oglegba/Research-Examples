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


//=== Data Structures =====
struct ipt_entry;
struct net;
struct xt_entry_target;
struct xt_tgchk_param;
/**
 * @brief {
 * modified =>{
 *    data-structures: {xt_entry_target},
 * 	how-it-was-modified: {
 * 		"xt_entry_target:: modified using ipt_get_target() operation using `ipt_entry` as a parameter",
 * 		},
 *    relationships:{
 *		xt_entry_target & ipt_entry ==> "`ipt_entry` was casted to `xt_entry_target` in addition to it's offset {(void *)e + e->target_offset} in ipt_get_target() operation",
 *		},  
 * }, 
 * read =>{
 *    data-structures: {ipt_entry, net, xt_entry_target, xt_tgchk_param},
 * 	how-it-was-read: {
 *    	"ipt_entry      :: used to get the value of data `xt_entry_target` via ipt_get_target operation", 
 *          "ipt_entry      :: used to set the value of elements of data `xt_tgchk_param` via assignments", 
 *          "net            :: used to set the value of the net element of data `xt_tgchk_param`", 
 *          "xt_entry_target:: used to set `xt_tgchk_param` elements (target & targinfo) via assignment",
 *          "xt_tgchk_param :: used with `xt_entry_target` & `ipt_entry` as parameters to xt_check_target operation",
 *         },
 *    relationships:{
 *		ipt_entry & xt_tgchk_param ==> "`xt_tgchk_param` is used to store `ipt_entry` via entryinfo element",
 *		net & xt_tgchk_param ==> "`xt_tgchk_param` is used to store `net` via net element",
 *		xt_entry_target & xt_tgchk_param ==> "`xt_tgchk_param` is used to store elemets of `xt_entry_target` via {target & targetinfo} elements",
 *		},  
 * 	},
 * }
 * 
 * @param e 
 * @param net 
 * @param name 
 * @return int 
 */
static int check_target(struct ipt_entry *e, struct net *net, const char *name)
{
	
	struct xt_entry_target *t = ipt_get_target(e);
	struct xt_tgchk_param par = {
		.net       = net,
		.table     = name,
		.entryinfo = e,
		.target    = t->u.kernel.target,
		.targinfo  = t->data,
		.hook_mask = e->comefrom,
		.family    = NFPROTO_IPV4,
	};
	int ret;

	ret = xt_check_target(&par, t->u.target_size - sizeof(*t),
	      e->ip.proto, e->ip.invflags & IPT_INV_PROTO);
	if (ret < 0) {
		duprintf("check failed for `%s'.\n",
			 t->u.kernel.target->name);
		return ret;
	}
	
	return 0;
}//check_target


//=== Data Structures =====
struct ipt_entry;
struct xt_entry_target;

/**
 * @brief {
 * modified =>{
 *   	data-structures: {xt_entry_target},
 * 	how-it-was-modified: {
 * 		"xt_entry_target:: modified using ipt_get_target_c() operation using `ipt_entry` as a parameter",
 * 		},
 *	relationships:{
 *		xt_entry_target & ipt_entry ==> "`ipt_entry` was casted to `xt_entry_target` in addition to it's offset {(void *)e + e->target_offset} in ipt_get_target_c() operation",
 *		}, 
 * }, 
 * read =>{
 *     data-structures: {ipt_entry, xt_entry_target},
 * 	 how-it-was-read: {
 *    	"ipt_entry      :: used to get the value of data `xt_entry_target` via ipt_get_target_c operation", 
 *          "xt_entry_target:: "
 *         } 
 * 	},
 * }
 * 
 * @param e 
 * @return int 
 */
static int check_entry(const struct ipt_entry *e)
{
	const struct xt_entry_target *t;

	if (!ip_checkentry(&e->ip))
		return -EINVAL;

	if (e->target_offset + sizeof(struct xt_entry_target) >
	    e->next_offset)
		return -EINVAL;

	t = ipt_get_target_c(e);
	if (e->target_offset + t->u.target_size > e->next_offset)
		return -EINVAL;

	return 0;
}//check_entry