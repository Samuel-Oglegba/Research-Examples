//=== Data Structures =====
struct ipt_entry;
struct net;
struct xt_entry_match;
struct xt_mtchk_param;

/**
 * @brief  * {
 * modified =>{
 *    data-structures: {ipt_entry, xt_entry_match, xt_mtchk_param},
 * 	how-it-was-modified: {
 * 		"ipt_entry     :: modified by assignment to xt_percpu_counter_alloc() operation",
 * 		"xt_entry_match:: modified by xt_ematch_foreach() operation using data `ipt_entry` as parameter",
 * 		"xt_mtchk_param:: modified by assignment to data `net`, `ipt_entry`, & a constant"
 * 		},
 *  	relationships:{
 *		xt_mtchk_param & net ==> "`xt_mtchk_param` has `net` as an element",
 *		xt_mtchk_param & ipt_entry ==> "`xt_mtchk_param` has a `void entryinfo` element that is assigned to the element of data `ipt_entry` (struct `ipt_ip` - child of `ipt_entry`)",
 *		}, 
 * }, 
 * read =>{
 *    data-structures: {ipt_entry, net, xt_entry_match, xt_mtchk_param},
 * 	how-it-was-read: {
*          "ipt_entry      :: used to set the value of elements in  data `xt_mtchk_param` by assignment", 
 *          "net           :: used to set the the net element of data `xt_mtchk_param` by assignment (mtpar.net = net)", 
 *          "xt_entry_match:: used to iterate over data `ipt_entry` via xt_ematch_foreach operation",
 *          "xt_entry_match:: used with data `xt_mtchk_param` as parameters of check_match operation",
 *         } 
 *	 }, 
 * }
 * 
 * @param e 
 * @param net 
 * @param name 
 * @return int 
 */
static int
compat_check_entry(struct ipt_entry *e, struct net *net, const char *name)
{
	struct xt_entry_match *ematch;
	struct xt_mtchk_param mtpar;
	unsigned int j;
	int ret = 0;

	e->counters.pcnt = xt_percpu_counter_alloc();
	if (IS_ERR_VALUE(e->counters.pcnt))
		return -ENOMEM;

	j = 0;
	mtpar.net	= net;
	mtpar.table     = name;
	mtpar.entryinfo = &e->ip;
	mtpar.hook_mask = e->comefrom;
	mtpar.family    = NFPROTO_IPV4;
	xt_ematch_foreach(ematch, e) {
		ret = check_match(ematch, &mtpar);
		if (ret != 0)
			goto cleanup_matches;
		++j;
	}

	ret = check_target(e, net, name);
	if (ret)
		goto cleanup_matches;
	return 0;

 cleanup_matches:
	xt_ematch_foreach(ematch, e) {
		if (j-- == 0)
			break;
		cleanup_match(ematch, net);
	}

	xt_percpu_counter_free(e->counters.pcnt);

	return ret;
}//compat_check_entry


//=== Data Structures =====
struct xt_entry_match;
struct xt_mtchk_param;
struct ipt_ip; //child of ipt_entry
/**
 * @brief {
 * modified =>{
 *    	data-structures: {xt_mtchk_param, ipt_ip},
 * 		how-it-was-modified: {
 * 			"xt_mtchk_param:: modified by assigning its elements (match,matchinfo) to  data `xt_entry_match` elements (m->u.kernel.match & m->data)",
 * 			"ipt_ip        :: modified by assigning data `xt_mtchk_param` element (par->entryinfo)",
 * 		},
 * 		relationships:{
 *			xt_mtchk_param & ipt_ip ==> "element of data `ipt_entry` (struct `ipt_ip` - child of `ipt_entry`) was assigned to element `void entryinfo` of data `xt_mtchk_param`",
 *		},  
 * }, 
 * read =>{
 *   		data-structures: {xt_entry_match, xt_mtchk_param, ipt_ip},
 * 		how-it-was-read: {
 *    	 	"xt_entry_match:: used to set the value of elements in  data `xt_mtchk_param` (match & matchinfo) by assignment", 
 *          	"xt_entry_match:: used with `xt_mtchk_param` & `ipt_ip` as parameters to xt_check_match operation"
 *          	"xt_mtchk_param:: used to set the value of data `ipt_ip` by assignment (par->entryinfo)", 
 *         } 
 *	 },
 * }
 * 
 * @param m 
 * @param par 
 * @return int 
 */
static int
check_match(struct xt_entry_match *m, struct xt_mtchk_param *par)
{
	const struct ipt_ip *ip = par->entryinfo;
	int ret;

	par->match     = m->u.kernel.match;
	par->matchinfo = m->data;

	ret = xt_check_match(par, m->u.match_size - sizeof(*m),
	      ip->proto, ip->invflags & IPT_INV_PROTO);
	if (ret < 0) {
		printf("check failed for `%s'.\n", par->match->name);
		return ret;
	}
	return 0;
}//check_match


//=== Data Structures =====
struct xt_mtchk_param;

/**
 * @brief unable to find the definition of xt_check_match
 * {
 * modified =>{
 *  	data-structures:{xt_mtchk_param},
 * 	how-it-was-modified: {}
 * }, 
 * read =>{
 * 	data-structures:{xt_mtchk_param},
 * 	how-it-was-read: {}
 * 	},
 * }
 * 
 * @param par 
 * @param match_size 
 * @param proto 
 * @param invflags 
 * @return int 
 */
int xt_check_match(struct xt_mtchk_param *par, unsigned short match_size,
	      unsigned short proto, unsigned char invflags){

	int ret;

	if (XT_ALIGN(par->match->matchsize) != size &&
	    par->match->matchsize != -1) {
		/*
		 * ebt_among is exempt from centralized matchsize checking
		 * because it uses a dynamic-size data set.
		 */
		printf("%s_tables: %s.%u match: invalid size "
		       "%u (kernel) != (user) %u\n",
		       xt_prefix[par->family], par->match->name,
		       par->match->revision,
		       XT_ALIGN(par->match->matchsize), size);
		return -EINVAL;
	}
	if (par->match->table != NULL &&
	    strcmp(par->match->table, par->table) != 0) {
		printf("%s_tables: %s match: only valid in %s table, not %s\n",
		       xt_prefix[par->family], par->match->name,
		       par->match->table, par->table);
		return -EINVAL;
	}
	if (par->match->hooks && (par->hook_mask & ~par->match->hooks) != 0) {
		char used[64], allow[64];

		printf("%s_tables: %s match: used from hooks %s, but only "
		       "valid from %s\n",
		       xt_prefix[par->family], par->match->name,
		       textify_hooks(used, sizeof(used), par->hook_mask,
		                     par->family),
		       textify_hooks(allow, sizeof(allow), par->match->hooks,
		                     par->family));
		return -EINVAL;
	}
	if (par->match->proto && (par->match->proto != proto || inv_proto)) {
		printf("%s_tables: %s match: only valid for protocol %u\n",
		       xt_prefix[par->family], par->match->name,
		       par->match->proto);
		return -EINVAL;
	}
	if (par->match->checkentry != NULL) {
		ret = par->match->checkentry(par);
		if (ret < 0)
			return ret;
		else if (ret > 0)
			/* Flag up potential errors. */
			return -EIO;
	}
	
	return 0;
}//xt_check_match