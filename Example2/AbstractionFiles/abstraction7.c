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
 * 		} 
 * }, 
 * read =>{
 *    data-structures: {ipt_entry, net, xt_entry_target, xt_tgchk_param},
 * 	how-it-was-read: {
 *    	"ipt_entry      :: used to get the value of data `xt_entry_target` via ipt_get_target operation", 
 *          "ipt_entry      :: used to set the value of elements of data `xt_tgchk_param` via assignments", 
 *          "net            :: used to set the value of the net element of data `xt_tgchk_param`", 
 *          "xt_entry_target:: used to set `xt_tgchk_param` elements (target & targinfo) via assignment",
 *          "xt_tgchk_param :: used with `xt_entry_target` & `ipt_entry` as parameters to xt_check_target operation",
 *         } 
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
 * 		} 
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