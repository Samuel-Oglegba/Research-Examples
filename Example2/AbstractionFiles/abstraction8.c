//=== Data Structures =====
struct xt_entry_match;
struct xt_mtchk_param;
struct ipt_ip;
/**
 * @brief {
 * modified =>{
 *    	data-structures: {xt_mtchk_param, ipt_ip},
 * 		how-it-was-modified: {
 * 			"xt_mtchk_param:: modified by assigning its elements (match,matchinfo) to  data `xt_entry_match` elements (m->u.kernel.match & m->data)",
 * 			"ipt_ip        :: modified by assigning data `xt_mtchk_param` element (par->entryinfo)",
 * 		} 
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


