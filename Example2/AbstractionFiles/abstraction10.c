//=== Data Structures =====
struct xt_entry_match;
struct xt_match;

/**
 * @brief  {
 * modified =>{xt_entry_match, xt_match}, 
 * read =>{xt_entry_match, xt_match},
 * used =>{
 *          "xt_entry_match:: used to get `xt_match` via xt_request_find_match operation", 
 *          "xt_match:: used to update the value of `xt_entry_match` element by assignment",
 *          "xt_match:: used as a parameter in xt_compat_match_offset operation" 
 *    } 
 * }
 * 
 * @param m 
 * @param name 
 * @param ip 
 * @param size 
 * @return int 
 */
static int compat_find_calc_match(struct xt_entry_match *m,
		       const char *name,
		       const struct ipt_ip *ip,
		       int *size)
{
	struct xt_match *match;

	match = xt_request_find_match(NFPROTO_IPV4, m->u.user.name,
				      m->u.user.revision);
	if (IS_ERR(match)) {
		printf("compat_check_calc_match: `%s' not found\n",
			 m->u.user.name);
		return PTR_ERR(match);
	}
	m->u.kernel.match = match;
	*size += xt_compat_match_offset(match);
	return 0;
}// compat_find_calc_match
