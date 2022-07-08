//=== Data Structures =====
struct xt_entry_match;
struct xt_match;
struct compat_xt_entry_match;

/**
 * @brief  {
 * modified =>{
 * 		data-structures: {xt_entry_match, xt_match, compat_xt_entry_match},
 * 		how-it-was-modified: {
 * 			"xt_entry_match       :: modified by assignment to a void pointer (m = *dstptr), memcpy(), memset(), & re-assignment to a it's origina size ",
 * 			"xt_match             :: modified by assignment to data `xt_entry_match` match element",
 * 			"compat_xt_entry_match:: modified by casting data `xt_entry_match`",
 * 		} 
 * }, 
 * read =>{
 *    	data-structures: {xt_entry_match, xt_match, compat_xt_entry_match},
 * 		how-it-was-read: {
 *    	 	 "xt_entry_match       :: used to get the data `xt_match` via assignment (m->u.kernel.match)", 
 *          	 "xt_entry_match       :: used to get the data `compat_xt_entry_match` via casting", 
 *          	 "xt_match             :: used to update the value of `xt_entry_match` elements via compat_from_user, memset, & assignment operations",
 *          	 "compat_xt_entry_match:: used to update the value of `xt_entry_match` elements via compat_from_user & memset operations", 
 *         		} 
 * 	}, 
 * }
 * 
 * @param m 
 * @param dstptr 
 * @param size 
 * @return int 
 */
int xt_compat_match_from_user(struct xt_entry_match *m, void **dstptr,
			      unsigned int *size)
{
	const struct xt_match *match = m->u.kernel.match;
	struct compat_xt_entry_match *cm = (struct compat_xt_entry_match *)m;
	int pad, off = xt_compat_match_offset(match);
	u_int16_t msize = cm->u.user.match_size;

	m = *dstptr;
	memcpy(m, cm, sizeof(*cm));
	if (match->compat_from_user)
		match->compat_from_user(m->data, cm->data);
	else
		memcpy(m->data, cm->data, msize - sizeof(*cm));
	pad = XT_ALIGN(match->matchsize) - match->matchsize;
	if (pad > 0)
		memset(m->data + match->matchsize, 0, pad);

	msize += off;
	m->u.user.match_size = msize;

	*size += off;
	*dstptr += msize;
	return 0;
}//xt_compat_match_from_user


//=== Data Structures =====
struct xt_entry_match;
struct xt_match;
/**
 * @brief  {
 * modified =>{
 * 		data-structures: {xt_entry_match, xt_match},
 * 		how-it-was-modified: {
 * 			"xt_entry_match:: modified by assigning data `xt_match` to it's match element",
 * 			"xt_match      :: modified via xt_request_find_match() operation using data `xt_entry_match` elements as parameter",
 * 		} 
 * }, 
 * read =>{
 * 		data-structures: {xt_entry_match, xt_match},
 * 		how-it-was-read: {
 *    	 	"xt_entry_match:: used to get data `xt_match` via xt_request_find_match operation", 
 *          	"xt_match      :: used to update the value of `xt_entry_match` element by assignment",
 *         } 
 * 	},
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
