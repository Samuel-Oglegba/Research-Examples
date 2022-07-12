//=== Data Structures =====
struct xt_entry_target;
struct xt_target;
struct compat_xt_entry_target;

/**
 * 
 * @brief {
 * modified =>{
 *  	data-structures: {xt_entry_target, xt_target, compat_xt_entry_target},
 * 	how-it-was-modified: {
 * 		"xt_entry_target       :: modified by assignment to a void pointer (*dstptr)",
 * 		"xt_entry_target       :: modified by memcpy(), & memset() operations using data `compat_xt_entry_target` and `xt_target` as parameters respectively",
 * 		"xt_target             :: modified by assignment to data `xt_entry_target` target element",
 * 		"compat_xt_entry_target:: modified by assignment via casting of data `xt_entry_target`"
 * 		},
 *   	relationships:{
 *		xt_entry_target & xt_target ==> "`xt_table` is a child/element of `xt_entry_target`",
 *		compat_xt_entry_target & xt_entry_target ==> "they both have same elements TODO: convertion abtraction:: compat_xt_entry_target may be the 64-bit equivalent of xt_entry_target"
 *		}, 
 * }, 
 * read =>{
 *     data-structures: {xt_entry_target, xt_target, compat_xt_entry_target},
 * 	 how-it-was-read: {
 *	      "xt_entry_target       :: used to set the value of data `xt_target` by assignment", 
 *          "xt_target             :: used to update data `xt_entry_target` to `compat_xt_entry_target` via target->compat_from_user operation", 
 *          "compat_xt_entry_target:: sets new values of data `xt_entry_target` via memcpy & target->compat_from_user() operation"
 *         } 
 * 	} 
 * }
 * 
 * @param t 
 * @param dstptr 
 * @param size 
 */
void xt_compat_target_from_user(struct xt_entry_target *t, void **dstptr,
				unsigned int *size)
{
	const struct xt_target *target = t->u.kernel.target;
	struct compat_xt_entry_target *ct = (struct compat_xt_entry_target *)t;
	int pad, off = xt_compat_target_offset(target);
	u_int16_t tsize = ct->u.user.target_size;

	t = *dstptr;
	memcpy(t, ct, sizeof(*ct));
	if (target->compat_from_user)
		target->compat_from_user(t->data, ct->data);
	else
		memcpy(t->data, ct->data, tsize - sizeof(*ct));
	pad = XT_ALIGN(target->targetsize) - target->targetsize;
	if (pad > 0)
		memset(t->data + target->targetsize, 0, pad);

	tsize += off;
	t->u.user.target_size = tsize;

	*size += off;
	*dstptr += tsize;
}//xt_compat_target_from_user