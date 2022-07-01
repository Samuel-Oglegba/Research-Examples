
struct xt_entry_target;
const struct xt_target;
struct compat_xt_entry_target;


/**
 * @brief {modified =>{xt_entry_target, xt_target}, used =>{xt_entry_target}, read =>{compat_xt_entry_target}}
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







/////////////////////////////////////////////======================================================



const struct sock *sk;

/**
 * @brief {used => {sock}}
 * 
 * @param sk 
 * @return struct net* 
 */
static inline
struct net *sock_net(const struct sock *sk)
{
	return read_pnet(&sk->sk_net);
}//sock_net