static void ipt_destroy_target(struct xt_entry_target *t)
{
	struct xt_tgdtor_param par = {
		.target   = t->u.kernel.target,
		.targinfo = t->data,
		.family   = NFPROTO_IPV4,
	};
	if (par.target->destroy != NULL)
		par.target->destroy(&par);
	module_put(par.target->me);
}