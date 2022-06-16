static void compat_release_entry(struct compat_ipt_entry *e)
{
	struct xt_entry_target *t;
	struct xt_entry_match *ematch;

	/* Cleanup all matches */
	xt_ematch_foreach(ematch, e)
		module_put(ematch->u.kernel.match->me);
	t = compat_ipt_get_target(e);
	module_put(t->u.kernel.target->me);
}