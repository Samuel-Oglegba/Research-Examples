static int __tcf_ipt_init(struct tc_action_net *tn, struct nlattr *nla,
			  struct nlattr *est, struct tc_action *a, int ovr,
			  int bind)
{
	struct nlattr *tb[TCA_IPT_MAX + 1];
	struct tcf_ipt *ipt;
	struct xt_entry_target *td, *t;
	char *tname;
	int ret = 0, err;
	u32 hook = 0;
	u32 index = 0;

	if (nla == NULL)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_IPT_MAX, nla, ipt_policy);
	if (err < 0)
		return err;

	if (tb[TCA_IPT_HOOK] == NULL)
		return -EINVAL;
	if (tb[TCA_IPT_TARG] == NULL)
		return -EINVAL;

	td = (struct xt_entry_target *)nla_data(tb[TCA_IPT_TARG]);
	if (nla_len(tb[TCA_IPT_TARG]) < td->u.target_size)
		return -EINVAL;

	if (tb[TCA_IPT_INDEX] != NULL)
		index = nla_get_u32(tb[TCA_IPT_INDEX]);

	if (!tcf_hash_check(tn, index, a, bind)) {
		ret = tcf_hash_create(tn, index, est, a, sizeof(*ipt), bind,
				      false);
		if (ret)
			return ret;
		ret = ACT_P_CREATED;
	} else {
		if (bind)/* dont override defaults */
			return 0;
		tcf_hash_release(a, bind);

		if (!ovr)
			return -EEXIST;
	}
	ipt = to_ipt(a);

	hook = nla_get_u32(tb[TCA_IPT_HOOK]);

	err = -ENOMEM;
	tname = kmalloc(IFNAMSIZ, GFP_KERNEL);
	if (unlikely(!tname))
		goto err1;
	if (tb[TCA_IPT_TABLE] == NULL ||
	    nla_strlcpy(tname, tb[TCA_IPT_TABLE], IFNAMSIZ) >= IFNAMSIZ)
		strcpy(tname, "mangle");

	t = kmemdup(td, td->u.target_size, GFP_KERNEL);
	if (unlikely(!t))
		goto err2;

	err = ipt_init_target(t, tname, hook);
	if (err < 0)
		goto err3;

	spin_lock_bh(&ipt->tcf_lock);
	if (ret != ACT_P_CREATED) {
		ipt_destroy_target(ipt->tcfi_t);
		kfree(ipt->tcfi_tname);
		kfree(ipt->tcfi_t);
	}
	ipt->tcfi_tname = tname;
	ipt->tcfi_t     = t;
	ipt->tcfi_hook  = hook;
	spin_unlock_bh(&ipt->tcf_lock);
	if (ret == ACT_P_CREATED)
		tcf_hash_insert(tn, a);
	return ret;

err3:
	kfree(t);
err2:
	kfree(tname);
err1:
	if (ret == ACT_P_CREATED)
		tcf_hash_cleanup(a, est);
	return err;
}