static int tcf_ipt_dump(struct sk_buff *skb, struct tc_action *a, int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_ipt *ipt = a->priv;
	struct xt_entry_target *t;
	struct tcf_t tm;
	struct tc_cnt c;

	/* for simple targets kernel size == user size
	 * user name = target name
	 * for foolproof you need to not assume this
	 */

	t = kmemdup(ipt->tcfi_t, ipt->tcfi_t->u.user.target_size, GFP_ATOMIC);
	if (unlikely(!t))
		goto nla_put_failure;

	c.bindcnt = ipt->tcf_bindcnt - bind;
	c.refcnt = ipt->tcf_refcnt - ref;
	strcpy(t->u.user.name, ipt->tcfi_t->u.kernel.target->name);

	if (nla_put(skb, TCA_IPT_TARG, ipt->tcfi_t->u.user.target_size, t) ||
	    nla_put_u32(skb, TCA_IPT_INDEX, ipt->tcf_index) ||
	    nla_put_u32(skb, TCA_IPT_HOOK, ipt->tcfi_hook) ||
	    nla_put(skb, TCA_IPT_CNT, sizeof(struct tc_cnt), &c) ||
	    nla_put_string(skb, TCA_IPT_TABLE, ipt->tcfi_tname))
		goto nla_put_failure;
	tm.install = jiffies_to_clock_t(jiffies - ipt->tcf_tm.install);
	tm.lastuse = jiffies_to_clock_t(jiffies - ipt->tcf_tm.lastuse);
	tm.expires = jiffies_to_clock_t(ipt->tcf_tm.expires);
	if (nla_put(skb, TCA_IPT_TM, sizeof (tm), &tm))
		goto nla_put_failure;
	kfree(t);
	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	kfree(t);
	return -1;
}