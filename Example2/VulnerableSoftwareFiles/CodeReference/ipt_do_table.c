/* Returns one of the generic firewall policies, like NF_ACCEPT. */
unsigned int
ipt_do_table(struct sk_buff *skb,
	     const struct nf_hook_state *state,
	     struct xt_table *table)
{
	unsigned int hook = state->hook;
	static const char nulldevname[IFNAMSIZ] __attribute__((aligned(sizeof(long))));
	const struct iphdr *ip;
	/* Initializing verdict to NF_DROP keeps gcc happy. */
	unsigned int verdict = NF_DROP;
	const char *indev, *outdev;
	const void *table_base;
	struct ipt_entry *e, **jumpstack;
	unsigned int stackidx, cpu;
	const struct xt_table_info *private;
	struct xt_action_param acpar;
	unsigned int addend;

	/* Initialization */
	stackidx = 0;
	ip = ip_hdr(skb);
	indev = state->in ? state->in->name : nulldevname;
	outdev = state->out ? state->out->name : nulldevname;
	/* We handle fragments by dealing with the first fragment as
	 * if it was a normal packet.  All other fragments are treated
	 * normally, except that they will NEVER match rules that ask
	 * things we don't know, ie. tcp syn flag or ports).  If the
	 * rule is also a fragment-specific rule, non-fragments won't
	 * match it. */
	acpar.fragoff = ntohs(ip->frag_off) & IP_OFFSET;
	acpar.thoff   = ip_hdrlen(skb);
	acpar.hotdrop = false;
	acpar.net     = state->net;
	acpar.in      = state->in;
	acpar.out     = state->out;
	acpar.family  = NFPROTO_IPV4;
	acpar.hooknum = hook;

	IP_NF_ASSERT(table->valid_hooks & (1 << hook));
	local_bh_disable();
	addend = xt_write_recseq_begin();
	private = table->private;
	cpu        = smp_processor_id();
	/*
	 * Ensure we load private-> members after we've fetched the base
	 * pointer.
	 */
	smp_read_barrier_depends();
	table_base = private->entries;
	jumpstack  = (struct ipt_entry **)private->jumpstack[cpu];

	/* Switch to alternate jumpstack if we're being invoked via TEE.
	 * TEE issues XT_CONTINUE verdict on original skb so we must not
	 * clobber the jumpstack.
	 *
	 * For recursion via REJECT or SYNPROXY the stack will be clobbered
	 * but it is no problem since absolute verdict is issued by these.
	 */
	if (static_key_false(&xt_tee_enabled))
		jumpstack += private->stacksize * __this_cpu_read(nf_skb_duplicated);

	e = get_entry(table_base, private->hook_entry[hook]);

	pr_debug("Entering %s(hook %u), UF %p\n",
		 table->name, hook,
		 get_entry(table_base, private->underflow[hook]));

	do {
		const struct xt_entry_target *t;
		const struct xt_entry_match *ematch;
		struct xt_counters *counter;

		IP_NF_ASSERT(e);
		if (!ip_packet_match(ip, indev, outdev,
		    &e->ip, acpar.fragoff)) {
 no_match:
			e = ipt_next_entry(e);
			continue;
		}

		xt_ematch_foreach(ematch, e) {
			acpar.match     = ematch->u.kernel.match;
			acpar.matchinfo = ematch->data;
			if (!acpar.match->match(skb, &acpar))
				goto no_match;
		}

		counter = xt_get_this_cpu_counter(&e->counters);
		ADD_COUNTER(*counter, skb->len, 1);

		t = ipt_get_target(e);
		IP_NF_ASSERT(t->u.kernel.target);

#if IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_TRACE)
		/* The packet is traced: log it */
		if (unlikely(skb->nf_trace))
			trace_packet(state->net, skb, hook, state->in,
				     state->out, table->name, private, e);
#endif
		/* Standard target? */
		if (!t->u.kernel.target->target) {
			int v;

			v = ((struct xt_standard_target *)t)->verdict;
			if (v < 0) {
				/* Pop from stack? */
				if (v != XT_RETURN) {
					verdict = (unsigned int)(-v) - 1;
					break;
				}
				if (stackidx == 0) {
					e = get_entry(table_base,
					    private->underflow[hook]);
					pr_debug("Underflow (this is normal) "
						 "to %p\n", e);
				} else {
					e = jumpstack[--stackidx];
					pr_debug("Pulled %p out from pos %u\n",
						 e, stackidx);
					e = ipt_next_entry(e);
				}
				continue;
			}
			if (table_base + v != ipt_next_entry(e) &&
			    !(e->ip.flags & IPT_F_GOTO)) {
				jumpstack[stackidx++] = e;
				pr_debug("Pushed %p into pos %u\n",
					 e, stackidx - 1);
			}

			e = get_entry(table_base, v);
			continue;
		}

		acpar.target   = t->u.kernel.target;
		acpar.targinfo = t->data;

		verdict = t->u.kernel.target->target(skb, &acpar);
		/* Target might have changed stuff. */
		ip = ip_hdr(skb);
		if (verdict == XT_CONTINUE)
			e = ipt_next_entry(e);
		else
			/* Verdict */
			break;
	} while (!acpar.hotdrop);
	pr_debug("Exiting %s; sp at %u\n", __func__, stackidx);

	xt_write_recseq_end(addend);
	local_bh_enable();

#ifdef DEBUG_ALLOW_ALL
	return NF_ACCEPT;
#else
	if (acpar.hotdrop)
		return NF_DROP;
	else return verdict;
#endif
}