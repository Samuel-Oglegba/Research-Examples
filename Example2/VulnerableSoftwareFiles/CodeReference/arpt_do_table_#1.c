unsigned int arpt_do_table(struct sk_buff *skb,
                    const struct nf_hook_state *state,
                    struct xt_table *table)
{
     unsigned int hook = state->hook;
     static const char nulldevname[IFNAMSIZ] __attribute__((aligned(sizeof(long))));
     unsigned int verdict = NF_DROP;
     const struct arphdr *arp;
     struct arpt_entry *e, **jumpstack;
     const char *indev, *outdev;
     const void *table_base;
     unsigned int cpu, stackidx = 0;
     const struct xt_table_info *private;
     struct xt_action_param acpar;
     unsigned int addend;
 
     if (!pskb_may_pull(skb, arp_hdr_len(skb->dev)))
           return NF_DROP;
 
     indev = state->in ? state->in->name : nulldevname;
     outdev = state->out ? state->out->name : nulldevname;
 
     local_bh_disable();
     addend = xt_write_recseq_begin();
     private = table->private;
     cpu     = smp_processor_id();
     /*
      * Ensure we load private-> members after we've fetched the base
      * pointer.
      */
     smp_read_barrier_depends();
     table_base = private->entries;
     jumpstack  = (struct arpt_entry **)private->jumpstack[cpu];
 
     /* No TEE support for arptables, so no need to switch to alternate
      * stack.  All targets that reenter must return absolute verdicts.
      */
     e = get_entry(table_base, private->hook_entry[hook]);
 
     acpar.net     = state->net;
     acpar.in      = state->in;
     acpar.out     = state->out;
     acpar.hooknum = hook;
     acpar.family  = NFPROTO_ARP;
     acpar.hotdrop = false;
 
     arp = arp_hdr(skb);
     do {
           const struct xt_entry_target *t;
           struct xt_counters *counter;
 
           if (!arp_packet_match(arp, skb->dev, indev, outdev, &e->arp)) {
                 e = arpt_next_entry(e);
                 continue;
           }
 
           counter = xt_get_this_cpu_counter(&e->counters);
           ADD_COUNTER(*counter, arp_hdr_len(skb->dev), 1);
 
           t = arpt_get_target_c(e);
 
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
                       } else {
                             e = jumpstack[--stackidx];
                             e = arpt_next_entry(e);
                       }
                       continue;
                 }
                 if (table_base + v
                     != arpt_next_entry(e)) {
                       jumpstack[stackidx++] = e;
                 }
 
                 e = get_entry(table_base, v);
                 continue;
           }
 
           acpar.target   = t->u.kernel.target;
           acpar.targinfo = t->data;
           verdict = t->u.kernel.target->target(skb, &acpar);
 
           /* Target might have changed stuff. */
           arp = arp_hdr(skb);
 
           if (verdict == XT_CONTINUE)
                 e = arpt_next_entry(e);
           else
                 /* Verdict */
                 break;
     } while (!acpar.hotdrop);
     xt_write_recseq_end(addend);
     local_bh_enable();
 
     if (acpar.hotdrop)
           return NF_DROP;
     else
           return verdict;
}
