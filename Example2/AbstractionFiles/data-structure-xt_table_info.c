// x_tables.h (line188) – Used as part of the table struct

/* Furniture shopping... */
struct xt_table {
     struct list_head list;
     /* What hooks you will enter on */
     unsigned int valid_hooks;
     /* Man behind the curtain... */
     struct xt_table_info *private;
     /* Set this to THIS_MODULE if you are a module, otherwise NULL */
     struct module *me;
     u_int8_t af;            /* address/protocol family */
     int priority;           /* hook order */
     /* called when table is needed in the given netns */
     int (*table_init)(struct net *net);
     /* A unique name... */
     const char name[XT_TABLE_MAXNAMELEN];
};


// arp_tables.c (line249) – accessed by using the base of the entries

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

// arp_table.c (line237)
static inline struct arpt_entry *
get_entry(const void *base, unsigned int offset)
{
     return (struct arpt_entry *)(base + offset);
}


// arp_table.c (line373)
// ip_tables.c (line449)
 
/* Figures out from what hook each rule can be called: returns 0 if
* there are loops.  Puts hook bitmask in comefrom.
*/
static int mark_source_chains(const struct xt_table_info *newinfo,
                       unsigned int valid_hooks, void *entry0)
{
     unsigned int hook;
 
     /* No recursion; use packet counter to save back ptrs (reset
      * to 0 as we leave), and comefrom to save source hook bitmask.
      */
     for (hook = 0; hook < NF_ARP_NUMHOOKS; hook++) {
           unsigned int pos = newinfo->hook_entry[hook];
           struct arpt_entry *e
                 = (struct arpt_entry *)(entry0 + pos);
 
           if (!(valid_hooks & (1 << hook)))
                 continue;
 
           /* Set initial back pointer. */
           e->counters.pcnt = pos;
 
           for (;;) {
                 const struct xt_standard_target *t
                       = (void *)arpt_get_target_c(e);
                 int visited = e->comefrom & (1 << hook);
 
                 if (e->comefrom & (1 << NF_ARP_NUMHOOKS)) {
                       pr_notice("arptables: loop hook %u pos %u %08X.\n",
                              hook, pos, e->comefrom);
                       return 0;
                 }
                 e->comefrom
                       |= ((1 << hook) | (1 << NF_ARP_NUMHOOKS));
 
                 /* Unconditional return/END. */
                 if ((unconditional(e) &&
                      (strcmp(t->target.u.user.name,
                            XT_STANDARD_TARGET) == 0) &&
                      t->verdict < 0) || visited) {
                       unsigned int oldpos, size;
 
                       if ((strcmp(t->target.u.user.name,
                                 XT_STANDARD_TARGET) == 0) &&
                           t->verdict < -NF_MAX_VERDICT - 1) {
                             duprintf("mark_source_chains: bad "
                                   "negative verdict (%i)\n",
                                               t->verdict);
                             return 0;
                       }
 
                       /* Return: backtrack through the last
                        * big jump.
                        */
                       do {
                             e->comefrom ^= (1<<NF_ARP_NUMHOOKS);
                             oldpos = pos;
                             pos = e->counters.pcnt;
                             e->counters.pcnt = 0;
 
                             /* We're at the start. */
                             if (pos == oldpos)
                                   goto next;
 
                             e = (struct arpt_entry *)
                                   (entry0 + pos);
                       } while (oldpos == pos + e->next_offset);
 
                       /* Move along one */
                       size = e->next_offset;
                       e = (struct arpt_entry *)
                             (entry0 + pos + size);
                       e->counters.pcnt = pos;
                       pos += size;
                 } else {
                       int newpos = t->verdict;
 
                       if (strcmp(t->target.u.user.name,
                                XT_STANDARD_TARGET) == 0 &&
                           newpos >= 0) {
                             if (newpos > newinfo->size -
                                   sizeof(struct arpt_entry)) {
                                   duprintf("mark_source_chains: "
                                         "bad verdict (%i)\n",
                                               newpos);
                                   return 0;
                             }
 
                             /* This a jump; chase it. */
                             duprintf("Jump rule %u -> %u\n",
                                    pos, newpos);
                       } else {
                             /* ... this is a fallthru */
                             newpos = pos + e->next_offset;
                       }
                       e = (struct arpt_entry *)
                             (entry0 + newpos);
                       e->counters.pcnt = pos;
                       pos = newpos;
                 }
           }
next:
           duprintf("Finished chain %u\n", hook);
     }
     return 1;
}

// arp_table.c (line564)
// ip_tables.c (line727)
 
static inline int check_entry_size_and_hooks(struct arpt_entry *e,
                                  struct xt_table_info *newinfo,
                                  const unsigned char *base,
                                  const unsigned char *limit,
                                  const unsigned int *hook_entries,
                                  const unsigned int *underflows,
                                  unsigned int valid_hooks)
{
     unsigned int h;
     int err;
 
     if ((unsigned long)e % __alignof__(struct arpt_entry) != 0 ||
         (unsigned char *)e + sizeof(struct arpt_entry) >= limit ||
         (unsigned char *)e + e->next_offset > limit) {
           duprintf("Bad offset %p\n", e);
           return -EINVAL;
     }
 
     if (e->next_offset
         < sizeof(struct arpt_entry) + sizeof(struct xt_entry_target)) {
           duprintf("checking: element %p size %u\n",
                  e, e->next_offset);
           return -EINVAL;
     }
 
     err = check_entry(e);
     if (err)
           return err;
 
     /* Check hooks & underflows */
     for (h = 0; h < NF_ARP_NUMHOOKS; h++) {
           if (!(valid_hooks & (1 << h)))
                 continue;
           if ((unsigned char *)e - base == hook_entries[h])
                 newinfo->hook_entry[h] = hook_entries[h];
           if ((unsigned char *)e - base == underflows[h]) {
                 if (!check_underflow(e)) {
                       pr_debug("Underflows must be unconditional and "
                              "use the STANDARD target with "
                              "ACCEPT/DROP\n");
                       return -EINVAL;
                 }
                 newinfo->underflow[h] = underflows[h];
           }
     }
 
     /* Clear counters and comefrom */
     e->counters = ((struct xt_counters) { 0, 0 });
     e->comefrom = 0;
     return 0;
}

// arp_table.c (line634)
// ip_tables.c (line805)
/* Checks and translates the user-supplied table segment (held in
* newinfo).
*/
static int translate_table(struct xt_table_info *newinfo, void *entry0,
                    const struct arpt_replace *repl)
{
     struct arpt_entry *iter;
     unsigned int i;
     int ret = 0;
 
     newinfo->size = repl->size;
     newinfo->number = repl->num_entries;
 
     /* Init all hooks to impossible value. */
     for (i = 0; i < NF_ARP_NUMHOOKS; i++) {
           newinfo->hook_entry[i] = 0xFFFFFFFF;
           newinfo->underflow[i] = 0xFFFFFFFF;
     }
 
     duprintf("translate_table: size %u\n", newinfo->size);
     i = 0;
 
     /* Walk through entries, checking offsets. */
     xt_entry_foreach(iter, entry0, newinfo->size) {
           ret = check_entry_size_and_hooks(iter, newinfo, entry0,
                                    entry0 + repl->size,
                                    repl->hook_entry,
                                    repl->underflow,
                                    repl->valid_hooks);
           if (ret != 0)
                 break;
           ++i;
           if (strcmp(arpt_get_target(iter)->u.user.name,
               XT_ERROR_TARGET) == 0)
                 ++newinfo->stacksize;
     }
     duprintf("translate_table: ARPT_ENTRY_ITERATE gives %d\n", ret);
     if (ret != 0)
           return ret;
 
     if (i != repl->num_entries) {
           duprintf("translate_table: %u not %u entries\n",
                  i, repl->num_entries);
           return -EINVAL;
     }
 
     /* Check hooks all assigned */
     for (i = 0; i < NF_ARP_NUMHOOKS; i++) {
           /* Only hooks which are valid */
           if (!(repl->valid_hooks & (1 << i)))
                 continue;
           if (newinfo->hook_entry[i] == 0xFFFFFFFF) {
                 duprintf("Invalid hook entry %u %u\n",
                        i, repl->hook_entry[i]);
                 return -EINVAL;
           }
           if (newinfo->underflow[i] == 0xFFFFFFFF) {
                 duprintf("Invalid underflow %u %u\n",
                        i, repl->underflow[i]);
                 return -EINVAL;
           }
     }
 
     if (!mark_source_chains(newinfo, repl->valid_hooks, entry0)) {
           duprintf("Looping hook\n");
           return -ELOOP;
     }
 
     /* Finally, each sanity check must pass */
     i = 0;
     xt_entry_foreach(iter, entry0, newinfo->size) {
           ret = find_check_entry(iter, repl->name, repl->size);
           if (ret != 0)
                 break;
           ++i;
     }
 
     if (ret != 0) {
           xt_entry_foreach(iter, entry0, newinfo->size) {
                 if (i-- == 0)
                       break;
                 cleanup_entry(iter);
           }
           return ret;
     }
 
     return ret;
}










// arp_table.c (line720)
// ip_tables.c (line885)
 
static void get_counters(const struct xt_table_info *t,
                  struct xt_counters counters[])
{
     struct arpt_entry *iter;
     unsigned int cpu;
     unsigned int i;
 
     for_each_possible_cpu(cpu) {
           seqcount_t *s = &per_cpu(xt_recseq, cpu);
 
           i = 0;
           xt_entry_foreach(iter, t->entries, t->size) {
                 struct xt_counters *tmp;
                 u64 bcnt, pcnt;
                 unsigned int start;
 
                 tmp = xt_get_per_cpu_counter(&iter->counters, cpu);
                 do {
                       start = read_seqcount_begin(s);
                       bcnt = tmp->bcnt;
                       pcnt = tmp->pcnt;
                 } while (read_seqcount_retry(s, start));
 
                 ADD_COUNTER(counters[i], bcnt, pcnt);
                 ++i;
           }
     }
}

// arp_table.c (line749)
// ip_tables.c (line915)
 
static struct xt_counters *alloc_counters(const struct xt_table *table)
{
     unsigned int countersize;
     struct xt_counters *counters;
     const struct xt_table_info *private = table->private;
 
     /* We need atomic snapshot of counters: rest doesn't change
      * (other than comefrom, which userspace doesn't care
      * about).
      */
     countersize = sizeof(struct xt_counters) * private->number;
     counters = vzalloc(countersize);
 
     if (counters == NULL)
           return ERR_PTR(-ENOMEM);
 
     get_counters(private, counters);
 
     return counters;
}

// arp_table.c (line770)
// ip_tables.c (line935)
static int copy_entries_to_user(unsigned int total_size,
                       const struct xt_table *table,
                       void __user *userptr)
{
     unsigned int off, num;
     const struct arpt_entry *e;
     struct xt_counters *counters;
     struct xt_table_info *private = table->private;
     int ret = 0;
     void *loc_cpu_entry;
 
     counters = alloc_counters(table);
     if (IS_ERR(counters))
           return PTR_ERR(counters);
 
     loc_cpu_entry = private->entries;
     /* ... then copy entire thing ... */
     if (copy_to_user(userptr, loc_cpu_entry, total_size) != 0) {
           ret = -EFAULT;
           goto free_counters;
     }
 
     /* FIXME: use iterator macros --RR */
     /* ... then go back and fix counters and names */
     for (off = 0, num = 0; off < total_size; off += e->next_offset, num++){
           const struct xt_entry_target *t;
 
           e = (struct arpt_entry *)(loc_cpu_entry + off);
           if (copy_to_user(userptr + off
                        + offsetof(struct arpt_entry, counters),
                        &counters[num],
                        sizeof(counters[num])) != 0) {
                 ret = -EFAULT;
                 goto free_counters;
           }
 
           t = arpt_get_target_c(e);
           if (copy_to_user(userptr + off + e->target_offset
                        + offsetof(struct xt_entry_target,
                                 u.user.name),
                        t->u.kernel.target->name,
                        strlen(t->u.kernel.target->name)+1) != 0) {
                 ret = -EFAULT;
                 goto free_counters;
           }
     }
 
free_counters:
     vfree(counters);
     return ret;
}

// arp_table.c (line841)
// ip_tables.c (line1024)
static int compat_calc_entry(const struct arpt_entry *e,
                      const struct xt_table_info *info,
                      const void *base, struct xt_table_info *newinfo)
{
     const struct xt_entry_target *t;
     unsigned int entry_offset;
     int off, i, ret;
 
     off = sizeof(struct arpt_entry) - sizeof(struct compat_arpt_entry);
     entry_offset = (void *)e - base;
 
     t = arpt_get_target_c(e);
     off += xt_compat_target_offset(t->u.kernel.target);
     newinfo->size -= off;
     ret = xt_compat_add_offset(NFPROTO_ARP, entry_offset, off);
     if (ret)
           return ret;
 
     for (i = 0; i < NF_ARP_NUMHOOKS; i++) {
           if (info->hook_entry[i] &&
               (e < (struct arpt_entry *)(base + info->hook_entry[i])))
                 newinfo->hook_entry[i] -= off;
           if (info->underflow[i] &&
               (e < (struct arpt_entry *)(base + info->underflow[i])))
                 newinfo->underflow[i] -= off;
     }
     return 0;
}

// arp_table.c (line870)
// ip_tables.c (line1055)
static int compat_table_info(const struct xt_table_info *info,
                      struct xt_table_info *newinfo)
{
     struct arpt_entry *iter;
     const void *loc_cpu_entry;
     int ret;
 
     if (!newinfo || !info)
           return -EINVAL;
 
     /* we dont care about newinfo->entries */
     memcpy(newinfo, info, offsetof(struct xt_table_info, entries));
     newinfo->initial_entries = 0;
     loc_cpu_entry = info->entries;
     xt_compat_init_offsets(NFPROTO_ARP, info->number);
     xt_entry_foreach(iter, loc_cpu_entry, info->size) {
           ret = compat_calc_entry(iter, info, loc_cpu_entry, newinfo);
           if (ret != 0)
                 return ret;
     }
     return 0;
}

// arp_table.c (line894)
// ip_tables.c (line1079)
static int get_info(struct net *net, void __user *user,
               const int *len, int compat)
{
     char name[XT_TABLE_MAXNAMELEN];
     struct xt_table *t;
     int ret;
 
     if (*len != sizeof(struct arpt_getinfo)) {
           duprintf("length %u != %Zu\n", *len,
                  sizeof(struct arpt_getinfo));
           return -EINVAL;
     }
 
     if (copy_from_user(name, user, sizeof(name)) != 0)
           return -EFAULT;
 
     name[XT_TABLE_MAXNAMELEN-1] = '\0';
#ifdef CONFIG_COMPAT
     if (compat)
           xt_compat_lock(NFPROTO_ARP);
#endif
     t = try_then_request_module(xt_find_table_lock(net, NFPROTO_ARP, name),
                           "arptable_%s", name);
     if (!IS_ERR_OR_NULL(t)) {
           struct arpt_getinfo info;
           const struct xt_table_info *private = t->private;
#ifdef CONFIG_COMPAT
           struct xt_table_info tmp;
 
           if (compat) {
                 ret = compat_table_info(private, &tmp);
                 xt_compat_flush_offsets(NFPROTO_ARP);
                 private = &tmp;
           }
#endif
           memset(&info, 0, sizeof(info));
           info.valid_hooks = t->valid_hooks;
           memcpy(info.hook_entry, private->hook_entry,
                  sizeof(info.hook_entry));
           memcpy(info.underflow, private->underflow,
                  sizeof(info.underflow));
           info.num_entries = private->number;
           info.size = private->size;
           strcpy(info.name, name);
 
           if (copy_to_user(user, &info, *len) != 0)
                 ret = -EFAULT;
           else
                 ret = 0;
           xt_table_unlock(t);
           module_put(t->me);
     } else
           ret = t ? PTR_ERR(t) : -ENOENT;
#ifdef CONFIG_COMPAT
     if (compat)
           xt_compat_unlock(NFPROTO_ARP);
#endif
     return ret;
}

// arp_table.c (line954)
static int get_entries(struct net *net, struct arpt_get_entries __user *uptr,
                  const int *len)
{
     int ret;
     struct arpt_get_entries get;
     struct xt_table *t;
 
     if (*len < sizeof(get)) {
           duprintf("get_entries: %u < %Zu\n", *len, sizeof(get));
           return -EINVAL;
     }
     if (copy_from_user(&get, uptr, sizeof(get)) != 0)
           return -EFAULT;
     if (*len != sizeof(struct arpt_get_entries) + get.size) {
           duprintf("get_entries: %u != %Zu\n", *len,
                  sizeof(struct arpt_get_entries) + get.size);
           return -EINVAL;
     }
 
     t = xt_find_table_lock(net, NFPROTO_ARP, get.name);
     if (!IS_ERR_OR_NULL(t)) {
           const struct xt_table_info *private = t->private;
 
           duprintf("t->private->number = %u\n",
                  private->number);
           if (get.size == private->size)
                 ret = copy_entries_to_user(private->size,
                                      t, uptr->entrytable);
           else {
                 duprintf("get_entries: I've got %u not %u!\n",
                        private->size, get.size);
                 ret = -EAGAIN;
           }
           module_put(t->me);
           xt_table_unlock(t);
     } else
           ret = t ? PTR_ERR(t) : -ENOENT;
 
     return ret;
}

// arp_table.c (line995)
// ip_tables.c (line1180)
static int __do_replace(struct net *net, const char *name,
                 unsigned int valid_hooks,
                 struct xt_table_info *newinfo,
                 unsigned int num_counters,
                 void __user *counters_ptr)
{
     int ret;
     struct xt_table *t;
     struct xt_table_info *oldinfo;
     struct xt_counters *counters;
     void *loc_cpu_old_entry;
     struct arpt_entry *iter;
 
     ret = 0;
     counters = vzalloc(num_counters * sizeof(struct xt_counters));
     if (!counters) {
           ret = -ENOMEM;
           goto out;
     }
 
     t = try_then_request_module(xt_find_table_lock(net, NFPROTO_ARP, name),
                           "arptable_%s", name);
     if (IS_ERR_OR_NULL(t)) {
           ret = t ? PTR_ERR(t) : -ENOENT;
           goto free_newinfo_counters_untrans;
     }
 
     /* You lied! */
     if (valid_hooks != t->valid_hooks) {
           duprintf("Valid hook crap: %08X vs %08X\n",
                  valid_hooks, t->valid_hooks);
           ret = -EINVAL;
           goto put_module;
     }
 
     oldinfo = xt_replace_table(t, num_counters, newinfo, &ret);
     if (!oldinfo)
           goto put_module;
 
     /* Update module usage count based on number of rules */
     duprintf("do_replace: oldnum=%u, initnum=%u, newnum=%u\n",
           oldinfo->number, oldinfo->initial_entries, newinfo->number);
     if ((oldinfo->number > oldinfo->initial_entries) ||
         (newinfo->number <= oldinfo->initial_entries))
           module_put(t->me);
     if ((oldinfo->number > oldinfo->initial_entries) &&
         (newinfo->number <= oldinfo->initial_entries))
           module_put(t->me);
 
     /* Get the old counters, and synchronize with replace */
     get_counters(oldinfo, counters);
 
     /* Decrease module usage counts and free resource */
     loc_cpu_old_entry = oldinfo->entries;
     xt_entry_foreach(iter, loc_cpu_old_entry, oldinfo->size)
           cleanup_entry(iter);
 
     xt_free_table_info(oldinfo);
     if (copy_to_user(counters_ptr, counters,
                  sizeof(struct xt_counters) * num_counters) != 0) {
           /* Silent error, can't fail, new table is already in place */
           net_warn_ratelimited("arptables: counters copy to user failed while replacing table\n");
     }
     vfree(counters);
     xt_table_unlock(t);
     return ret;
 
put_module:
     module_put(t->me);
     xt_table_unlock(t);
free_newinfo_counters_untrans:
     vfree(counters);
out:
     return ret;
}

// arp_table.c (line1071)
// ip_tables.c (line1253)
static int do_replace(struct net *net, const void __user *user,
                 unsigned int len)
{
     int ret;
     struct arpt_replace tmp;
     struct xt_table_info *newinfo;
     void *loc_cpu_entry;
     struct arpt_entry *iter;
 
     if (copy_from_user(&tmp, user, sizeof(tmp)) != 0)
           return -EFAULT;
 
     /* overflow check */
     if (tmp.num_counters >= INT_MAX / sizeof(struct xt_counters))
           return -ENOMEM;
     if (tmp.num_counters == 0)
           return -EINVAL;
 
     tmp.name[sizeof(tmp.name)-1] = 0;
     newinfo = xt_alloc_table_info(tmp.size);
     if (!newinfo)
           return -ENOMEM;
 
     loc_cpu_entry = newinfo->entries;
     if (copy_from_user(loc_cpu_entry, user + sizeof(tmp),
                    tmp.size) != 0) {
           ret = -EFAULT;
           goto free_newinfo;
     }
 
     ret = translate_table(newinfo, loc_cpu_entry, &tmp);
     if (ret != 0)
           goto free_newinfo;
 
     duprintf("arp_tables: Translated table\n");
 
     ret = __do_replace(net, tmp.name, tmp.valid_hooks, newinfo,
                    tmp.num_counters, tmp.counters);
     if (ret)
           goto free_newinfo_untrans;
     return 0;
 
free_newinfo_untrans:
     xt_entry_foreach(iter, loc_cpu_entry, newinfo->size)
           cleanup_entry(iter);
free_newinfo:
     xt_free_table_info(newinfo);
     return ret;
}
// arp_table.c (line1122)
// ip_tables.c (line1304)
static int do_add_counters(struct net *net, const void __user *user,
                    unsigned int len, int compat)
{
     unsigned int i;
     struct xt_counters_info tmp;
     struct xt_counters *paddc;
     unsigned int num_counters;
     const char *name;
     int size;
     void *ptmp;
     struct xt_table *t;
     const struct xt_table_info *private;
     int ret = 0;
     struct arpt_entry *iter;
     unsigned int addend;
#ifdef CONFIG_COMPAT
     struct compat_xt_counters_info compat_tmp;
 
     if (compat) {
           ptmp = &compat_tmp;
           size = sizeof(struct compat_xt_counters_info);
     } else
#endif
     {
           ptmp = &tmp;
           size = sizeof(struct xt_counters_info);
     }
 
     if (copy_from_user(ptmp, user, size) != 0)
           return -EFAULT;
 
#ifdef CONFIG_COMPAT
     if (compat) {
           num_counters = compat_tmp.num_counters;
           name = compat_tmp.name;
     } else
#endif
     {
           num_counters = tmp.num_counters;
           name = tmp.name;
     }
 
     if (len != size + num_counters * sizeof(struct xt_counters))
           return -EINVAL;
 
     paddc = vmalloc(len - size);
     if (!paddc)
           return -ENOMEM;
 
     if (copy_from_user(paddc, user + size, len - size) != 0) {
           ret = -EFAULT;
           goto free;
     }
 
     t = xt_find_table_lock(net, NFPROTO_ARP, name);
     if (IS_ERR_OR_NULL(t)) {
           ret = t ? PTR_ERR(t) : -ENOENT;
           goto free;
     }
 
     local_bh_disable();
     private = t->private;
     if (private->number != num_counters) {
           ret = -EINVAL;
           goto unlock_up_free;
     }
 
     i = 0;
 
     addend = xt_write_recseq_begin();
     xt_entry_foreach(iter,  private->entries, private->size) {
           struct xt_counters *tmp;
 
           tmp = xt_get_this_cpu_counter(&iter->counters);
           ADD_COUNTER(*tmp, paddc[i].bcnt, paddc[i].pcnt);
           ++i;
     }
     xt_write_recseq_end(addend);
unlock_up_free:
     local_bh_enable();
     xt_table_unlock(t);
     module_put(t->me);
free:
     vfree(paddc);
 
     return ret;
}


// arp_table.c (line1219)
static inline int
check_compat_entry_size_and_hooks(struct compat_arpt_entry *e,
                         struct xt_table_info *newinfo,
                         unsigned int *size,
                         const unsigned char *base,
                         const unsigned char *limit,
                         const unsigned int *hook_entries,
                         const unsigned int *underflows,
                         const char *name)
{
     struct xt_entry_target *t;
     struct xt_target *target;
     unsigned int entry_offset;
     int ret, off, h;
 
     duprintf("check_compat_entry_size_and_hooks %p\n", e);
     if ((unsigned long)e % __alignof__(struct compat_arpt_entry) != 0 ||
         (unsigned char *)e + sizeof(struct compat_arpt_entry) >= limit ||
         (unsigned char *)e + e->next_offset > limit) {
           duprintf("Bad offset %p, limit = %p\n", e, limit);
           return -EINVAL;
     }
 
     if (e->next_offset < sizeof(struct compat_arpt_entry) +
                      sizeof(struct compat_xt_entry_target)) {
           duprintf("checking: element %p size %u\n",
                  e, e->next_offset);
           return -EINVAL;
     }
 
     /* For purposes of check_entry casting the compat entry is fine */
     ret = check_entry((struct arpt_entry *)e);
     if (ret)
           return ret;
 
     off = sizeof(struct arpt_entry) - sizeof(struct compat_arpt_entry);
     entry_offset = (void *)e - (void *)base;
 
     t = compat_arpt_get_target(e);
     target = xt_request_find_target(NFPROTO_ARP, t->u.user.name,
                             t->u.user.revision);
     if (IS_ERR(target)) {
           duprintf("check_compat_entry_size_and_hooks: `%s' not found\n",
                  t->u.user.name);
           ret = PTR_ERR(target);
           goto out;
     }
     t->u.kernel.target = target;
 
     off += xt_compat_target_offset(target);
     *size += off;
     ret = xt_compat_add_offset(NFPROTO_ARP, entry_offset, off);
     if (ret)
           goto release_target;
 
     /* Check hooks & underflows */
     for (h = 0; h < NF_ARP_NUMHOOKS; h++) {
           if ((unsigned char *)e - base == hook_entries[h])
                 newinfo->hook_entry[h] = hook_entries[h];
           if ((unsigned char *)e - base == underflows[h])
                 newinfo->underflow[h] = underflows[h];
     }
 
     /* Clear counters and comefrom */
     memset(&e->counters, 0, sizeof(e->counters));
     e->comefrom = 0;
     return 0;
 
release_target:
     module_put(t->u.kernel.target->me);
out:
     return ret;
}


// arp_table.c (line1293)
static int
compat_copy_entry_from_user(struct compat_arpt_entry *e, void **dstptr,
                     unsigned int *size, const char *name,
                     struct xt_table_info *newinfo, unsigned char *base)
{
     struct xt_entry_target *t;
     struct xt_target *target;
     struct arpt_entry *de;
     unsigned int origsize;
     int ret, h;
 
     ret = 0;
     origsize = *size;
     de = (struct arpt_entry *)*dstptr;
     memcpy(de, e, sizeof(struct arpt_entry));
     memcpy(&de->counters, &e->counters, sizeof(e->counters));
 
     *dstptr += sizeof(struct arpt_entry);
     *size += sizeof(struct arpt_entry) - sizeof(struct compat_arpt_entry);
 
     de->target_offset = e->target_offset - (origsize - *size);
     t = compat_arpt_get_target(e);
     target = t->u.kernel.target;
     xt_compat_target_from_user(t, dstptr, size);
 
     de->next_offset = e->next_offset - (origsize - *size);
     for (h = 0; h < NF_ARP_NUMHOOKS; h++) {
           if ((unsigned char *)de - base < newinfo->hook_entry[h])
                 newinfo->hook_entry[h] -= origsize - *size;
           if ((unsigned char *)de - base < newinfo->underflow[h])
                 newinfo->underflow[h] -= origsize - *size;
     }
     return ret;
}


// arp_table.c (line1328)
// ip_tables.c (line1648)
static int translate_compat_table(const char *name,
                         unsigned int valid_hooks,
                         struct xt_table_info **pinfo,
                         void **pentry0,
                         unsigned int total_size,
                         unsigned int number,
                         unsigned int *hook_entries,
                         unsigned int *underflows)
{
     unsigned int i, j;
     struct xt_table_info *newinfo, *info;
     void *pos, *entry0, *entry1;
     struct compat_arpt_entry *iter0;
     struct arpt_entry *iter1;
     unsigned int size;
     int ret = 0;
 
     info = *pinfo;
     entry0 = *pentry0;
     size = total_size;
     info->number = number;
 
     /* Init all hooks to impossible value. */
     for (i = 0; i < NF_ARP_NUMHOOKS; i++) {
           info->hook_entry[i] = 0xFFFFFFFF;
           info->underflow[i] = 0xFFFFFFFF;
     }
 
     duprintf("translate_compat_table: size %u\n", info->size);
     j = 0;
     xt_compat_lock(NFPROTO_ARP);
     xt_compat_init_offsets(NFPROTO_ARP, number);
     /* Walk through entries, checking offsets. */
     xt_entry_foreach(iter0, entry0, total_size) {
           ret = check_compat_entry_size_and_hooks(iter0, info, &size,
                                         entry0,
                                         entry0 + total_size,
                                         hook_entries,
                                         underflows,
                                         name);
           if (ret != 0)
                 goto out_unlock;
           ++j;
     }
 
     ret = -EINVAL;
     if (j != number) {
           duprintf("translate_compat_table: %u not %u entries\n",
                  j, number);
           goto out_unlock;
     }
 
     /* Check hooks all assigned */
     for (i = 0; i < NF_ARP_NUMHOOKS; i++) {
           /* Only hooks which are valid */
           if (!(valid_hooks & (1 << i)))
                 continue;
           if (info->hook_entry[i] == 0xFFFFFFFF) {
                 duprintf("Invalid hook entry %u %u\n",
                        i, hook_entries[i]);
                 goto out_unlock;
           }
           if (info->underflow[i] == 0xFFFFFFFF) {
                 duprintf("Invalid underflow %u %u\n",
                        i, underflows[i]);
                 goto out_unlock;
           }
     }
 
     ret = -ENOMEM;
     newinfo = xt_alloc_table_info(size);
     if (!newinfo)
           goto out_unlock;
 
     newinfo->number = number;
     for (i = 0; i < NF_ARP_NUMHOOKS; i++) {
           newinfo->hook_entry[i] = info->hook_entry[i];
           newinfo->underflow[i] = info->underflow[i];
     }
     entry1 = newinfo->entries;
     pos = entry1;
     size = total_size;
     xt_entry_foreach(iter0, entry0, total_size) {
           ret = compat_copy_entry_from_user(iter0, &pos, &size,
                                     name, newinfo, entry1);
           if (ret != 0)
                 break;
     }
     xt_compat_flush_offsets(NFPROTO_ARP);
     xt_compat_unlock(NFPROTO_ARP);
     if (ret)
           goto free_newinfo;
 
     ret = -ELOOP;
     if (!mark_source_chains(newinfo, valid_hooks, entry1))
           goto free_newinfo;
 
     i = 0;
     xt_entry_foreach(iter1, entry1, newinfo->size) {
           iter1->counters.pcnt = xt_percpu_counter_alloc();
           if (IS_ERR_VALUE(iter1->counters.pcnt)) {
                 ret = -ENOMEM;
                 break;
           }
 
           ret = check_target(iter1, name);
           if (ret != 0) {
                 xt_percpu_counter_free(iter1->counters.pcnt);
                 break;
           }
           ++i;
           if (strcmp(arpt_get_target(iter1)->u.user.name,
               XT_ERROR_TARGET) == 0)
                 ++newinfo->stacksize;
     }
     if (ret) {
           /*
            * The first i matches need cleanup_entry (calls ->destroy)
            * because they had called ->check already. The other j-i
            * entries need only release.
            */
           int skip = i;
           j -= i;
           xt_entry_foreach(iter0, entry0, newinfo->size) {
                 if (skip-- > 0)
                       continue;
                 if (j-- == 0)
                       break;
                 compat_release_entry(iter0);
           }
           xt_entry_foreach(iter1, entry1, newinfo->size) {
                 if (i-- == 0)
                       break;
                 cleanup_entry(iter1);
           }
           xt_free_table_info(newinfo);
           return ret;
     }
 
     *pinfo = newinfo;
     *pentry0 = entry1;
     xt_free_table_info(info);
     return 0;
 
free_newinfo:
     xt_free_table_info(newinfo);
out:
     xt_entry_foreach(iter0, entry0, total_size) {
           if (j-- == 0)
                 break;
           compat_release_entry(iter0);
     }
     return ret;
out_unlock:
     xt_compat_flush_offsets(NFPROTO_ARP);
     xt_compat_unlock(NFPROTO_ARP);
     goto out;
}

// arp_table.c (line1499)
// ip_tables.c (line1800)
static int compat_do_replace(struct net *net, void __user *user,
                      unsigned int len)
{
     int ret;
     struct compat_arpt_replace tmp;
     struct xt_table_info *newinfo;
     void *loc_cpu_entry;
     struct arpt_entry *iter;
 
     if (copy_from_user(&tmp, user, sizeof(tmp)) != 0)
           return -EFAULT;
 
     /* overflow check */
     if (tmp.size >= INT_MAX / num_possible_cpus())
           return -ENOMEM;
     if (tmp.num_counters >= INT_MAX / sizeof(struct xt_counters))
           return -ENOMEM;
     if (tmp.num_counters == 0)
           return -EINVAL;
 
     tmp.name[sizeof(tmp.name)-1] = 0;
 
     newinfo = xt_alloc_table_info(tmp.size);
     if (!newinfo)
           return -ENOMEM;
 
     loc_cpu_entry = newinfo->entries;
     if (copy_from_user(loc_cpu_entry, user + sizeof(tmp), tmp.size) != 0) {
           ret = -EFAULT;
           goto free_newinfo;
     }
 
     ret = translate_compat_table(tmp.name, tmp.valid_hooks,
                            &newinfo, &loc_cpu_entry, tmp.size,
                            tmp.num_entries, tmp.hook_entry,
                            tmp.underflow);
     if (ret != 0)
           goto free_newinfo;
 
     duprintf("compat_do_replace: Translated table\n");
 
     ret = __do_replace(net, tmp.name, tmp.valid_hooks, newinfo,
                    tmp.num_counters, compat_ptr(tmp.counters));
     if (ret)
           goto free_newinfo_untrans;
     return 0;
 
free_newinfo_untrans:
     xt_entry_foreach(iter, loc_cpu_entry, newinfo->size)
           cleanup_entry(iter);
free_newinfo:
     xt_free_table_info(newinfo);
     return ret;
}


// arp_table.c (line1613)
static int compat_copy_entries_to_user(unsigned int total_size,
                              struct xt_table *table,
                              void __user *userptr)
{
     struct xt_counters *counters;
     const struct xt_table_info *private = table->private;
     void __user *pos;
     unsigned int size;
     int ret = 0;
     unsigned int i = 0;
     struct arpt_entry *iter;
 
     counters = alloc_counters(table);
     if (IS_ERR(counters))
           return PTR_ERR(counters);
 
     pos = userptr;
     size = total_size;
     xt_entry_foreach(iter, private->entries, total_size) {
           ret = compat_copy_entry_to_user(iter, &pos,
                                   &size, counters, i++);
           if (ret != 0)
                 break;
     }
     vfree(counters);
     return ret;
}


// arp_table.c (line1647)
// ip_tables.c (line1917)
static int compat_get_entries(struct net *net,
                       struct compat_arpt_get_entries __user *uptr,
                       int *len)
{
     int ret;
     struct compat_arpt_get_entries get;
     struct xt_table *t;
 
     if (*len < sizeof(get)) {
           duprintf("compat_get_entries: %u < %zu\n", *len, sizeof(get));
           return -EINVAL;
     }
     if (copy_from_user(&get, uptr, sizeof(get)) != 0)
           return -EFAULT;
     if (*len != sizeof(struct compat_arpt_get_entries) + get.size) {
           duprintf("compat_get_entries: %u != %zu\n",
                  *len, sizeof(get) + get.size);
           return -EINVAL;
     }
 
     xt_compat_lock(NFPROTO_ARP);
     t = xt_find_table_lock(net, NFPROTO_ARP, get.name);
     if (!IS_ERR_OR_NULL(t)) {
           const struct xt_table_info *private = t->private;
           struct xt_table_info info;
 
           duprintf("t->private->number = %u\n", private->number);
           ret = compat_table_info(private, &info);
           if (!ret && get.size == info.size) {
                 ret = compat_copy_entries_to_user(private->size,
                                           t, uptr->entrytable);
           } else if (!ret) {
                 duprintf("compat_get_entries: I've got %u not %u!\n",
                        private->size, get.size);
                 ret = -EAGAIN;
           }
           xt_compat_flush_offsets(NFPROTO_ARP);
           module_put(t->me);
           xt_table_unlock(t);
     } else
           ret = t ? PTR_ERR(t) : -ENOENT;
 
     xt_compat_unlock(NFPROTO_ARP);
     return ret;
}

// arp_table.c (line1784)
// ip_tables.c (line2065)
static void __arpt_unregister_table(struct xt_table *table)
{
     struct xt_table_info *private;
     void *loc_cpu_entry;
     struct module *table_owner = table->me;
     struct arpt_entry *iter;
 
     private = xt_unregister_table(table);
 
     /* Decrease module usage counts and free resources */
     loc_cpu_entry = private->entries;
     xt_entry_foreach(iter, loc_cpu_entry, private->size)
           cleanup_entry(iter);
     if (private->number > private->initial_entries)
           module_put(table_owner);
     xt_free_table_info(private);
}
 







// arp_table.c (line1802)
// ip_tables.c (line2083) – ipt_register_table() function name in this file

int arpt_register_table(struct net *net,
                 const struct xt_table *table,
                 const struct arpt_replace *repl,
                 const struct nf_hook_ops *ops,
                 struct xt_table **res)
{
     int ret;
     struct xt_table_info *newinfo;
     struct xt_table_info bootstrap = {0};
     void *loc_cpu_entry;
     struct xt_table *new_table;
 
     newinfo = xt_alloc_table_info(repl->size);
     if (!newinfo)
           return -ENOMEM;
 
     loc_cpu_entry = newinfo->entries;
     memcpy(loc_cpu_entry, repl->entries, repl->size);
 
     ret = translate_table(newinfo, loc_cpu_entry, repl);
     duprintf("arpt_register_table: translate table gives %d\n", ret);
     if (ret != 0)
           goto out_free;
 
     new_table = xt_register_table(net, table, &bootstrap, newinfo);
     if (IS_ERR(new_table)) {
           ret = PTR_ERR(new_table);
           goto out_free;
     }
 
     /* set res now, will see skbs right after nf_register_net_hooks */
     WRITE_ONCE(*res, new_table);
 
     ret = nf_register_net_hooks(net, ops, hweight32(table->valid_hooks));
     if (ret != 0) {
           __arpt_unregister_table(new_table);
           *res = NULL;
     }
 
     return ret;
 
out_free:
     xt_free_table_info(newinfo);
     return ret;
}


================================================================================================================================================
// ip_tables.c (line249)

static void trace_packet(struct net *net,
                  const struct sk_buff *skb,
                  unsigned int hook,
                  const struct net_device *in,
                  const struct net_device *out,
                  const char *tablename,
                  const struct xt_table_info *private,
                  const struct ipt_entry *e)
{
     const struct ipt_entry *root;
     const char *hookname, *chainname, *comment;
     const struct ipt_entry *iter;
     unsigned int rulenum = 0;
 
     root = get_entry(private->entries, private->hook_entry[hook]);
 
     hookname = chainname = hooknames[hook];
     comment = comments[NF_IP_TRACE_COMMENT_RULE];
 
     xt_entry_foreach(iter, root, private->size - private->hook_entry[hook])
           if (get_chainname_rulenum(iter, e, hookname,
               &chainname, &comment, &rulenum) != 0)
                 break;
 
     nf_log_trace(net, AF_INET, hook, skb, in, out, &trace_loginfo,
                "TRACE: %s:%s:%s:%u ",
                tablename, chainname, comment, rulenum);
}

// ip_tables.c (line162)
/* Performance critical */
static inline struct ipt_entry *
get_entry(const void *base, unsigned int offset)
{
     return (struct ipt_entry *)(base + offset);
}

// ip_tables.c (line286)
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





// ip_tables.c (line1024)
static int compat_calc_entry(const struct ipt_entry *e,
                      const struct xt_table_info *info,
                      const void *base, struct xt_table_info *newinfo)
{
     const struct xt_entry_match *ematch;
     const struct xt_entry_target *t;
     unsigned int entry_offset;
     int off, i, ret;
 
     off = sizeof(struct ipt_entry) - sizeof(struct compat_ipt_entry);
     entry_offset = (void *)e - base;
     xt_ematch_foreach(ematch, e)
           off += xt_compat_match_offset(ematch->u.kernel.match);
     t = ipt_get_target_c(e);
     off += xt_compat_target_offset(t->u.kernel.target);
     newinfo->size -= off;
     ret = xt_compat_add_offset(AF_INET, entry_offset, off);
     if (ret)
           return ret;
 
     for (i = 0; i < NF_INET_NUMHOOKS; i++) {
           if (info->hook_entry[i] &&
               (e < (struct ipt_entry *)(base + info->hook_entry[i])))
                 newinfo->hook_entry[i] -= off;
           if (info->underflow[i] &&
               (e < (struct ipt_entry *)(base + info->underflow[i])))
                 newinfo->underflow[i] -= off;
     }
     return 0;
}


// ip_tables.c (line1476)
static int
check_compat_entry_size_and_hooks(struct compat_ipt_entry *e,
                         struct xt_table_info *newinfo,
                         unsigned int *size,
                         const unsigned char *base,
                         const unsigned char *limit,
                         const unsigned int *hook_entries,
                         const unsigned int *underflows,
                         const char *name)
{
     struct xt_entry_match *ematch;
     struct xt_entry_target *t;
     struct xt_target *target;
     unsigned int entry_offset;
     unsigned int j;
     int ret, off, h;
 
     duprintf("check_compat_entry_size_and_hooks %p\n", e);
     if ((unsigned long)e % __alignof__(struct compat_ipt_entry) != 0 ||
         (unsigned char *)e + sizeof(struct compat_ipt_entry) >= limit ||
         (unsigned char *)e + e->next_offset > limit) {
           duprintf("Bad offset %p, limit = %p\n", e, limit);
           return -EINVAL;
     }
 
     if (e->next_offset < sizeof(struct compat_ipt_entry) +
                      sizeof(struct compat_xt_entry_target)) {
           duprintf("checking: element %p size %u\n",
                  e, e->next_offset);
           return -EINVAL;
     }
 
     /* For purposes of check_entry casting the compat entry is fine */
     ret = check_entry((struct ipt_entry *)e);
     if (ret)
           return ret;
 
     off = sizeof(struct ipt_entry) - sizeof(struct compat_ipt_entry);
     entry_offset = (void *)e - (void *)base;
     j = 0;
     xt_ematch_foreach(ematch, e) {
           ret = compat_find_calc_match(ematch, name, &e->ip, &off);
           if (ret != 0)
                 goto release_matches;
           ++j;
     }
 
     t = compat_ipt_get_target(e);
     target = xt_request_find_target(NFPROTO_IPV4, t->u.user.name,
                             t->u.user.revision);
     if (IS_ERR(target)) {
           duprintf("check_compat_entry_size_and_hooks: `%s' not found\n",
                  t->u.user.name);
           ret = PTR_ERR(target);
           goto release_matches;
     }
     t->u.kernel.target = target;
 
     off += xt_compat_target_offset(target);
     *size += off;
     ret = xt_compat_add_offset(AF_INET, entry_offset, off);
     if (ret)
           goto out;
 
     /* Check hooks & underflows */
     for (h = 0; h < NF_INET_NUMHOOKS; h++) {
           if ((unsigned char *)e - base == hook_entries[h])
                 newinfo->hook_entry[h] = hook_entries[h];
           if ((unsigned char *)e - base == underflows[h])
                 newinfo->underflow[h] = underflows[h];
     }
 
     /* Clear counters and comefrom */
     memset(&e->counters, 0, sizeof(e->counters));
     e->comefrom = 0;
     return 0;
 
out:
     module_put(t->u.kernel.target->me);
release_matches:
     xt_ematch_foreach(ematch, e) {
           if (j-- == 0)
                 break;
           module_put(ematch->u.kernel.match->me);
     }
     return ret;
}


// ip_tables.c (line1564)
static int
compat_copy_entry_from_user(struct compat_ipt_entry *e, void **dstptr,
                     unsigned int *size, const char *name,
                     struct xt_table_info *newinfo, unsigned char *base)
{
     struct xt_entry_target *t;
     struct xt_target *target;
     struct ipt_entry *de;
     unsigned int origsize;
     int ret, h;
     struct xt_entry_match *ematch;
 
     ret = 0;
     origsize = *size;
     de = (struct ipt_entry *)*dstptr;
     memcpy(de, e, sizeof(struct ipt_entry));
     memcpy(&de->counters, &e->counters, sizeof(e->counters));
 
     *dstptr += sizeof(struct ipt_entry);
     *size += sizeof(struct ipt_entry) - sizeof(struct compat_ipt_entry);
 
     xt_ematch_foreach(ematch, e) {
           ret = xt_compat_match_from_user(ematch, dstptr, size);
           if (ret != 0)
                 return ret;
     }
     de->target_offset = e->target_offset - (origsize - *size);
     t = compat_ipt_get_target(e);
     target = t->u.kernel.target;
     xt_compat_target_from_user(t, dstptr, size);
 
     de->next_offset = e->next_offset - (origsize - *size);
     for (h = 0; h < NF_INET_NUMHOOKS; h++) {
           if ((unsigned char *)de - base < newinfo->hook_entry[h])
                 newinfo->hook_entry[h] -= origsize - *size;
           if ((unsigned char *)de - base < newinfo->underflow[h])
                 newinfo->underflow[h] -= origsize - *size;
     }
     return ret;
}


// ip_tables.c (line1888)
static int
compat_copy_entries_to_user(unsigned int total_size, struct xt_table *table,
                     void __user *userptr)
{
     struct xt_counters *counters;
     const struct xt_table_info *private = table->private;
     void __user *pos;
     unsigned int size;
     int ret = 0;
     unsigned int i = 0;
     struct ipt_entry *iter;
 
     counters = alloc_counters(table);
     if (IS_ERR(counters))
           return PTR_ERR(counters);
 
     pos = userptr;
     size = total_size;
     xt_entry_foreach(iter, private->entries, total_size) {
           ret = compat_copy_entry_to_user(iter, &pos,
                                   &size, counters, i++);
           if (ret != 0)
                 break;
     }
 
     vfree(counters);
     return ret;
}


=========================================================================

// xt_tables.c (line657)
struct xt_table_info *xt_alloc_table_info(unsigned int size)
{
     struct xt_table_info *info = NULL;
     size_t sz = sizeof(*info) + size;
 
     if (sz < sizeof(*info))
           return NULL;
 
     /* Pedantry: prevent them from hitting BUG() in vmalloc.c --RR */
     if ((SMP_ALIGN(size) >> PAGE_SHIFT) + 2 > totalram_pages)
           return NULL;
 
     if (sz <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER))
           info = kmalloc(sz, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY);
     if (!info) {
           info = vmalloc(sz);
           if (!info)
                 return NULL;
     }
     memset(info, 0, sizeof(*info));
     info->size = size;
     return info;
}

// xt_tables.c (line682)
void xt_free_table_info(struct xt_table_info *info)
{
     int cpu;
 
     if (info->jumpstack != NULL) {
           for_each_possible_cpu(cpu)
                 kvfree(info->jumpstack[cpu]);
           kvfree(info->jumpstack);
     }
 
     kvfree(info);
}


// xt_tables.c (line770)
static int xt_jumpstack_alloc(struct xt_table_info *i)
{
     unsigned int size;
     int cpu;
 
     size = sizeof(void **) * nr_cpu_ids;
     if (size > PAGE_SIZE)
           i->jumpstack = vzalloc(size);
     else
           i->jumpstack = kzalloc(size, GFP_KERNEL);
     if (i->jumpstack == NULL)
           return -ENOMEM;
 
     /* ruleset without jumps -- no stack needed */
     if (i->stacksize == 0)
           return 0;
 
     /* Jumpstack needs to be able to record two full callchains, one
      * from the first rule set traversal, plus one table reentrancy
      * via -j TEE without clobbering the callchain that brought us to
      * TEE target.
      *
      * This is done by allocating two jumpstacks per cpu, on reentry
      * the upper half of the stack is used.
      *
      * see the jumpstack setup in ipt_do_table() for more details.
      */
     size = sizeof(void *) * i->stacksize * 2u;
     for_each_possible_cpu(cpu) {
           if (size > PAGE_SIZE)
                 i->jumpstack[cpu] = vmalloc_node(size,
                       cpu_to_node(cpu));
           else
                 i->jumpstack[cpu] = kmalloc_node(size,
                       GFP_KERNEL, cpu_to_node(cpu));
           if (i->jumpstack[cpu] == NULL)
                 /*
                  * Freeing will be done later on by the callers. The
                  * chain is: xt_replace_table -> __do_replace ->
                  * do_replace -> xt_free_table_info.
                  */
                 return -ENOMEM;
     }
 
     return 0;
}


// xt_tables.c (line770)
struct xt_table_info *
xt_replace_table(struct xt_table *table,
           unsigned int num_counters,
           struct xt_table_info *newinfo,
           int *error)
{
     struct xt_table_info *private;
     int ret;
 
     ret = xt_jumpstack_alloc(newinfo);
     if (ret < 0) {
           *error = ret;
           return NULL;
     }
 
     /* Do the substitution. */
     local_bh_disable();
     private = table->private;
 
     /* Check inside lock: is the old number correct? */
     if (num_counters != private->number) {
           pr_debug("num_counters != table->private->number (%u/%u)\n",
                  num_counters, private->number);
           local_bh_enable();
           *error = -EAGAIN;
           return NULL;
     }
 
     newinfo->initial_entries = private->initial_entries;
     /*
      * Ensure contents of newinfo are visible before assigning to
      * private.
      */
     smp_wmb();
     table->private = newinfo;
 
     /*
      * Even though table entries have now been swapped, other CPU's
      * may still be using the old entries. This is okay, because
      * resynchronization happens because of the locking done
      * during the get_counters() routine.
      */
     local_bh_enable();
 
#ifdef CONFIG_AUDIT
     if (audit_enabled) {
           struct audit_buffer *ab;
 
           ab = audit_log_start(current->audit_context, GFP_KERNEL,
                            AUDIT_NETFILTER_CFG);
           if (ab) {
                 audit_log_format(ab, "table=%s family=%u entries=%u",
                              table->name, table->af,
                              private->number);
                 audit_log_end(ab);
           }
     }
#endif
 
     return private;
}

// xt_tables.c (line880)
struct xt_table *xt_register_table(struct net *net,
                          const struct xt_table *input_table,
                          struct xt_table_info *bootstrap,
                          struct xt_table_info *newinfo)
{
     int ret;
     struct xt_table_info *private;
     struct xt_table *t, *table;
 
     /* Don't add one object to multiple lists. */
     table = kmemdup(input_table, sizeof(struct xt_table), GFP_KERNEL);
     if (!table) {
           ret = -ENOMEM;
           goto out;
     }
 
     mutex_lock(&xt[table->af].mutex);
     /* Don't autoload: we'd eat our tail... */
     list_for_each_entry(t, &net->xt.tables[table->af], list) {
           if (strcmp(t->name, table->name) == 0) {
                 ret = -EEXIST;
                 goto unlock;
           }
     }
 
     /* Simplifies replace_table code. */
     table->private = bootstrap;
 
     if (!xt_replace_table(table, 0, newinfo, &ret))
           goto unlock;
 
     private = table->private;
     pr_debug("table->private->number = %u\n", private->number);
 
     /* save number of initial entries */
     private->initial_entries = private->number;
 
     list_add(&table->list, &net->xt.tables[table->af]);
     mutex_unlock(&xt[table->af].mutex);
     return table;
 
unlock:
     mutex_unlock(&xt[table->af].mutex);
     kfree(table);
out:
     return ERR_PTR(ret);
}


// xt_tables.c (line929)
void *xt_unregister_table(struct xt_table *table)
{
     struct xt_table_info *private;
 
     mutex_lock(&xt[table->af].mutex);
     private = table->private;
     list_del(&table->list);
     mutex_unlock(&xt[table->af].mutex);
     kfree(table);
 
     return private;
}

