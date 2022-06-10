### The call sequence as explained in this articale: https://github.com/google/security-research/security/advisories/GHSA-xxx5-8mvq-3528
### the vulnerable function is xt_compat_target_from_user()

### ip_tables.c
      ⇒ case IPT_SO_SET_REPLACE:
              ret = compat_do_replace(sock_net(sk), user, len);

      ⇒ compat_do_replace(struct net *net, void __user *user, unsigned int len)
            
            ret = translate_compat_table(net, tmp.name, tmp.valid_hooks,
                            &newinfo, &loc_cpu_entry, tmp.size,
                            tmp.num_entries, tmp.hook_entry,
                            tmp.underflow);
      
      ⇒ static int translate_compat_table(struct net *net,
		       const char *name,
		       unsigned int valid_hooks,
		       struct xt_table_info **pinfo,
		       void **pentry0,
		       unsigned int total_size,
		       unsigned int number,
		       unsigned int *hook_entries,
		       unsigned int *underflows)
            
            ⇒ newinfo = xt_alloc_table_info(size);
            ⇒  xt_entry_foreach(iter0, entry0, total_size) {

                  ret = compat_copy_entry_from_user(iter0, &pos, &size,
                                     name, newinfo, entry1);

                  }
      
      ⇒ static int compat_copy_entry_from_user(struct compat_ipt_entry *e, void **dstptr,
                     unsigned int *size, const char *name,
                     struct xt_table_info *newinfo, unsigned char *base)

            

### x_tables.c

            ⇒ xt_compat_target_from_user(t, dstptr, size); -- the vulnerable function

================================================================================
### x_tables.h (Some Data Structures of Interest --- used in the vulnerable fuction)

      ⇒ xt_entry_target 

      ⇒ compat_xt_entry_target 

      ⇒ xt_target


           

 