#include <iostream>
extern "C"
{
      #define _GNU_SOURCE
      #include <err.h>
      #include <errno.h>
      #include <fcntl.h>
      #include <inttypes.h>
      #include <sched.h>
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include <unistd.h>
      #include <net/if.h>
      #include <netinet/in.h>
      #include <sys/ipc.h>
      #include <sys/msg.h>

      #include <sys/syscall.h>
     //#include <linux/netfilter_ipv4/ip_tables.h>

      #include <asm/types.h>

      #include <stdbool.h>

      #include <asm-generic/int-ll64.h>
}

using namespace std;

typedef struct {
	int counter;
} atomic_t;


/* Internet address.  */
typedef uint32_t in_addr_t;
#ifndef __user
#define __user
#endif
typedef unsigned int u32;
typedef u32		compat_uint_t;
typedef unsigned int u64;
typedef u64		compat_u64;
typedef u32		compat_uptr_t;


class Mutex
{
      private:
            //* 1: unlocked, 0: locked, negative: locked, possible waiters */
            atomic_t		count;
            /*
            spinlock_t		wait_lock;
            struct list_head	wait_list;
            #if defined(CONFIG_DEBUG_MUTEXES) || defined(CONFIG_MUTEX_SPIN_ON_OWNER)
                  struct task_struct	*owner;
            #endif
            #ifdef CONFIG_MUTEX_SPIN_ON_OWNER
                  struct optimistic_spin_queue osq; /* Spinner MCS lock */
            /*
            #endif
            #ifdef CONFIG_DEBUG_MUTEXES
                  void			*magic;
            #endif
            #ifdef CONFIG_DEBUG_LOCK_ALLOC
                  struct lockdep_map	dep_map;
            #endif
            */

};

class ListHead
{
      public:
            ListHead *next, *prev;
};

class XtAf
{
      public:
                  Mutex mutex;
                  ListHead match;
                  ListHead target;
            //#ifdef CONFIG_COMPAT
                  Mutex compat_mutex;
                 // struct compat_delta *compat_tab;
                  unsigned int number; /* number of slots in compat_tab[] */
                  unsigned int cur; /* number of used slots in compat_tab[] */
            // #endif

};

/* Registration hooks for targets. */
class XtTarget
{
      public:
            ListHead list;

            const char name[32];
            u_int8_t revision;

            /* Returns verdict. Argument order changed since 2.6.9, as this
            must now handle non-linear skbs, using skb_copy_bits and
            skb_ip_make_writable. */
            unsigned int (*target)(struct sk_buff *skb,
                              const struct xt_action_param *);

            /* Called when user tries to insert an entry of this type:
            hook_mask is a bitmask of hooks from which it can be
            called. */
            /* Should return 0 on success or an error code otherwise (-Exxxx). */
            int (*checkentry)(const struct xt_tgchk_param *);

            /* Called when entry of this type deleted. */
           // void (*destroy)(const struct xt_tgdtor_param *);
           // #ifdef CONFIG_COMPAT
                  /* Called when userspace align differs from kernel space one */
                  void (*compat_from_user)(void *dst, const void *src);
                  int (*compat_to_user)(void __user *dst, const void *src);
            //#endif
                  /* Set this to THIS_MODULE if you are a module, otherwise NULL */
                  struct module *me;

                  const char *table;
                  unsigned int targetsize;
           // #ifdef CONFIG_COMPAT
                  unsigned int compatsize;
           // #endif
                  unsigned int hooks;
                  unsigned short proto;

                  unsigned short family;

};


class XtMatch
{
      public:
            ListHead list;

            const char name[32];
            u_int8_t revision;

            /* Return true or false: return FALSE and set *hotdrop = 1 to
            force immediate packet drop. */
            /* Arguments changed since 2.6.9, as this must now handle
            non-linear skb, using skb_header_pointer and
            skb_ip_make_writable. */
            //bool (*match)(const struct sk_buff *skb,
            //	      struct xt_action_param *);

            /* Called when user tries to insert an entry of this type. */
            int (*checkentry)(const struct xt_mtchk_param *);

            /* Called when entry of this type deleted. */
            void (*destroy)(const struct xt_mtdtor_param *);
      // #ifdef CONFIG_COMPAT
                  /* Called when userspace align differs from kernel space one */
                  void (*compat_from_user)(void *dst, const void *src);
                  int (*compat_to_user)(void __user *dst, const void *src);
      //  #endif
                  /* Set this to THIS_MODULE if you are a module, otherwise NULL */
                  struct module *me;

                  const char *table;
                  unsigned int matchsize;
      // #ifdef CONFIG_COMPAT
                  unsigned int compatsize;
      // #endif
                  unsigned int hooks;
                  unsigned short proto;

                  unsigned short family;

};

class XtEntryMatch
{
public:
      union {
		struct {
			__u16 match_size;

			/* Used by userspace */
			char name[32];
			__u8 revision;
		} user;
		struct {
			__u16 match_size;

			/* Used inside the kernel */
			XtMatch *match;
		} kernel;

		/* Total length */
		__u16 match_size;
	} u;

	unsigned char data[0];
};


class XtEntryTarget
{
      public:
            union {
                  struct {
                        __u16 target_size;

                        /* Used by userspace */
                        char name[32];
                        __u8 revision;
                  } user;
                  struct {
                        __u16 target_size;

                        /* Used inside the kernel */
                        XtTarget *target;
                  } kernel;

                  /* Total length */
                  __u16 target_size;
            } u;

            unsigned char data[0];
};

class InAddr
{
      private:
            in_addr_t s_addr;
};

class IptIp
{
      private:
            /* Source and destination IP addr */
            //struct in_addr src, dst;
            InAddr src, dst;
            /* Mask for src and dest IP addr */
            struct in_addr smsk, dmsk;
            char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
            unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];

            /* Protocol, 0 = ANY */
            __u16 proto;

            /* Flags word */
            __u8 flags;
            /* Inverse flags */
            __u8 invflags;

};

class CompatIptEntry
{
      private:
            //struct ipt_ip ip;
            IptIp ip;
	      compat_uint_t nfcache;
	      __u16 target_offset;
	      __u16 next_offset;
	      compat_uint_t comefrom;
	      //struct compat_xt_counters counters;
	      unsigned char elems[0];

};

class IptEntry
{
      public:
            //struct ipt_ip ip;
            IptIp ip;
            /* Mark with fields that we care about. */
            unsigned int nfcache;

            /* Size of ipt_entry + matches */
            __u16 target_offset;
            /* Size of ipt_entry + matches + target */
            __u16 next_offset;

            /* Back pointer */
            unsigned int comefrom;

            /* Packet and byte counters. */
            //struct xt_counters counters;

            /* The matches (if any), then the target. */
            unsigned char elems[0];
      
      //public:
            /* for const-correctness */
            static inline const XtEntryTarget *
            ipt_get_target_c(const IptEntry *e)
            {
                  return ipt_get_target((IptEntry *)e);
            }

            /* Helper functions */
            static __inline__ XtEntryTarget *
            ipt_get_target(IptEntry *e)
            {                  
                  //return (void *)e + e->target_offset;
                  return (XtEntryTarget *)e + e->target_offset;
            }
      
};

class CompatXtEntryMatch {
      public:
            union {
                        struct {
                              u_int16_t match_size;
                              char name[31];
                              u_int8_t revision;
                        } user;
                        struct {
                              u_int16_t match_size;
                              compat_uptr_t match;
                        } kernel;
                        u_int16_t match_size;
                  } u;
                  unsigned char data[0];
};

class XtTableInfo
{
    //private:
      //static XtAf *xt;

    public:
        /* Size per table */
        unsigned int size;
        /* Number of entries: FIXME. --RR */
        unsigned int number;
         /* Initial number of entries. Needed for module usage count */
        unsigned int initial_entries;
         /* Entry points and underflows */
        unsigned int hook_entry[5];
        unsigned int underflow[5];
         /*
             * Number of user chains. Since tables cannot have loops, at most
             * @stacksize jumps (number of user chains) can possibly be made.
        */
         unsigned int stacksize;
         void ***jumpstack;
 
         unsigned char entries[0];// __aligned(8);

         int xt_compat_add_offset(u_int8_t af, unsigned int offset, int delta)
            {
                  /*
                  struct xt_af *xp = &xt[af];

                  if (!xp->compat_tab) {
                        if (!xp->number)
                              return -EINVAL;
                        xp->compat_tab = vmalloc(sizeof(struct compat_delta) * xp->number);
                        if (!xp->compat_tab)
                              return -ENOMEM;
                        xp->cur = 0;
                  }

                  if (xp->cur >= xp->number)
                        return -EINVAL;

                  if (xp->cur)
                        delta += xp->compat_tab[xp->cur - 1].delta;
                  xp->compat_tab[xp->cur].offset = offset;
                  xp->compat_tab[xp->cur].delta = delta;
                  xp->cur++;
                  */
                  return 0;
            }

            int xt_compat_target_offset(const XtTarget *target)
            {
                  u_int16_t csize = target->compatsize ? : target->targetsize;
                  //return XT_ALIGN(target.targetsize) - COMPAT_XT_ALIGN(csize);
                  return target->targetsize - csize;
            }

            int xt_compat_match_offset(const XtMatch *match)
            {
                  u_int16_t csize = match->compatsize ? : match->matchsize;
                  //return XT_ALIGN(match->matchsize) - COMPAT_XT_ALIGN(csize);
                  return match->matchsize - csize;
            }

            int xt_compat_match_to_user(const XtEntryMatch *m,
			    void __user **dstptr, unsigned int *size)
            {
                  const XtMatch *match = m->u.kernel.match;
                  //CompatXtEntryMatch __user *cm = *dstptr;
                  CompatXtEntryMatch __user *cm = (CompatXtEntryMatch *) *dstptr;
                  int off = xt_compat_match_offset(match);
                  u_int16_t msize = m->u.user.match_size - off;
                  /*
                  if (copy_to_user(cm, m, sizeof(*cm)) ||
                  put_user(msize, &cm->u.user.match_size) ||
                  copy_to_user(cm->u.user.name, m->u.kernel.match->name,
                              strlen(m->u.kernel.match->name) + 1))
                        return -EFAULT;
                  */
                  if (match->compat_to_user) {
                        if (match->compat_to_user((void __user *)cm->data, m->data))
                              return -EFAULT;
                  } else {
                       // if (copy_to_user(cm->data, m->data, msize - sizeof(*cm)))
                       //       return -EFAULT;
                  }

                  *size -= off;
                  //*dstptr += msize;
                  *dstptr = *dstptr + msize;
                  return 0;
            }

            void xt_compat_init_offsets(u_int8_t af, unsigned int number)
            {
                  static XtAf *xt;
                  xt[af].number = number;
                  xt[af].cur = 0;
            }
            
            static int compat_calc_entry(const IptEntry *e, const XtTableInfo *info, const void *base, XtTableInfo *newinfo)
                  {
                        const XtEntryMatch *ematch;
                        const XtEntryTarget *t;
                        unsigned int entry_offset;
                        int off, i, ret;

                        off = sizeof(IptEntry) - sizeof(CompatIptEntry);
                        //entry_offset = (void *)e - base;
                        entry_offset = (int *)e - (int *)base;
                       
                        IptEntry ipt_entry;
                        //ipt_entry.xt_ematch_foreach(ematch,e);
                        //       off += xt_compat_match_offset(ematch->u.kernel.match);
                        
                        XtTableInfo xt_table_info;

                         for ((ematch) = (XtEntryMatch *)e->elems; 
                              (ematch) < (XtEntryMatch *)((char *)(e) + (e)->target_offset); 
                              (ematch) = (XtEntryMatch *)((char *)(ematch) + (ematch)->u.match_size))
                        {
                              off += xt_table_info.xt_compat_match_offset(ematch->u.kernel.match);

                        }//for
                        
                        t = ipt_entry.ipt_get_target_c(e);

                        off += xt_table_info.xt_compat_target_offset(t->u.kernel.target);
                        newinfo->size -= off;
                        ret = xt_table_info.xt_compat_add_offset(AF_INET, entry_offset, off);
                          if (ret)
                              return ret;
                        
                        //for (i = 0; i < NF_INET_NUMHOOKS; i++) {
                        for (i = 0; i < 32; i++) {
                              if (info->hook_entry[i] &&
                                    (e < (IptEntry *)(base + info->hook_entry[i])))
                                    newinfo->hook_entry[i] -= off;
                              if (info->underflow[i] &&
                                    (e < (IptEntry *)(base + info->underflow[i])))
                                    newinfo->underflow[i] -= off;
                        }
                        return 0;

                  }

};

class XtTable
{
      private:
            ListHead list;

            /* What hooks you will enter on */
            unsigned int valid_hooks;

            /* Man behind the curtain... */
            //struct xt_table_info *private;
            XtTableInfo *private_xt_table_info;

            /* Set this to THIS_MODULE if you are a module, otherwise NULL */
            struct module *me;

            u_int8_t af;		/* address/protocol family */
            int priority;		/* hook order */

            /* called when table is needed in the given netns */
            //int (*table_init)(struct net *net);

            /* A unique name... */
            const char name[32];
           
};

int main ()
{
  
      const XtTableInfo *info;
      XtTableInfo *newinfo, tmp;
      IptEntry *iter;
      const void *loc_cpu_entry;
      int ret;
      ////////////////////////////////
            //ToDo - set of info
            tmp.size = 0;
            tmp.number = 0;
            tmp.initial_entries=0;
            tmp.stacksize = 0;

            info = &tmp;         
      ////////////////////////////////
      if (!newinfo || !info)
            return -EINVAL;
 
      /* we dont care about newinfo->entries */
      //memcpy(newinfo, info, offsetof(struct xt_table_info, entries));  
      
      cout << "i came here0\n"; 
      memcpy(newinfo, info, sizeof(tmp.entries));
      cout << "i came here 1\n";

      newinfo->initial_entries = 0;
      loc_cpu_entry = info->entries;
      
      tmp.xt_compat_init_offsets(AF_INET, info->number);
      
      for ((iter) = (typeof(iter))(loc_cpu_entry); 
                  (iter) < (typeof(iter))((char *)(loc_cpu_entry) + (info->size)); 
                        (iter) = (typeof(iter))((char *)(iter) + (iter)->next_offset))
      {

                  ret = tmp.compat_calc_entry(iter, info, loc_cpu_entry, newinfo);
                  if (ret != 0)
                        return ret;

      }//for                  
      
      return 0;
}

  /*
                         for ((ematch) = (struct xt_entry_match *)e->elems; 
                              (ematch) < (struct xt_entry_match *)((char *)(e) + (e)->target_offset); 
                              (ematch) = (struct xt_entry_match *)((char *)(ematch) + (ematch)->u.match_size))
                        { 
                             // off += xt_compat_match_offset(ematch->u.kernel.match);

                        }//for
                        */