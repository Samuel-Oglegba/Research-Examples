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

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#define __bitwise __bitwise__

typedef unsigned int __u32;
typedef __u32 __bitwise __be32;

#define NF_DROP 0
#define NF_ACCEPT 1

#define XT_FUNCTION_MAXNAMELEN 30
#define XT_EXTENSION_MAXNAMELEN 29
#define XT_TABLE_MAXNAMELEN 32
#define NF_INET_NUMHOOKS 5

#define XCHAL_DCACHE_LINESIZE		32	/* D-cache line size in bytes */
#define L1_CACHE_BYTES	XCHAL_DCACHE_LINESIZE
#define SMP_CACHE_BYTES	L1_CACHE_BYTES
#define SMP_ALIGN(x) (((x) + SMP_CACHE_BYTES-1) & ~(SMP_CACHE_BYTES-1))


# define __force
# define __must_check
#define ___GFP_DIRECT_RECLAIM	0x400000u
#define ___GFP_KSWAPD_RECLAIM	0x2000000u
#define ___GFP_IO		0x40u
#define ___GFP_FS		0x80u

#define __GFP_IO	((__force gfp_t)___GFP_IO)
#define __GFP_FS	((__force gfp_t)___GFP_FS)

//extern unsigned long totalram_pages;
unsigned long totalram_pages;

#define PAGE_SHIFT	12

typedef unsigned __bitwise__ gfp_t;

#define __GFP_RECLAIM ((__force gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))
/**
 * @brief 
 * could not find the correct definition to this __XTENSA_UL_CONST(1)
 */
#define __XTENSA_UL (x)	((unsigned long)(x))
#define __XTENSA_UL_CONST(x)   x##UL
#define PAGE_SIZE	(__XTENSA_UL_CONST(1) << PAGE_SHIFT)
#define PAGE_ALLOC_COSTLY_ORDER 3
#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)

#define ___GFP_NOWARN		0x200u
#define __GFP_NOWARN	((__force gfp_t)___GFP_NOWARN)

#define ___GFP_NORETRY		0x1000u
#define __GFP_NORETRY	((__force gfp_t)___GFP_NORETRY)

#define for_each_cpu(cpu, mask)			\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)

extern struct cpumask __cpu_possible_mask;
#define cpu_possible_mask ((const struct cpumask *)&__cpu_possible_mask)

#define for_each_possible_cpu(cpu) for_each_cpu((cpu), cpu_possible_mask)

#ifdef CONFIG_DEBUG_SPINLOCK

typedef struct {
	volatile unsigned int slock;
} arch_spinlock_t;

#define __ARCH_SPIN_LOCK_UNLOCKED { 1 }

#else

typedef struct { } arch_spinlock_t;

#define __ARCH_SPIN_LOCK_UNLOCKED { }

#endif

/* Standard return verdict, or do jump. */
#define XT_STANDARD_TARGET ""
#define NF_STOP 5	/* Deprecated, for userspace nf_queue compatibility. */
#define NF_MAX_VERDICT NF_STOP

typedef struct raw_spinlock {
	arch_spinlock_t raw_lock;
#ifdef CONFIG_GENERIC_LOCKBREAK
	unsigned int break_lock;
#endif
#ifdef CONFIG_DEBUG_SPINLOCK
	unsigned int magic, owner_cpu;
	void *owner;
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} raw_spinlock_t;

typedef struct spinlock {
	union {
		struct raw_spinlock rlock;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
		struct {
			u8 __padding[LOCK_PADSIZE];
			struct lockdep_map dep_map;
		};
#endif
	};
} spinlock_t;

#define IPT_F_MASK		0x03	/* All possible flag bits mask. */
#define IPT_INV_MASK		0x7F	/* All possible flag bits mask. */

/* pos is normally a struct ipt_entry/ip6t_entry/etc. */
#define xt_entry_foreach(pos, ehead, esize) \
	for ((pos) = (typeof(pos))(ehead); \
	     (pos) < (typeof(pos))((char *)(ehead) + (esize)); \
	     (pos) = (typeof(pos))((char *)(pos) + (pos)->next_offset))

struct list_head {
	struct list_head *next, *prev;
};

/*
 * Maximum supported processors.  Setting this smaller saves quite a
 * bit of memory.  Use nr_cpu_ids instead of this except for static bitmaps.
 */
#ifndef CONFIG_NR_CPUS
/* FIXME: This should be fixed in the arch's Kconfig */
#define CONFIG_NR_CPUS	1
#endif

/* Places which use this should consider cpumask_var_t. */
#define NR_CPUS		CONFIG_NR_CPUS

#if NR_CPUS == 1
#define nr_cpu_ids		1
#else
extern int nr_cpu_ids;
#endif

#ifndef cpu_to_node
#define cpu_to_node(cpu)	((void)(cpu),0)
#endif

struct mutex {
	/* 1: unlocked, 0: locked, negative: locked, possible waiters */
	atomic_t		count;
	spinlock_t		wait_lock;
	struct list_head	wait_list;
      #if defined(CONFIG_DEBUG_MUTEXES) || defined(CONFIG_MUTEX_SPIN_ON_OWNER)
            struct task_struct	*owner;
      #endif
      #ifdef CONFIG_MUTEX_SPIN_ON_OWNER
            struct optimistic_spin_queue osq; /* Spinner MCS lock */
      #endif
      #ifdef CONFIG_DEBUG_MUTEXES
            void			*magic;
      #endif
      #ifdef CONFIG_DEBUG_LOCK_ALLOC
            struct lockdep_map	dep_map;
      #endif
};

struct compat_delta {
	unsigned int offset; /* offset in kernel */
	int delta; /* delta in 32bit user land */
};

struct xt_af {
	struct mutex mutex;
	struct list_head match;
	struct list_head target;
//#ifdef CONFIG_COMPAT
	struct mutex compat_mutex;
	struct compat_delta *compat_tab;
	unsigned int number; /* number of slots in compat_tab[] */
	unsigned int cur; /* number of used slots in compat_tab[] */
//#endif
};

/* Registration hooks for targets. */
struct xt_target {
	struct list_head list;

	const char name[XT_EXTENSION_MAXNAMELEN];
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
	void (*destroy)(const struct xt_tgdtor_param *);
#ifdef CONFIG_COMPAT
	/* Called when userspace align differs from kernel space one */
	void (*compat_from_user)(void *dst, const void *src);
	int (*compat_to_user)(void __user *dst, const void *src);
#endif
	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	const char *table;
	unsigned int targetsize;
//#ifdef CONFIG_COMPAT
	unsigned int compatsize;
//#endif
	unsigned int hooks;
	unsigned short proto;

	unsigned short family;
};

struct xt_match {
	struct list_head list;

	const char name[XT_EXTENSION_MAXNAMELEN];
	u_int8_t revision;

	/* Return true or false: return FALSE and set *hotdrop = 1 to
           force immediate packet drop. */
	/* Arguments changed since 2.6.9, as this must now handle
	   non-linear skb, using skb_header_pointer and
	   skb_ip_make_writable. */
	bool (*match)(const struct sk_buff *skb,
		      struct xt_action_param *);

	/* Called when user tries to insert an entry of this type. */
	int (*checkentry)(const struct xt_mtchk_param *);

	/* Called when entry of this type deleted. */
	void (*destroy)(const struct xt_mtdtor_param *);
//#ifdef CONFIG_COMPAT
	/* Called when userspace align differs from kernel space one */
	void (*compat_from_user)(void *dst, const void *src);
	int (*compat_to_user)(void __user *dst, const void *src);
//#endif
	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	const char *table;
	unsigned int matchsize;
//#ifdef CONFIG_COMPAT
	unsigned int compatsize;
//#endif
	unsigned int hooks;
	unsigned short proto;

	unsigned short family;
};

struct xt_entry_match {
	union {
		struct {
			__u16 match_size;

			/* Used by userspace */
			char name[XT_EXTENSION_MAXNAMELEN];
			__u8 revision;
		} user;
		struct {
			__u16 match_size;

			/* Used inside the kernel */
			struct xt_match *match;
		} kernel;

		/* Total length */
		__u16 match_size;
	} u;

	unsigned char data[0];
};

struct xt_entry_target {
	union {
		struct {
			__u16 target_size;

			/* Used by userspace */
			char name[XT_EXTENSION_MAXNAMELEN];
			__u8 revision;
		} user;
		struct {
			__u16 target_size;

			/* Used inside the kernel */
			struct xt_target *target;
		} kernel;

		/* Total length */
		__u16 target_size;
	} u;

	unsigned char data[0];
};

struct compat_xt_counters {
	compat_u64 pcnt, bcnt;			/* Packet and byte counters */
};// struct compat_xt_counters

/*
struct in_addr {
	__be32	s_addr;
};
*/

struct ipt_ip {
	/* Source and destination IP addr */
	struct in_addr src, dst;
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

struct compat_ipt_entry {
	struct ipt_ip ip;
	compat_uint_t nfcache;
	__u16 target_offset;
	__u16 next_offset;
	compat_uint_t comefrom;
	struct compat_xt_counters counters;
	unsigned char elems[0];
};

struct xt_counters {
	__u64 pcnt, bcnt;			/* Packet and byte counters */
};

struct ipt_entry {
	struct ipt_ip ip;

	/* Mark with fields that we care about. */
	unsigned int nfcache;

	/* Size of ipt_entry + matches */
	__u16 target_offset;
	/* Size of ipt_entry + matches + target */
	__u16 next_offset;

	/* Back pointer */
	unsigned int comefrom;

	/* Packet and byte counters. */
	struct xt_counters counters;

	/* The matches (if any), then the target. */
	unsigned char elems[0];
};

struct compat_xt_entry_match {
	union {
		struct {
			u_int16_t match_size;
			char name[XT_FUNCTION_MAXNAMELEN - 1];
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

/* The table itself */
struct xt_table_info {
	/* Size per table */
	unsigned int size;
	/* Number of entries: FIXME. --RR */
	unsigned int number;
	/* Initial number of entries. Needed for module usage count */
	unsigned int initial_entries;

	/* Entry points and underflows */
	unsigned int hook_entry[NF_INET_NUMHOOKS];
	unsigned int underflow[NF_INET_NUMHOOKS];

	/*
	 * Number of user chains. Since tables cannot have loops, at most
	 * @stacksize jumps (number of user chains) can possibly be made.
	 */
	unsigned int stacksize;
	void ***jumpstack;

	unsigned char entries[0];// __aligned(8);
};

static struct xt_af *xt = (struct xt_af *)malloc(sizeof *xt);

struct xt_standard_target {
	struct xt_entry_target target;
	int verdict;
};
              
 #define xt_ematch_foreach(pos, entry) \
                              for ((pos) = (struct xt_entry_match *)entry->elems; \
                              (pos) < (struct xt_entry_match *)((char *)(entry) + \
                                          (entry)->target_offset); \
                              (pos) = (struct xt_entry_match *)((char *)(pos) + \
                                          (pos)->u.match_size))

 /* Helper functions */
static __inline__ struct xt_entry_target *ipt_get_target(struct ipt_entry *e)
{
      //return (void *)e + e->target_offset;
      return (struct xt_entry_target *)((void *)e + e->target_offset);
}

 /* for const-correctness */
static inline const struct xt_entry_target *ipt_get_target_c(const struct ipt_entry *e)
{
      return ipt_get_target((struct ipt_entry *)e);
}

int xt_compat_add_offset(u_int8_t af, unsigned int offset, int delta)
{
      struct xt_af *xp = &xt[af];

      if (!xp->compat_tab) {
            if (!xp->number)
                  return -EINVAL;
            //xp->compat_tab = vmalloc(sizeof(struct compat_delta) * xp->number);
            xp->compat_tab = (struct compat_delta *) malloc(sizeof(struct compat_delta) * xp->number);
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
      
      return 0;
}

int xt_compat_target_offset(const struct xt_target *target)
{
      u_int16_t csize = target->compatsize ? : target->targetsize;
      /**
       * @brief The definition of XT_ALIGN was not found (system call)
       * 
       */
      //return XT_ALIGN(target.targetsize) - COMPAT_XT_ALIGN(csize);
      return target->targetsize - csize;
}

int xt_compat_match_offset(const struct xt_match *match)
{                 
      u_int16_t csize = match->compatsize ? : match->matchsize;
            /**
       * @brief The definition of XT_ALIGN was not found (system call)
       * 
       */
      //return XT_ALIGN(match->matchsize) - COMPAT_XT_ALIGN(csize);
      return match->matchsize - csize;
}

/* All zeroes == unconditional rule. */
/* Mildly perf critical (only if packet tracing is on) */
static inline bool unconditional(const struct ipt_entry *e)
{
	//static const struct ipt_ip uncond;
	struct ipt_ip uncond;

	return e->target_offset == sizeof(struct ipt_entry) &&
	       memcmp(&e->ip, &uncond, sizeof(uncond)) == 0;
//#undef FWINV
}

static bool
ip_checkentry(const struct ipt_ip *ip)
{
	if (ip->flags & ~IPT_F_MASK) {
		//duprintf("Unknown flag bits set: %08X\n",ip->flags & ~IPT_F_MASK);
		printf("Unknown flag bits set: %08X\n",ip->flags & ~IPT_F_MASK);
		return false;
	}
	if (ip->invflags & ~IPT_INV_MASK) {
		//duprintf("Unknown invflag bits set: %08X\n",ip->invflags & ~IPT_INV_MASK);
		printf("Unknown invflag bits set: %08X\n",ip->invflags & ~IPT_INV_MASK);
		return false;
	}
	return true;
}

static int check_entry(const struct ipt_entry *e)
{
	const struct xt_entry_target *t;

	if (!ip_checkentry(&e->ip))
		return -EINVAL;

	if (e->target_offset + sizeof(struct xt_entry_target) >
	    e->next_offset)
		return -EINVAL;

	t = ipt_get_target_c(e);
	if (e->target_offset + t->u.target_size > e->next_offset)
		return -EINVAL;

	return 0;

}//check_entry

static bool check_underflow(const struct ipt_entry *e)
{
	const struct xt_entry_target *t;
	unsigned int verdict;

	if (!unconditional(e))
		return false;
	t = ipt_get_target_c(e);
	if (strcmp(t->u.user.name, XT_STANDARD_TARGET) != 0)
		return false;
	verdict = ((struct xt_standard_target *)t)->verdict;
	verdict = -verdict - 1;
	return verdict == NF_DROP || verdict == NF_ACCEPT;

}//check_underflow

void xt_compat_init_offsets(u_int8_t af, unsigned int number)
{                 
      xt[af].number = number;
      xt[af].cur = 0;
}//xt_compat_init_offsets

static inline long __must_check PTR_ERR(__force const void *ptr)
{
	return (long) ptr;
}

/* Helper functions */
static inline struct xt_entry_target *
compat_ipt_get_target(struct compat_ipt_entry *e)
{
	//return (void *)e + e->target_offset;
	return (struct xt_entry_target *)e + e->target_offset;
}

/// @brief //==============================================================================================================

class XtTableInfo
{

    private:
        /* Size per table */
        unsigned int size;
        /* Number of entries: FIXME. --RR */
        unsigned int number;
         /* Initial number of entries. Needed for module usage count */
        unsigned int initial_entries;
         /* Entry points and underflows */
        unsigned int hook_entry[NF_INET_NUMHOOKS];
        unsigned int underflow[NF_INET_NUMHOOKS];
         /*
             * Number of user chains. Since tables cannot have loops, at most
             * @stacksize jumps (number of user chains) can possibly be made.
        */
         unsigned int stacksize;
         void ***jumpstack;
 
         unsigned char entries[0]; //__aligned(8);
      
      protected:        
            /**
             * @brief creats the linkedLinked from the base of the table and calculating the next table row pointer
             * Input Parameter:(newinfo, valid_hooks, entry0)
             *                @param newinfo - The network routing table.
             *                @param valid_hooks - checking for which row has valid data
             *                @param entry0 - This pointer is the base or starting point of the routing table entries and was
             *                                used with e (struct ipt_entry) to get the next table row. 
             * Output Parameter:()            
             *@return int 
             */
            int mark_source_chains(const XtTableInfo *newinfo, unsigned int valid_hooks, void *entry0);

            int check_entry_size_and_hooks(struct ipt_entry *e,
                        XtTableInfo *newinfo,
                        const unsigned char *base,
                        const unsigned char *limit,
                        const unsigned int *hook_entries,
                        const unsigned int *underflows,
                        unsigned int valid_hooks);
            
      
            int compat_table_info(const XtTableInfo *info, XtTableInfo *newinfo);
            int xt_jumpstack_alloc(XtTableInfo *i);

      public:
         XtTableInfo();//default constructor
         
         XtTableInfo(unsigned int mSize, unsigned int mNumber, 
                        unsigned int mInitial_entries,unsigned int mStacksize){
            size = mSize;
            number = mNumber;
            initial_entries = mInitial_entries;
            stacksize = mStacksize;
         }

         unsigned int getSize(){
            return size;
         }

         unsigned int getNumber(){
            return number;
         }

         unsigned int getInitialEntries(){
            return initial_entries;
         }

         unsigned int getStackSize(){
            return stacksize;
         }

        const void * getEntries(){
            return entries;
        }
      
      /**
       * @brief allocate memory to the XtTableInfo abstraction
       * Input Parameter:(size)
       *    @param size - the size of the table rows (usually size of struct ipt_replace, compat_ipt_replace, arpt_replace, & compat_arpt_replace)
       * 
       * Output Parameter:(XtTableInfo*)
       *    @param XtTableInfo* - pointer to the newly allocated memory address 
       * 
       * @return XtTableInfo* 
       */
      XtTableInfo *xt_alloc_table_info(unsigned int size);

      /**
       * @brief uses abstraction element "unsigned char entries[0]" to calculate the size of rows of the table
       * Input Parameter:(e, info, base, newinfo)
       *    @param e - LinkedList used to store the row entries of the table (like storing a row of the table which points to the next row)
       *    @param info - The network routing table.
       *    @param base - This pointer is the base or starting point of the routing table entries and was 
       *                  used with e (struct ipt_entry) to get the next table row. 
       *                  Same as the abstraction element "unsigned char entries[0]"  
       *    @param newinfo - The new network routing table that gets returned as output
       * 
       * Output Parameter:(newinfo)        
       *         
       * @return (int) -- returning different error codes, possible output {0 -- success, a negative errno code, positive exit code on failure}.
       */  
      int compat_calc_entry(const struct ipt_entry *e, const XtTableInfo *info, const void *base, XtTableInfo *newinfo);

       /**
       * @brief free the routing table memory
       * 
       * @param info 
       */
      void xt_free_table_info(XtTableInfo *info);

	void modify_xt_table_info(XtTableInfo *info);

      void printXtTableInfo(const struct ipt_entry *e, const void *loc_cpu_entry, unsigned int size);

};
///////////////////////////////////////////////////////////////////////////////////////////////////////////////


void XtTableInfo::modify_xt_table_info(XtTableInfo *info){

	int off, i, ret;
	const struct ipt_entry *e;
	char name[XT_TABLE_MAXNAMELEN];
	struct xt_table *t;
	//const struct xt_table_info *private = t->private;
	//newinfo->size -= off;
	XtTableInfo *newinfo;
	const void *base;		

	//=========== compat_calc_entry() =====
	for (i = 0; i < NF_INET_NUMHOOKS; i++) {
           if (info->hook_entry[i] &&
               (e < (struct ipt_entry *)(base + info->hook_entry[i])))
                 newinfo->hook_entry[i] -= off;
           if (info->underflow[i] &&
               (e < (struct ipt_entry *)(base + info->underflow[i])))
                 newinfo->underflow[i] -= off;
      }
	//=====================================

}//modify_xt_table_info



/**
 * @brief allocate memory space
 * Input Parameter:(i)
 *    @param i - 
 * Output Parameter:(i)
 *    @param i - Return the allocated memory pointer to the network routing table
 * @return int 
 */
int XtTableInfo::xt_jumpstack_alloc(XtTableInfo *i)
{
     unsigned int size;
     int cpu;
 
     size = sizeof(void **) * nr_cpu_ids;
     if (size > PAGE_SIZE){
        // i->jumpstack = vzalloc(size);
         i->jumpstack = (void ***) malloc(size);
     }
           
     else{
           // i->jumpstack = kzalloc(size, GFP_KERNEL);
            i->jumpstack = (void ***) calloc(size, GFP_KERNEL);
     }
           
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
           if (size > PAGE_SIZE){
                  // i->jumpstack[cpu] = vmalloc_node(size,cpu_to_node(cpu));
                  i->jumpstack[cpu] = (void **) malloc(size);
           }
           else{
                 // i->jumpstack[cpu] = kmalloc_node(size,GFP_KERNEL, cpu_to_node(cpu));
                  i->jumpstack[cpu] = (void **) calloc(size,GFP_KERNEL);
           }                 
           if (i->jumpstack[cpu] == NULL)
                 /*
                  * Freeing will be done later on by the callers. The
                  * chain is: xt_replace_table -> __do_replace ->
                  * do_replace -> xt_free_table_info.
                  */
                 return -ENOMEM;
     }
 
     return 0;

}//xt_jumpstack_alloc

/**
 * @brief This function calcuates the value of the table offsets & overflows which is required for
 *        backward compatibility to allow accessing/modifying the routing table 
 *        entries iteratively.
 * 
 * Input Parameter:(info,newinfo)
 *    @param info -- The network routing table, it is keyed by destination IP address. 
 *    @param newinfo -- The new network routing table. Serves as an input & output parameter
 * 
 * Output Parameter:(newinfo*) 
 *    @param newinfo -- The new network routing table. The value of the info is copied to newinfo using memcpy
 * 
 * @return int 
 */
int XtTableInfo::compat_table_info(const XtTableInfo *info, XtTableInfo *newinfo)
{
	struct ipt_entry *iter;
	const void *loc_cpu_entry;
	int ret;

	if (!newinfo || !info)
		return -EINVAL;

	/* we dont care about newinfo->entries */
	memcpy(newinfo, info, offsetof(struct xt_table_info, entries));
	newinfo->initial_entries = 0;
	loc_cpu_entry = info->entries;
	xt_compat_init_offsets(AF_INET, info->number);

      xt_entry_foreach(iter, loc_cpu_entry, info->size) {
	 
		ret = compat_calc_entry(iter, info, loc_cpu_entry, newinfo);
		if (ret != 0)
			return ret;
	}
	return 0;
      
}//compat_table_info

/**
 * @brief Walk through routing table entries, checking offsets
 * 
 * @param e 
 * @param newinfo 
 * @param base 
 * @param limit 
 * @param hook_entries 
 * @param underflows 
 * @param valid_hooks 
 * @return int 
 */
int XtTableInfo::check_entry_size_and_hooks(struct ipt_entry *e,
			   XtTableInfo *newinfo,
			   const unsigned char *base,
			   const unsigned char *limit,
			   const unsigned int *hook_entries,
			   const unsigned int *underflows,
			   unsigned int valid_hooks)
{
	unsigned int h;
	int err;

	if ((unsigned long)e % __alignof__(struct ipt_entry) != 0 ||
	    (unsigned char *)e + sizeof(struct ipt_entry) >= limit ||
	    (unsigned char *)e + e->next_offset > limit) {
		//duprintf("Bad offset %p\n", e);
		printf("Bad offset %p\n", e);
		return -EINVAL;
	}

	if (e->next_offset
	    < sizeof(struct ipt_entry) + sizeof(struct xt_entry_target)) {
		//duprintf("checking: element %p size %u\n",e, e->next_offset);
		printf("checking: element %p size %u\n",e, e->next_offset);
		return -EINVAL;
	}

	err = check_entry(e);
	if (err)
		return err;

	/* Check hooks & underflows */
	for (h = 0; h < NF_INET_NUMHOOKS; h++) {
		if (!(valid_hooks & (1 << h)))
			continue;
		if ((unsigned char *)e - base == hook_entries[h])
			newinfo->hook_entry[h] = hook_entries[h];
		if ((unsigned char *)e - base == underflows[h]) {
			if (!check_underflow(e)) {
				//pr_debug("Underflows must be unconditional and use the STANDARD target with ACCEPT/DROP\n");
				printf("Underflows must be unconditional and use the STANDARD target with ACCEPT/DROP\n");
				return -EINVAL;
			}
			newinfo->underflow[h] = underflows[h];
		}
	}

	/* Clear counters and comefrom */
	e->counters = ((struct xt_counters) { 0, 0 });
	e->comefrom = 0;
	return 0;

}//check_entry_size_and_hooks


/**
 * @brief Figures out from what hook each rule can be called: returns 0 if
 *        there are loops.  Puts hook bitmask in comefrom.
 * 
 * @param newinfo 
 * @param valid_hooks 
 * @param entry0 
 * @return int 
 */
/* Figures out from what hook each rule can be called: returns 0 if
   there are loops.  Puts hook bitmask in comefrom. */
int XtTableInfo::mark_source_chains(const XtTableInfo *newinfo, unsigned int valid_hooks, void *entry0)
{
	unsigned int hook;

	/* No recursion; use packet counter to save back ptrs (reset
	   to 0 as we leave), and comefrom to save source hook bitmask */
	for (hook = 0; hook < NF_INET_NUMHOOKS; hook++) {
		unsigned int pos = newinfo->hook_entry[hook];
		struct ipt_entry *e = (struct ipt_entry *)(entry0 + pos);

		if (!(valid_hooks & (1 << hook)))
			continue;

		/* Set initial back pointer. */
		e->counters.pcnt = pos;

		for (;;) {
			//const struct xt_standard_target *t = (void *)ipt_get_target_c(e); xt_entry_target
			const struct xt_standard_target *t = (struct xt_standard_target *)ipt_get_target_c(e);
                  
			int visited = e->comefrom & (1 << hook);

			if (e->comefrom & (1 << NF_INET_NUMHOOKS)) {
				printf("iptables: loop hook %u pos %u %08X.\n",hook, pos, e->comefrom);
				return 0;
			}
			e->comefrom |= ((1 << hook) | (1 << NF_INET_NUMHOOKS));

			/* Unconditional return/END. */
			if ((unconditional(e) &&
			     (strcmp(t->target.u.user.name,
				     XT_STANDARD_TARGET) == 0) &&
                             
			     t->verdict < 0) || visited) {
				unsigned int oldpos, size;

				if ((strcmp(t->target.u.user.name,
					    XT_STANDARD_TARGET) == 0) &&
				    t->verdict < -NF_MAX_VERDICT - 1) {
					printf("mark_source_chains: bad negative verdict (%i)\n",t->verdict);
					return 0;
				}

				/* Return: backtrack through the last
				   big jump. */
				do {
					e->comefrom ^= (1<<NF_INET_NUMHOOKS);
                  #ifdef DEBUG_IP_FIREWALL_USER
					if (e->comefrom
					    & (1 << NF_INET_NUMHOOKS)) {
						printf("Back unset on hook %u rule %u\n",hook, pos);
					}
                  #endif
					oldpos = pos;
					pos = e->counters.pcnt;
					e->counters.pcnt = 0;

					/* We're at the start. */
					if (pos == oldpos)
						goto next;

					e = (struct ipt_entry *)
						(entry0 + pos);
				} while (oldpos == pos + e->next_offset);

				/* Move along one */
				size = e->next_offset;
				e = (struct ipt_entry *)
					(entry0 + pos + size);
				e->counters.pcnt = pos;
				pos += size;
			} else {
				int newpos = t->verdict;

				if (strcmp(t->target.u.user.name,
					   XT_STANDARD_TARGET) == 0 &&
				    newpos >= 0) {
					if (newpos > newinfo->size -
						sizeof(struct ipt_entry)) {
						printf("mark_source_chains: bad verdict (%i)\n",newpos);
						return 0;
					}
					/* This a jump; chase it. */
					printf("Jump rule %u -> %u\n",pos, newpos);
				} else {
					/* ... this is a fallthru */
					newpos = pos + e->next_offset;
				}
				e = (struct ipt_entry *)
					(entry0 + newpos);
				e->counters.pcnt = pos;
				pos = newpos;
			}
		}
            next:
		printf("Finished chain %u\n", hook);
	}
	return 1;
}

/**
 * @brief used to allocate memory and initialize the abstraction
 * 
 * @param size 
 * @return struct XtTableInfo* 
 */
struct XtTableInfo * XtTableInfo::xt_alloc_table_info(unsigned int size)
{
      XtTableInfo *info = NULL;
      size_t sz = sizeof(*info) + size;

      if (sz < sizeof(*info))
            return NULL;

      /* Pedantry: prevent them from hitting BUG() in vmalloc.c --RR */
	// unable to get this condition to work now
      //if ((SMP_ALIGN(size) >> PAGE_SHIFT) + 2 > totalram_pages)
       //     return NULL;

      if (sz <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER)){
            // info = kmalloc(sz, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY);
            info = (XtTableInfo *) calloc(sz, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY);
      }  
	              
      if (!info) {
            // info = vmalloc(sz);
            info = (XtTableInfo *) malloc(sz);
            if (!info)
                  return NULL;
      }
	
      memset(info, 0, sizeof(*info));
      info->size = size;
      return info;

}//xt_alloc_table_info

/**
 * @brief free up resources allocated to the struct xt_table_inf (the abstraction class)
 * 
 * @param info 
 */
void XtTableInfo::xt_free_table_info(XtTableInfo *info)
{
	int cpu;
      cout << "i came to free memory" << "\n";
/*
	if (info->jumpstack != NULL) {
		for_each_possible_cpu(cpu)
			free(info->jumpstack[cpu]);
			//kvfree(info->jumpstack[cpu]);
		free(info->jumpstack);
		//kvfree(info->jumpstack);
	}
	*/

	//kvfree(info);
	free(info);
      
}//xt_free_table_info     

/**
 * @brief 
 * 
 * @param e 
 * @param info 
 * @param base 
 * @param newinfo 
 * @return int 
 */
int XtTableInfo::compat_calc_entry(const struct ipt_entry *e, const XtTableInfo *info, const void *base, XtTableInfo *newinfo)
{
      const struct xt_entry_match *ematch;
      const struct xt_entry_target *t;
      unsigned int entry_offset;
      int off, i, ret;

      off = sizeof(struct ipt_entry) - sizeof(struct compat_ipt_entry);
      //entry_offset = (void *)e - base;
      entry_offset = (int *)(void *)e - (int *)base;
      
      //allocate memory to the pointer
      ematch = (struct xt_entry_match *)malloc(sizeof *ematch);

      
      /**
       * @brief generates segmentation fault 
       * leading to an infinite loop possible because of the test data supplied 
       * 
       */
      xt_ematch_foreach(ematch,e);
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
}//compat_calc_entry

void XtTableInfo::printXtTableInfo(const struct ipt_entry *iter, const void *loc_cpu_entry, unsigned int size){

      for ((iter) = (typeof(iter))(loc_cpu_entry); 
                  (iter) < (typeof(iter))((char *)(loc_cpu_entry) + (size)); 
                        (iter) = (typeof(iter))((char *)(iter) + (iter)->next_offset))
      {         
                  cout << "iter::comefrom==> " << iter->comefrom << "\n"; 
                  cout << "iter::counters.pcnt==> " << iter->counters.pcnt << "\n"; 
                  cout << "iter::iter->counters.bcnt==> " << iter->counters.bcnt << "\n"; 
                  cout << "iter::elems==> " << iter->elems << "\n"; 
                  cout << "iter::ip.flags==> " << iter->ip.flags << "\n"; 
                  cout << "iter::next_offset==> " << iter->next_offset << "\n"; 
                  cout << "iter::nfcache==> " << iter->nfcache << "\n"; 
                  cout << "iter::target_offset==> " << iter->target_offset << "\n";                                   

      }//for  

}//printXtTableInfo



int main ()
{
     // const XtTableInfo *info;
      XtTableInfo *info;
      XtTableInfo *newinfo;
      struct ipt_entry *iter;
      const void *loc_cpu_entry;
      int ret;
      ////////////////////////////////
            //- The data came from printing out the content of this data structure in the VM
            XtTableInfo tmp(4022,0,0,0);       
           // XtTableInfo tmp(0,0,0,0);       

            info = tmp.xt_alloc_table_info(sizeof *info);  
   
            newinfo = tmp.xt_alloc_table_info(sizeof *newinfo);    

            info = &tmp;    
		cout << "info sizeof==> " << sizeof(info) << "\n";  
		cout << "newinfo sizeof==> " << sizeof(newinfo) << "\n";  

		cout << "info size==> " << info->getSize() << "\n";  
		cout << "newinfo size==> " << newinfo->getSize() << "\n";  

      ////////////////////////////////
      if (!newinfo || !info)
            return -EINVAL;

	 
      memcpy(newinfo, info, offsetof(struct xt_table_info, entries));   

      loc_cpu_entry = info->getEntries();

	cout << "sizeof loc_cpu_entry::==> " << sizeof(loc_cpu_entry) << "\n"; 

   
      xt_compat_init_offsets(AF_INET, info->getNumber());

   /*
      for ((iter) = (typeof(iter))(loc_cpu_entry); 
                  (iter) < (typeof(iter))((char *)(loc_cpu_entry) + (info->getSize())); 
                        (iter) = (typeof(iter))((char *)(iter) + (iter)->next_offset))
      {
                 cout << "iter==> " << iter << "\n"; 
                 cout << "loc_cpu_entry==> " << loc_cpu_entry << "\n"; 

                  ret = tmp.compat_calc_entry(iter, info, loc_cpu_entry, newinfo);
                  if (ret != 0)
                        return ret;

      }//for  

	*/   

	// free up memory
	tmp.xt_free_table_info(info);
	tmp.xt_free_table_info(newinfo);
      
      return 0;
}
