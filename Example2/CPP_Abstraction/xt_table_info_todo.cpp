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

      #include <stddef.h>
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
unsigned long totalram_pages = 512; //512 gotten from the linux code -- fixme

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
/* Error verdict. */
#define XT_ERROR_TARGET "ERROR"
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

struct _xt_align {
	__u8 u8;
	__u16 u16;
	__u32 u32;
	__u64 u64;
};

#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)

#define XT_ALIGN(s) __ALIGN_KERNEL((s), __alignof__(struct _xt_align))


struct _compat_xt_align {
	__u8 u8;
	__u16 u16;
	__u32 u32;
	compat_u64 u64;
};
#define COMPAT_XT_ALIGN(s) __ALIGN_KERNEL((s), __alignof__(struct _compat_xt_align))

enum {
	NFPROTO_UNSPEC =  0,
	NFPROTO_INET   =  1,
	NFPROTO_IPV4   =  2,
	NFPROTO_ARP    =  3,
	NFPROTO_NETDEV =  5,
	NFPROTO_BRIDGE =  7,
	NFPROTO_IPV6   = 10,
	NFPROTO_DECNET = 12,
	NFPROTO_NUMPROTO,
};

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

struct compat_xt_entry_target {
	union {
		struct {
			u_int16_t target_size;
			char name[XT_FUNCTION_MAXNAMELEN - 1];
			u_int8_t revision;
		} user;
		struct {
			u_int16_t target_size;
			compat_uptr_t target;
		} kernel;
		u_int16_t target_size;
	} u;
	unsigned char data[0];
};

struct compat_xt_counters {
	compat_u64 pcnt, bcnt;			/* Packet and byte counters */
};// struct compat_xt_counters


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

static struct xt_af *xt;

struct xt_standard_target {
	struct xt_entry_target target;
	int verdict;
};

#define PRIMARY_SIZE 0x1000

/* The argument to IPT_SO_SET_REPLACE. */
struct ipt_replace {
	/* Which table. */
	char name[XT_TABLE_MAXNAMELEN];

	/* Which hook entry points are valid: bitmask.  You can't
           change this. */
	unsigned int valid_hooks;

	/* Number of entries */
	unsigned int num_entries;

	/* Total size of new entries */
	unsigned int size;

	/* Hook entry points. */
	unsigned int hook_entry[NF_INET_NUMHOOKS];

	/* Underflow points. */
	unsigned int underflow[NF_INET_NUMHOOKS];

	/* Information about old entries: */
	/* Number of counters (must be equal to current number of entries). */
	unsigned int num_counters;
	/* The old entries' counters. */
	struct xt_counters *counters;

	/* The entries (hang off end: not really an array). */
	struct ipt_entry entries[0];
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
	if(target){
		printf("target->targetsize:: %u\n",target->targetsize);
		u_int16_t csize = target->compatsize ? : target->targetsize;
		return XT_ALIGN(target->targetsize) - COMPAT_XT_ALIGN(csize);
	} 
	return 0;  	
}

int xt_compat_match_offset(const struct xt_match *match)
{
	u_int16_t csize = match->compatsize ? : match->matchsize;
      
	return XT_ALIGN(match->matchsize) - COMPAT_XT_ALIGN(csize);
      
}

/* All zeroes == unconditional rule. */
/* Mildly perf critical (only if packet tracing is on) */
static inline bool unconditional(const struct ipt_entry *e)
{
	//static const struct ipt_ip uncond;
	struct ipt_ip uncond;

	return e->target_offset == sizeof(struct ipt_entry) &&
	       memcmp(&e->ip, &uncond, sizeof(uncond)) == 0;
#undef FWINV
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
}//ip_checkentry

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

void xt_compat_lock(u_int8_t af)
{
	//mutex_lock(&xt[af].compat_mutex); -- using mutex may be really tricky to implement here
}

static inline long __must_check PTR_ERR(__force const void *ptr)
{
	return (long) ptr;
}

/* Helper functions */
static inline struct xt_entry_target *
compat_ipt_get_target(struct compat_ipt_entry *e)
{
	//return (void *)e + e->target_offset; //compilation error from this casting
	return (struct xt_entry_target *)e + e->target_offset;
}

static int
compat_find_calc_match(struct xt_entry_match *m,
		       const char *name,
		       const struct ipt_ip *ip,
		       int *size)
{
	struct xt_match *match;

	match = xt_request_find_match(NFPROTO_IPV4, m->u.user.name,
				      m->u.user.revision);
	if (IS_ERR(match)) {
		printf("compat_check_calc_match: `%s' not found\n",
			 m->u.user.name);
		return PTR_ERR(match);
	}
	m->u.kernel.match = match;
	*size += xt_compat_match_offset(match);
	return 0;
}// compat_find_calc_match



////////// C++ Abstraction Definition ////////////////////////
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

		int compat_calc_entry(const struct ipt_entry *e,
			     const XtTableInfo *info,
			     const void *base, XtTableInfo *newinfo);
		
		//makes the call to the vulnerable function
		int check_compat_entry_size_and_hooks(struct compat_ipt_entry *e,
				  XtTableInfo *newinfo,
				  unsigned int *size,
				  const unsigned char *base,
				  const unsigned char *limit,
				  const unsigned int *hook_entries,
				  const unsigned int *underflows,
				  const char *name);
		
		int mark_source_chains(const XtTableInfo *newinfo, unsigned int valid_hooks, void *entry0);
      
      public:
         XtTableInfo();//default constructor

	/* Getters */
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

        void * getEntries(){
            return entries;
        }

	  unsigned int * getHookEntry(){
            return hook_entry;
        }

	 unsigned int * getUnderflow(){
            return underflow;
       }
      /* End Getters */

      //allocate memory to the abstraction (xt_table_info)
      XtTableInfo *xt_alloc_table_info(unsigned int size);

	//free memory from the abstraction (xt_table_info)
      void xt_free_table_info(XtTableInfo *info);

	/* 
	getting table info -- compat_do_ipt_get_ctl offspring
	*/
	int compat_table_info(const XtTableInfo *info, XtTableInfo *newinfo);
	
	/* 
	setting table info -- compat_do_ipt_set_ctl offspring
	*/
	
	//translate abstraction (xt_table_info) from user-space to kernel-space
	int translate_compat_table(struct net *net,
		       const char *name,
		       unsigned int valid_hooks,
		       XtTableInfo **pinfo,
		       void **pentry0,
		       unsigned int total_size,
		       unsigned int number,
		       unsigned int *hook_entries,
		       unsigned int *underflows);
	
      

};
////////// End C++ Abstraction Definition ////////////////////////


///////// PRIVATE/PROTECTED ABSTRACTION METHODS ////////////////////

/**
* @brief private function because it was only used one time within a another function
* 
* Input Parameter:(e, info, base, newinfo)
*    @param e - LinkedList used to store the row entries of the routing table 
*    @param info - The network routing table.
*    @param base - Pointer to the starting position of the routing table entries and was 
*                  used with e (struct ipt_entry) to get the next table row. 
*    @param newinfo - The new network routing table that gets returned as output
* 
* Output Parameter:(newinfo)  
*     @param newinfo - the new table (abstraction.size, abstraction.hook_entry & abstraction.underflow are modified)      
*      
* @return (int) -- returning different error codes, possible output {0 -- success, a negative errno code, positive exit code on failure}.
*/  
int XtTableInfo::compat_calc_entry(const struct ipt_entry *e,
			     const XtTableInfo *info,
			     const void *base, XtTableInfo *newinfo)
{
	const struct xt_entry_match *ematch;
	const struct xt_entry_target *t;
	unsigned int entry_offset;
	int off, i, ret;

	off = sizeof(struct ipt_entry) - sizeof(struct compat_ipt_entry);
	//entry_offset = (void *)e - base;
	entry_offset = (int *)(void *)e - (int *)base;
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

}//compat_calc_entry

int
XtTableInfo::check_compat_entry_size_and_hooks(struct compat_ipt_entry *e,
				  XtTableInfo *newinfo,
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

		printf("check_compat_entry_size_and_hooks %p\n", e);
		if ((unsigned long)e % __alignof__(struct compat_ipt_entry) != 0 ||
		(unsigned char *)e + sizeof(struct compat_ipt_entry) >= limit ||
		(unsigned char *)e + e->next_offset > limit) {
			printf("Bad offset %p, limit = %p\n", e, limit);
			return -EINVAL;
		}

		if (e->next_offset < sizeof(struct compat_ipt_entry) +
				sizeof(struct compat_xt_entry_target)) {
			printf("checking: element %p size %u\n",
				e, e->next_offset);
			return -EINVAL;
		}

		/* For purposes of check_entry casting the compat entry is fine */
		ret = check_entry((struct ipt_entry *)e);
		if (ret)
			return ret;

		off = sizeof(struct ipt_entry) - sizeof(struct compat_ipt_entry);
		//entry_offset = (void *)e - (void *)base;
		entry_offset = (unsigned int *)(void *)e - (unsigned int *)(void *)base;
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
			printf("check_compat_entry_size_and_hooks: `%s' not found\n",
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

///////// END PRIVATE/PROTECTED ABSTRACTION METHODS ////////////////////


///////// PUBLIC ABSTRACTION  METHODS ////////////////////
/**
 * @brief allocate memory to the XtTableInfo abstraction
 * Input Parameter:(size)
 *    @param size - the size per table (usually size of struct ipt_replace, compat_ipt_replace, arpt_replace, or compat_arpt_replace)
 * 
 * Output Parameter:(XtTableInfo*)
 *    @param XtTableInfo* - pointer to the newly allocated memory address 
 * 
 * @return XtTableInfo* -- new pointer to abstraction class
 * 
 * Constraints{ // both already enforced in the c-code
 *    "input.size": "input.size > 0"
 *    "abstraction.size": "input.size = abstraction.size"
 * }
 */
XtTableInfo * XtTableInfo::xt_alloc_table_info(unsigned int size)
{
	XtTableInfo *info = NULL;
	size_t sz = sizeof(*info) + size;

	if (sz < sizeof(*info))
		return NULL;

	/* Pedantry: prevent them from hitting BUG() in vmalloc.c --RR */
	if ((SMP_ALIGN(size) >> PAGE_SHIFT) + 2 > totalram_pages)
		return NULL;

	if (sz <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER))		
		info = (XtTableInfo *)calloc(sz, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY); //info = kmalloc(sz, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY);
	if (!info) {
		//info = vmalloc(sz);
		info = (XtTableInfo *)malloc(sz);
		if (!info)
			return NULL;
	}
	memset(info, 0, sizeof(*info));
	info->size = size;
	return info;
}

/**
 * @brief free the routing table memory
 * 
 * @param info 
 */
void XtTableInfo::xt_free_table_info(XtTableInfo *info)
{
	int cpu;

	if (info->jumpstack != NULL) {
		for_each_possible_cpu(cpu)
			free(info->jumpstack[cpu]); //kvfree(info->jumpstack[cpu]);			
		free(info->jumpstack); //kvfree(info->jumpstack);
	}

	//kvfree(info);
	free(info);
}

/**
 * @brief copy all the abstraction elements to a 
 * 
 * @param info 
 * @param newinfo 
 * @return int 
 */
int XtTableInfo::compat_table_info(const XtTableInfo *info,
			     XtTableInfo *newinfo)
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
 * @brief 
 * 
 * @param net 
 * @param name 
 * @param valid_hooks 
 * @param pinfo 
 * @param pentry0 
 * @param total_size 
 * @param number 
 * @param hook_entries 
 * @param underflows 
 * @return int 
 */
int XtTableInfo::translate_compat_table(struct net *net,
		       const char *name,
		       unsigned int valid_hooks,
		       XtTableInfo **pinfo,
		       void **pentry0,
		       unsigned int total_size,
		       unsigned int number,
		       unsigned int *hook_entries,
		       unsigned int *underflows)
{
		unsigned int i, j;
		XtTableInfo *newinfo, *info;
		void *pos, *entry0, *entry1;
		struct compat_ipt_entry *iter0;
		struct ipt_entry *iter1;
		unsigned int size;
		int ret;

		info = *pinfo;
		entry0 = *pentry0;
		size = total_size;
		info->number = number;

		/* Init all hooks to impossible value. */
		for (i = 0; i < NF_INET_NUMHOOKS; i++) {
			info->hook_entry[i] = 0xFFFFFFFF;
			info->underflow[i] = 0xFFFFFFFF;
		}

		printf("translate_compat_table: size %u\n", info->size);
		j = 0;
		xt_compat_lock(AF_INET);
		xt_compat_init_offsets(AF_INET, number);
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
			printf("translate_compat_table: %u not %u entries\n",
				j, number);
			goto out_unlock;
		}

		/* Check hooks all assigned */
		for (i = 0; i < NF_INET_NUMHOOKS; i++) {
			/* Only hooks which are valid */
			if (!(valid_hooks & (1 << i)))
				continue;
			if (info->hook_entry[i] == 0xFFFFFFFF) {
				printf("Invalid hook entry %u %u\n",
					i, hook_entries[i]);
				goto out_unlock;
			}
			if (info->underflow[i] == 0xFFFFFFFF) {
				printf("Invalid underflow %u %u\n",
					i, underflows[i]);
				goto out_unlock;
			}
		}

		ret = -ENOMEM;
		newinfo = xt_alloc_table_info(size);
		if (!newinfo)
			goto out_unlock;

		newinfo->number = number;
		for (i = 0; i < NF_INET_NUMHOOKS; i++) {
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
		xt_compat_flush_offsets(AF_INET);
		xt_compat_unlock(AF_INET);
		if (ret)
			goto free_newinfo;

		ret = -ELOOP;
		if (!mark_source_chains(newinfo, valid_hooks, entry1))
			goto free_newinfo;

		i = 0;
		xt_entry_foreach(iter1, entry1, newinfo->size) {
			ret = compat_check_entry(iter1, net, name);
			if (ret != 0)
				break;
			++i;
			if (strcmp(ipt_get_target(iter1)->u.user.name,
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
				cleanup_entry(iter1, net);
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
		xt_compat_flush_offsets(AF_INET);
		xt_compat_unlock(AF_INET);
		goto out;

}//translate_compat_table

///////// END PUBLIC ABSTRACTION METHODS ////////////////////




int main (int argc, char *argv[])
{
     
      XtTableInfo *info;
      XtTableInfo *newinfo;
      struct ipt_entry *iter;
      const void *loc_cpu_entry;
      int ret;
      xt = (struct xt_af *)malloc(sizeof *xt);

	struct ipt_replace tmp;

	///////////////////////// Exploit Code Data /////////////////////////////////

	struct __attribute__((__packed__)) {
	struct ipt_replace replace;
	struct ipt_entry entry;
	struct xt_entry_match match;
	char pad[0x108 + PRIMARY_SIZE - 0x200 - 0x2];
	struct xt_entry_target target;
	} data = {0};

	data.replace.num_counters = 1;
	data.replace.num_entries = 1;
	data.replace.size = (sizeof(data.entry) + sizeof(data.match) +
				sizeof(data.pad) + sizeof(data.target));

	data.entry.next_offset = (sizeof(data.entry) + sizeof(data.match) +
					sizeof(data.pad) + sizeof(data.target));
	data.entry.target_offset =
		(sizeof(data.entry) + sizeof(data.match) + sizeof(data.pad));

	data.match.u.user.match_size = (sizeof(data.match) + sizeof(data.pad));
	strcpy(data.match.u.user.name, "icmp");
	data.match.u.user.revision = 0;
	////////////////////
	data.match.u.kernel.match_size = (sizeof(data.match) + sizeof(data.pad));
	data.match.u.kernel.match = (struct xt_match *)malloc(sizeof(data.match.u.kernel.match));
	////////////////////

	data.target.u.user.target_size = sizeof(data.target);
	strcpy(data.target.u.user.name, "NFQUEUE");
	data.target.u.user.revision = 1;

	////////////////////
	data.target.u.kernel.target_size = sizeof(data.target);
	data.target.u.kernel.target = (struct xt_target *)malloc(sizeof(data.target.u.kernel.target));
	////////////////////	
	////////////////////////// END Exploit Code Data ///////////////////////////////

	//copy user data, similar to copy_from_user
	memcpy(&tmp, &data, sizeof(tmp));

	tmp.name[sizeof(tmp.name)-1] = 0;
	
      ////////////////////////////////
            info = info->xt_alloc_table_info(tmp.size);
			//info->setNumber(1);
            newinfo = newinfo->xt_alloc_table_info(sizeof(info));    
      ////////////////////////////////	
	memcpy(info->getEntries(), &data.entry, tmp.size);

      loc_cpu_entry = info->getEntries();

      //ToDo -- use of proper test data for both C++ and C codes
	memcpy(newinfo, info, offsetof(struct xt_table_info, entries));
	
	//xt_compat_init_offsets(AF_INET, info->getNumber());
	xt_compat_init_offsets(AF_INET, 1);

	//iter = (struct ipt_entry *)malloc(sizeof(iter)); 

	//memcpy(&iter, &data.entry, sizeof(iter));

	///////////// calling function Test function ///////////////////
            xt_entry_foreach(iter, loc_cpu_entry, info->getSize()) {
                 // ret = newinfo->compat_calc_entry(iter, info, loc_cpu_entry, newinfo);
                  if (ret != 0)
                        return ret;
            }	            
	////////////////////////////////		
	////////////////////////////////

	printf("ret:: %d\n",ret);		
	printf("newinfo->size:: %u\n",newinfo->getSize());
	
	// free up memory
	newinfo->xt_free_table_info(newinfo);
	info->xt_free_table_info(info);	
      
      return 0;
}
