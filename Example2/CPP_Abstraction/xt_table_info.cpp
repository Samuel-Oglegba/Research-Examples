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

#ifndef INT_MAX
#define INT_MAX 0x7fffffff
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

struct compat_ipt_replace {
	char			name[XT_TABLE_MAXNAMELEN];
	u32			valid_hooks;
	u32			num_entries;
	u32			size;
	u32			hook_entry[NF_INET_NUMHOOKS];
	u32			underflow[NF_INET_NUMHOOKS];
	u32			num_counters;
	compat_uptr_t		counters;	/* struct xt_counters * */
	struct compat_ipt_entry	entries[0];
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



////////// C++ Abstraction ////////////////////////
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
	
	XtTableInfo *xt_alloc_table_info(unsigned int size);

      void xt_free_table_info(XtTableInfo *info);

	bool valideUserInput(__user void *user);
      
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

    //for testing constraints
    int testConstraint(void __user *user){
		int ret;
		struct compat_ipt_replace tmp;
		struct xt_table_info newinfo;
		void *loc_cpu_entry;
		struct ipt_entry iter;
		struct xt_entry_target target;
		struct xt_entry_match match;
		
		__u16 next_offset = sizeof(iter) + sizeof(match) + sizeof(target);
		__u16 target_size = sizeof(iter) + sizeof(match);
		
		memcpy(&tmp, user, sizeof(tmp));

		//constraint 1: entry.next_offset = sizeof(entry) + sizeof(match) + sizeof(target)
		//constraint 2:  entry.next_offset = tmp.size = struct xt_table_info newinfo.size  (size per table row)
		if(tmp.size == next_offset){
			cout << "Correct table row size!::" << next_offset << "\n";
			return 1;
		}
		else{
			cout << "tmp.size::" << tmp.size << "\n";
			cout << "next_offset::" << next_offset << "\n";
			cout << "Invalid table row size!::" << tmp.size-next_offset << "\n";
		}
		
		return -1;
    }
      
};
////////// End C++ Abstraction ////////////////////////

/**
 * @brief allocate memory to the XtTableInfo abstraction
 * Input Parameter:(size)
 *    @param size - the size per table (usually size of struct ipt_replace, compat_ipt_replace, arpt_replace, & compat_arpt_replace)
 * 
 * Output Parameter:(XtTableInfo*)
 *    @param XtTableInfo* - pointer to the newly allocated memory address 
 * 
 * @return XtTableInfo* -- new pointer to abstraction class
 * 
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




int main ()
{
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

	data.target.u.user.target_size = sizeof(data.target);
	strcpy(data.target.u.user.name, "NFQUEUE");
	data.target.u.user.revision = 1;
	////////////////////////// END Exploit Code Data ///////////////////////////////

	//Test call illustration
	cout << "data.match.u.user.match_size:: " << data.match.u.user.match_size << "\n";
	cout << "data.target.u.user.target_size:: " << data.target.u.user.target_size << "\n";
	XtTableInfo * info;
	//info->testConstraint(&data);	
	cout << "(sizeof(data.entry) + sizeof(data.match) + sizeof(data.target)):: " << (sizeof(data.entry) + sizeof(data.match) + sizeof(data.target)) << "\n";
      
      return 0;
}
