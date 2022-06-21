#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netfilter_ipv6/ip6_tables.h>


#include <fcntl.h>
#include <inttypes.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <linux/netfilter_ipv4/ip_tables.h>

typedef unsigned int u32;
typedef unsigned int u64;
typedef u32		compat_uptr_t;
typedef u64		compat_u64;
typedef u32		compat_uint_t;
#define __user
#define __aligned(x)		__attribute__((aligned(x)))

struct compat_xt_counters {
	compat_u64 pcnt, bcnt;			/* Packet and byte counters */
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
};
/*
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
*/
/*
struct xt_entry_match {
	union {
		struct {
			__u16 match_size;

			/* Used by userspace */
/*			char name[XT_EXTENSION_MAXNAMELEN];
			__u8 revision;
		} user;
		struct {
			__u16 match_size;

			/* Used inside the kernel */
	/*		struct xt_match *match;
		} kernel;

		/* Total length */
	/*	__u16 match_size;
	} u;

	unsigned char data[0];
};
*/

struct list_head {
	struct list_head *next, *prev;
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
	/*
	bool (*match)(const struct sk_buff *skb,
		      struct xt_action_param *);
			*/

	/* Called when user tries to insert an entry of this type. */
	int (*checkentry)(const struct xt_mtchk_param *);

	/* Called when entry of this type deleted. */
	void (*destroy)(const struct xt_mtdtor_param *);
#ifdef CONFIG_COMPAT
	/* Called when userspace align differs from kernel space one */
	void (*compat_from_user)(void *dst, const void *src);
	int (*compat_to_user)(void __user *dst, const void *src);
#endif
	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	const char *table;
	unsigned int matchsize;
#ifdef CONFIG_COMPAT
	unsigned int compatsize;
#endif
	unsigned int hooks;
	unsigned short proto;

	unsigned short family;
};

/*
struct xt_entry_target {
	union {
		struct {
			__u16 target_size;

			/* Used by userspace */
		/*	char name[XT_EXTENSION_MAXNAMELEN];
			__u8 revision;
		} user;
		struct {
			__u16 target_size;

			/* Used inside the kernel */
	/*		struct xt_target *target;
		} kernel;

		/* Total length */
	/*	__u16 target_size;
	} u;

	unsigned char data[0];
};
*/

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
#ifdef CONFIG_COMPAT
	unsigned int compatsize;
#endif
	unsigned int hooks;
	unsigned short proto;

	unsigned short family;
};

/*
#define copy_from_user(to, from, n)					\
({									\
	void *__cu_to;							\
	const void __user *__cu_from;					\
	long __cu_len;							\
									\
	__cu_to = (to);							\
	__cu_from = (from);						\
	__cu_len = (n);							\
	if (eva_kernel_access()) {					\
		__cu_len = __invoke_copy_from_kernel(__cu_to,		\
						     __cu_from,		\
						     __cu_len);		\
	} else {							\
		if (access_ok(VERIFY_READ, __cu_from, __cu_len)) {	\
			might_fault();                                  \
			__cu_len = __invoke_copy_from_user(__cu_to,	\
							   __cu_from,	\
							   __cu_len);   \
		}							\
	}								\
	__cu_len;							\
})
*/

extern unsigned long totalram_pages;
#define PAGE_SHIFT	12
#define PAGE_SIZE	1000//(__XTENSA_UL_CONST(1) << PAGE_SHIFT)
#define PAGE_ALLOC_COSTLY_ORDER 3
#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)


struct xt_table_info *xt_alloc_table_info(unsigned int size)
{
	struct xt_table_info *info = NULL;
	size_t sz = sizeof(*info) + size;

	if (sz < sizeof(*info))
		return NULL;

	/* Pedantry: prevent them from hitting BUG() in vmalloc.c --RR */
	//if ((SMP_ALIGN(size) >> PAGE_SHIFT) + 2 > totalram_pages)
	//	return NULL;

	if (sz <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER))
		//info = kmalloc(sz, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY);
		info = calloc(PAGE_ALLOC_COSTLY_ORDER, sz);
	if (!info) {
		//info = vmalloc(sz);
		info = malloc(sz);
		if (!info)
			return NULL;
	}

	memset(info, 0, sizeof(*info));
	info->size = size;
	return info;
}


/******** STEP 1 ***/
static int
compat_do_replace(struct net *net, void __user *user, unsigned int len)
{
	int ret;
	struct compat_ipt_replace tmp;
	struct xt_table_info *newinfo;
	void *loc_cpu_entry;
	struct ipt_entry *iter;

	//if (copy_from_user(&tmp, user, sizeof(tmp)) != 0)
	if (0 != 0)
		return -EFAULT;
printf("i came here\n");

	/* overflow check */
	//if (tmp.size >= INT_MAX / num_possible_cpus())
	if (tmp.size >= INT_MAX / 4)
		return -ENOMEM;
	if (tmp.num_counters >= INT_MAX / sizeof(struct xt_counters))
		return -ENOMEM;
	if (tmp.num_counters == 0)
		return -EINVAL;

	tmp.name[sizeof(tmp.name)-1] = 0;

	newinfo = xt_alloc_table_info(tmp.size);
	//newinfo = (int *)malloc(tmp.size);

printf("i came here again\n");

	if (!newinfo)
		return -ENOMEM;

	loc_cpu_entry = newinfo->entries;
/*
	if (copy_from_user(loc_cpu_entry, user + sizeof(tmp),
			   tmp.size) != 0) {
		ret = -EFAULT;
		goto free_newinfo;
	}
*/
     /*
	ret = translate_compat_table(net, tmp.name, tmp.valid_hooks,
				     &newinfo, &loc_cpu_entry, tmp.size,
				     tmp.num_entries, tmp.hook_entry,
				     tmp.underflow);
      */
     
	if (ret != 0)
		goto free_newinfo;

	//duprintf("compat_do_replace: Translated table\n");
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

}// END of STEP 1


/** MAIN FUNCTION **/
int main(int argc, char *argv[]) {

//call the first function 

//compat_do_replace(struct net *net, void __user *user, unsigned int len);
compat_do_replace(NULL, NULL, 0);


return 0;
} /** END OF MAIN **/