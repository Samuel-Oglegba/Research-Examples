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

#include <stdbool.h>
#include <linux/types.h>

#include <linux/if.h>
#include <linux/netfilter_ipv4.h>

#include <linux/netfilter/x_tables.h>

typedef unsigned int u32;
typedef unsigned int u64;
typedef u32		compat_uptr_t;
typedef u64		compat_u64;
typedef u32		compat_uint_t;
#define __user

struct _compat_xt_align {
	__u8 u8;
	__u16 u16;
	__u32 u32;
	compat_u64 u64;
};

#define COMPAT_XT_ALIGN(s) __ALIGN_KERNEL((s), __alignof__(struct _compat_xt_align))
#define __aligned(x)		__attribute__((aligned(x)))


extern unsigned long totalram_pages;
#define PAGE_SHIFT	12
#define PAGE_SIZE	100//(__XTENSA_UL_CONST(1) << PAGE_SHIFT)
#define PAGE_ALLOC_COSTLY_ORDER 3
#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)

struct list_head {
	struct list_head *next, *prev;
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
	//char			name[XT_TABLE_MAXNAMELEN];
	//u32			valid_hooks;
	//u32			num_entries;
	//u32			size;
	// u32			hook_entry[NF_INET_NUMHOOKS];
	// u32			underflow[NF_INET_NUMHOOKS];
	//u32			num_counters;
	//compat_uptr_t		counters;	/* struct xt_counters * */
	//struct compat_ipt_entry	entries[0];
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

int xt_compat_target_offset(const struct xt_target *target)
{
	u_int16_t csize = target->compatsize ? : target->targetsize;
	return XT_ALIGN(target->targetsize) - COMPAT_XT_ALIGN(csize);
}

/* Helper functions */
static inline struct xt_entry_target *
compat_ipt_get_target(struct compat_ipt_entry *e)
{
	return (void *)e + e->target_offset;
}

struct xt_table_info *xt_alloc_table_info(unsigned int size)
{
	struct xt_table_info *info = NULL;
	size_t sz = sizeof(*info) + size;

	if (sz < sizeof(*info))
		return NULL;

	/* Pedantry: prevent them from hitting BUG() in vmalloc.c --RR */
	//if ((SMP_ALIGN(size) >> PAGE_SHIFT) + 2 > totalram_pages)
	//	return NULL;

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

}//xt_table_info

void xt_compat_target_from_user(struct xt_entry_target *t, void **dstptr,
				unsigned int *size)
{
	const struct xt_target *target = t->u.kernel.target;
	struct compat_xt_entry_target *ct = (struct compat_xt_entry_target *)t;
	int pad, off = xt_compat_target_offset(target);
	u_int16_t tsize = ct->u.user.target_size;

	//t = *dstptr;
	memcpy(t, ct, sizeof(*ct));

      printf("data address 1:: %p\n",&t->data);
	if (target->compat_from_user){
            target->compat_from_user(t->data, ct->data);
      }		
	else{
            memcpy(t->data, ct->data, tsize - sizeof(*ct));
      }	

	printf("data address 2 %p\n",&t->data);

	//printf("xt_align %d\n",XT_ALIGN(target->targetsize));
      //printf("target size %d\n",target->targetsize);

      pad = XT_ALIGN(target->targetsize) - target->targetsize;
     
      printf("pad %d\n",pad);

      printf("size of Data: %ld\n",sizeof(t->data));
	//if (pad > 0)
	if (pad == 0)
		memset(t->data + target->targetsize, 0, 5);
		//memset(t->data + target->targetsize, 0, pad);

      printf("size of Data2: %ld\n",sizeof(t->data));
	tsize += off;
	t->u.user.target_size = tsize;

       printf("Outputs \n");
	 printf("t.u.user.target_size:: %d\n",t->u.user.target_size);
	 printf("t.u.user.name:: %s\n",t->u.user.name);
	 printf("t.u.user.revision:: %d\n",t->u.user.revision);
	 printf("t.data:: %p\n",&t->data);

	//*size += off;
	//*dstptr += tsize;
}


/** MAIN FUNCTION **/
int main(int argc, char *argv[]) {
      struct compat_ipt_entry *e;
      struct xt_table_info *newinfo, *info;
      struct xt_entry_target *t;
      void **dstptr;
      void *pos, *entry0, *entry1;
      unsigned int *size;
	struct compat_ipt_replace tmp;

     //*dstptr += sizeof(struct ipt_entry);      
      size += sizeof(struct ipt_entry) - sizeof(struct compat_ipt_entry);
      //size += sizeof(t);

	//printf("Location of ",);
      //newinfo = xt_alloc_table_info(tmp.size);
	//printf("New Info: %ld\n",sizeof(newinfo));

       t->u.user.target_size = sizeof(t);
       strcpy(t->u.user.name, "NFQUEUE");
       t->u.user.revision = 1;

	 printf("Inputs \n");
	 printf("u.user.target_size:: %d\n",t->u.user.target_size);
	 printf("u.user.name:: %s\n",t->u.user.name);
	 printf("u.user.revision:: %d\n",t->u.user.revision);


      //t = compat_ipt_get_target(NULL);
      xt_compat_target_from_user(t, dstptr,size);

      return 0;
} /** END OF MAIN **/