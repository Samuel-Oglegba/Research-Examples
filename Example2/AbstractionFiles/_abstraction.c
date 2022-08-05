//=== Data Structures =====
//** Note: structures with prefix compat_ ==> means backward compatibility
//The compat module allows code from newer kernel releases to be used on older kernels without modifications with a few exceptions using header files

struct net; //(network namespace) 

/**
 *@brief  
 *Input Parameter:(net, user, len)
 *			@param net --  A struct of independent logical copy of the host network stack (it has it's own routing table, set of IP addresses, socket listing, etc). 
 *				   Represents the virtual container useful for communication between the application with the physical network devices.
 *				
 * 			@param user -- Holds the data from the user space when they configure socket options using  setsockopt() system call.
 * 				   Used for copying data from user space to kernel space. 
 * 
 * 			@param len --  was not used in this function implementation
 * 
 *Output Parameter:()	
 *
 *Return Value	: @return (int) -- returning different error codes, possible output {0 -- default operation, 1 -- for success, negative values for when something goes wrong}. 	  
 *	
 */

static int
compat_do_replace(struct net *net, void __user *user, unsigned int len)
{
	int ret;
	struct compat_ipt_replace tmp; //set of ip addresses using hooks (which is a way to use callbacks in order to filter packets inside the kernel)
	struct xt_table_info *newinfo; // The network routing table, it is keyed by destination IP address. 
	void *loc_cpu_entry; // The routing table entries, (can be likened to the rows of the routing table). Used as the starting point to iterate through all the firewall rules 
	struct ipt_entry *iter; //This structure defines each of the firewall rules (ip header, match, target to perform if rule matches)

      /**
      * @brief    Copy a block of data from user space to kernel space.
      * Input	@tmp:  Destination address, in kernel space.
      * 		@user: Source address, in user space.
      * 		@sizeof(tmp): Number of bytes to copy.
	* Output	@return error code 
      */
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

      /**
       * @brief allocate memory space to the routing table
       * 
       */
	newinfo = xt_alloc_table_info(tmp.size);
	if (!newinfo)
		return -ENOMEM;

	loc_cpu_entry = newinfo->entries;

	if (copy_from_user(loc_cpu_entry, user + sizeof(tmp),
			   tmp.size) != 0) {
		ret = -EFAULT;
		goto free_newinfo;
	}

      /**
       * @brief checks all table entries for validity and computes the new structure size in kernel-space when converting from 32bit to 64bit
       * 
       */
	ret = translate_compat_table(net, tmp.name, tmp.valid_hooks,
				     &newinfo, &loc_cpu_entry, tmp.size,
				     tmp.num_entries, tmp.hook_entry,
				     tmp.underflow);
	if (ret != 0)
		goto free_newinfo;

	duprintf("compat_do_replace: Translated table\n");

      /**
       * @brief This function replaces the table entries by swapping values old with new
       * 
       */
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


/**
 * @brief 
 *Input Parameters:(net, name, valid_hooks, pinfo, pentry0, total_size, number, hook_entries, underflows) 
 * 			@param net -- A struct of independent logical copy of the host network stack (it has it's own routing table, set of IP addresses, socket listing, etc). 
 *				  Represents the virtual container useful for communication between the application with the physical network devices.
 * 			@param name -- An array of rounting table. The name tells us which table to look at.
 * 			@param valid_hooks -- Which hook entry points are valid: bitmask. Used for verification
 * 			@param pinfo -- The network routing table, it is keyed by destination IP address.
 * 			@param pentry0 -- The routing table entries, (can be likened to the rows of the routing table). Used as the starting point to iterate through all the firewall rules.
 * 			@param total_size -- Total size of new entries. Used to allocate memory to the routing table
 * 			@param number -- Number of table entries
 * 			@param hook_entries -- Hook entry points.
 * 			@param underflows -- Underflow points.
 * 
 *Output Parameters:(pinfo, pentry0)
 *			@param pinfo -- The network routing table, it is keyed by destination IP address 
 *			@param pentry0 -- The routing table entries, (can be likened to the rows of the routing table). Used to iterate through all the firewall rules 
 *
 *Return Values:	@return (int) -- returning different error codes, possible output {0 -- default operation, 1 -- for success, negative values for when something goes wrong}. 
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
	struct xt_table_info *newinfo, *info; // The network routing table, it is keyed by destination IP address. 
	void *pos, *entry0, *entry1; // The routing table entries, (can be likened to the rows of the routing table).
	struct compat_ipt_entry *iter0; //Backward compatible. This structure defines each of the firewall rules (ip header, match, target to perform if rule matches)
	struct ipt_entry *iter1; //This structure defines each of the firewall rules (ip header, match, target to perform if rule matches)
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
 * @brief 
 *Input Parameters:(e, newinfo, size, base, limit, hook_entries, underflows, name)
 * 			@param e -- Backward compatible. This structure defines each of the firewall rules (ip header, match, target to perform if rule matches)
 * 			@param newinfo -- The network routing table, it is keyed by destination IP address.
 * 			@param size -- Total size of new entries.
 * 			@param base -- The routing table entries, (can be likened to the rows of the routing table).
 * 			@param limit -- the maximum size of the new entries.
 * 			@param hook_entries -- Hook entry points.
 * 			@param underflows -- Underflow points.
 * 			@param name -- The name tells us which table to look at.
 *Output Parameters:	
 *Return Value:	@return (int) -- returning different error codes, possible output {0 -- default operation, 1 -- for success, negative values for when something goes wrong}.  
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
	struct xt_entry_match *ematch; //the matches from the firwall rules data structure `compat_ipt_entry`
	struct xt_entry_target *t; //the targets from the firwall rules data structure `compat_ipt_entry`
	struct xt_target *target; //the registration hooks for targets from the firwall rules data structure `compat_ipt_entry`
	unsigned int entry_offset; //calculating the location of the table entry
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
 * @brief 
 *Input Parameter:(e, dstptr, size, name, newinfo, base)
 * 			@param e -- Backward compatible. This structure defines each of the firewall rules (ip header, match, target to perform if rule matches)
 * 			@param dstptr -- The pointer location of the routing table entries, (can be likened to the rows of the routing table).
 * 			@param size -- Total size of new entries
 * 			@param name -- The name tells us which table to look at.
 * 			@param newinfo -- The network routing table, it is keyed by destination IP address.
 * 			@param base -- The routing table entries, (can be likened to the rows of the routing table).
 *Output Parameter:	
 *Return Value:	@return (int) -- returning different error codes, possible output {0 -- default operation, 1 -- for success, negative values for when something goes wrong}. 
 */
static int compat_copy_entry_from_user(struct compat_ipt_entry *e, void **dstptr,
			    unsigned int *size, const char *name,
			    struct xt_table_info *newinfo, unsigned char *base)
{
	struct xt_entry_target *t; //the targets from the firwall rules data structure `compat_ipt_entry`
	struct xt_target *target; //the registration hooks for targets from the firwall rules data structure `compat_ipt_entry`
	struct ipt_entry *de; //This structure defines each of the firewall rules (ip header, match, target to perform if rule matches)
	unsigned int origsize;
	int ret, h;
	struct xt_entry_match *ematch; //the matches from the firwall rules data structure `compat_ipt_entry`

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

/**
 * @brief 
 *Input Parameters:(t, dstptr, size)
 * 			@param t -- the targets from the firwall rules data structure `compat_ipt_entry`
 * 			@param dstptr -- The pointer location of the routing table entries, (can be likened to the rows of the routing table).
 * 			@param size -- Total size of new entries
 * 
 *Output Parameters:(t, dstptr)
 *			@param t -- the targets from the firwall rules data structure `compat_ipt_entry`
 * 			@param dstptr -- The pointer location of the routing table entries, (can be likened to the rows of the routing table).
 * 	
 *Return Value:	@return ()
 */
void xt_compat_target_from_user(struct xt_entry_target *t, void **dstptr,
				unsigned int *size)
{
	const struct xt_target *target = t->u.kernel.target; //the registration hooks for targets from the firwall rules data structure `compat_ipt_entry`
	struct compat_xt_entry_target *ct = (struct compat_xt_entry_target *)t; //backward compatible. The targets from the firwall rules data structure `compat_ipt_entry`
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

