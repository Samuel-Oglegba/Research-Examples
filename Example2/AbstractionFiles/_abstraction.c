//=== Data Structures =====
struct net; //(network namespace) 

/**
 *@brief  
 *Input:	(net, user, len)
 *		@param net --  A struct of independent logical copy of the host network stack (it has it's own routing table, set of IP addresses, socket listing, etc). 
 *				   Represents the virtual container useful for communication between the application with the physical network devices.
 *				
 * 		@param user -- Holds the data from the user space when they configure socket options using  setsockopt() system call.
 * 				   Used for copying data from user space to kernel space. 
 * 
 * 		@param len --  was not used in this function implementation
 * 
 *Output:	@return (int)
 *			  newinfo       -- The network routing table, it is keyed by destination IP address. 
 						 Not a global variable but the allocated memory exist outside the scope of this function
 *			  loc_cpu_entry -- The routing table entries, (rows of the table). 
 						 Not a global variable but the allocated memory exist outside the scope of this function 
 *			  int           -- returning different error codes, possible output {0 -- default operation, 1 -- for success, negative values for when something goes wrong}. 
 *	
 */
static int
compat_do_replace(struct net *net, void __user *user, unsigned int len)
{
	int ret;
	struct compat_ipt_replace tmp;
	struct xt_table_info *newinfo;
	void *loc_cpu_entry;
	struct ipt_entry *iter;

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
       * @brief allocate memory space to variable newinfo
       * 
       */
	newinfo = xt_alloc_table_info(tmp.size);
	if (!newinfo)
		return -ENOMEM;

	loc_cpu_entry = newinfo->entries;

      /**
      * @brief Copy a block of data from user space to kernel space.
      */
	if (copy_from_user(loc_cpu_entry, user + sizeof(tmp),
			   tmp.size) != 0) {
		ret = -EFAULT;
		goto free_newinfo;
	}

      /**
       * @brief checks all entries for validity and computes the new structure size in kernel-space when converting from 32bit to 64bit
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
}