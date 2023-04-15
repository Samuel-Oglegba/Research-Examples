#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct ipt_replace replace;
    // fill in the ipt_replace structure with the new rule
    // ...

    int option = IPT_SO_SET_REPLACE;
    int ret = setsockopt(sockfd, SOL_IP, option, &replace, sizeof(replace));
    if (ret < 0) {
        perror("setsockopt");
        return 1;
    }

    close(sockfd);
    return 0;
}
