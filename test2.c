   int sock = socket(AF_INET, SOCK_STREAM, 0);

      if (sock == -1) {
          // error handling
          printf("unable to create socket\n");
      }

      // set SO_ERROR option
      int optval = 1;
      int optlen = sizeof(optval);
      int myret = setsockopt(sock, SOL_SOCKET, SO_ERROR, &optval, optlen);
      if (myret == -1) {
          // error handling
          printf("unable to configure socket: %d\n", myret);
      }

      // check for pending errors
      optval = 0;
      optlen = sizeof(optval);
      if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
          // error handling
          printf("unable to get socket: SO_ERROR");
      }

      if (optval != 0) {
          // handle pending error
          printf("invalid optval\n");
      }

      printf("optval:: %d\n", optval);

// TRY THIS ON THE SERVER
 #include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    int sockfd;
    struct sockaddr_in serveraddr;

    // create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // initialize the server address
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons(8080);

    // bind the socket to the server address
    if (bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        perror("socket bind failed");
        exit(EXIT_FAILURE);
    }

    printf("UDP socket created and bound successfully.\n");

    return 0;
}
