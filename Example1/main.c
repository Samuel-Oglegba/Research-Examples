#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "jsonparse.c"


int main(int argc, char **argv) 
{
     struct jsonparse_state theState;   
     int len = 20;
     char *c;
     char m = '{';
     int i = 0;

     if (argc != 2) {
        printf("Argument: char is required\n");
        exit(1);
      }
     
      c = argv[1];
      char *json = "{ \"msg-type\": [ \"0xdeadbeef\", \"irc log\" ], \
            \"msg-from\": { \"class\": \"soldier\", \"name\": \"Wixilav\" }, \
            \"msg-to\": { \"class\": \"supreme-commander\", \"name\": \"[Redacted]\" }, \
            \"msg-log\": [ \
                  \"soldier: Boss there is a slight problem with the piece offering to humans\", \
                  \"supreme-commander: Explain yourself soldier!\", \
                  \"soldier: Well they don't seem to move anymore...\", \
                  \"supreme-commander: Oh snap, I came here to see them twerk!\" \
                  ] \
            }";
            

     jsonparse_setup(&theState, json, len);
     bool res;
     for(i = 0; i<20; i++){
        res = push(&theState, c[0]);
        res ? printf("Push: %d, char: %c\n",res, theState.stack[0]) : printf("--\n");
     }

      
      bool res1 = modify(&theState, m);
      /// pop(&theState);
        
      printf("Modify: %d, char1: %c\n",res1, theState.stack[theState.depth - 1]);
}
