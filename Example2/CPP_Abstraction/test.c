#include <stdio.h>
#include <string.h>


int main (int argc, char *argv[])
{

    int a = 0;
    int b = 22;

     printf("just testing \n");
     memset(&a, b, 1);

   //  printf("sizeof(a): %ld\n", sizeof(a)); 
     printf("%d\n", a); 

}