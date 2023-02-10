#include <math.h>

#define N 10000000UL

#define USELESSNESS(n)                          \
    do {                                        \
        unsigned long i;                        \
        double x = 42;                          \
        for (i = 0; i < (n); i++) x = sin(x);   \
    } while (0)

void baz()
{
    USELESSNESS(N);
}

void bar()
{
    USELESSNESS(2 * N);
    baz();
}

void foo()
{
    USELESSNESS(3 * N);
    bar();
    baz();
}

int main()
{
    foo();
    return 0;
}