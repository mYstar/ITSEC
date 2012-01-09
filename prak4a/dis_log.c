#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define ALPHA 1468
#define G 1357
#define P 2281

unsigned long mod_pow(unsigned long base, unsigned long power, unsigned long modulo)
{
  unsigned long res=1, i;

  for(i=0;power!=0; i++)
  {
    if(power & 1)
      res = (res*res *base)%modulo;
    else
      res = (res*res)%modulo;
    power >>= 1;
  }
  return res;
}

int main()
{
  int alpha=0, a=0;

  for(a=0; alpha!=ALPHA; a++)
  {
    alpha=mod_pow(G,a,P);
  }

  printf("a= %d\n, %lu\n", a-1, mod_pow(G,a,P));
  return 0;
}
