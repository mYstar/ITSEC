#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define ALPHA 1468
#define G 1357
#define P 2281

long long mod_pow(long long base, long long power, long long modulo)
{
  long long res=base;

  int numshift = (int)(log2((double)power))-1; //because of initialisation the first 1 can be ommitted

  for(; numshift>=0; numshift--)
  {
    if((power>>numshift) & 1)
      res = (res*res *base)%modulo;
    else
      res = (res*res)%modulo;
  }
  return res;
}

int main()
{
  long long a, alpha;

  for(a=1; alpha!=ALPHA; a++)
    alpha = mod_pow(G,a,P);

  printf("%llu\n",a-1);

  return 0;
}
