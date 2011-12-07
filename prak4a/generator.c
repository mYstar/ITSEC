#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define G 700
#define P 65267

long long mod_pow(long long base, long long power, long long modulo)
{
  long long res=1, i;

  int numshift = (int)(log2((double)power)+0.5);
  printf("%d\n", numshift);

  //for(i=0;power!=0; i++)
  {
    if(power & 1)
      res = (res*res *base)%modulo;
    else
      res = (res*res)%modulo;
  }
  return res;
}

int main()
{
  long long a;

  /*for(a=G;;a++)
  {
    if(mod_pow(a,2,P)==1)
      continue;
    if(mod_pow(a,(P-1)/2,P)==1)
      continue;
    break; //found the number
  }*/
  mod_pow(1, 8, 500);
  printf("%llu\n",a);

  return 0;
}
