#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define ALPHA 1468
#define G 1357
#define P 2281

int mod_pow(int base, int power, int modulo)
{
  int res=1, i, numshift = (sizeof(int)*8);

  for(i=0; i<numshift; i++)
  {
    if(power & (1<<(numshift-1)))
      res = ((int)(pow(res, 2) + 0.5) *base)%modulo;
    else
      res = ((int)(pow(res, 2) + 0.5))%modulo;
    power <<= 1;
  }
  return res;
}

int main()
{
  printf("%d\n", mod_pow(13, 7, 100));

  return 0;
}
