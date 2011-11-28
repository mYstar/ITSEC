#include <fcntl.h>                     /* O_RDONLY */
#include <stdio.h>                       /* printf */
#include <string.h>                      /* memcpy */
#include <unistd.h>                        /* read */
#include <openssl/blowfish.h>              /* BF_* */
#include <sys/time.h>

unsigned char input[512];    /* for encrypted text */
unsigned char output[512];   /* for decrypted text */

unsigned char key[16] = {           /* 128 bit key */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

unsigned char expected[16] = {           /* my expected result */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

int main(void)
{
	int i, t, keylen;
	long length;
	BF_KEY bfkey;
  struct timeval start, end;
  long mtime, seconds, useconds;

	/* open the given text file */
	t = open("blowfish.bin", O_RDONLY);
	if (t < 0) {
		perror("blowfish.bin");
		return 1;
	}
	length = 512;
  keylen=16;
	/* read 512 bytes from file descriptor t */
	read(t, input, length);
	/* brute-force attack with known plaintext */
	for (i = 0; i < 0x10000; i++) {
		/* REPLACE THE FOLLOWING FIVE COMMENTS BY CODE */
		/* set key[0] and key[1] */
    if(i==0)
     gettimeofday(&start, NULL);
    key[0]=i&0xff;
    key[1]=(i>>8)&0xff;
		/* use BF_set_key to initialise bfkey */
    BF_set_key(&bfkey, keylen, key);
		/* call BF_ecb_encrypt with parameter BF_DECRYPT */
    BF_ecb_encrypt(&input[504], &output[0], &bfkey, BF_DECRYPT);
		/* Did it work? (Look for expected plain text.) */
    if(memcmp(output, expected, keylen)==0)
      break;
		/* pseudo code: IF key is correct THEN leave the loop; */
    if(i==0)
    {
     gettimeofday(&end, NULL);
     seconds  = end.tv_sec  - start.tv_sec;
     useconds = end.tv_usec - start.tv_usec;

     mtime = ((seconds) * 1000000 + useconds);

     printf("Elapsed time: %ld microseconds\n", mtime);
    }
  }
  if (i == 0x10000) {
    printf("key not found\n");
    return 1;
  }
  /* show the key that we just determined */
  printf("key = {\n\t%d", key[0]);
  for (i = 1; i < sizeof(key); i++) {
    printf(", %d", key[i]);
  }
  printf("\n};\n");
  /* decrypt input */
  for (i = 0; i < length; i += 8)
    BF_ecb_encrypt(input + i, output + i, &bfkey, BF_DECRYPT);
  /* show decrypted text on stdout */
  printf("%s\n", output);

  return 0;
}
