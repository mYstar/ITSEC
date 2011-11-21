#include <fcntl.h>                     /* O_RDONLY */
#include <stdio.h>                       /* printf */
#include <string.h>                      /* memcpy */
#include <unistd.h>                        /* read */
#include <openssl/idea.h>                /* idea_* */

unsigned char input[512];    /* for encrypted text */
unsigned char output[512];   /* for decrypted text */

unsigned char key[16] = {           /* 128 bit key */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

static unsigned char iv[8] = {  /* 64 bit IV block */
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

int main(void)
{
	int i, n, t1, t2, t3, t4;
	long length;
	IDEA_KEY_SCHEDULE encrypt_ks, decrypt_ks;
	unsigned char tmp[8];

	/* open the given text files */
	t1 = open("text1.bin", O_RDONLY);
	t2 = open("text2.bin", O_RDONLY);
	t3 = open("text3.bin", O_RDONLY);
	t4 = open("text4.bin", O_RDONLY);
	length = 512;

	/* read 512 bytes from file t4 */
	read(t4, input, length);
	/* ... decrypt input in ECB mode */
	idea_set_encrypt_key(key, &encrypt_ks);
	idea_set_decrypt_key(&encrypt_ks,&decrypt_ks);
        for(i=0; i<length; i+=8)
	{
		idea_ecb_encrypt(&input[i],&output[i],&decrypt_ks);
	}
	/* show decrypted text on stdout */
	printf("%s\n", output);

	read(t1, input, length);
	/* ... decrypt input in CBC mode */
        for(i=0; i<length; i+=8)
	{
		idea_cbc_encrypt(&input[i],&output[i],8,&decrypt_ks,iv, IDEA_DECRYPT);
	}
	printf("%s\n", output);

	read(t2, input, length);
	/* ... decrypt input in CFB mode */
	printf("%s\n", output);

	read(t3, input, length);
	/* ... decrypt input in OFB mode */
	printf("%s\n", output);

	return 0;
}
