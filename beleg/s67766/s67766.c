#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <memory.h>

char *clobbered_key_file = "./s67766-clobbered-key.bin";
char *cipher_of_signed_key_file = "./s67766-cipher-of-signed-key.bin";

void print_bytes(unsigned char *data, int length)
{
  int i;
  for(i=0; i<length; i++)
    printf("%02X", data[i]);
}

int main(int argc, char *argv[])
{
  int clobbered_key_fd, cipher_of_signed_key_fd;
  unsigned char *cam128_key, *cam128_iv;
  unsigned char *cipher_of_signed_key, *signed_key;
  unsigned char *rc4_40_key, *rc4_40_iv;
  const EVP_CIPHER *cam128_cfb8, *rc4_40;
  EVP_CIPHER_CTX cam128_cfb8_ctx;
  const EVP_MD *sha;
  EVP_MD_CTX *sha_ctx;
  int cam128_cfb8_keylen, cam128_cfb8_ivlen, rc4_40_keylen, rc4_40_ivlen, sha_hashsize, cipher_of_signed_key_size, signed_key_size;
  int ret, count;
  struct stat file_prop;

  // get the parameters for CAMELLIA128_cfb8
  cam128_cfb8 = EVP_camellia_128_cfb8();
  cam128_cfb8_keylen = EVP_CIPHER_key_length(cam128_cfb8);
  cam128_cfb8_ivlen = EVP_CIPHER_iv_length(cam128_cfb8);

  // get the parameters for RC4_40
  rc4_40 = EVP_rc4_40();
  rc4_40_keylen = EVP_CIPHER_key_length(rc4_40);
  rc4_40_ivlen = EVP_CIPHER_iv_length(rc4_40);

  // get the parameters for sha
  sha = EVP_sha();

  printf("cam128_cfb8_keylen: %d, cam128_cfb8_ivlen: %d\n", cam128_cfb8_keylen, cam128_cfb8_ivlen);
  printf("rc4_40_keylen: %d,  rc4_40_ivlen: %d\n", rc4_40_keylen, rc4_40_ivlen);

  // read the s67766-clobbered-key.bin and store the key and iv for CAMELLIA128-cfb8
  cam128_key = malloc(cam128_cfb8_keylen);
  cam128_iv = malloc(cam128_cfb8_ivlen);
  ret = clobbered_key_fd = open(clobbered_key_file, O_RDONLY);
  if(ret == -1)
  {
    printf("opening file %s failed\n", clobbered_key_file);
    perror("");
  }

  ret = read(clobbered_key_fd, cam128_key, cam128_cfb8_keylen);
  if(ret != cam128_cfb8_keylen)
  {
    printf("reading cam128_key failed, %d Bytes read\n", ret);
    if(ret==-1)
      perror("");
  }

  ret = read(clobbered_key_fd, cam128_iv, cam128_cfb8_ivlen);
  if(ret != cam128_cfb8_ivlen)
  {
    printf("reading cam128_iv failed, %d Bytes read\n", ret);
    if(ret==-1)
      perror("");
  }

  close(clobbered_key_fd);
  if(ret == -1)
  {
    printf("closing file %s failed\n", clobbered_key_file);
    perror("");
  }

  printf("cam128_key: ");
  print_bytes(cam128_key, cam128_cfb8_keylen);
  printf(", cam128_iv: ");
  print_bytes(cam128_iv, cam128_cfb8_ivlen);
  printf("\n");

  // read the s67766-cipher-of-signed-key.bin
  ret = cipher_of_signed_key_fd = open(cipher_of_signed_key_file, O_RDONLY);
  if(ret == -1)
  {
    printf("opening file %s failed\n", cipher_of_signed_key_file);
    perror("");
  }

  fstat(cipher_of_signed_key_fd, &file_prop);
  cipher_of_signed_key_size = file_prop.st_size;
  printf("cipher_of_signed_key_size: %d\n", cipher_of_signed_key_size);

  cipher_of_signed_key = malloc(cipher_of_signed_key_size);

  ret = read(cipher_of_signed_key_fd, cipher_of_signed_key, cipher_of_signed_key_size);
  if(ret != cipher_of_signed_key_size)
  {
    printf("reading cam128_key failed, %d Bytes read\n", ret);
    if(ret==-1)
      perror("");
  }

  close(cipher_of_signed_key_fd);
  if(ret == -1)
  {
    printf("closing file %s failed\n", clobbered_key_file);
    perror("");
  }

  printf("cipher_of_signed_key: ");
  print_bytes(cipher_of_signed_key, cipher_of_signed_key_size);
  printf("\n");

  // restore the clobbered key with bruteforce
  signed_key = malloc(cipher_of_signed_key_size);
  for(count = 0; count<=0; count++)
  {
    memset(cam128_key, count, 1);
    //print_bytes(cam128_key, cam128_cfb8_keylen);
    //printf("\n");

    //decrypt the cipher with guessed key
    EVP_CIPHER_CTX_init(&cam128_cfb8_ctx);
    if(EVP_DecryptInit_ex(&cam128_cfb8_ctx, cam128_cfb8, NULL, cam128_key, cam128_iv)==0)
    {
      printf("EVP_DecryptInit failed for CAMELLIA128_cfb8\n");
    }
    if(EVP_DecryptUpdate(&cam128_cfb8_ctx, signed_key, &signed_key_size, cipher_of_signed_key, cipher_of_signed_key_size)==0)
    {
      printf("EVP_DecryptUpdate failed for CAMELLIA128_cfb8\n");
    }
    printf("signed_key_size: %d\n", signed_key_size);
    if(EVP_DecryptFinal(&cam128_cfb8_ctx, signed_key+signed_key_size, &signed_key_size)==0)
    {
      printf("EVP_DecryptFinal failed for CAMELLIA128_cfb8\n");
    }

    //check signature of encrypted key
    printf("signed_key: ");
    print_bytes(signed_key, cipher_of_signed_key_size);
    printf("\n");
  }
  return 0;
}
