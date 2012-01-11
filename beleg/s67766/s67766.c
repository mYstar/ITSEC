#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <memory.h>

char *clobbered_key_file = "./s67766-clobbered-key.bin";
char *cipher_of_signed_key_file = "./s67766-cipher-of-signed-key.bin";
char *cipher_of_secret_text_file = "./s67766-cipher-of-secret-text.bin";
char *rsapub_key_file = "./rsapub.pem";
char *plain_file = "./s67766-plain.bin";

void print_bytes(unsigned char *data, int length)
{
  int i;
  for(i=0; i<length; i++)
    printf("%02X", data[i]);
}

long read_file(char *file, unsigned char **data_out)
{
  int file_descriptor;
  struct stat file_prop;
  long file_size, read_size;

  file_descriptor = open(file, O_RDONLY);
  if(file_descriptor == -1)
  {
    printf("opening file %s returned error\n", file);
    perror("");
    return -1;
  }

  fstat(file_descriptor, &file_prop);
  file_size = file_prop.st_size;

  *data_out = malloc(file_size);

  read_size = read(file_descriptor, *data_out, file_size);
  if(read_size != file_size)
  {
    printf("reading %s returned error, %ld Bytes read\n",file, read_size);
    if(read_size==-1)
      perror("");
    return -1;
  }

  if(close(file_descriptor) == -1)
  {
    printf("closing file %s returned error\n", file);
    perror("");
    return -1;
  }
  return read_size;
}

int main(int argc, char *argv[])
{
  int clobbered_key_fd, cipher_of_secret_text_fd, cipher_of_signed_key_fd, plain_fd;
	FILE *rsapub_key_fp;
  unsigned char *cam128_key, *cam128_iv;
  unsigned char *cipher_of_secret_text, *cipher_of_signed_key, *signed_key, *secret_text, *clobbered_key;
	EVP_PKEY *rsapub_key;
  unsigned char *rc4_40_key;
  const EVP_CIPHER *cam128_cfb8, *rc4_40;
  EVP_CIPHER_CTX cam128_cfb8_ctx, rc4_40_ctx;
  const EVP_MD *sha;
  EVP_MD_CTX sha_ctx;
  int cam128_cfb8_keylen, cam128_cfb8_ivlen, rc4_40_keylen, cipher_of_secret_text_size,  secret_text_size, signed_key_size;
  int ret, count;
  struct stat file_prop;
  long cipher_of_signed_key_size, clobbered_key_size;

  // get the parameters for CAMELLIA128_cfb8
  cam128_cfb8 = EVP_camellia_128_cfb8();
  cam128_cfb8_keylen = EVP_CIPHER_key_length(cam128_cfb8);
  cam128_cfb8_ivlen = EVP_CIPHER_iv_length(cam128_cfb8);

  // get the parameters for RC4_40
  rc4_40 = EVP_rc4_40();
  rc4_40_keylen = EVP_CIPHER_key_length(rc4_40);

  // get the parameters for sha
  sha = EVP_sha();

  printf("cam128_cfb8_keylen: %d, cam128_cfb8_ivlen: %d\n", cam128_cfb8_keylen, cam128_cfb8_ivlen);
  printf("rc4_40_keylen: %d\n", rc4_40_keylen);

  // read the s67766-clobbered-key.bin and store the key and iv for CAMELLIA128-cfb8
  cam128_key = malloc(cam128_cfb8_keylen);
  cam128_iv = malloc(cam128_cfb8_ivlen);

  clobbered_key_size = read_file(clobbered_key_file, &clobbered_key);
  if(clobbered_key_size != cam128_cfb8_keylen+cam128_cfb8_ivlen)
  {
    printf("reading file %s returned not enough Bytes: %ld, instead of: %d\n", clobbered_key_file, clobbered_key_size, cam128_cfb8_keylen+cam128_cfb8_ivlen);
    perror("");
  }
  memcpy(cam128_key, clobbered_key, cam128_cfb8_keylen);
  memcpy(cam128_iv, clobbered_key+cam128_cfb8_keylen, cam128_cfb8_ivlen);

  printf("cam128_key: ");
  print_bytes(cam128_key, cam128_cfb8_keylen);
  printf(", cam128_iv: ");
  print_bytes(cam128_iv, cam128_cfb8_ivlen);
  printf("\n");

  // read the s67766-cipher-of-signed-key.bin
  cipher_of_signed_key_size = read_file(cipher_of_signed_key_file, &cipher_of_signed_key);

  printf("cipher_of_signed_key: ");
  print_bytes(cipher_of_signed_key, cipher_of_signed_key_size);
  printf("\n");

  // read the public key from rsapub.pem
	rsapub_key_fp = fopen(rsapub_key_file, "r");
	if (!rsapub_key_fp)
  {
    printf("opening file %s returned error\n", rsapub_key_file);
    perror("");
  }

  rsapub_key = PEM_read_PUBKEY(rsapub_key_fp, NULL, NULL, NULL);
  if (!rsapub_key)
  {
    printf("PEM_read_PUBKEY returned error for RSA\n");
  }

  if(fclose(rsapub_key_fp) != 0)
  {
    printf("closing file %s returned error\n", rsapub_key_file);
    perror("");
  }

  // restore the clobbered key with bruteforce
  signed_key = malloc(cipher_of_signed_key_size);
  for(count = 0; count<=255; count++)
  {
    memset(cam128_key, count, 1);
    signed_key_size = 0;
    //print_bytes(cam128_key, cam128_cfb8_keylen);
    //printf("\n");

    //decrypt the cipher with guessed key
    EVP_CIPHER_CTX_init(&cam128_cfb8_ctx);
    if(EVP_DecryptInit_ex(&cam128_cfb8_ctx, cam128_cfb8, NULL, cam128_key, cam128_iv)==0)
    {
      printf("EVP_DecryptInit returned error for CAMELLIA128_cfb8\n");
    }
    if(EVP_DecryptUpdate(&cam128_cfb8_ctx, signed_key, &ret, cipher_of_signed_key, cipher_of_signed_key_size)==0)
    {
      printf("EVP_DecryptUpdate returned error for CAMELLIA128_cfb8\n");
    }
    signed_key_size+=ret;
    if(EVP_DecryptFinal(&cam128_cfb8_ctx, signed_key+signed_key_size, &ret)==0)
    {
      printf("EVP_DecryptFinal returned error for CAMELLIA128_cfb8\n");
    }
    signed_key_size+=ret;
    printf("signed_key_size: %d\n", signed_key_size);

    if(EVP_VerifyInit(&sha_ctx, sha) == 0)
    {
      printf("EVP_VerifyInit returned error for SHA\n");
    }
    if(EVP_VerifyUpdate(&sha_ctx, signed_key, rc4_40_keylen) == 0)
    {
      printf("EVP_VerifyUpdate returned error for SHA\n");
    }
    ret = EVP_VerifyFinal(&sha_ctx, signed_key+rc4_40_keylen, signed_key_size-rc4_40_keylen, rsapub_key);
    switch(ret)
    {
      case -1:
        printf("EVP_VerifyFinal returned error for SHA\n");
        break;
      case 0:
        printf("EVP_VerifyFinal failed with byte: %02X\n", count);
        break;
      case 1:
        printf("EVP_VerifyFinal succeeded with byte: %02X\n", count);
        count = 255;
        break;
    }
  }
  // extract the key for RC-4 40
  rc4_40_key = malloc(rc4_40_keylen);
  memcpy(rc4_40_key, signed_key, rc4_40_keylen);
  printf("rc4_40_key: ");
  print_bytes(rc4_40_key, rc4_40_keylen);
  printf("\n");

  // read the s67766-cipher-of-secret-text.bin
  cipher_of_secret_text_size = read_file(cipher_of_secret_text_file, &cipher_of_secret_text);

  printf("cipher_of_secret_text: ");
  print_bytes(cipher_of_secret_text, cipher_of_secret_text_size);
  printf("\n");

  // decrypt s67766-cipher-of-secret-text.bin
  secret_text = malloc(cipher_of_secret_text_size);
  secret_text_size = 0;

  //decrypt the cipher with extracted key
  EVP_CIPHER_CTX_init(&rc4_40_ctx);
  if(EVP_DecryptInit_ex(&rc4_40_ctx, rc4_40, NULL, rc4_40_key, NULL)==0)
  {
    printf("EVP_DecryptInit returned error for RC-4_40\n");
  }
  if(EVP_DecryptUpdate(&rc4_40_ctx, secret_text, &ret, cipher_of_secret_text, cipher_of_secret_text_size)==0)
  {
    printf("EVP_DecryptUpdate returned error for RC-4_40\n");
  }
  secret_text_size+=ret;
  if(EVP_DecryptFinal(&rc4_40_ctx, secret_text+secret_text_size, &ret)==0)
  {
    printf("EVP_DecryptFinal returned error for RC-4_40\n");
  }
  secret_text_size+=ret;
  printf("secret_text_size: %d\n", secret_text_size);
  printf("secret_text: %s %s\n", secret_text, secret_text+11);

  // write the s67766-plain.bin
  plain_fd = open(plain_file, O_WRONLY | O_CREAT);
  if(plain_fd == -1)
  {
    printf("opening file %s returned error\n", plain_file);
    perror("");
  }

  ret = write(plain_fd, secret_text, secret_text_size);
  if(ret != secret_text_size)
  {
    printf("writing %s returned error, %d Bytes read\n",plain_file, ret);
    if(ret==-1)
      perror("");
  }

  if(close(plain_fd) == -1)
  {
    printf("closing file %s returned error\n", plain_file);
    perror("");
  }

  return 0;
}
