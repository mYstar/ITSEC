#include <ctype.h>		/* isalnum */
#include <fcntl.h>		/* O_RDONLY */
#include <stdio.h>		/* fopen */
#include <unistd.h>		/* read */
#include <openssl/pem.h>	/* PEM_read_PUBKEY */

#define BSIZE 512
void dump_output(unsigned char *output, int length)
{
	int i;

	printf("%d bytes decrypted\n", length);
	output[length] = 0;
	printf("decrypted text:\n");
	for (i = 0; i < length; i++) {
		printf("%02x ", output[i]);
		if (i % 16 == 7)
			printf(" ");
		else if (i % 16 == 15)
			printf("\n");
	}
	printf("\n\"");
	for (i = 0; i < length; i++)
		printf("%c", isprint(output[i]) ? output[i] : '.');
	printf("\"\n");
}

int main()
{
	FILE *keyfp;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	unsigned char input[BSIZE];
	unsigned char output[BSIZE];
	int t, length;

	keyfp = fopen("pubkey.pem", "r");
	if (!keyfp)
		return 1;

	/*
	 * PRAKTIKUM
	 * Lesen Sie den öffentlichen Testschlüssel mit der
	 * Funktion PEM_read_PUBKEY ein. Weisen Sie das Ergebnis
	 * der Variable pkey zu.
	 * man pem
	 */
  pkey = PEM_read_PUBKEY(keyfp, NULL, NULL, NULL);
	if (!pkey)
		return 2;

	/*
	 * PRAKTIKUM
	 * Wandeln Sie den eingelesenen Schlüssel pkey unter
	 * Verwendung der Funktion EVP_PKEY_get1_RSA in eine
	 * RSA-Datenstruktur (Variable rsa) um
	 * man EVP_PKEY_get1_RSA
	 */
  rsa = EVP_PKEY_get1_RSA(pkey);
	EVP_PKEY_free(pkey);
	if (!rsa)
		return 3;
	printf("key size is %d bits\n", RSA_size(rsa) * 8);

	/* Passen Sie ggf. den Namen der Signaturdatei an. */
        t = open("test.txt.signed", O_RDONLY);
	length = read(t, input, 2 * RSA_size(rsa));
	if (length < 0)
		return 4;

	/*
	 * PRAKTIKUM
	 * Entschlüsseln Sie die in input eingelesene Signaturdatei
	 * mit der Funktion RSA_public_decrypt. Als Parameter
	 * padding übergeben Sie RSA_PKCS1_PADDING.
	 * man RSA_public_decrypt
	 */
  RSA_public_decrypt(length, input, output, rsa, RSA_PKCS1_PADDING);
	dump_output(output, length);

	return 0;
}
