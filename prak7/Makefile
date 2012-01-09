OPENSSLDIR=~/src/openssl-1.0.0e

.c:
	cc -Wall -g -L $(OPENSSLDIR) -I $(OPENSSLDIR)/include $< -lcrypto -ldl -o $@
