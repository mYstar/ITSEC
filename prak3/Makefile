OPENSSLDIR=~/src/openssl-1.0.0e

idea: idea.c
	cc -Wall -g -L $(OPENSSLDIR) -I $(OPENSSLDIR)/include idea.c -lcrypto -o idea
