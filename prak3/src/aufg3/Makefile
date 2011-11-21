OPENSSLDIR=/home/rex/fi3/ia11/s67766/7.Sem/ITSEC/prak3/src/openssl-1.0.0e

idea: idea.c
	cc -Wall -g -L $(OPENSSLDIR) -I $(OPENSSLDIR)/include idea.c -lcrypto -o idea

ideatest: ideatest.c
	cc -Wall -g -L $(OPENSSLDIR) -I $(OPENSSLDIR)/include ideatest.c -lcrypto -o ideatest

