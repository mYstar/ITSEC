OPENSSLDIR=~/7.Sem/ITSEC/openssl-1.0.0e

idea-template: idea-template.c
	cc -Wall -g -L $(OPENSSLDIR) -I $(OPENSSLDIR)/include idea-template.c -lcrypto -o idea-template

ideatest: ideatest.c
	cc -Wall -g -L $(OPENSSLDIR) -I $(OPENSSLDIR)/include ideatest.c -lcrypto -o ideatest

