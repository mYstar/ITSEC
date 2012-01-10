#!/bin/sh
echo "hello" > test.txt
openssl rsautl -in test.txt -out test.txt.signed -inkey keypair.pem -sign
