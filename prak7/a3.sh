#!/bin/sh
openssl rsa -in keypair.pem -passin pass:egalegal -out pubkey.pem -pubout
