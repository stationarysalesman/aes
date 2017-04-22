#!/bin/bash

python AEStestvectors.py > in.tmp
../src/AES e Acceptance1key.txt in.tmp
../src/AES d Acceptance1key.txt in.tmp.enc
diff -i in.tmp.enc.dec in.tmp
