#!/bin/bash

python AEStestvectors.py > in.tmp
  ../src/AES -e -k Acceptance1key.txt -i in.tmp -o acceptance1.enc
  ../src/AES -d -k Acceptance1key.txt -i acceptance1.enc -o acceptance1.dec
  diff -i acceptance1.dec in.tmp

