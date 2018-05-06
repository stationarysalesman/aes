#!/bin/bash

python aestestvectors.py > in.tmp
  ../src/aes -e -k Acceptance1key.txt -i in.tmp -o acceptance1.enc
  ../src/aes -d -k Acceptance1key.txt -i acceptance1.enc -o acceptance1.dec
  diff -i acceptance1.dec in.tmp

