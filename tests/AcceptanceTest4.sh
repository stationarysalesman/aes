#!/bin/bash

  ../src/aes -e -k Acceptance1key.txt -i paper.pdf -o acceptance4.enc
  ../src/aes -d -k Acceptance1key.txt -i acceptance4.enc -o acceptance4.dec
  diff -i acceptance4.dec paper.pdf 

