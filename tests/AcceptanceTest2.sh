#!/bin/bash

 ../src/aes -e -k Acceptance1key.txt -i example_binary2 -o acceptance2.enc
 ../src/aes -d -k Acceptance1key.txt -i acceptance2.enc -o acceptance2.dec
  diff -i acceptance2.dec example_binary2

