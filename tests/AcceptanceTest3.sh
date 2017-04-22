#!/bin/bash

  ../src/AES -e -k Acceptance1key.txt -i example_binary3 -o acceptance3.enc
  ../src/AES -d -k Acceptance1key.txt -i acceptance3.enc -o acceptance3.dec
  diff -i acceptance3.dec example_binary3 

