#!/bin/bash

for file in allcerts/*
do
    ./x509parse.py --skip-fp-check --pem --root < ${file}
done