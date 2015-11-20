#!/bin/bash
echo "building..."
gcc main.c -o main -lssl -lcrypto
echo "execution..."
./main
echo "finish"
