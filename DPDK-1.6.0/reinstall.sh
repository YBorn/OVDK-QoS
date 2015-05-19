#!/bin/bash

echo "Configure"
make config T=x86_64-ivshmem-linuxapp-gcc
read

echo "Make"
make
read

echo "Make install"
make install T=x86_64-ivshmem-linuxapp-gcc

