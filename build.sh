#!/bin/bash
NGINX_VERSION="1.20.2"
cd libs/nginx-$NGINX_VERSION
#./configure --with-compat --with-debug --add-dynamic-module=../../src
./configure --with-compat --with-threads --with-debug --with-openssl=../openssl-1.1.1 --add-module=../../src
make -j 8
cd ../..
