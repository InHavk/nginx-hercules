#!/bin/bash
NGINX_VERSION="1.20.2"
cd libs/nginx-$NGINX_VERSION
#./configure --with-compat --with-debug --add-dynamic-module=../../src
./configure --with-compat --with-threads --with-debug --add-module=../../src
make
cd ../..
