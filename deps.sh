#!/bin/bash
NGINX_VERSION="1.20.2"
cd libs
rm -Rf openssl-1.1.1 nginx-$NGINX_VERSION
wget https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
tar -xzvf nginx-$NGINX_VERSION.tar.gz
rm nginx-$NGINX_VERSION.tar.gz
wget https://github.com/chipitsine/openssl/archive/v1.1.1.tar.gz
tar -xzvf v1.1.1.tar.gz
rm v1.1.1.tar.gz
cd ../..
