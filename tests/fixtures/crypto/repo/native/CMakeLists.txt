cmake_minimum_required(VERSION 3.20)
project(sample-native C)
find_package(OpenSSL 3.0 REQUIRED)
pkg_check_modules(TLS REQUIRED gnutls)
