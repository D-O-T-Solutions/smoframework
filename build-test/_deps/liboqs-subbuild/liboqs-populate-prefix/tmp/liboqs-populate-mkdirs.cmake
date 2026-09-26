# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/liboqs-src"
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/liboqs-build"
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/liboqs-subbuild/liboqs-populate-prefix"
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/liboqs-subbuild/liboqs-populate-prefix/tmp"
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/liboqs-subbuild/liboqs-populate-prefix/src/liboqs-populate-stamp"
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/liboqs-subbuild/liboqs-populate-prefix/src"
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/liboqs-subbuild/liboqs-populate-prefix/src/liboqs-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/liboqs-subbuild/liboqs-populate-prefix/src/liboqs-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/liboqs-subbuild/liboqs-populate-prefix/src/liboqs-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
