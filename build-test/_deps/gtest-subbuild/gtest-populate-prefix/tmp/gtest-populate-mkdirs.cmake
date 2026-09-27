# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/gtest-src"
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/gtest-build"
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/gtest-subbuild/gtest-populate-prefix"
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/gtest-subbuild/gtest-populate-prefix/tmp"
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/gtest-subbuild/gtest-populate-prefix/src/gtest-populate-stamp"
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/gtest-subbuild/gtest-populate-prefix/src"
  "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/gtest-subbuild/gtest-populate-prefix/src/gtest-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/gtest-subbuild/gtest-populate-prefix/src/gtest-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/nguyenduccanh/shellmap_project/smoframework/build-test/_deps/gtest-subbuild/gtest-populate-prefix/src/gtest-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
