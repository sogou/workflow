#!/bin/bash

clang_format_version=`clang-format --version | awk '{print int($3)}'`
if [ $clang_format_version -ge 15 ] ; then
    clang-format -i `find src/kernel/ -type f -name *.h`
    clang-format -i `find src/kernel/ -type f -name *.c`
    clang-format -i `find src/kernel/ -type f -name *.cc`
else
    echo "clang-format version:"$clang_format_version
    echo "clang-format version must is >= 15"
fi
