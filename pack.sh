#!/bin/bash
VERSION=`grep "GDB_RC_VERSION" gdb/Makefile | head -1 | sed "s/GDB_RC_VERSION = //"`
ln -s gdb gdb-$VERSION
tar -cvLf gdb-$VERSION.tar gdb-$VERSION
gzip -c gdb-$VERSION.tar >gdb-$VERSION.tar.gz
rm -f gdb-$VERSION.tar

