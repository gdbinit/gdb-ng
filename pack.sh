#!/bin/bash
VERSION=1824
ln -s gdb gdb-$VERSION
tar -cvLf gdb-$VERSION.tar gdb-$VERSION
gzip -c gdb-$VERSION.tar >gdb-$VERSION.tar.gz
rm -f gdb-$VERSION.tar

