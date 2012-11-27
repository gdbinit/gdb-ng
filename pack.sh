#!/bin/bash

tar -cvf gdb-1822.tar gdb
gzip -c gdb-1822.tar >gdb-1822.tar.gz
rm -f gdb-1822.tar

