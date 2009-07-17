#!/bin/sh

# You need autoconf 2.5x, preferably 2.57 or later
# You need automake 1.7 or later. 1.6 might work.

set -e

# libtoolize needs to be run twice, for some reason
# to avoid errors relating to ltmain.sh installation

libtoolize --force
aclocal
autoheader
automake --gnu --add-missing --copy
autoconf
libtoolize --force
