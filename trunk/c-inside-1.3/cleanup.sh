#!/bin/bash

# C-Inside (libc-inside) - C language interpreter library
# Copyright (C) 2008-2015  Jason Todd <jtodd1@earthlink.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# cleanup.sh - make pre-dist, ONLY to be used to assist development of C-Inside

# follow with "autoreconf --install"

make uninstall &> /dev/null
make distclean &> /dev/null
rm -rf aclocal.m4 ar-lib autom4te.cache/ autoscan.log compile config.guess \
    config.h config.h.in config.log config.status config.sub configure \
    configure.scan depcomp .deps/ .gdb_history install-sh ltmain.sh Makefile \
    Makefile.in missing stamp-h1
rm -f support/* m4/* 
for dir in libc-inside/ utilities/; do
    make -C ${dir} -f makefile-dev clean &> /dev/null
    rm -rf ${dir}.deps/ ${dir}Makefile ${dir}Makefile.in
done
