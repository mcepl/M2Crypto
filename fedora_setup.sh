#!/bin/sh
set -eu
# This script is meant to work around the differences on Fedora Core-based
# distributions (Redhat, CentOS, ...) compared to other common Linux
# distributions.
# 
# Usage: ./fedora_setup.sh [setup.py options]
#
arch=`uname -m`
trap "mv -f SWIG/_ec.i.bak SWIG/_ec.i ; mv -f SWIG/_evp.i.bak SWIG/_evp.i" EXIT
for IFILE in SWIG/_{ec,evp}.i ; do
    cp -f "${IFILE}" "${IFILE}.bak"
    sed -i -e "s/opensslconf\./opensslconf-${arch}\./" "$IFILE"
done

SWIG_FEATURES=-cpperraswarn python3 setup.py $*

