#!/usr/bin/python3
#
# This file is part of idahunt.
# Copyright (c) 2022, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2022, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# Filter for diffing with diaphora to be used by idahunt.py command line:
# e.g. idahunt.py --filter "filters/diff.py -n ntdll.dll"
import argparse
import os
import re
import sys
import subprocess
import time

def logmsg(s, end=None, debug=True):
    if not debug:
        return
    if type(s) == str:
        if end != None:
            print("[diff] " + s),
        else:
            print("[diff] " + s)
    else:
        print(s)

# do we actually treat it?
def filter(f, name, verbose=True):
    if name and name != os.path.basename(f):
        logmsg("Skipping non-matching name %s != %s" % (name, os.path.basename(f)), debug=verbose)
        return None
    arch_ = "auto"
    return f, arch_

def main(f, cmdline):
    # We override sys.argv so argparse can parse our arguments :)
    sys.argv = cmdline.split()

    parser = argparse.ArgumentParser(prog=cmdline)
    parser.add_argument('-n', dest='name', default=None, help='exact name to match')
    parser.add_argument('-v', dest='verbose', default=False, action='store_true'
                        , help='be more verbose to debug script')
    args = parser.parse_args()

    return filter(f, args.name, args.verbose)
