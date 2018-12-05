#!/usr/bin/python3
#
# This file is part of idahunt.
# Copyright (c) 2018, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2018, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# Filter for HP iLO servers to be used by idahunt.py command line:
# e.g. idahunt.py --filter "filters/hpilo.py -m 244 -M 250 -i 4 -I 4 -v -n .webserv.elf.text"

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
            print("[hpilo] " + s),
        else:
            print("[hpilo] " + s)
    else:
        print(s)

# parse the version from the firmware name
# examples: ilo4_250.bin
def build_version(dirname):
    match = re.search(r'ilo([^\\/.]+)_([^\\/.]+)\.bin', dirname)
    if not match:
        logmsg("Could not find the asaXXX.bin in string: %s" % dirname)
        return '', ''

    ilo_version = match.group(1)
    release_version = match.group(2)
    return ilo_version, release_version

# do we actually treat it?
def filter(f, min_ilo, max_ilo, min, max, name, verbose):
    # Check hardcoded whitelist as a sanity check
    # We expect something like ".webserv.elf.text"
    if ".text" not in os.path.basename(f) and ".RO" not in os.path.basename(f):
        #logmsg("Skipping unrecognized file: %s" % os.path.basename(f))
        return None
    # Check user-specified whitelist
    if name and name != os.path.basename(f):
        logmsg("Skipping wrong filename: %s" % f, debug=verbose)
        return None
    ilo_version, release_version = build_version(f)
    if ilo_version == None or len(ilo_version) == 0 or release_version == None or len(release_version) == 0:
        return None
    if max != None and release_version > max:
        logmsg("Skipping release version too high: %s" % f, debug=verbose)
        return None
    if min != None and release_version < min:
        logmsg("Skipping release version too low: %s" % f, debug=verbose)
        return None
    if max != None and ilo_version > max_ilo:
        logmsg("Skipping iLO version too high: %s" % f, debug=verbose)
        return None
    if min != None and ilo_version < min_ilo:
        logmsg("Skipping iLO version too low: %s" % f, debug=verbose)
        return None

    # all iLOs are 32-bit ARM atm
    arch_ = 32
    return f, arch_

def main(f, cmdline):
    # We override sys.argv so argparse can parse our arguments :)
    sys.argv = cmdline.split()

    parser = argparse.ArgumentParser(prog=cmdline)
    parser.add_argument('-i', dest='minimum_ilo', default=None, help='Minimum \
                        iLO version to include in the analysis (eg: 4 for iLO4)')
    parser.add_argument('-I', dest='maximum_ilo', default=None, help='Maximum \
                        iLO version to include in the analysis (eg: 5 for iLO 5)')
    parser.add_argument('-m', dest='minimum', default=None, help='Minimum \
                        version to include in the analysis \
                        (eg: 244 for ilo4_244.bin)')
    parser.add_argument('-M', dest='maximum', default=None, help='Maximum \
                        version to include in the analysis (eg: 250 for ilo4_250.bin)')
    parser.add_argument('-n', dest='name', default=None, help='Restrict to \
                        a given name (eg: .webserv.elf.text)')
    parser.add_argument('-v', dest='verbose', default=False, action='store_true'
                        , help='be more verbose to debug script')
    args = parser.parse_args()

    return filter(f, args.minimum_ilo, args.maximum_ilo, args.minimum, args.maximum, args.name,
                  args.verbose)
