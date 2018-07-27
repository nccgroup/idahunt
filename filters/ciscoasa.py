#!/usr/bin/python3
#
# This file is part of idahunt.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# Filter for Cisco ASA firewalls to be used by idahunt.py command line:
# e.g. idahunt.py --filter "filters/ciscoasa.py -m 924 -M 941 -a 64 -v"

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
            print("[ciscoasa] " + s),
        else:
            print("[ciscoasa] " + s)
    else:
        print(s)

# return True if version 1 >= version 2
def is_more_than_or_equal(v1, v2, digit_syntax=False):
    return not is_less_than(v1, v2, digit_syntax)

def is_more_than(v1, v2, digit_syntax=False):
    # XXX - this is a dirty hack as we should not have -smp here in the first place
    if v1.endswith("-smp"):
        v1 = v1[:-4]
    if v2.endswith("-smp"):
        v2 = v2[:-4]
    return v1 != v2 and is_more_than_or_equal(v1, v2, digit_syntax=digit_syntax)

def is_less_than_or_equal(v1, v2, digit_syntax=False):
    # XXX - this is a dirty hack as we should not have -smp here in the first place
    if v1.endswith("-smp"):
        v1 = v1[:-4]
    if v2.endswith("-smp"):
        v2 = v2[:-4]
    return v1 == v2 or is_less_than(v1, v2, digit_syntax=digit_syntax)

# return True if version 1 < version 2
def is_less_than(v1, v2, digit_syntax=False):
    # XXX - this is a dirty hack as we should not have -smp here in the first place
    if v1.endswith("-smp"):
        v1 = v1[:-4]
    if v2.endswith("-smp"):
        v2 = v2[:-4]
    if digit_syntax:
        v1 = digitsonly2normalized(v1)
        v2 = digitsonly2normalized(v2)
    l = [v1, v2]
    l = sorted(l, key=lambda s:list(map(int, s.split("."))))
    if l[0] == l[1]:
        return False
    if l[0] == v1:
        return True
    return False

def digitsonly2normalized(v):
    version = ""
    if len(v) < 3:
        logmsg("Version should be at least 3 digits")
        return None
    version = "%s.%s.%s" % (v[0], v[1], v[2])
    if len(v) >= 4:
        version += ".%s" % v[3:]
    return version
    
def normalize2digitsonly(version):
    return version.replace(".", "")


# XXX - This is a direct copy from asadbg/helper.py. It should be all in the
# same place eventually
# parse the version from the firmware name
# examples: asa811-smp-k8.bin, asa825-k8.bin, asa805-31-k8.bin
def build_version(dirname):

    version = ''
    if "asav" in dirname:
        match = re.search(r'asav([^\\/.]+)\.qcow2', dirname)
        if not match:
            # XXX - This is noisy and would be nice to remove eventually
            logmsg("Could not find the asavXXX.qcow2 in string: %s" % dirname)
            return ''
    elif "SPA" in dirname:
        match = re.search(r'asa([^\\/.]+)\.SPA', dirname)
        if not match:
            logmsg("Could not find the asaXXX.SPA in string: %s" % dirname)
            return ''
    else:
        match = re.search(r'asa([^\\/.]+)\.bin', dirname)
        if not match:
            logmsg("Could not find the asaXXX.bin in string: %s" % dirname)
            return ''

    verName = match.group(1)
    elts = verName.split("-")
    first = True
    try:
        for e in elts:
            if first:
                for c in e:
                    if not first:
                        version += '.'
                    version += '%c' % c
                    first = False
            else:
                version += '.%d' % int(e)
    # assume we get one at some point (eg: "k8") - it means we are done for now
    except ValueError:
        pass

    return version

# do we actually treat it?
def filter(f, min, max, arch, name, verbose):
    # Check hardcoded whitelist as a sanity check
    files = ["lina", "lina_monitor", "libc.so.6"]
    if os.path.basename(f) not in files:
        #logmsg("Skipping unrecognized file: %s" % os.path.basename(f))
        return None
    # Check user-specified whitelist
    if name and name != os.path.basename(f):
        logmsg("Skipping wrong filename: %s" % f, debug=verbose)
        return None
    asaver = normalize2digitsonly(build_version(f))
    if asaver == None or len(asaver) == 0:
        return None
    if max != None and is_more_than(asaver, max, digit_syntax=True):
        logmsg("Skipping version too high: %s" % f, debug=verbose)
        return None
    if min != None and is_less_than(asaver, min, digit_syntax=True):
        logmsg("Skipping version too low: %s" % f, debug=verbose)
        return None
    if arch == "32":
        if "smp" in f or "asav" in f:
            logmsg("Skipping non 32-bit: %s" % f, debug=verbose)
            return None
    if arch == "64":
        if not "smp" in f:
            logmsg("Skipping non 64-bit: %s" % f, debug=verbose)
            return None
    if arch == "asav":
        if not "asav" in f:
            logmsg("Skipping non ASAv: %s" % f, debug=verbose)
            return None

    if "smp" in f or "asav" in f:
        arch_ = 64
    else:
        arch_ = 32
    return f, arch_

def main(f, cmdline):
    # We override sys.argv so argparse can parse our arguments :)
    sys.argv = cmdline.split()

    parser = argparse.ArgumentParser(prog=cmdline)
    parser.add_argument('-m', dest='minimum', default=None, help='Minimum \
                        version to include in the analysis \
                        (eg: 802 for asa802-k8.bin)')
    parser.add_argument('-M', dest='maximum', default=None, help='Maximum \
                        version to include in the analysis (eg: 83240 for \
                        asa832-40-k8.bin)')
    parser.add_argument('-a', dest='arch', default=None, help='Restrict to \
                        one architecture only ("32" for 32-bit, "64" for 64-bit,\
                        "asav" for ASAv firmware)')
    parser.add_argument('-n', dest='name', default=None, help='Restrict to \
                        a given name (lina, lina_monitor)')
    parser.add_argument('-v', dest='verbose', default=False, action='store_true'
                        , help='be more verbose to debug script')
    args = parser.parse_args()

    return filter(f, args.minimum, args.maximum, args.arch, args.name,
                  args.verbose)
