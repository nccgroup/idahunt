#!/usr/bin/python3
#
# This file is part of idahunt.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# Filter for arbitrary names to be used by idahunt.py command line:
# e.g. idahunt.py --filter "filters/names.py -n Download -e exe -a 32"
#      idahunt.py --filter "filters/names.py -l 64"

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
            print("[ignore] " + s),
        else:
            print("[ignore] " + s)
    else:
        print(s)

def main(f, cmdline):
    filename, file_extension = os.path.splitext(f)
    # Ignore .c source, .sh bash scripts files
    if file_extension == ".c" or file_extension == ".sh":
        return None

    return f, "auto"
