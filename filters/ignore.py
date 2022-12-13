#!/usr/bin/python3
#
# This file is part of idahunt.
# Copyright (c) 2022, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2022, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# Filter for ignoring certain files based on name, extension or content to be used by idahunt.py command line:
# e.g. idahunt.py --filter "filters/ignore.py"

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
    if file_extension == ".c" or file_extension == ".sh"  or file_extension == ".txt":
        return None
    fd = open(f, "rb")
    data = fd.read(len(b"#!/bin/sh"))
    fd.close()
    if data == b"#!/bin/sh":
        return None

    return f, "auto"
