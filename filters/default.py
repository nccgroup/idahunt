#!/usr/bin/python3
#
# This file is part of idahunt.
# Copyright (c) 2020, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2020, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# Default filter to be used by idahunt.py command line:
# e.g. idahunt.py --filter "filters/default.py"

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
            print("[default] " + s),
        else:
            print("[default] " + s)
    else:
        print(s)

def main(f, cmdline):
    return f, "auto"
