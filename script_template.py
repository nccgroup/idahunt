#!/usr/bin/python3
#
# This file is part of idahunt.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# IDA Python script doing nothing except printing hello world to be used by 
# idahunt.py command line:
# e.g. idahunt.py --scripts "/absolute/path/to/script_template.py"
# You can use this as a template to build your own scripts.

import os

print("[script_template] I execute in IDA, yay!")
if "DO_EXIT" in os.environ:
    Exit(1)