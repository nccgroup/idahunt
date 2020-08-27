![](img/banner.png)

<!-- vim-markdown-toc GFM -->
* [Overview](#overview)
  * [Requirements](#requirements)
  * [Features](#features)
  * [Scripting](#scripting)
* [Usage](#usage)
  * [Simulate without executing](#simulate-without-executing)
  * [Initial analysis](#initial-analysis)
  * [Execute IDA Python script](#execute-ida-python-script)
  * [Filters](#filters)
    * [Architecture detection](#architecture-detection)
* [Known projects using idahunt](#known-projects-using-idahunt)
<!-- vim-markdown-toc -->

# Overview

**idahunt** is a framework to analyze binaries with IDA Pro and hunt for things
in IDA Pro. It is command line tool to analyse all executable files
recursively from a given folder. It executes IDA in the background so you don't have
to open manually each file. It supports executing external IDA Python scripts.

## Requirements

* Python3 only (except IDA Python scripts which can be Python2/Python3 depending on your IDA setup)
* IDA Pro
* Windows, Linux, OS X

## Features

* Specify how many instances of IDA you want to run simultaneously
* Automate creation of IDBs for multiple executables
* Execute IDA Python scripts across multiple executables
* Open multiple existing IDBs
* Support any binary format (raw assembly/PE/ELF/MACH-O/etc.) supported by IDA
* (Optional) Include IDA Python helpers. You can use these
  to easily build your own IDA Python scripts or you can use any other IDA Python library like
  [sark](https://sark.readthedocs.io/en/latest/) or [bip](https://github.com/synacktiv/bip)
  to name a few

Useful examples include (non-exhaustive list):

* Analyse Microsoft Patch Tuesday updates
* Analyse malware of the same family
* Analyse multiple versions of the same software
* Analyse a bunch of binaries (UEFI, HP iLO, Cisco IOS router, Cisco ASA firewall, etc.)

## Scripting

IDA Python scripts capabilities are unlimited. You can import any existing IDA
Python script or build your own. Some examples:

* Rename functions based on debugging strings
* Decrypt strings (e.g. malware)
* Hunt for the same symbol across multiple versions (using heuristics)
* Hunt for ROP gadgets
* Port reversed function names / symbols from one version to another using tools like [diaphora](https://github.com/joxeankoret/diaphora)
* Etc.

# Usage

* `idahunt.py`: main tool to analyse executable files
* `filters/`: contains basic filters to decide which fiels in an input dir to analyze with IDA
    * `filters/default.py`: default basic filter not filtering anything and used by default
    * `filters/ciscoasa.py`: useful for analyzing Cisco ASA Firewall images
    * `filters/hpilo.py`: useful for analyzing HP iLO images
    * `filters/names.py`: basic filter based on name, name length or extension 
* `script_template.py`: contains a `hello world` IDA Python script

```
C:\idahunt> C:\Python37-x64\python.exe .\idahunt.py -h
usage: idahunt.py [-h] [--inputdir INPUTDIR] [--analyse] [--open]
                  [--ida-args IDA_ARGS] [--scripts SCRIPTS [SCRIPTS ...]]
                  [--filter FILTER] [--cleanup] [--temp-cleanup] [--verbose]
                  [--max-ida MAX_IDA] [--list-only] [--version IDA_VERSION]

optional arguments:
  -h, --help            show this help message and exit
  --inputdir INPUTDIR   Input folder to search for files
  --analyse, --analyze  analyse all files i.e. create .idb for all of them
  --open                open all files into IDA (debug only)
  --ida-args IDA_ARGS   Additional arguments to pass to IDA (e.g.
                        -p<processor> -i<entry_point> -b<load_addr>)
  --scripts SCRIPTS [SCRIPTS ...]
                        List of IDA Python scripts to execute in this order
  --filter FILTER       External python script with optional arguments
                        defining a filter for the names of the files to
                        analyse. See filters/names.py for example
  --cleanup             Cleanup i.e. remove .asm files that we don't need
  --temp-cleanup        Cleanup temporary database files i.e. remove .id0,
                        .id1, .id2, .nam, .dmp files if IDA Pro crashed and
                        did not delete them
  --verbose             be more verbose to debug script
  --max-ida MAX_IDA     Maximum number of instances of IDA to run at a time
                        (default: 10)
  --list-only           List only what files would be handled without
                        executing IDA
  --version IDA_VERSION
                        Override IDA version (e.g. "7.5"). This is used to
                        find the path of IDA on Windows.
```

## Simulate without executing

You can use `--list-only` with any command line to just list what the tool would
do without actually doing it.

```
C:\idahunt>idahunt.py --inputdir C:\re --analyse --filter "filters\names.py -a 32 -v" --list-only
[idahunt] Simulating only...
[idahunt] ANALYSING FILES
[idahunt] Analysing C:\re\cves\cve-2014-4076.dll
[idahunt] Analysing C:\re\cves\cve-2014-4076.exe
[idahunt] Analysing C:\re\DownloadExecute.exe
[idahunt] Analysing C:\re\ReverseShell.exe
```

## Initial analysis

Here we start an initial analysis. It finishes after a few seconds:

```
C:\idahunt>idahunt.py --inputdir C:\re --analyse --filter "filters\names.py -a 32 -v"
[idahunt] ANALYSING FILES
[idahunt] Analysing C:\re\cves\cve-2014-4076.dll
[idahunt] Analysing C:\re\cves\cve-2014-4076.exe
[idahunt] Analysing C:\re\DownloadExecute.exe
[idahunt] Analysing C:\re\ReverseShell.exe
[idahunt] Waiting on remaining 4 IDA instances
```

Here we cleanup temporary `.asm` files created by the initial analysis:

```
C:\idahunt>idahunt.py --inputdir C:\re --cleanup
[idahunt] Deleting C:\re\cves\cve-2014-4076.asm
[idahunt] Deleting C:\re\DownloadExecute.asm
[idahunt] Deleting C:\re\ReverseShell.asm
```

We can see the generated `.idb` as well as some `.log` files that contain the
IDA Pro output window.

```
C:\idahunt>tree /f C:\re
Folder PATH listing
Volume serial number is XXXX-XXXX
C:\RE
│   DownloadExecute.exe
│   DownloadExecute.idb
│   DownloadExecute.log
│   ReverseShell.exe
│   ReverseShell.idb
│   ReverseShell.log
│
└───cves
        cve-2014-4076.dll
        cve-2014-4076.exe
        cve-2014-4076.idb
        cve-2014-4076.log
```

## Execute IDA Python script

Here we execute a basic IDA Python script that prints
`[script_template] I execute in IDA, yay!` in the IDA Pro output window.

```
C:\idahunt>idahunt.py --inputdir C:\re --filter "filters\names.py -a 32 -v" --scripts C:\idahunt\script_template.py
[idahunt] EXECUTE SCRIPTS
[idahunt] Executing script C:\idahunt\script_template.py for C:\re\cves\cve-2014-4076.dll
[idahunt] Executing script C:\idahunt\script_template.py for C:\re\cves\cve-2014-4076.exe
[idahunt] Executing script C:\idahunt\script_template.py for C:\re\DownloadExecute.exe
[idahunt] Executing script C:\idahunt\script_template.py for C:\re\ReverseShell.exe
[idahunt] Waiting on remaining 4 IDA instances
```

Since it is saved in the `.log` file, we can check it successfully executed:

```
Autoanalysis subsystem has been initialized.
Database for file 'ReverseShell.exe' has been loaded.
Compiling file 'C:\Program Files (x86)\IDA 6.95\idc\ida.idc'...
Executing function 'main'...
[script_template] I execute in IDA, yay!
```

## Filters

We can filter that idahunt only analyses files with a given pattern in the name
(`-n Download` below):

```
C:\idahunt>idahunt.py --inputdir C:\re --filter "filters\names.py -a 32 -v -n Download" --scripts C:\idahunt\script_template.py --list-only
[idahunt] Simulating only...
[idahunt] EXECUTE SCRIPTS
[names] Skipping non-matching name Download in cve-2014-4076.dll
[names] Skipping non-matching name Download in cve-2014-4076.exe
[idahunt] Executing script C:\idahunt\script_template.py for C:\re\DownloadExecute.exe
[names] Skipping non-matching name Download in ReverseShell.exe
```

We can also filter that idahunt only analyses files with a given
extension (`-e dll` below):

```
C:\idahunt>idahunt.py --inputdir C:\re --filter "filters\names.py -a 32 -v -e dll" --scripts C:\idahunt\script_template.py --list-only
[idahunt] Simulating only...
[idahunt] EXECUTE SCRIPTS
[idahunt] Executing script C:\idahunt\script_template.py for C:\re\cves\cve-2014-4076.dll
[names] Skipping non-matching extension .dll in cve-2014-4076.exe
[names] Skipping non-matching extension .dll in DownloadExecute.exe
[names] Skipping non-matching extension .dll in ReverseShell.exe
```

### Architecture detection

The architecture is required to know in advance due to IDA Pro architecture and the fact
that it contains 2 different executables `idaq.exe` and `idaq64.exe` to analyse
binaries of the two architectures 32-bit and 64-bit. This is especially true if you want to
use the HexRays decompiler.

idahunt will automatically detect i386, ia64 and amd64 architectures in Windows PE files.
If you need to automatically detect other architectures, you can create an issue or add it 
to idahunt and do a PR.

If you forget to provide the architecture of the files you want to analyse, the
basic `filters\names.py` will return an error:

```
C:\idahunt>idahunt.py --inputdir C:\re --filter "filters\names.py -v -e dll" --scripts C:\idahunt\script_template.py --list-only
[idahunt] Simulating only...
[idahunt] EXECUTE SCRIPTS
[names] Unknown architecture: None. You need to specify it with -a
[names] Skipping non-matching extension .dll in cve-2014-4076.exe
[names] Skipping non-matching extension .dll in DownloadExecute.exe
[names] Skipping non-matching extension .dll in ReverseShell.exe
```

# Known projects using idahunt

* [asadbg](https://github.com/nccgroup/asadbg)
