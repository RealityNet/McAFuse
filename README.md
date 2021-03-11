# McAFuse

McAFuse was developed as a Master's thesis project in <a href="https://courses.unige.it/10852">Computer Science</a> of <a href="https://github.com/A-725-K">*Andrea Canepa*</a> (@A-725-K) in collaboration with <a href="https://www.realitynet.it">*RealityNet (Reality Net System Solutions)*</a>.

This project aim is to bring to the **DFIR** community an open source utility to handle encrypted disk images built with `McAfee FDE` toolset during digital investigations. It exposes a static **FUSE** *read-only* filesystem containing 2 files:
- ***SafeBoot.disk***: a plain FAT partition present in the encrypted disk
- ***encdisk.img***: the encrypted disk

## Getting started
To run this project you have to clone or download this repository, with the command:
```
git clone https://github.com/RealityNet/McAFuse
```
Then you have to install the `Python3` libraries using the requirements file:
```
python3 -m pip install -r requirements.txt
```
Finally you can launch `mcafuse.py` with the requested parameters.

## How to launch the program
You have to run this command from your terminal, as a *superuser*:
```
./mcafuse.py [-h/--help] [--debug] [-i/--info] [-a/--all] [-v/--verbose] MOUNT_POINT DISK_IMAGE [-k/--keyfile KEY_FILE]
```
where the following are mandatory:
- ***MOUNT_POINT***: the new root of the static filesystem you are going to serve
- ***DISK_IMAGE***: the encrypted image of the disk you want to analyze

and these are optional:
- ***-k/--keyfile KEY_FILE***: the XML file provided by McAfee FDE installation containing a \<**key**\> tag with *base64* encoded password to decrypt the disk
- ***-h/--help***: print the help and quit immediately
- ***-i/--info***: print the disk information gathered from SafeBootDiskInfo
- ***-a/--all***: expose all disk and not only an encrypted volume
- ***-v/--verbose***: to print more information on the execution
- ***--debug***: print debug information

In case a keyfile is not specified, only *SafeBoot.disk* will be provided to the final user.

## Authors

* ***Andrea Canepa*** - *Computer Science, UNIGE* - DFIR 2021
* ***Francesco Picasso*** - *RealityNet* - DFIR 2021
* ***Giovanni Lagorio*** - *Computer Science Teacher, UNIGE* - DFIR 2021