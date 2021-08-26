**THIS PROJECT IS NOT OFFICIALLY SPONSORED, ENDORSED OR REVIEWED BY THE NATIONAL INSTITUTE OF STANDARDS AND TECHNOLOGY (NIST) OF THE U.S. DEPARTMENT OF COMMERCE**


## Introduction

This project provides a server for the SHA256/MD5 hashes of the National Software Reference Library from the NIST.

The National Software Reference Library (NSRL) is designed to collect software from various sources and incorporate file profiles computed from this software into a Reference Data Set (RDS) of information.

The server is a TCP server named `hashchecker` and written in C/C++, a Python client is located inside the folder `python` and a web backend with installation instructions is located under the `web` folder.

For improving speed and memory footprint `hashchecker` requires an input file with all the SHA256/MD5 hashes in binary format, the companion tool named `binaryze` can generate that file, see the INSTALLATION section below.

## Building

To build the `hashchecker` server and the companion tools we use the Autotools build system, to compile just follow the steps below:
```
$ ./autogen.sh
$ ./configure
$ make
$ make install
```

## Python bindings

The Python bindings for using from a Python3 client are available under the folder `python`, see its README.md for a more detailed explanation and usage.

## Web backend

A web backend for Apache, Flask, Redis and RQ is located under the `web` folder, take into account that there's no currently a front-end available but it'd be easy to make one.

See its README.md for a depthful explanation.

## Installation for SHA256 hashes

Get the SHA1-to-SHA256 file from NIST:
```
$ curl https://s3.amazonaws.com/docs.nsrl.nist.gov/morealgs/blockhash/rds241-sha256.zip -o rds241-sha256.zip
```

Decompress the file and use the file `rds241-sha256.txt` as a parameter for the bash script `norm-sha256.sh` located in the `extras` folder:
```
$ ./norm-sha256.sh rds241-sha256.txt sha256-ordered.bin

** Checking output file... OK

** Checking input files... OK

** Creating ordered text file. Process could last several minutes... OK

** Converting ordered text file to binary format... OK

** Script finished OK. Binary file successfully created on /home/aandres/github/hashnist/extras/sha256-ordered.bin

** You can use this file as the input parameter for the hashchecker server this way:

    $ hashchecker -p 25900 -i /home/aandres/github/hashnist/extras/sha256-ordered.bin
```

...and now you can start the `hashchecker` server with the binary file generated:
```
$ hashchecker -p 25900 -i sha256-ordered.bin
Loading SHA256 context...
Loading binary hashes from file /home/aandres/github/hashnist/data/sha256/sha256-ordered.bin...
SHA256 hashes loaded in memory: 16801737
Server started at port 25900...
```

## Installation for MD5 hashes

Get the latest Modern RDS (minimal) file from NIST:
```
$ curl https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip -o rds_modernm.zip
```

Decompress the downloaded file and remove the first line of the `NSRLFile.txt` file.

Use the file `NSRLFile.txt` as a parameter for the bash script `norm-md5.sh` located in the `extras` folder:
```
$ ./norm-md5.sh NSRLFile.txt md5-ordered.bin

** Checking output file... OK

** Checking input files... OK

** Creating ordered text file. Process could last several minutes... OK

** Converting ordered text file to binary format... OK

** Script finished OK. Binary file successfully created on /home/aandres/github/hashnist/extras/md5-ordered.bin

** You can use this file as the input parameter for the hashchecker server this way:

    $ hashchecker --use-md5 -i /home/aandres/github/hashnist/extras/md5-ordered.bin
```

...and now you can start the `hashchecker` server with the binary file generated in the previous step:
```
$ hashchecker --use-md5 -i md5-ordered.bin
Loading MD5 context...
Loading binary hashes from file md5-ordered.bin...
MD5 hashes loaded in memory: 35854732
Server started at port 25800...
```

## Extras

The `extras` folder contains a few scripts for helping generating the binary files needed for the server.

If you want to add MD5/SHA256 hashes from your Windows computer that aren't available in the NSRL dataset use the `hash.cmd` Windows script.

See the `README.md` file in the `extras` folder for instructions

## REFERENCES

[National Software Reference Library](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl)
