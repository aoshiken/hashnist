**THIS PROJECT IS NOT OFFICIALLY SPONSORED, ENDORSED OR REVIEWED BY THE NATIONAL INSTITUTE OF STANDARDS AND TECHNOLOGY (NIST) OF THE U.S. DEPARTMENT OF COMMERCE**


## Introduction

This project provides a server for the SHA256/MD5 hashes of the National Software Reference Library from the NIST.

The National Software Reference Library (NSRL) is designed to collect software from various sources and incorporate file profiles computed from this software into a Reference Data Set (RDS) of information.

The server is a TCP server named `hashchecker` and written in C/C++, a Python client is located inside the folder `python` and a web backend with installation instructions is located under the `web` folder.

For improving speed and memory footprint `hashchecker` requires an input file with all the SHA256/MD5 hashes in binary format, the companion tools named `binaryze` and `binaryzemd5` can generate that file, see the INSTALLATION section below.

## Building

To build the `hashchecker` server and the companion tools we use the Autotools build system, to compile just follow the steps below:
```
$ ./autogen.sh
$ ./configure
$ make
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

Convert the NIST SHA256 data to a file with all of the SHA256 hashes ordered in
just one line with no blanks in between:
```
$ cut -f 2 rds241-sha256.txt | LC_ALL=C sort -u | tr --delete '\n' > sha256-ordered.txt
```

Now you can convert the file from the previous step into a binary file using
 the `binaryze` utility:
```
$ binaryze -i sha256-ordered.txt -o sha256-ordered.bin
```

...and now you can start the `hashchecker` server with the file generated:
```
$ hashchecker -i sha256-ordered.bin
Loading SHA256 context...
Loading binary hashes from file /home/aandres/github/hashnist/data/sha256/sha256-ordered.bin...
SHA256 hashes loaded in memory: 16801737
Server started at port 25800...
```

## Installation for MD5 hashes

Get the latest Modern RDS (minimal) file from NIST:
```
$ curl https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip -o rds_modernm.zip
```
Decompress the compressed file and remove the first line of the `NSRLFile.txt` file.

Convert the NIST MD5 data to a file with all of the MD5 hashes ordered in
just one line with no blanks in between:
```
$ cut -f 4 -d '"' NSRLFile.txt | LC_ALL=C sort -u | tr --delete '\n' > md5-ordered.txt
```

Now you can convert the file from the previous step into a binary file using
 the `binaryzemd5` utility:
```
$ binaryzemd5 -i md5-ordered.txt -o md5-ordered.bin
```

...and now you can start the `hashchecker` server with the file generated:
```
$ hashchecker --use-md5 -i md5-ordered.bin
Loading MD5 context...
Loading binary hashes from file md5-ordered.bin...
MD5 hashes loaded in memory: 35854732
Server started at port 25800...
```

## REFERENCES

[National Software Reference Library](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl)
