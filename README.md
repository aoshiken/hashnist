**THIS PROJECT IS NOT OFFICIALLY SPONSORED, ENDORSED OR REVIEWED BY THE NATIONAL INSTITUTE OF STANDARDS AND TECHNOLOGY (NIST) OF THE U.S. DEPARTMENT OF COMMERCE**


## Introduction

This project provides a server for the SHA-256 hashes of the National Software Reference Library from the NIST.

The National Software Reference Library (NSRL) is designed to collect software from various sources and incorporate file profiles computed from this software into a Reference Data Set (RDS) of information.

The server is a TCP server named `hashchecker` and written in C/C++, a Python client is located inside the folder `python` and a web backend with installation instructions is located under the `web` folder.

For improving speed and memory footprint `hashchecker` requires an input file with all the SHA256 hashes in binary format, the companion tool named `binaryze` can generate that file, see the INSTALLATION section below.

## Building

To build the `hashchecker` server and the `binaryze` tool we use the Autotools build system, to compile just follow the steps below:
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

## Installation

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
 the `binaryzer` utility:
```
$ binaryze -i sha256-ordered.txt -o sha256-ordered.bin
```

...and now you can start the `hashchecker` server with the file generated:
```
$ hashchecker -i sha256-ordered.bin
Loading SHA256 context...
Loading binary hashes from file /tmp/sha256-ordered.bin...
Server started at port 25800...
```

## REFERENCES

[National Software Reference Library](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl)
