### norm-md5.sh

Bash script for normalyzing the MD5 text source files and generate, through the use of the `binaryze` utility, the binary file needed for the `hashchecker` server.

```
Usage:
    $ norm-md5.sh [source1] [source2] ... [output_binary_file]


Example:
    $ norm-md5.sh NSRLFile.txt md5-win10.txt md5-win7.txt md5-ordered.bin
```

### norm-sha256.sh

Bash script for normalyzing the SHA256 text source files and generate, through the use of the `binaryze` utility, the binary file needed for the `hashchecker` server.

```
Usage:
    $ norm-sha256.sh [source1] [source2] ... [output_binary_file]


Example:
    $ norm-sha256.sh rds241-sha256.txt sha256-win10.txt sha256-win7.txt sha256-ordered.bin
```

### hash.cmd

Windows cmd file for extracting MD5/SHA256 hash of folders and files in Windows 7/10 platforms.
See the code for specifying what folders and files will be hashed.

The output format is different according to the chosen algorithm for remaining
compatible with the NSRL files format.

This script has been tested with Windows 7 SP1 N x64 and Windows 10 Pro.

#### Generating MD5 hashes

Run the script in your Windows computer redirecting the output to a file:
```
Microsoft Windows [Versión 10.0.19041.1110]
(c) Microsoft Corporation. Todos los derechos reservados.

C:\Users\test> hash.cmd md5 > md5-win10.txt
```

Upload the generated file into the Linux machine where you have the `hashnist` suite installed.

Once uploaded you can generate the binary file using the bash script `norm-md5.sh` located in the `extras` folder, pass as parameters the generated file and the NSRL file `NSRLFile.txt` (see the README.md in the main folder of `hashnist` for instructions on acquiring this file) this way:
```
$ ./norm-md5.sh NSRLFile.txt md5-win10.txt md5-ordered.bin

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

#### Generating SHA256 hashes

Run the script in your Windows computer redirecting the output to a file:
```
Microsoft Windows [Versión 10.0.19041.1110]
(c) Microsoft Corporation. Todos los derechos reservados.

C:\Users\test>hash.cmd sha256 > sha256-win10.txt
```

Upload the generated file into the Linux machine where you have the `hashnist` suite installed.

Once uploaded you can generate the binary file using the bash script `norm-sha256.sh` located in the `extras` folder, pass as parameters the generated file and the NSRL file `rds241-sha256.txt` (see the README.md in the main folder of `hashnist` for instructions on acquiring this file) this way: 
```
$ ./norm-sha256.sh rds241-sha256.txt sha256-win10.txt sha256-ordered.bin

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
SHA256 hashes loaded in memory: 16802394
Server started at port 25900...
```
