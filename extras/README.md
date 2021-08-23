
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

Once uploaded you can generate the text file including the NSRL MD5 hashes file `NSRLFile.txt` (see the README.md in the main folder of `hashnist` for instructions on acquiring this file) this way: 
```
$ cut -f 4 -d '"' md5-win10.txt NSRLFile.txt | LC_ALL=C sort -u | tr --delete '\n' > md5-ordered.txt
```

...and the final step would be using the `binaryze` tool for generating the binary file:
```
$ binaryze --use-md5 -i md5-ordered.txt -o md5-ordered.bin
```

Now you can start the `hashchecker` server with the generated binary file:
```
$ hashchecker --use-md5 -i /home/test/md5-ordered.bin
Loading MD5 context...
Loading binary hashes from file /home/test/md5-ordered.bin...
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

Once uploaded you can generate the text file including the NSRL SHA256 hashes file `rds241-sha256.txt` (see the README.md in the main folder of `hashnist` for instructions on acquiring this file) this way: 
```
$ cut -f 2 sha256-win10.txt rds241-sha256.txt | LC_ALL=C sort -u | tr --delete '\n' > sha256-ordered.txt
```

...and the final step would be using the `binaryze` tool for generating the binary file:
```
$ binaryze -i sha256-ordered.txt -o sha256-ordered.bin
```

Now you can start the `hashchecker` server with the generated binary file:
```
$ hashchecker -i /home/test/sha256-ordered.bin
Loading SHA256 context...
Loading binary hashes from file /home/test/sha256-ordered.bin...
SHA256 hashes loaded in memory: 16801737
Server started at port 25800...
```
