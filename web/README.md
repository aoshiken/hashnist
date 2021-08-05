### QUICK INSTALL WITH APACHE2, FLASK, REDIS AND RQ IN DEBIAN10

IMPORTANT: This is intended just as a backend web

If you don't have a Redis instance ready to use you can install it from docker
 and bind its port to the official Redis port (6379/tcp):
``` 
$ sudo docker run --name redis-hashnist -p 6379:6379 -d redis:6.0.9
```

Install Apache2 and WSGI:
```
$ sudo apt-get install apache2 libapache2-mod-wsgi-py3
```

Create the Apache root document folder, we'll use `/var/www/hashnist` and our
user will be `myuser`:
```
$ sudo mkdir /var/www/hashnist
$ sudo chown myuser.www-data /var/www/hashnist
```

Create the Python3 virtual environment inside the root document folder:
```
$ virtualenv -p python3 /var/www/hashnist/venv
```

Copy all the files from the folder `web` to the document folder.
The folders structure should looks like this:
```
/var/www/
└── hashnist
    ├── hashnist.wsgi
    ├── requirements.txt
    ├── settings.py
    ├── tasks.py
    ├── test.py
    ├── venv
    ├── worker.py
    └── wshashnist.py
```

Change the file `settings.py` to suit your needs, set the variable `SERVER_USE_MD5`to `False` if you wan to use the server with SHA256 hashes.

Enable and update the Python virtual environment:
```
$ source /var/www/hashnist/venv/bin/activate
(venv) $ pip install -r /var/www/hashnist/requirements.txt
 ```

Install the hashnist python bindings:
```
(venv) $ cd ~/github/hashnist/python
(venv) $ python setup.py install
```
 
Add this to your Apache2 configuration file:
```
WSGIDaemonProcess hashnist user=myuser group=www-data threads=5 python-home=/var/www/hashnist/venv python-path=/var/www/hashnist

WSGIScriptAlias /hashnist /var/www/hashnist/hashnist.wsgi

<Directory /var/www/hashnist>
    WSGIProcessGroup hashnist
    WSGIApplicationGroup %{GLOBAL}
    Order deny,allow
    Allow from all
</Directory>
```

Restart Apache:
```
$ sudo service apache2 restart
```

### USAGE

Open a terminal and start the hashchecker server for SHA256 hashes...
```
$ hashchecker -i sha256-ordered.bin
Loading SHA256 context...
Loading binary hashes from file sha256-ordered.bin...
SHA256 hashes loaded in memory: 16801737
Server started at port 25800...
```

...or start the hashchecker server this way for MD5 hashes...
```
$ hashchecker --use-md5 -i md5-ordered.bin
Loading MD5 context...
Loading binary hashes from file md5-ordered.bin...
MD5 hashes loaded in memory: 35854732
Server started at port 25800...
```

Open another terminal, activate the virtual environment and start an RQ worker:
```
$ cd /var/www/hashnist
$ source venv/bin/activate
(venv) $ python worker.py
07:16:20 Worker rq:worker:3616ab7c7fa046b6bc4189c228fbb978: started, version 1.6.1
07:16:20 Subscribing to channel rq:pubsub:3616ab7c7fa046b6bc4189c228fbb978
07:16:20 *** Listening on hashtasks...
07:16:20 Cleaning registries for queue: hashtasks
```

Open a 3rd terminal and test the server if configured for SHA256 hashes...
```
$ cd /var/www/hashnist
$ source venv/bin/activate
(venv) $ python test.py sha256
{
    'results': {'error': ['00001X03AD8F3BCC664675D4291487845EBAB8580E1C333320FB79497FF6174B'],
                'found': ['00000A1ED7F56E4DFA4582BFB55739113A135BC4F6EB2DA750654B6FA66B3CBA',
                          '00001203AD8F3BCC664675D4291487845EBAB8580E1C333320FB79497FF6174B',
                          '00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C76',
                          'FFFFFF60E2F34314B6FD7DD7E827BC2D854BF364C5815C46E5E9A0A3B6661303'],
            'not_found': ['00001203AD8F3BCC664675D4291487845EBAB8580E1C333320FB79497FF617FF'],
            'status': 'SUCCESS'
     },
     'status': 'FINISHED'
}
```

 ...or this way if configured for MD5 hashes...
```
$ cd /var/www/hashnist
$ source venv/bin/activate
(venv) $ python test.py md5
{
    'results': {'error': ['8DC95C39D41DG8A3929345A47FD6DE21'],
                'found': ['FFFFFEFBD0575D00A526A4F793EC32E2',
                          '8DC95C916D94B2C1A60D627B01BE6816',
                          'FFFFFF79923A38E08EB5E3C26AC5F6E4',
                          '000002B1180F80CBB246BAE338903BDD',
                          '8DC95B8205AAB55B98A66CDAEE79EA7B',
                          '8DC95C4A59DBA54C8109747A85F4D387',
                          '8DC95F1B7270384EDB0084D894B9B0EE',
                          'FFFFFFBAC715AFD1EC723F4A982CE620',
                          '8DC95B58251B21FE63908C41844B7179',
                          '000001D847E693AB82A15E6925D281ED',
                          '8DC95D00759FE7FD83C63673D501EBC8',
                          '8DC95F3EE3F7D57FD76FF61E02A33DD5',
                          '8DC95A4139F01F9401F18069DD675D93',
                          '8DC95EFE81F47D08039FDDDC2F7A2BF5',
                          '8DC95C39D41D48A3929345A47FD6DE21',
                          '0000015367EEDD3FAF7EE378DD1992CC',
                          'FFFFFF7D4B83424314F9378F17B895C9',
                          '000002012397DB2E45A4B605C6422948'],
            'not_found': ['FFFFFEFBD0575D006666666666666666'],
            'status': 'SUCCESS'
     },
     'status': 'FINISHED'
}
```
