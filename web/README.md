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
$ sudo service restart apache2
```

### USAGE

Open a terminal and start the hashchecker server:
```
$ hashchecker -r ../../data/sha256-ordered.bin
  Loading SHA256 context...
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

Open a 3rd terminal and test the server:
```
$ cd /var/www/hashnist
$ source venv/bin/activate
(venv) $ python ./test.py
       {'results': {'error': ['00001X03AD8F3BCC664675D4291487845EBAB8580E1C333320FB79497FF6174B'],
                     'found': ['00000A1ED7F56E4DFA4582BFB55739113A135BC4F6EB2DA750654B6FA66B3CBA',
                               'FFFFFF60E2F34314B6FD7DD7E827BC2D854BF364C5815C46E5E9A0A3B6661303',
                               '00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C76',
                               '00001203AD8F3BCC664675D4291487845EBAB8580E1C333320FB79497FF6174B'],
                 'not_found': ['00001203AD8F3BCC664675D4291487845EBAB8580E1C333320FB79497FF617FF'],
                    'status': 'SUCCESS'},
       'status': 'FINISHED'}
```
