## USAGE

The usage is very simple through the `analyze_md5` or the `analyze_sha256` function:
```
def analyze_md5( hash_list, server_name, server_port, group_size=1000, sock_timeout=40 )

def analyze_sha256( hash_list, server_name, server_port, group_size=1000, sock_timeout=40 )
```

* hash_list. List of SHA256/MD5 hashes (str) to looking for
* server_name. IP addres or name of the `hashchecker` server
* server_port. TCP port of the `hashchecker` server
* group_size. Group size for bulk queries to be sent to the `haschecker` server. If the `hash_list` parameter contains 20.000 hashes and this parameter specifies 1000 then, internally, instead of make just one query with 20.000 hashes we'll make 20 queries of 1000 hashes per query
* sock_timeout. Timeout in seconds for socket operations

The object returned by the `analyze` function is of type `AnalysisResult`:
```
class AnalysisResult( object ):

    def __init__(self):

        self.found     = [] # List of hashes found
        self.not_found = [] # List of hashes not found
        self.error     = [] # List of hashes with errors
        self.status
    [...]
```

The `status` field can be one of the following values:

* STATUS_SUCCESS. Operation finished with success
* STATUS_ERR_INVALID. Invalid response received from server
* STATUS_NOT_CONNECTED. The `hashchecker`server is not connected
* STATUS_SOCKET_ERR. Generic socket error


## EXAMPLE

```
(venv) test@debian10:~/github/hashnist/python$ python setup.py install
[...]

(venv) test@debian10:~/github/hashnist/python$ python
Python 3.7.3 (default, Jul 25 2020, 13:03:44)
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
>>> from hashnist.analysis import analyze_sha256 as hashnist_analyze_sha
>>>
>>> hash_list = [ 'FFFFFEDDB8EB0B1EB1A6384C2D8A3215FF2D170C497EFC43ABD9B5A864588FE2',
... '0000052254BC56B39BD9D8EE6EE459EDC157A13A640DF7881ED484572C08473A',
... '0000052254BC56B39BD9D88888888888C157A13A640DF7881ED484572C08473A',
... '0000052254BC56B39BD9DDDDDDD459EDC157A13A640DF7881ED484572C08473A',
... '00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C7X',
... '00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6CX6',
... ]
>>>
... ret_obj = hashnist_analyze_sha( hash_list   = hash_list,
...                                 server_name = '127.0.0.1',
...                                 server_port = 25900,
...                                 group_size  = 1000,
...                                 sock_timeout= 30 )
>>>
>>> ret_obj.error
['00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C7X', '00001D55121052597C78A59CADCE6F218C88A4F270A577132FB
C3C834F4C6CX6']
>>>
>>> ret_obj.not_found
['0000052254BC56B39BD9D88888888888C157A13A640DF7881ED484572C08473A', '0000052254BC56B39BD9DDDDDDD459EDC157A13A640DF7881ED
484572C08473A']
>>>
>>> ret_obj.found
['FFFFFEDDB8EB0B1EB1A6384C2D8A3215FF2D170C497EFC43ABD9B5A864588FE2', '0000052254BC56B39BD9D8EE6EE459EDC157A13A640DF7881ED
484572C08473A']
>>>
```
