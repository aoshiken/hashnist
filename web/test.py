import sys
import requests
import json
import time

sha256_list = [ '00000A1ED7F56E4DFA4582BFB55739113A135BC4F6EB2DA750654B6FA66B3CBA',
                'FFFFFF60E2F34314B6FD7DD7E827BC2D854BF364C5815C46E5E9A0A3B6661303',
                '00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C76',
                '00001203AD8F3BCC664675D4291487845EBAB8580E1C333320FB79497FF6174B',
                '00001X03AD8F3BCC664675D4291487845EBAB8580E1C333320FB79497FF6174B',
                '00001203AD8F3BCC664675D4291487845EBAB8580E1C333320FB79497FF617FF',
                ]

md5_list = [ '0000015367EEDD3FAF7EE378DD1992CC',
             '000001D847E693AB82A15E6925D281ED',
             '000002012397DB2E45A4B605C6422948',
             '000002B1180F80CBB246BAE338903BDD',
             '8DC95A4139F01F9401F18069DD675D93',
             '8DC95B58251B21FE63908C41844B7179',
             '8DC95B8205AAB55B98A66CDAEE79EA7B',
             '8DC95C39D41D48A3929345A47FD6DE21',
             '8DC95C39D41DG8A3929345A47FD6DE21',
             '8DC95C4A59DBA54C8109747A85F4D387',
             '8DC95C916D94B2C1A60D627B01BE6816',
             '8DC95D00759FE7FD83C63673D501EBC8',
             '8DC95EFE81F47D08039FDDDC2F7A2BF5',
             '8DC95F1B7270384EDB0084D894B9B0EE',
             '8DC95F3EE3F7D57FD76FF61E02A33DD5',
             'FFFFFEFBD0575D006666666666666666',
             'FFFFFEFBD0575D00A526A4F793EC32E2',
             'FFFFFF79923A38E08EB5E3C26AC5F6E4',
             'FFFFFF7D4B83424314F9378F17B895C9',
             'FFFFFFBAC715AFD1EC723F4A982CE620'
            ]

###############################################################################

def print_async_results( analysis_id ):

    done      = False
    json_dict = {}

    while not done:

        print("Pending analysis. Waiting 1 second before retrying...\n" )

        time.sleep( 1 )

        async_req = requests.get( 'http://localhost/hashnist/results/%s' % analysis_id )

        json_dict = async_req.json()

        if json_dict.get('status') != 'PENDING':

            done = True

    print( json.dumps( json_dict, indent=3,separators=(", ", " = ") ) )

###############################################################################

def print_results( req_obj ):

    json_dict = req_obj.json()

    if json_dict.get('status') == 'PENDING':

        print_async_results( json_dict.get('analysis_id') )

    else:

        print( json.dumps( json_dict, indent=3,separators=(", ", " = ") ) )

###############################################################################

if len( sys.argv) == 2 :

    if sys.argv[1] in [ 'md5', 'sha256' ]:

        if sys.argv[1] == 'md5':
            url       = 'http://localhost/hashnist/analyzemd5'
            hash_list = md5_list
        else:
            url       = 'http://localhost/hashnist/analyzesha'
            hash_list = sha256_list

        #r = requests.post('http://localhost:5000/analyze', json={ "hashes": lista })
        req_obj = requests.post( url, json={ "hashes": hash_list })

        print_results( req_obj )

    else:
        print("Invalid argument!!")

else:
    print("Invalid argument!!")
