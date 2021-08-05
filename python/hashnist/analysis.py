#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import re

# Propios...
from hashnist import utilsock


################################################################################

if __name__ == "__main__":
    log = logging.getLogger()
else:
    log = logging.getLogger(__name__)

################################################################################


RESPONSE_ITEM_LEN_SHA = 65
RESPONSE_ITEM_LEN_MD5 = 33

STATUS_SUCCESS       = "SUCCESS"
STATUS_ERR_INVALID   = "INVALID_SERVER_RESP"
STATUS_NOT_CONNECTED = "SERVER_NOT_CONNECTED"
STATUS_SOCKET_ERR    = "SOCKET_ERROR"

class AnalysisResult( object ):

    def __init__(self):

        self.found     = set() # Set of hashes found
        self.not_found = set() # Set of hashes not found
        self.error     = set() # Set of hashes with errors
        self.status    = STATUS_SUCCESS

    def add( self, other ):

        self.found     |= other.found
        self.not_found |= other.not_found
        self.error     |= other.error
        self.status    =  other.status

    def add_errors( self, hash_err_set ):

        self.error |= hash_err_set

    def to_dict( self ):

        return { 'found'    : [ hash_item.upper() for hash_item in self.found ],
                 'not_found': [ hash_item.upper() for hash_item in self.not_found ],
                 'error'    : [ hash_item.upper() for hash_item in self.error ],
                 'status'   : self.status }

################################################################################

def extract_items( buff_response, response_item_len ):
    '''64 bytes of SHA256 (or 32 bytes of MD5) string plus 1 byte of result string
       (0 FOUND, 1 NOT_FOUND, 2 ERROR):
       00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C760
       00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C761
       00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C762
    '''
    result_obj = AnalysisResult()

    for i in range( 0, len( buff_response ), response_item_len ):

        item = buff_response[i:i + response_item_len]

        # HASH_SEARCH_FOUND     = 0
        # HASH_SEARCH_NOT_FOUND = 1
        # HASH_SEARCH_ERROR     = 2

        if item[response_item_len - 1] == 0:

            result_obj.found.add( item[:response_item_len-1].decode("utf-8") )

        elif item[response_item_len-1] == 1:

            result_obj.not_found.add( item[:response_item_len-1].decode("utf-8") )

        elif item[response_item_len-1] == 2:

            result_obj.error.add( item[:response_item_len-1].decode("utf-8") )

        else:
            log.warning( "Invalid entry from server! [%s]" % 
                         item.decode("utf-8"))

            result_obj.status = STATUS_ERR_INVALID

            break

    return result_obj

################################################################################

def read_group_result( server_sock, read_size, sock_timeout, use_md5=False ):

    ret_sock, buff_read = utilsock.read( sock    = server_sock,
                                         size    = read_size,
                                         timeout = sock_timeout )

    if use_md5:

        result_obj = extract_items( buff_read, response_item_len=RESPONSE_ITEM_LEN_MD5 )

    else:

        result_obj = extract_items( buff_read, response_item_len=RESPONSE_ITEM_LEN_SHA )

    if ret_sock != utilsock.SOCK_OK:

        result_obj.status = STATUS_SOCKET_ERR

    return result_obj

################################################################################

def analyze( hash_list, server_name, server_port, group_size=1000,
             sock_timeout=40, use_md5=False ):

    result_obj = AnalysisResult()

    if hash_list:

        server_sock = utilsock.connect( hostname = server_name,
                                        port     = server_port,
                                        timeout  = sock_timeout/2 )
        if server_sock is not None:

            re_compiled = re.compile( '^[a-fA-F0-9]{%d}$' % ( 32 if use_md5 else 64 ) )

            hash_list     = list( set( hash_list ) )
            hash_list_ok  = list( filter( re_compiled.match, hash_list ) )
            hash_list_err = set( hash_list ) - set( hash_list_ok )

            result_obj.add_errors( hash_list_err )

            hash_list_err = None
            hash_list     = None

            for i in range( 0, len( hash_list_ok), group_size ):

                current_group = hash_list_ok[ i:i + group_size ]

                plain_group   = "".join( current_group ).strip( '\r\n ')

                read_size = len( plain_group ) + len( current_group )

                ret_write = utilsock.write( sock       = server_sock,
                                            buff_write = plain_group.encode('utf-8'),
                                            timeout    = sock_timeout )

                if ret_write == utilsock.SOCK_OK:

                    group_obj = read_group_result( server_sock,
                                                   read_size,
                                                   sock_timeout,
                                                   use_md5 = use_md5)

                    result_obj.add( group_obj )

                else:

                    result_obj.status = STATUS_SOCKET_ERR

                if result_obj.status != STATUS_SUCCESS:

                    break

            server_sock.close()

        else:

            result_obj.status = STATUS_NOT_CONNECTED

    return result_obj

################################################################################

def analyze_md5( hash_list, server_name, server_port, group_size=1000,
                 sock_timeout=40 ):

    return analyze( hash_list    = hash_list,
                    server_name  = server_name,
                    server_port  = server_port,
                    group_size   = 1000,
                    sock_timeout = sock_timeout,
                    use_md5      = True )

################################################################################

def analyze_sha256( hash_list, server_name, server_port, group_size=1000,
                    sock_timeout=40 ):

    return analyze( hash_list    = hash_list,
                    server_name  = server_name,
                    server_port  = server_port,
                    group_size   = 1000,
                    sock_timeout = sock_timeout,
                    use_md5      = False )


################################################################################
#
#
#
################################################################################


if __name__ == "__main__":
    import sys
    import time

    logging.basicConfig( format='%(asctime)s %(levelname)s:: %(message)s',
                         level=logging.INFO)

    hash_list_sha = [
             'FFFFFEDDB8EB0B1EB1A6384C2D8A3215FF2D170C497EFC43ABD9B5A864588FE2',
             'FFFFFF60E2F34314B6FD7DD7E827BC2D854BF364C5815C46E5E9A0A3B6661303',
             '000001CC4C5656DF79BDB8E77A6B646F9F9BC583445738097202974DB79047FB',
             '000003913386C774072A360FB555C5588A0B8BCF552872D27AD8BAAEC7A678AE',
             '0000052254BC56B39BD9D8EE6EE459EDC157A13A640DF7881ED484572C08473A',
             '00000657CE612FC6A4CE31EB1B678BBC2CA94088B288CF86F705AB3D692A9705',
             '000006773238A90A697C79A9B127A5D871815BD36356011A13F2479C19885161',
             '00000869829E1DAAE9AFD1EF79EA01DC130FE1F8191A8AAB49ABE1E43933F36B',
             '00000A1ED7F56E4DFA4582BFB55739113A135BC4F6EB2DA750654B6FA66B3CBA',
             '00001A87CE4C0BE3FA201FCAC3950AEA56F55A9E59DDF0F052400F4D258094FE',
             '00001AF50C7A74B4F9459FD81ED2A602AECF513150255D1C2D687DD1D8FC561B',
             '00001B6BD8D761DD4788118D8BF518DC8BE7B0E1A26986999CE1E234A1318AA4',
             '00001BB6F50AF9C81E041B10FDB088F76EFBBAD95EC226421364FD4CB88D76BE',
             '00001C970722D5BA0166D07A8740BF12A43A32E81A79CE73230C374F6551B177',
             '00001CF5573F7AD584E91C3CFB94A137107128DC3B44EE8109993C68F272B3FF',
             '00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C76',
             '00001X55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C76',
             '00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6CX6',
             '00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C7X'
    ]

    hash_list_md5 = [ '0000015367EEDD3FAF7EE378DD1992CC',
                      '01234c0e41fc23bb5e1946f69e6c6221',
                      '018d3c34a296edd32e1b39b7276dcf7f',
                      '019b68e26df8750e2f9f580b150b7293',
                      '01fa52a4f9268948b6c508fef0377299',
                      '022bd2040ec0476d8eb80d1d9dc5cc92',
                      '76c5dca8dc9b1241b8c9a376abab0cc5',
                      '782202b09f72b3cfdc93ffb096ca27de',
                      '7836c4a36cc66d4bcbd84abb25857d21',
                      '78a0af31a5c7e4aee0f9acde74547207',
                      '7969dc3c87a3d5e672b05ff2fe93f710',
                      '7a09bf329b0b311cc552405a38747445',
                      '7a63ea3f49a96fa0b53a84e59f005019',
                      '7b3f959ab775032a3ca317ebb52189c4',
                      '7b710f9731ad3d6e265ae67df2758d50',
                      '7bd10b5c8de94e195b7da7b64af1f229',
                      '7c036ba51a3818ddc8d51cf5'
    ]

    start = time.time()

    if sys.argv[1] == 'md5':

        hash_list = hash_list_md5

        print("Starting analysis with %d distinct hashes...\n" % ( len(set(hash_list))))

        ret_obj = analyze_md5( hash_list   = hash_list,
                               server_name = '127.0.0.1',
                               server_port = 25800,
                               group_size  = 30,
                               sock_timeout= 30 )

    elif  sys.argv[1] == 'sha256':

        hash_list = hash_list_sha

        print("Starting analysis with %d distinct hashes...\n" % ( len(set(hash_list))))

        ret_obj = analyze_sha256( hash_list   = hash_list,
                                  server_name = '127.0.0.1',
                                  server_port = 25800,
                                  group_size  = 30,
                                  sock_timeout= 30 )
    else:
        print("Invalid argument!!")
        sys.exit()

    end = time.time()

    print("The analysis status is %s\n" % ret_obj.status )

    print("%d hashes FOUND:" % len(ret_obj.found));
    for i in list(ret_obj.found)[0:10]: print(i)

    print("\n%d hashes NOT FOUND:" % len(ret_obj.not_found));
    for i in list(ret_obj.not_found)[0:10]: print(i)

    print("\n%d hashes ERR:" % len(ret_obj.error));
    for i in list(ret_obj.error)[0:10]: print(i)

    total = len(ret_obj.found) + len(ret_obj.not_found) + len(ret_obj.error)

    print( "\nTested %d hashes, results %d hashes\n" % (len(hash_list),
                                                        total))

    if total != len(set(hash_list)):
        print("\nERROR!! Invalid number of results\n")

    print( "FINISHED analysis, took %s seconds" % str(end - start))
