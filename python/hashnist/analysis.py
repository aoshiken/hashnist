#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging

# Propios...
from hashnist import utilsock


################################################################################

if __name__ == "__main__":
    log = logging.getLogger()
else:
    log = logging.getLogger(__name__)

################################################################################


RESPONSE_ITEM_LEN = 65

STATUS_SUCCESS       = "SUCCESS"
STATUS_ERR_INVALID   = "INVALID_SERVER_RESP"
STATUS_NOT_CONNECTED = "SERVER_NOT_CONNECTED"
STATUS_SOCKET_ERR    = "SOCKET_ERROR"

class AnalysisResult( object ):

    def __init__(self):

        self.found     = [] # List of hashes found
        self.not_found = [] # List of hashes not found
        self.error     = [] # List of hashes with errors 
        self.status    = STATUS_SUCCESS

    def add( self, other ):

        self.found     += other.found
        self.not_found += other.not_found
        self.error     += other.error
        self.status    =  other.status

    def to_dict( self ):

        return { 'found'    : self.found,
                 'not_found': self.not_found,
                 'error'    : self.error,
                 'status'   : self.status }

################################################################################

def extract_items( buff_response ):
    '''64 bytes of SHA256 string plus 1 byte of result string
       (0 FOUND, 1 NOT_FOUND, 2 ERROR):
       00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C760
       00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C761
       00001D55121052597C78A59CADCE6F218C88A4F270A577132FBC3C834F4C6C762
    '''
    result_obj = AnalysisResult()

    for i in range( 0, len( buff_response ), RESPONSE_ITEM_LEN ):

        item = buff_response[i:i + RESPONSE_ITEM_LEN]

        # SHA_SEARCH_FOUND     = 0
        # SHA_SEARCH_NOT_FOUND = 1
        # SHA_SEARCH_ERROR     = 2

        if item[64] == 0:

            result_obj.found.append( item[:64].decode("utf-8") )

        elif item[64] == 1:

            result_obj.not_found.append( item[:64].decode("utf-8") )

        elif item[64] == 2:

            result_obj.error.append( item[:64].decode("utf-8") )

        else:
            log.warning( "Invalid entry from server! [%s]" % 
                         item.decode("utf-8"))

            result_obj.status = STATUS_ERR_INVALID

            break

    return result_obj

################################################################################

def read_group_result( server_sock, read_size, sock_timeout ):

    ret_sock, buff_read = utilsock.read( sock    = server_sock,
                                         size    = read_size,
                                         timeout = sock_timeout )

    result_obj = extract_items( buff_read )

    if ret_sock != utilsock.SOCK_OK:

        result_obj.status = STATUS_SOCKET_ERR

    return result_obj

################################################################################

def analyze( hash_list, server_name, server_port, group_size=1000, sock_timeout=40 ):

    result_obj = AnalysisResult()

    if hash_list:

        server_sock = utilsock.connect( hostname = server_name,
                                        port     = server_port,
                                        timeout  = sock_timeout/2 )

        if server_sock is not None:

            for i in range( 0, len( hash_list), group_size ):

                current_group = hash_list[ i:i + group_size ]
                plain_group   = "".join( current_group ).strip( '\r\n ')

                read_size = len( plain_group ) + len( current_group )

                ret_write = utilsock.write( sock       = server_sock,
                                            buff_write = plain_group.encode('utf-8'),
                                            timeout    = sock_timeout )

                if ret_write == utilsock.SOCK_OK:

                    group_obj = read_group_result( server_sock,
                                                   read_size,
                                                   sock_timeout )

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
#
#
#
################################################################################


if __name__ == "__main__":

    logging.basicConfig( format='%(asctime)s %(levelname)s:: %(message)s',
                         level=logging.INFO)

    hash_list = [
             'FFFFFEDDB8EB0B1EB1A6384C2D8A3215FF2D170C497EFC43ABD9B5A864588FE2',
             'FFFFFF60E2F34314B6FD7DD7E827BC2D854BF364C5815C46E5E9A0A3B6661303',
             '000001CC4C5656DF79BDB8E77A6B646F9F9BC583445738097202974DB79047FB',
             '000003913386C774072A360FB555C5588A0B8BCF552872D27AD8BAAEC7A678AE',
             '0000052254BC56B39BD9D8EE6EE459EDC157A13A640DF7881ED484572C08473A',
             '00000657CE612FC6A4CE31EB1B678BBC2CA94088B288CF86F705AB3D692A9705',
             '000006773238A90A697C79A9B127A5D871815BD36356011A13F2479C19885161',
             '00000869829E1DAAE9AFD1EF79EA01DC130FE1F8191A8AAB49ABE1E43933F36B',
             '00000A1ED7F56E4DFA4582BFB55739113A135BC4F6EB2DA750654B6FA66B3CBA',
             '00000A922338335C4AE86642BB01F0C4FC79AD73249479CF7403B3CAD69E30AB',
             '00000B90D1E5A49D45555A196FEDD98619D6F4AFD313AE49BD01C0754FB1F179',
             '00000CBE1DC2DF2BF59F3E3D2999C806C63DE163F49210D14AA6E7E9D2291E4F',
             '00000CF3C27E104C10E9B56F448184004BDD52034BD07A6F89448E41B1EB593F',
             '00000FB17D328A07290A21C8FE2A57385F4E5D785AC16876CF20C97ABEF3A6FA',
             '00001203AD8F3BCC664675D429F487845EBAB8580E1C333320FB79497FF6174B',
             '000012D15E8981C12C0493A82995493B76BFE77BF439DDB586324D17713AEC7A',
             '000013F7BB612C5C6A7B03E28DDA5E6314F378C599091FBF6297B9FE84CAC51F',
             '0000147D8BD268C35359CA088F9FB270AC3CF5B36F403900CA6D2CC95C080DE3',
             '0000164A50B97762B5C1BED31A2A86191B99E2272F14E8AC2BDFC9DCA9451332',
             '000016A88208FD83FB702A1B05CE3A149B09DBF230E1CC9FAD9FEC16F2AE0CBA',
             '000019A42EDF7725C6E98806190F393C91CEDE5DC28262FE2A1189DCDB8E4E2E',
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

    print(" Loading hash list...")

    hash_list += hash_list
    hash_list += hash_list
    hash_list += hash_list
    #hash_list += hash_list
    #hash_list += hash_list
    #hash_list += hash_list
    #hash_list += hash_list
    #hash_list += hash_list
    #hash_list += hash_list
    #hash_list += hash_list
    #hash_list += hash_list
    #hash_list += hash_list
    #hash_list += hash_list
    #hash_list += hash_list

    import time
    start = time.time()
    print("Starting analysis...\n")

    ret_obj = analyze( hash_list   = hash_list,
                       server_name = '127.0.0.1',
                       server_port = 25800,
                       group_size  = 1000,
                       sock_timeout= 30 )

    end = time.time()

    print("The analysis status is %s\n" % ret_obj.status )

    print("%d hashes FOUND:" % len(ret_obj.found));
    for i in ret_obj.found[0:10]: print(i)

    print("\n%d hashes NOT FOUND:" % len(ret_obj.not_found));
    for i in ret_obj.not_found[0:10]: print(i)

    print("\n%d hashes ERR:" % len(ret_obj.error));
    for i in ret_obj.error[0:10]: print(i)

    total = len(ret_obj.found) + len(ret_obj.not_found) + len(ret_obj.error)

    print( "\nTested %d hashes, results %d hashes\n" % (len(hash_list),
                                                        total))

    if total != len(hash_list):
        print("\nERROR!! Invalid number of results\n")

    print( "FINISHED analysis, took %s seconds" % str(end - start))
