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

            re_compiled = re.compile( '^[a-fA-F0-9]{%d}$' % 32 if use_md5 else 64 )

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

    hash_list = [ '0000015367EEDD3FAF7EE378DD1992CC',
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

    hash_list = [ '0000015367EEDD3FAF7EE378DD1992CC',
                  '01234c0e41fc23bb5e1946f69e6c6221',
                  '018d3c34a296edd32e1b39b7276dcf7f',
                  '019b68e26df8750e2f9f580b150b7293',
                  '01fa52a4f9268948b6c508fef0377299',
                  '022bd2040ec0476d8eb80d1d9dc5cc92',
                  '039d9ca446e79f2f4310dc7dcc60ec55',
                  '043f6cdca33ce68b1ebe0fd79e4685af',
                  '04918772a2a6ccd049e42be16bcbee39',
                  '04dc4ca70f788b10f496a404c4903ac6',
                  '060067666435370e0289d4add7a07c3b',
                  '062c759d04106e46e027bbe3b93f33ef',
                  '07083008885d2d0b31b137e896c7266c',
                  '079068181a728d0d603fe72ebfc7e910',
                  '0803f8c5ee4a152f2108e64c1e7f0233',
                  '4b93159610aaadbaaf7f60bea69f21a4',
                  '09143a14272a29c56ff32df160dfdb30',
                  '0985f757b1b51533b6c5cf9b1467f388',
                  '09aab083fb399527f8ff3065f7796443',
                  '0b7bb3e23a1be2f26b9adf7004fc6b52',
                  '0b9a614a2bbc64c1f32b95988e5a3359',
                  '0bbe092a2120b1be699387be16b5f8fb',
                  '4b93159610aaadbaaf7f60bea69f21a4',
                  '0bbe769505ca3db6016da400539f77aa',
                  '0c3c00c01f4c4bad92b5ba56bd5a9598',
                  '0c4fa4dfbe0b07d3425fea3efe60be1c',
                  '4b93159610aaadbaaf7f60bea69f21a4',
                  '0ca936a564508a1f9c91cb7943e07c30',
                  '0d69eefede612493afd16a7541415b95',
                  '0da08b4bfe84eacc9a1d9642046c3b3c',
                  '0dd7f10fdf60fc36d81558e0c4930984',
                  '0e01ec14c25f9732cc47cf6344107672',
                  '4b93159610aaadbaaf7f60bea69f21a4',
                  '10191b6ce29b4e2bddb9e57d99e6c471',
                  '105757d1499f3790e69fb1a41e372fd9',
                  '207e3c538231eb0fd805c1fc137a7b46',
                  '20e52d2d1742f3a3caafbac07a8aa99a',
                  '226042db47bdd3677bd16609d18930bd',
                  '22823fed979903f8dfe3b5d28537eb47',
                  '2366918da9a484735ec3a9808296aab8',
                  '239a22c0431620dc937bc36476e5e245',
                  '2499390148fc99a0f38148655d8059e7',
                  '24dbcd8e8e478a35943a05c7adfc87cc',
                  '25a06ab7675e8f9e231368d328d95344',
                  '25b79ba11f4a22c962fea4a13856da7f',
                  '25fc4713290000cdf01d3e7a0cea7cef',
                  '2639805ae43e60c8f04955f0fe18391c',
                  '270df5aab66c4088f8c9de29ef1524b9',
                  '280e5a3b9671db31cf003935c34f8cf9',
                  '28366de82d9c4441f82b84246369ad3b',
                  '28628f709a23d5c02c91d6445e961645',
                  '28c6f235946fd694d2634c7a2f24c1ba',
                  '29c1b4ec0bc4e224af2d82c443cce415',
                  '2b8a06d1de446db3bbbd712cdb2a70ce',
                  '2bf998d954a88b12dbec1ee96b072cb9',
                  '2c408385acdb04f0679167223d70192b',
                  '2c9737c6922b6ca67bf12729dcf038f9',
                  '2dd9aab33fcdd039d3a860f2c399d1b1',
                  '2de0e31fda6bc801c86645b37ee6f955',
                  '2e5b59c62e6e2f3b180db9453968d817',
                  '2ee7168c0cc6e0df13d0f658626474bb',
                  '2eee367a6273ce89381d85babeae1576',
                  '2f0a52ce4f445c6e656ecebbcaceade5',
                  '2f9995bc34452c789005841bc1d8da09',
                  '30701b1d1e28107f8bd8a15fcc723110',
                  '31a72e3bf5b1d33368202614ffd075db',
                  '3389dae361af79b04c9c8e7057f60cc6',
                  '33d18e29b4ecc0f14c20c46448523fc8',
                  '46e80d49764a4e0807e67101d4c60720',
                  '480f3a13998069821e51cda3934cc978',
                  '48101bbdd897877cc62b8704a293a436',
                  '48548309036005b16544e5f3788561dc',
                  '4a23e0f2c6f926a41b28d574cbc6ac30',
                  '4ab825dc6dabf9b261ab1cf959bfc15d',
                  '4b18b1b56b468c7c782700dd02d621f4',
                  '4b93159610aaadbaaf7f60bea69f21a4',
                  '4beb3f7fd46d73f00c16b4cc6453dcdb',
                  '4dd6eab0fa77adb41b7bd265cfb32013',
                  '4e79e2cade96e41931f3f681cc49b60a',
                  '4ef1c48197092e0f3dea0e7a9030edc8',
                  '503f8dc2235f96242063b52440c5c229',
                  '50527c728506a95b657ec4097f819be6',
                  '5064dc5915a46bfa472b043be9d0f52f',
                  '513f559bf98e54236c1d4379e489b4bc',
                  '51e21a697aec4cc01e57264b8bfaf978',
                  '51f31ed78cec9dbe853d2805b219e6e7',
                  '52b0f7d77192fe6f08b03f0d4ea48e46',
                  '53ceeaf0a67239b3bc4b533731fd84af',
                  '56a9ff904b78644dee6ef5b27985f441',
                  '56b18ba219c8868a5a7b354d60429368',
                  '56d6d3aa1297c62c6b0f84e5339a6c22',
                  '57849bb3949b73e2cd309900adafc853',
                  '5826e0bd3cd907cb24c1c392b42152ca',
                  '5875dfe9a15dd558ef51f269dcc407b5',
                  '58e7fd4530a212b05481f004e82f7bc1',
                  '5957ef4b609ab309ea2f17f03eb78b2d',
                  '5984955cbc41b1172ae3a688ab0246c5',
                  '59ce71ffb298a5748c3115bc834335bf',
                  '5a8d488819f2072caed31ead6aeaf2fc',
                  '4b93159610aaadbaaf7f60bea69f21a4',
                  '5acac898428f6d20f6f085d79d86db9c',
                  '5b2cddac9ebd7b0cd3f3d3ac15026ffb',
                  '6f6d12da9e5cf8b4a7f26e53cc8e9fbd',
                  '700d2582ccb35713b7d1272aa7cfc598',
                  '70206725df8da51f26d6362e21d8fadb',
                  '70e0052d1a2828c3da5ae3c90bc969ea',
                  '720xc1f6f1f4698ac99c6350f4611391',
                  '72a7fd2b3d1b829a9f01db312fdd1cd7',
                  '7327993142260cee445b846a12cf4e85',
                  '7525bc47e2828464ce07fa8a0db6844f',
                  '76adaa87f429111646a27c2e60bda61e',
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

    import time
    start = time.time()
    print("Starting analysis with %d distinct hashes...\n" % ( len(set(hash_list))))

    ret_obj = analyze_md5( hash_list   = hash_list,
                              server_name = '127.0.0.1',
                              server_port = 25800,
                              group_size  = 30,
                              sock_timeout= 30 )

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
