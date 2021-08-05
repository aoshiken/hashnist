#! /usr/bin/env python

# Propios...
import settings
from hashnist.analysis import analyze as hashnist_analyze


###############################################################################

def analyze( hash_list ):

    result_obj = hashnist_analyze( hash_list    = hash_list,
                                   server_name  = settings.HOSTNAME,
                                   server_port  = settings.PORT,
                                   group_size   = settings.GROUP_SIZE,
                                   sock_timeout = settings.SOCKET_TIMEOUT,
                                   use_md5      = settings.SERVER_USE_MD5 )

    ret_dict = { 'status' : 'FINISHED', 'results' : result_obj.to_dict() }

    return ret_dict

###############################################################################

