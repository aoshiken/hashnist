#! /usr/bin/env python

# Propios...
import settings
from hashnist.analysis import analyze_md5 as analyze_md5
from hashnist.analysis import analyze_sha256 as analyze_sha


###############################################################################

def analyze( hash_list, use_md5=True ):

    if use_md5:

        result_obj = analyze_md5( hash_list    = hash_list,
                                  server_name  = settings.MD5_HOSTNAME,
                                  server_port  = settings.MD5_PORT,
                                  group_size   = settings.MD5_GROUP_SIZE,
                                  sock_timeout = settings.MD5_SOCKET_TIMEOUT )
    else:

        result_obj = analyze_sha( hash_list    = hash_list,
                                  server_name  = settings.SHA256_HOSTNAME,
                                  server_port  = settings.SHA256_PORT,
                                  group_size   = settings.SHA256_GROUP_SIZE,
                                  sock_timeout = settings.SHA256_SOCKET_TIMEOUT )

    ret_dict = { 'status' : 'FINISHED', 'results' : result_obj.to_dict() }

    return ret_dict

###############################################################################
