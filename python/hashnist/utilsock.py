#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import logging
import select
import traceback


################################################################################

if __name__ == "__main__":
    log = logging.getLogger()
else:
    log = logging.getLogger(__name__)

################################################################################

SOCK_OK      = 0
SOCK_CLOSED  = 1
SOCK_TIMEOUT = 2
SOCK_ERROR   = 3

################################################################################

def connect( hostname, port, timeout=20 ):

    ret_sock = None

    try:

        ret_sock = socket.create_connection( ( hostname, port ),
                                              timeout = timeout )

        ret_sock.settimeout( None )

    except Exception:

        log.error('EXCEPT!! utilsock.connect -> %s' % traceback.format_exc())

    return ret_sock

################################################################################

# Read data from socket until size bytes are read, peer close the socket or
# timeout...

def read( sock, size, timeout=0 ):

    ret_code     = SOCK_ERROR
    ret_buff     = b''
    finished     = False
    left_to_read = size

    while not finished:

        try:

            read_set, write_set, except_set = select.select( [sock],
                                                             [],
                                                             [sock],
                                                             timeout )
        except select.error: # EINTR

            continue

        if sock in read_set:

            try:

                data_read = sock.recv( min( left_to_read, 2048 ) )

            except Exception:

                log.error( 'EXCEPT!! utilsock.read -> %s' %
                            traceback.format_exc())
                data_read = None
                finished  = True

            if data_read:

                ret_buff += data_read
                left_to_read -= len(data_read)

                if len(ret_buff) == size:
                    ret_code = SOCK_OK
                    finished = True
            else:
                ret_code = SOCK_CLOSED
                finished = True

        elif sock in except_set:

            log.warning("Socket exception on utilsock.read()")
            ret_code = SOCK_ERROR
            finished = True

        else:

            log.warning("Timeout exception on utilsock.read()")
            ret_code = SOCK_TIMEOUT
            finished = True

    return ret_code, ret_buff

################################################################################

# Write data to socket until server close the socket or timeout...

def write( sock, buff_write, timeout=0 ):

    ret_code      = SOCK_ERROR
    finished      = False
    total_written = 0
    buff_len      = len( buff_write )

    while not finished:

        try:

            read_set, write_set, except_set = select.select( [],
                                                             [sock],
                                                             [sock],
                                                             timeout )
        except select.error:  # EINTR

            continue

        if sock in write_set:

            try:
                
                data_written = sock.send( buff_write[ total_written: ] )

            except Exception:

                log.error( 'EXCEPT!! utilsock.write -> %s' %
                           traceback.format_exc())
                finished     = True
                data_written = None

            if data_written:

                total_written = total_written + data_written

                if total_written == buff_len:
                    ret_code = SOCK_OK
                    finished = True

            else:
                ret_code = SOCK_CLOSED
                finished = True

        elif sock in except_set:

            ret_code = SOCK_ERROR
            finished = True
            log.warning("Socket exception on utilsock.write()")

        else:

            ret_code = SOCK_TIMEOUT
            finished = True
            log.warning("Timeout exception on utilsock.write()")

    return ret_code
