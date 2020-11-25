#define _REENTRANT

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "util.h"
#include "context.h"


///////////////////////////////////////////////////////////////////////////////

CONTEXT *context_init( void )
{
    CONTEXT *ret_ctx = (CONTEXT *)calloc( 1, sizeof( CONTEXT ) );

    if ( ret_ctx )
    {
        ret_ctx->max_clients    = CTX_DFL_CLIENTS ;
        ret_ctx->port           = CTX_DFL_TCP_PORT ;
        ret_ctx->ip             = 0x100007F ;
        ret_ctx->socket_timeout = CTX_DFL_TIMEOUT ;
        ret_ctx->item_size      = 64 ;
    }

    return ret_ctx; 
}

///////////////////////////////////////////////////////////////////////////////

void context_fini( CONTEXT *ctx )
{
    if ( ctx )
    {
        if ( ctx->hashes_file )
            free( (void *)ctx->hashes_file );

        free( ctx );
    }
}

///////////////////////////////////////////////////////////////////////////////

