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

#include "../common/util.h"
#include "../common/sha256.h"
#include "context.h"


///////////////////////////////////////////////////////////////////////////////

CONTEXT *context_init( void )
{
    CONTEXT *ret_ctx = (CONTEXT *)calloc( 1, sizeof( CONTEXT ) );

    if ( ret_ctx )
    {
        ret_ctx->max_clients      = CTX_DFL_CLIENTS ;
        ret_ctx->port             = CTX_DFL_TCP_PORT ;
        ret_ctx->ip               = 0x100007F ;
        ret_ctx->socket_timeout   = CTX_DFL_TIMEOUT ;
        ret_ctx->item_size        = 64 ; // SHA256 hashes by default
        ret_ctx->hash_load_file   = sha256_load_file ;
        ret_ctx->hash_free_buffer = sha256_free_buffer ;
        ret_ctx->hash_search      = sha256_search ;
        ret_ctx->hash_init_ctx    = sha256_init_ctx ;
        ret_ctx->hash_fini_ctx    = sha256_fini_ctx ;
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

