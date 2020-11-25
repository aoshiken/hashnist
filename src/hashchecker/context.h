#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include "sha256.h"

#define CTX_DFL_TCP_PORT 25800
#define CTX_DFL_CLIENTS  30
#define CTX_DFL_TIMEOUT  50

typedef struct _CONTEXT {
    SHA_CONTEXT *sha_ctx ;
    const char *hashes_file; // File with all of the SHA256 hashes in binary
                             // format and ordered
    unsigned short port ;    // TCP Listen at port
    unsigned int ip ;        // TCP Listen at IP address
    size_t item_size ;          // Size of item read in the socket (SHA_256 string size 64 bytes)
    int socket_timeout ;
    int max_clients ;
    bool daemonize ;
    bool debug ;
} CONTEXT ;


CONTEXT *context_init( void );
void context_fini( CONTEXT *ctx );

#endif
