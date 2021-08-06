#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include "sha256.h"
#include "md5.h"

#define CTX_DFL_TCP_PORT 25800
#define CTX_DFL_CLIENTS  30
#define CTX_DFL_TIMEOUT  50

typedef struct _CONTEXT {
    SHA_CONTEXT *sha_ctx ;
    MD5_CONTEXT *md5_ctx ;
    const char *hashes_file; // File with all of the hashes ordered in binary format
    time_t modif_time;       // Last modification time of the hashes file
    unsigned short port ;    // TCP Listen at port
    unsigned int ip ;        // TCP Listen at IP address
    size_t item_size ;       // Size of item read in the socket (SHA_256 string size 64 bytes)
    int socket_timeout ;
    int max_clients ;
    bool daemonize ;
    bool debug ;
    bool use_md5 ;          // Use MD5 hashes instead of SHA256
} CONTEXT ;


CONTEXT *context_init( void );
void context_fini( CONTEXT *ctx );

#endif
