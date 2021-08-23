#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include "../common/search.h"

#define CTX_DFL_TCP_PORT 25800
#define CTX_DFL_CLIENTS  30
#define CTX_DFL_TIMEOUT  50

typedef struct _CONTEXT {
    void *hash_ctx ;
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
    bool (*hash_load_file)( void *ctx, const char *file_path_src );
    void (*hash_free_buffer)( void *ctx );
    hash_search_ret (*hash_search)( void *ctx_arg, char *hex_str );
    void *(*hash_init_ctx)( const char *file_path_src );
    void (*hash_fini_ctx)( void *ctx_arg );
} CONTEXT ;


CONTEXT *context_init( void );
void context_fini( CONTEXT *ctx );

#endif
