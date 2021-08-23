#ifndef __SHA_256_H__
#define __SHA_256_H__

#include <inttypes.h>
#include <regex.h>
#include "search.h"

typedef union _SHA_256 {

    struct {
        __uint128_t first ;
        __uint128_t second ;
    } num128 ;

    struct {
        uint64_t first ;
        uint64_t second ;
        uint64_t third ;
        uint64_t fourth ;
    } num64 ;

} SHA_256 ;


typedef struct _SHA_CONTEXT {
    unsigned char *buffer ; // Read buffer
    SHA_256 *sha_first ;    // First SHA256 in buffer
    SHA_256 *sha_last ;     // Last SHA256 in buffer
    regex_t preg ;          // Regex handle
} SHA_CONTEXT ;

void *sha256_init_ctx( const char *file_path );
void sha256_fini_ctx( void *sha_ctx );
hash_search_ret sha256_search( void *sha_ctx, char *hex_str );
char *sha256_to_hex( SHA_256 *sha );
SHA_256 *sha256_from_hex( char *hex_str );
bool sha256_from_hex_allocated( char *hex_str, void *ret_sha );
bool sha256_less_or_equal( SHA_256 *sha256_left, SHA_256 *sha256_right );
bool sha256_great( SHA_256 *sha256_left, SHA_256 *sha256_right );
bool sha256_great_or_equal( SHA_256 *sha256_left, SHA_256 *sha256_right );
bool sha256_not_equal( SHA_256 *sha256_left, SHA_256 *sha256_right );
bool sha256_load_file( void *sha_ctx, const char *file_path_src );
void sha256_free_buffer( void *ctx_arg );

#endif
