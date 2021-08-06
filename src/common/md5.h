#ifndef __MD5_H__
#define __MD5_H__

#include <inttypes.h>
#include <regex.h>

typedef union _MD5 {

    __uint128_t num128 ;

    struct {
        uint64_t first ;
        uint64_t second ;
    } num64 ;

} MD5 ;


typedef struct _MD5_CONTEXT {
    unsigned char *buffer ; // Read buffer
    MD5 *md5_first ;    // First MD5 in buffer
    MD5 *md5_last ;     // Last MD5 in buffer
    regex_t preg ;      // Regex handle
} MD5_CONTEXT ;

enum md5_search_ret
{
    MD5_SEARCH_FOUND     = 0,
    MD5_SEARCH_NOT_FOUND = 1,
    MD5_SEARCH_ERROR     = 2
};

MD5_CONTEXT *md5_init_ctx( const char *file_path );
void md5_fini_ctx( MD5_CONTEXT *md5_ctx );
md5_search_ret md5_search( MD5_CONTEXT *md5_ctx, char *hex_str ); 
char *md5_to_hex( MD5 *md5 );
MD5 *md5_from_hex( char *hex_str );
bool md5_from_hex_allocated( char *hex_str, void *ret_md5 );
bool md5_less_or_equal( MD5 *md5_left, MD5 *md5_right );
bool md5_great( MD5 *md5_left, MD5 *md5_right );
bool md5_great_or_equal( MD5 *md5_left, MD5 *md5_right );
bool md5_not_equal( MD5 *md5_left, MD5 *md5_right );
bool md5_load_file( MD5_CONTEXT *md5_ctx, const char *file_path_src );
void md5_free_buffer( MD5_CONTEXT *ctx );

#endif
