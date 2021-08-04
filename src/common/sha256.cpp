#define _REENTRANT

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <regex.h>
#include <fcntl.h>

#include "util.h"
#include "sha256.h"
#include "sha256-inline.h"


////////////////////////////////////////////////////////////////////////////////

bool sha256_from_hex_allocated( char *hex_str, SHA_256 *ret_sha )
{
    char *hex_begin = hex_str ;
    char *hex_end   = hex_begin + 16 ;
    char aux        = *hex_end ;

    *hex_end = 0 ;

    if ( util_to_uint64( hex_begin, &ret_sha->num64.second ) )
    {
        *hex_end   = aux ;
        hex_begin += 16 ;
        hex_end   += 16 ;
        aux        = *hex_end ;
        *hex_end   = 0;

        if ( util_to_uint64( hex_begin, &ret_sha->num64.first ) )
        {
            *hex_end   = aux ;
            hex_begin += 16 ;
            hex_end   += 16 ;
            aux        = *hex_end ;
            *hex_end   = 0;

            if ( util_to_uint64( hex_begin, &ret_sha->num64.fourth ) )
            {
                *hex_end   = aux ;
                hex_begin += 16 ;

                if ( util_to_uint64( hex_str + 48, &ret_sha->num64.third ) )

                    return true ;
            }
        }
    }

    return false ;
}

////////////////////////////////////////////////////////////////////////////////

SHA_256 *sha256_from_hex( char *hex_str )
{
    SHA_256 *ret_sha = (SHA_256 *)malloc( sizeof( SHA_256 ) );

    if ( ! sha256_from_hex_allocated( hex_str, ret_sha ) )
    {
        free( ret_sha );

        ret_sha = NULL ;
    }

    return ret_sha;
}

////////////////////////////////////////////////////////////////////////////////

bool sha256_great( SHA_256 *sha256_left, SHA_256 *sha256_right )
{
    if ( sha256_left->num128.first > sha256_right->num128.first )

        return true ;

    if ( ( ! memcmp( (void *)&sha256_left->num128.first, 
                     (void *)&sha256_right->num128.first, 16 ) ) &&
         ( sha256_left->num128.second > sha256_right->num128.second ) )

        return true ;

    return false ;
}

////////////////////////////////////////////////////////////////////////////////

bool sha256_less_or_equal( SHA_256 *sha256_left, SHA_256 *sha256_right )
{
    if ( ! memcmp( (void *)sha256_left, (void *)sha256_right, sizeof( SHA_256)))

        return true;

    return sha256_less( sha256_left, sha256_right ) ;
}

////////////////////////////////////////////////////////////////////////////////

bool sha256_great_or_equal( SHA_256 *sha256_left, SHA_256 *sha256_right )
{
    if ( ! memcmp((void *)sha256_left, (void *)sha256_right, sizeof( SHA_256 )))

        return true;

    return sha256_great( sha256_left, sha256_right ) ;
}

////////////////////////////////////////////////////////////////////////////////

bool sha256_not_equal( SHA_256 *sha256_left, SHA_256 *sha256_right )
{
    return memcmp((void *)sha256_left, (void *)sha256_right, sizeof( SHA_256 ));
}

////////////////////////////////////////////////////////////////////////////////

char *sha256_to_hex( SHA_256 *sha )
{
    char *ret_buff = (char *)calloc( 1, 65 );

    if ( ret_buff )
    {
        snprintf( ret_buff,
                  65,
                  "%016" PRIX64 "%016" PRIX64 "%016" PRIX64 "%016" PRIX64,
                  sha->num64.second,
                  sha->num64.first,
                  sha->num64.fourth,
                  sha->num64.third );
    }

    return ret_buff ;
}

////////////////////////////////////////////////////////////////////////////////

sha_search_ret sha256_search( SHA_CONTEXT *sha_ctx, char *hex_str )
{
    sha_search_ret ret = SHA_SEARCH_ERROR ;

    if ( ! regexec( &sha_ctx->preg, (const char *)hex_str, 0, NULL, 0 ) )
    {
        SHA_256 *sha_arg = sha256_from_hex( hex_str );

        if ( sha_arg )
        {
            SHA_256 *sha_first = sha_ctx->sha_first ;
            SHA_256 *sha_last  = sha_ctx->sha_last ;
            SHA_256 *sha_mid ;

            ret = SHA_SEARCH_NOT_FOUND;

            while( sha_first <= sha_last )
            {
                sha_mid = sha_first + ( sha_last - sha_first ) / 2;

                if ( sha256_is_equal( sha_arg, sha_mid ) )
                {
                    ret = SHA_SEARCH_FOUND ;
                    break;
                }

                if ( sha256_less( sha_arg, sha_mid ) )

                    sha_last = --sha_mid ;

                else

                    sha_first = ++sha_mid ;
            }

            free( sha_arg );
        }
    }

    return ret ; 
}

////////////////////////////////////////////////////////////////////////////////

bool sha256_load_buffer( SHA_CONTEXT *sha_ctx, int file_hnd, off64_t *buff_size)
{
    if ( *buff_size && ( ! ( *buff_size % sizeof( SHA_256 ) ) ) )
    {
        sha_ctx->buffer = (unsigned char *)malloc( *buff_size );

        if ( sha_ctx->buffer )
        {
            if ( read( file_hnd, (void *)sha_ctx->buffer, *buff_size ) ==
                     *buff_size )
            {
                sha_ctx->sha_first = (SHA_256 *)( sha_ctx->buffer );

                sha_ctx->sha_last  = (SHA_256 *)( sha_ctx->buffer + *buff_size -
                                                  sizeof(SHA_256)) ;

                return true ;
            }

            free( sha_ctx->buffer  );

            fprintf(stderr,"ERROR!! Unable to read file");
        }
    }
    else
        fprintf( stderr,"ERROR!! File size %ld not divisible by 32!!\n",
                 *buff_size );

    return false ;
}

////////////////////////////////////////////////////////////////////////////////

bool sha256_load_file( SHA_CONTEXT *sha_ctx, const char *file_path_src )
{
    bool ret = false ;
    int file_hnd = open( file_path_src, O_RDONLY );

    printf("Loading binary hashes from file %s...\n", file_path_src );

    if ( file_hnd != -1 )
    {
        struct stat64 statbuf ;

        posix_fadvise( file_hnd, 0, 0, POSIX_FADV_SEQUENTIAL );

        if ( ! fstat64( file_hnd, &statbuf) )
        {
            ret = sha256_load_buffer( sha_ctx, file_hnd, &statbuf.st_size );

            if ( ret )
                printf("SHA256 hashes loaded in memory: %ld\n", statbuf.st_size/32 );
        }

        close( file_hnd );
    }
    else

        fprintf( stderr,"ERROR!! Unable to open file %s\n",file_path_src );

    return ret ;
}

////////////////////////////////////////////////////////////////////////////////

SHA_CONTEXT *sha256_init_ctx( const char *file_path_src )
{
    SHA_CONTEXT *ret_ctx = (SHA_CONTEXT *)calloc( 1, sizeof( SHA_CONTEXT ) );

    if ( ret_ctx )
    {
        if ( ! regcomp( &ret_ctx->preg, "^[0-9A-Fa-f]\\{64\\}$", 0 ) )
        {
            if ( sha256_load_file( ret_ctx, file_path_src ) )
            {
                return ret_ctx;
            }

            regfree( &ret_ctx->preg );

            ret_ctx->preg.allocated = 0;
        }

        free(ret_ctx);
    }

    return NULL ;
}

////////////////////////////////////////////////////////////////////////////////

void sha256_fini_ctx( SHA_CONTEXT *ctx )
{
    if ( ctx )
    {
        if ( ctx->buffer )
            free( ctx->buffer );

        if ( ctx->preg.allocated )
            regfree( &ctx->preg );

        free( ctx );
    }
}

