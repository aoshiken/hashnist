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
#include "md5.h"
#include "md5-inline.h"


////////////////////////////////////////////////////////////////////////////////

bool md5_from_hex_allocated( char *hex_str, void *ret_md5_arg )
{
    MD5 *ret_md5 = (MD5 *)ret_md5_arg;
    char *hex_begin = hex_str ;
    char *hex_end   = hex_begin + 16 ;
    char aux        = *hex_end ;

    *hex_end = 0 ;

    if ( util_to_uint64( hex_begin, &ret_md5->num64.second ) )
    {
        *hex_end   = aux ;
        hex_begin += 16 ;
        hex_end   += 16 ;
        aux        = *hex_end ;
        *hex_end   = 0;

        if ( util_to_uint64( hex_begin, &ret_md5->num64.first ) )

            return true ;
    }

    return false ;
}

////////////////////////////////////////////////////////////////////////////////

MD5 *md5_from_hex( char *hex_str )
{
    MD5 *ret_md5 = (MD5 *)malloc( sizeof( MD5 ) );

    if ( ! md5_from_hex_allocated( hex_str, (void *)ret_md5 ) )
    {
        free( ret_md5 );

        ret_md5 = NULL ;
    }

    return ret_md5;
}

////////////////////////////////////////////////////////////////////////////////

bool md5_great( MD5 *md5_left, MD5 *md5_right )
{
    if ( md5_left->num128 > md5_right->num128 )

        return true ;

    return false ;
}

////////////////////////////////////////////////////////////////////////////////

bool md5_less_or_equal( MD5 *md5_left, MD5 *md5_right )
{
    if ( ! memcmp( (void *)md5_left, (void *)md5_right, sizeof( MD5)))

        return true;

    return md5_less( md5_left, md5_right ) ;
}

////////////////////////////////////////////////////////////////////////////////

bool md5_great_or_equal( MD5 *md5_left, MD5 *md5_right )
{
    if ( ! memcmp((void *)md5_left, (void *)md5_right, sizeof( MD5 )))

        return true;

    return md5_great( md5_left, md5_right ) ;
}

////////////////////////////////////////////////////////////////////////////////

bool md5_not_equal( MD5 *md5_left, MD5 *md5_right )
{
    return memcmp((void *)md5_left, (void *)md5_right, sizeof( MD5 ));
}

////////////////////////////////////////////////////////////////////////////////

char *md5_to_hex( MD5 *md5 )
{
    char *ret_buff = (char *)calloc( 1, 33 );

    if ( ret_buff )
    {
        snprintf( ret_buff,
                  33,
                  "%016" PRIX64 "%016" PRIX64,
                  md5->num64.second,
                  md5->num64.first );
    }

    return ret_buff ;
}

////////////////////////////////////////////////////////////////////////////////

md5_search_ret md5_search( MD5_CONTEXT *md5_ctx, char *hex_str )
{
    md5_search_ret ret = MD5_SEARCH_ERROR ;

    if ( ! regexec( &md5_ctx->preg, (const char *)hex_str, 0, NULL, 0 ) )
    {
        MD5 *md5_arg = md5_from_hex( hex_str );

        if ( md5_arg )
        {
            MD5 *md5_first = md5_ctx->md5_first ;
            MD5 *md5_last  = md5_ctx->md5_last ;
            MD5 *md5_mid ;

            ret = MD5_SEARCH_NOT_FOUND;

            while( md5_first <= md5_last )
            {
                md5_mid = md5_first + ( md5_last - md5_first ) / 2;

                if ( md5_is_equal( md5_arg, md5_mid ) )
                {
                    ret = MD5_SEARCH_FOUND ;
                    break;
                }

                if ( md5_less( md5_arg, md5_mid ) )

                    md5_last = --md5_mid ;

                else

                    md5_first = ++md5_mid ;
            }

            free( md5_arg );
        }
    }

    return ret ; 
}

////////////////////////////////////////////////////////////////////////////////

bool md5_load_buffer( MD5_CONTEXT *md5_ctx, int file_hnd, off64_t *buff_size)
{
    if ( *buff_size && ( ! ( *buff_size % sizeof( MD5 ) ) ) )
    {
        md5_ctx->buffer = (unsigned char *)malloc( *buff_size );

        if ( md5_ctx->buffer )
        {
            if ( read( file_hnd, (void *)md5_ctx->buffer, *buff_size ) ==
                     *buff_size )
            {
                md5_ctx->md5_first = (MD5 *)( md5_ctx->buffer );

                md5_ctx->md5_last  = (MD5 *)( md5_ctx->buffer + *buff_size -
                                                  sizeof(MD5)) ;

                return true ;
            }

            free( md5_ctx->buffer  );

            fprintf(stderr,"ERROR!! Unable to read file");
        }
    }
    else
        fprintf( stderr,"ERROR!! File size %ld not divisible by 32!!\n",
                 *buff_size );

    return false ;
}

////////////////////////////////////////////////////////////////////////////////

bool md5_load_file( MD5_CONTEXT *md5_ctx, const char *file_path_src )
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
            ret = md5_load_buffer( md5_ctx, file_hnd, &statbuf.st_size );

            if ( ret )
                printf("MD5 hashes loaded in memory: %ld\n", statbuf.st_size/16 );
        }

        close( file_hnd );
    }
    else

        fprintf( stderr,"ERROR!! Unable to open file %s\n",file_path_src );

    return ret ;
}

////////////////////////////////////////////////////////////////////////////////

MD5_CONTEXT *md5_init_ctx( const char *file_path_src )
{
    MD5_CONTEXT *ret_ctx = (MD5_CONTEXT *)calloc( 1, sizeof( MD5_CONTEXT ) );

    if ( ret_ctx )
    {
        if ( ! regcomp( &ret_ctx->preg, "^[0-9A-Fa-f]\\{32\\}$", 0 ) )
        {
            if ( md5_load_file( ret_ctx, file_path_src ) )
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

void md5_free_buffer( MD5_CONTEXT *ctx )
{
    if ( ctx )
    {
        if ( ctx->buffer )
        {
            free( ctx->buffer );
            ctx->buffer = NULL ;
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

void md5_fini_ctx( MD5_CONTEXT *ctx )
{
    if ( ctx )
    {
        md5_free_buffer( ctx );

        if ( ctx->preg.allocated )
            regfree( &ctx->preg );

        free( ctx );
    }
}

