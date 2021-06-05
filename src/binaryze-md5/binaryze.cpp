#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <regex.h>
#include <fcntl.h>

#include "util.h"
#include "md5.h"
#include "context.h"
#include "parser.h"


////////////////////////////////////////////////////////////////////////////////

static inline bool parse_buffer( CONTEXT *ctx )
{
    char *hash_begin = ctx->read_buffer ;
    char *buff_end   = ctx->read_buffer + ctx->bytes_read ;
    char *hash_end   = ctx->read_buffer + 32 ;
    char aux         = *hash_end ;
    *hash_end        = 0;

    while ( hash_end <= buff_end )
    {
        if ( ! regexec( &ctx->preg, (const char *)hash_begin, 0, NULL, 0 ) )
        {
            if ( md5_from_hex_allocated( hash_begin, &ctx->hash_obj ) )
            {
                if ( write( ctx->file_dst, (const void *)&ctx->hash_obj,
                            sizeof( MD5 ) ) != sizeof( MD5 ) )
                {
                    fprintf( stderr, "ERROR!! Iinvalid write!!\n");

                    return false;
                }
            }
        }
        else
            fprintf( stderr, "ERROR!! Invalid hash [%s]\n", hash_begin );

        *hash_end  = aux ;
        hash_begin = hash_end ;
        hash_end  += 32;

        if ( hash_end <= buff_end )
        {
            aux        = *hash_end ;
            *hash_end  = 0;
        }
    }

    return true ;
}

////////////////////////////////////////////////////////////////////////////////

bool treat_read_file( CONTEXT *ctx )
{
    bool ret = true ;

    ctx->bytes_read = read( ctx->file_src, ctx->read_buffer, BUFFER_SIZE );

    while( ( ctx->bytes_read > 0 ) && ret )
    {
        ret = parse_buffer( ctx );

        if ( ret )
        {
            ctx->bytes_read = read( ctx->file_src, ctx->read_buffer, BUFFER_SIZE );
        }
    }

    return ret;
}

////////////////////////////////////////////////////////////////////////////////

bool open_files( CONTEXT *ctx )
{
    ctx->file_src = open( ctx->hash_txt_path, O_RDONLY );

    if ( ctx->file_src != -1 )
    {
        posix_fadvise( ctx->file_src, 0, 0, POSIX_FADV_SEQUENTIAL );

        ctx->file_dst = creat( ctx->hash_bin_path,
                                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );

        if ( ctx->file_dst != -1 )
        {
            posix_fadvise( ctx->file_dst, 0, 0, POSIX_FADV_SEQUENTIAL );

            return true ;
        }

        close( ctx->file_src );
    }

    return false;
}

////////////////////////////////////////////////////////////////////////////////

CONTEXT *context_init( void )
{
    CONTEXT *ret_ctx = (CONTEXT *)calloc( 1, sizeof( CONTEXT ) );

    if ( ret_ctx )
    {
        ret_ctx->file_src = -1 ;
        ret_ctx->file_dst = -1 ;

        if ( ! regcomp( &ret_ctx->preg, "^[0-9A-Fa-f]\\{32\\}$", 0 ) )

            return ret_ctx;

        free( ret_ctx );
    }

    return NULL;
}

////////////////////////////////////////////////////////////////////////////////

void close_files( CONTEXT *ctx )
{
    if ( ctx->file_dst != -1 )
        close( ctx->file_dst );

    if ( ctx->file_src != -1 )
        close( ctx->file_src );
}

////////////////////////////////////////////////////////////////////////////////

void context_fini( CONTEXT *ctx )
{
    if ( ctx )
    {
        regfree( &ctx->preg );

        free( ctx );
    }
}

///////////////////////////////////////////////////////////////////////////////

int main( int argc, char **argv )
{
    int ret_code = EXIT_FAILURE ;

    CONTEXT *ctx = context_init();

    if ( ctx )
    {
        if ( parse_options( argc, argv, ctx ) )
        {
            if ( open_files( ctx ) )
            {
                if ( treat_read_file( ctx ) )

                    ret_code = EXIT_SUCCESS ;

                close_files( ctx );
            }
        }

        context_fini( ctx );
    }

    exit( ret_code );
}
