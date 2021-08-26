#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <regex.h>

#include "../common/md5.h"
#include "context.h"

static struct option long_options[] =
{
    { "help",        no_argument,       NULL, 'h' },
    { "input-file",  required_argument, NULL, 'i' },
    { "output-file", required_argument, NULL, 'o' },
    { "use-md5",     no_argument,       NULL, '5' },
    { "version",     no_argument,       NULL, 'V' },
    { NULL,          0,                 NULL, 0   }
};

///////////////////////////////////////////////////////////////////////////////

bool check_hashes_file( CONTEXT *ctx, const char *file_path )
{
    struct stat64 statbuf ;

    if ( ! stat64( file_path, &statbuf) )
    {
        if ( ( statbuf.st_size >= ctx->hash_str_size ) &&
             ( ! ( statbuf.st_size % ctx->hash_str_size ) ) )

            return true ;

        fprintf( stderr, "\nERROR!! Invalid file size %ld for hashes file %s!!\n\n",
                 statbuf.st_size, file_path );
    }
    else
        fprintf(stderr, "\nERROR!! Invalid or nonexistant hashes file %s!!\n\n",
                file_path );

    return false ;
}

///////////////////////////////////////////////////////////////////////////////

void show_help( char *progname )
{
    const char *cur = strrchr( progname, '/' );

    if ( ! cur )
        cur = progname;
    else
        cur++;

    fprintf(stderr, "\nGenerate a file of MD5/SHA256 hashes in binary format according to a source file\n");
    fprintf(stderr, "with JUST ONE LINE of ordered hashes in text format (all of the hashes\n");
    fprintf(stderr, "are stored in JUST ONE LINE with no blanks between).\n");
    fprintf(stderr, "The hashes of the source text file comes from the NIST National Software\n");
    fprintf(stderr, "Reference Library catalog.\n\n");
    fprintf(stderr, "Usage:\n    %s [-h] [-V] [-5] {-i file_path} {-o file_path}\n", cur);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "    -5, --use-md5               Use MD5 hashes instead of SHA256\n");
    fprintf(stderr, "    -h, --help                  This help screen\n");
    fprintf(stderr, "    -i --input-file  file_path  Input file with ordered hashes in text format\n");
    fprintf(stderr, "    -o --output-file file_path  Output file with hashes in binary format\n");
    fprintf(stderr, "    -V, --version               Show file version\n\n");

    exit( EXIT_FAILURE );
}

///////////////////////////////////////////////////////////////////////////////

bool parse_options( int argc, char **argv, CONTEXT *ctx )
{
    int ch ;

    if ( argc == 1)
        show_help(argv[0]);

    while ( (ch = getopt_long( argc, argv, "5hi:o:V", long_options, NULL)) != -1)
    {
        switch( ch )
        {
            case '5':
                regfree( &ctx->preg );
                if ( regcomp( &ctx->preg, "^[0-9A-Fa-f]\\{32\\}$", 0 ) )
                {
                    fprintf(stderr,"Unable to compile regex!!\n");
                    exit( EXIT_FAILURE );
                }
                ctx->use_md5       = true;
                ctx->hash_size     = 16 ;
                ctx->hash_str_size = 32 ;
                ctx->hash_from_hex = md5_from_hex_allocated ;
                break;
            case 'h':
                show_help( argv[0] );
                break;
            case 'i':
                ctx->hash_txt_path = realpath( optarg, NULL ) ;
                if ( ! ctx->hash_txt_path )
                    exit( EXIT_FAILURE );
                break;
            case 'o':
                ctx->hash_bin_path = optarg ;
                break;
            case 'V':
                printf("Version " PACKAGE_VERSION "\n");
                exit( EXIT_FAILURE );
                break;

            default:
                abort();
        }

    }

    if ( ! ctx->hash_txt_path )
    {
        fprintf( stderr, "\nERROR!! I need the path of the input file (option -i)!\n\n");
        exit( EXIT_FAILURE );
    }

    if ( ! check_hashes_file( ctx, ctx->hash_txt_path ) )
    {
        free( (void *)ctx->hash_txt_path );
        ctx->hash_txt_path = NULL ;
        return false;
    }

    if ( ! ctx->hash_bin_path )
    {
        fprintf( stderr, "\nERROR!! I need the path of the output file (option -o)!\n\n");
        exit( EXIT_FAILURE );
    }

    return true;
}
