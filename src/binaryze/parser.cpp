#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>

#include "context.h"


static struct option long_options[] =
{
    { "help",        no_argument,       NULL, 'h' },
    { "input-file",  required_argument, NULL, 'i' },
    { "output-file", required_argument, NULL, 'o' },
    { "version",     no_argument,       NULL, 'V' },
    { NULL,          0,                 NULL, 0   }
};

///////////////////////////////////////////////////////////////////////////////

bool check_hashes_file( char *file_path )
{
    struct stat64 statbuf ;

    if ( ! stat64( file_path, &statbuf) )
    {
        if ( statbuf.st_size && ( ! ( statbuf.st_size % 64 ) ) )

            return true ;

        fprintf( stderr, "\nERROR!! Invalid file size %ld for hashes file %s!!\n\n", statbuf.st_size,
                      file_path );
    }
    else
        fprintf(stderr, "\nERROR!! Invalid or nonexistant hashes file %s!!\n\n", file_path );

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

    fprintf(stderr, "\nGenerate a file of SHA256 hashes in binary format according to a source file\n");
    fprintf(stderr, "with JUST ONE LINE of ordered SHA256 hashes in text format (all of the hashes\n");
    fprintf(stderr, "are stored in JUST ONE LINE with no blanks between).\n");
    fprintf(stderr, "The SHA256 hashes of the source text file comes from the NIST National Software\n");
    fprintf(stderr, "Reference Library catalog.\n\n");
    fprintf(stderr, "Usage:\n    %s [-h] [-V] {-i file_path} {-o file_path}\n", cur);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "    -h, --help                  This help screen\n");
    fprintf(stderr, "    -i --input-file  file_path  Input file with ordered SHA256 hashes in text format\n");
    fprintf(stderr, "    -o --output-file file_path  Output file with SHA256 hashes in binary format\n");
    fprintf(stderr, "    -V, --version               Show file version\n\n");
  
    exit( EXIT_FAILURE );
}

///////////////////////////////////////////////////////////////////////////////

bool parse_options( int argc, char **argv, CONTEXT *ctx )
{
    int ch ;

    if ( argc == 1)
        show_help(argv[0]);

    while ( (ch = getopt_long( argc, argv, "hi:o:V", long_options, NULL)) != -1)
    {
        switch( ch )
        {
            case 'h':
                show_help( argv[0] );
                break;
            case 'i':
                if ( check_hashes_file( optarg ) )
                    ctx->hash_txt_path = optarg ;
                else
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

    if ( ! ctx->hash_bin_path )
    {
        fprintf( stderr, "\nERROR!! I need the path of the output file (option -o)!\n\n");
        exit( EXIT_FAILURE );
    }

    return true;
}
