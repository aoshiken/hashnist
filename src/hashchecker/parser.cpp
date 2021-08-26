#define _REENTRANT

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>

#include "../common/md5.h"
#include "context.h"


static struct option long_options[] =
{
    { "daemonize",      no_argument,       NULL, 'D' },
    { "debug",          no_argument,       NULL, 'd' },
    { "help",           no_argument,       NULL, 'h' },
    { "hostname",       optional_argument, NULL, 'H' },
    { "input-file",     required_argument, NULL, 'i' },
    { "use-md5",        no_argument,       NULL, '5' },
    { "max-clients",    optional_argument, NULL, 'M' },
    { "port",           optional_argument, NULL, 'p' },
    { "socket-timeout", required_argument, NULL, 't' },
    { "version",        no_argument,       NULL, 'V' },
    { NULL,             0,                 NULL, 0   }
};

///////////////////////////////////////////////////////////////////////////////

bool check_hashes_file( CONTEXT *ctx, const char *file_path )
{
    if ( file_path )
    {
        struct stat64 statbuf ;

        if ( ! stat64( file_path, &statbuf) )
        {
            if ( ( statbuf.st_size >= (long)( ctx->item_size / 2 ) &&
                 ( ! ( statbuf.st_size % ( ctx->item_size / 2 ) ) ) ) )

                return true ;

            fprintf( stderr, "\nERROR!! Invalid file size %ld for hashes file %s!!\n\n",
                     statbuf.st_size, file_path );
        }
        else
            fprintf(stderr, "\nERROR!! Invalid or nonexistant hashes file %s!!\n\n", file_path );

    }
    else
        fprintf(stderr, "\nERROR!! Invalid path %s!!\n\n", file_path );

    return false ;
}

///////////////////////////////////////////////////////////////////////////////

int get_ip4_address( char *ip_str )
{
    int ip4 ;

    if ( ! inet_pton( AF_INET, ip_str, &ip4) )
        ip4 = -1;

    return ip4;
}

///////////////////////////////////////////////////////////////////////////////

void show_help( char *progname )
{
    const char *cur = strrchr( progname, '/' );

    if ( ! cur )
        cur = progname;
    else
        cur++;

    fprintf(stderr,"\nRead an input file that contains SHA256 or MD5 hashes in binary format and start a TCP\n");
    fprintf(stderr,"server ready for searching hashes with reasonable speed.\n");
    fprintf(stderr,"The input file must be created by the 'binaryze' utility, the hashes in text format\n");
    fprintf(stderr,"comes from the NIST National Software Reference Library catalog.\n\n");
    fprintf(stderr,"Usage:\n");
    fprintf(stderr,"    %s [-d] [-D] [-M num] [-p port] [-H ip4_addr] {-i file_path} [-t secs] [-V] [-5]\n\n", cur );
    fprintf(stderr,"Options:\n");
    fprintf(stderr,"    -5, --use-md5               Enable MD5 hashes (default is disabled, using SHA256 hashes)\n");
    fprintf(stderr,"    -d, --debug                 Enable debug logs\n");
    fprintf(stderr,"    -D, --daemonize             Daemonize server\n");
    fprintf(stderr,"    -h, --help                  Show this help screen\n");
    fprintf(stderr,"    -H, --hostname=ip4_addr     Bind server to this IPv4 address (default: 127.0.0.1)\n");
    fprintf(stderr,"    -M, --max-clients=num       Max clients supported by the server (default: %d)\n", CTX_DFL_CLIENTS);
    fprintf(stderr,"    -p, --port=port             Bind server to this TCP port (default: %d)\n", CTX_DFL_TCP_PORT);
    fprintf(stderr,"    -i, --input-file=file_path  Input file with hashes in binary format\n");
    fprintf(stderr,"    -t, --socket-timeout=secs   Socket timeout in seconds (default: %d)\n", CTX_DFL_TIMEOUT);
    fprintf(stderr,"    -V, --version               Show program version\n\n" );

    exit( EXIT_FAILURE );
}

///////////////////////////////////////////////////////////////////////////////

bool parse_options( int argc, char **argv, CONTEXT *ctx )
{
    int ch ;

    if ( argc == 1)
        show_help(argv[0]);

    while ( (ch = getopt_long( argc, argv, "5dDhH:M:p:i:t:V", long_options, NULL)) != -1)
    {
        switch( ch )
        {
            case '5':
                ctx->use_md5          = true ;
                ctx->item_size        = 32;
                ctx->hash_load_file   = md5_load_file;
                ctx->hash_free_buffer = md5_free_buffer;
                ctx->hash_search      = md5_search;
                ctx->hash_init_ctx    = md5_init_ctx ;
                ctx->hash_fini_ctx    = md5_fini_ctx ;
                break;
            case 'D':
                ctx->daemonize = true ;
                break;
            case 'd':
                ctx->debug = true ;
                break;
            case 'H':
                ctx->ip = get_ip4_address( optarg );
                break;
            case 'h':
                show_help( argv[0] );
                break;
            case 'M':
                ctx->max_clients = atoi( optarg );
                break;
            case 'p':
                ctx->port = atoi( optarg );
                break;
            case 'i':
                ctx->hashes_file = realpath( optarg, NULL );
                if ( ! ctx->hashes_file )
                {
                    fprintf(stderr, "\nERROR!! Invalid input file '%s'!\n\n",optarg);
                    exit( EXIT_FAILURE );
                }
                break;
            case 't':
                ctx->socket_timeout = atoi( optarg );
                break;
            case 'V':
                printf("Version " PACKAGE_VERSION "\n");
                exit( EXIT_FAILURE );
                break;

            default:
                abort();
        }

    }

    if ( ! ctx->hashes_file )
    {
        fprintf( stderr, "\nERROR!! I need the path of the hashes file (option -i)!\n\n");
        return false ;
    }

    if ( ! check_hashes_file( ctx, ctx->hashes_file ) )
    {
        free( (void *)ctx->hashes_file );
        ctx->hashes_file = NULL ;
        return false;
    }

    if ( ctx->ip == 0xffffffff )
    {
        fprintf( stderr, "\nERROR!! Invalid IP4 addres specified (option -H)!\n\n");
        return false ;
    }

    return true;
}
