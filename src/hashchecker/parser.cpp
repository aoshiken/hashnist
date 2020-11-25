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

#include "context.h"


static struct option long_options[] =
{
    { "daemonize",      no_argument,       NULL, 'D' },
    { "debug",          no_argument,       NULL, 'd' },
    { "help",           no_argument,       NULL, 'h' },
    { "hostname",       optional_argument, NULL, 'H' },
    { "input-file",     required_argument, NULL, 'i' },
    { "max-clients",    optional_argument, NULL, 'M' },
    { "port",           optional_argument, NULL, 'p' },
    { "socket-timeout", required_argument, NULL, 't' },
    { "version",        no_argument,       NULL, 'V' },
    { NULL,             0,                 NULL, 0   }
};

///////////////////////////////////////////////////////////////////////////////

char *check_hashes_file( char *file_path )
{
    char *real_file_path = realpath( file_path, NULL );

    if ( real_file_path )
    {
        struct stat64 statbuf ;

        if ( ! stat64( real_file_path, &statbuf) )
        {
            if ( statbuf.st_size && ( ! ( statbuf.st_size % sizeof( SHA_256 ) ) ) )

                return real_file_path ;

            else
                fprintf( stderr, "\nERROR!! Invalid file size %ld for hashes file %s!!\n\n", statbuf.st_size,
                          real_file_path );
        }
        else
            fprintf(stderr, "\nERROR!! Invalid or nonexistant hashes file %s!!\n\n", real_file_path );

        free( real_file_path );

        real_file_path = NULL ;
    }
    else
        fprintf(stderr, "\nERROR!! Invalid path %s!!\n\n", file_path );

    return real_file_path ;
}

///////////////////////////////////////////////////////////////////////////////

int get_ip4_address( char *ip_str )
{
    int ip4 ;

    if ( ! inet_pton( AF_INET, ip_str, &ip4) )
        ip4 = -1;
    printf("IP ES 0x%X\n", ip4);
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

    fprintf(stderr,"\nRead an input file that contains SHA256 hashes in binary format and start a TCP\n");
    fprintf(stderr,"server ready for searching hashes with reasonable speed.\n");
    fprintf(stderr,"The source file must be created by the 'binaryze' utility, the SHA256 hashes\n");
    fprintf(stderr,"comes from the NIST National Software Reference Library catalog.\n\n");
    fprintf(stderr,"Usage:\n");
    fprintf(stderr,"    %s [-d] [-D] [-M num] [-p port] [-H ip4_addr] {-i file_path} [-t secs] [-V]\n\n", cur );
    fprintf(stderr,"Options:\n");
    fprintf(stderr,"    -d, --debug                  Enable debug logs\n");
    fprintf(stderr,"    -D, --daemonize              Daemonize server\n");
    fprintf(stderr,"    -h, --help                   Show this help screen\n"); 
    fprintf(stderr,"    -H, --hostname=ip4_addr      Bind server to this IPv4 address (default: 127.0.0.1)\n");
    fprintf(stderr,"    -M, --max-clients=num        Max clients supported by the server (default: %d)\n", CTX_DFL_CLIENTS);
    fprintf(stderr,"    -p, --port=port              Bind server to this TCP port (default: %d)\n", CTX_DFL_TCP_PORT);
    fprintf(stderr,"    -i, --input-file=file_path   Input file with SHA256 hashes in binary format\n");
    fprintf(stderr,"    -t, --socket-timeout=secs    Socket timeout in seconds (default: %d)\n", CTX_DFL_TIMEOUT);
    fprintf(stderr,"    -V, --version                Show program version\n\n" );

    exit( EXIT_FAILURE );
}

///////////////////////////////////////////////////////////////////////////////

bool parse_options( int argc, char **argv, CONTEXT *ctx )
{
    int ch ;

    if ( argc == 1)
        show_help(argv[0]);

    while ( (ch = getopt_long( argc, argv, "dDhH:M:p:i:t:V", long_options, NULL)) != -1)
    {
        switch( ch )
        {
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
                ctx->hashes_file = check_hashes_file( optarg );
                if ( ! ctx->hashes_file )
                    exit( EXIT_FAILURE );
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
        fprintf( stderr, "\nERROR!! I need the path of the hashes file (option -r)!\n\n");
        return false ;
    }

    if ( ctx->ip == 0xffffffff )
    {
        fprintf( stderr, "\nERROR!! Invalid IP4 addres specified (option -H)!\n\n");
        return false ;
    }

    return true;
}
