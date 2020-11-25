#define _REENTRANT

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "context.h"
#include "parser.h"
#include "server.h"


///////////////////////////////////////////////////////////////////////////////

static void make_daemon( void )
{
    pid_t pid = fork();

    if ( pid < 0 )

        exit( EXIT_FAILURE );

    if ( pid > 0 )

        exit( EXIT_SUCCESS );

    if ( setsid() == -1 )

        exit( EXIT_FAILURE );

    printf("Daemonized server started...\n");

    signal(SIGHUP, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    chdir( "/tmp" );
}


///////////////////////////////////////////////////////////////////////////////
//
//
//
///////////////////////////////////////////////////////////////////////////////


int main( int argc, char **argv )
{
    CONTEXT *ctx = context_init();

    if ( ctx )
    {
        if ( parse_options( argc, argv, ctx ) )
        {
            if ( ctx->daemonize )
            {
                make_daemon();

                setvbuf( stdout, NULL, _IONBF, 0);
                setvbuf( stderr, NULL, _IONBF, 0);
            }

            server_start( ctx );
        }

        context_fini( ctx );
    }

    exit( EXIT_SUCCESS );
}
