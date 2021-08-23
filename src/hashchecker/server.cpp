#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

#include "context.h"
#include "../common/util.h"


typedef struct _SIGNAL_CONTEXT {
    struct event_base *server_base ; // Libevent main base
    CONTEXT *ctx ;                   // Main app context
    struct event *ev_sigint ;        // Event for SIGINT
    struct event *ev_sigterm ;       // Event for SIGTERM
    struct event *ev_sighup ;        // Event for SIGHUP
} SIGNAL_CONTEXT ;


///////////////////////////////////////////////////////////////////////////////

static void sigterm_handler( int signal,
                             __attribute__((unused))short events,
                             void *arg )
{
    SIGNAL_CONTEXT *signal_ctx = (SIGNAL_CONTEXT *)arg;

    fprintf(stderr, "\nReceived signal %s. Exiting...\n", strsignal( signal ) );

    event_base_loopexit( signal_ctx->server_base, NULL );
}

///////////////////////////////////////////////////////////////////////////////

static bool reload_hashes( CONTEXT *ctx )
{
    printf( "Reloading %s hashes file in memory...\n",
            ctx->use_md5 ? "MD5" : "SHA256");

    (*ctx->hash_free_buffer)( ctx->hash_ctx );

    return (*ctx->hash_load_file)( ctx->hash_ctx, ctx->hashes_file );
}

///////////////////////////////////////////////////////////////////////////////

static bool needs_reload( CONTEXT *ctx )
{
    time_t modif_time = util_get_modif_time( ctx->hashes_file );

    if ( modif_time != ctx->modif_time )
    {
        ctx->modif_time = modif_time ;

        return true;
    }

    printf( "Hashes file [%s] seems to remains untouched...\n",
             ctx->hashes_file );

    return false;
}

///////////////////////////////////////////////////////////////////////////////

static void sighup_handler( __attribute__((unused))int signal,
                            __attribute__((unused))short events,
                            void *arg )
{
    SIGNAL_CONTEXT *signal_ctx = (SIGNAL_CONTEXT *)arg;

    printf( "\nReceived signal SIGHUP...\n" );

    if ( needs_reload( signal_ctx->ctx ) )
    {
        if ( reload_hashes( signal_ctx->ctx ) )
        {
            printf("Hashes reloaded OK\n");
        }
        else
        {
            fprintf( stderr,"ERROR Reloading hashes!! Exiting...\n");

            event_base_loopexit( signal_ctx->server_base, NULL );
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

static void net_event_callback( struct bufferevent *buff_ev,
                                short events,
                                __attribute__((unused))void *arg )
{
    if ( events & ( BEV_EVENT_TIMEOUT | BEV_EVENT_EOF | BEV_EVENT_ERROR ) )
    {
        evutil_socket_t sock = bufferevent_getfd( buff_ev );

        if ( events & BEV_EVENT_EOF )
            printf("sock[%d] DISCONNECTED\n", sock);

        if ( events & BEV_EVENT_TIMEOUT )
            printf("sock[%d] TIMEOUT\n", sock);

        if ( events & BEV_EVENT_ERROR )
            fprintf( stderr, "sock[%d] ERROR [%s]\n", sock,
                   evutil_socket_error_to_string( EVUTIL_SOCKET_ERROR() ) );

        bufferevent_free( buff_ev );
    }
}

///////////////////////////////////////////////////////////////////////////////

static void net_read_callback( struct bufferevent *buff_ev, void *arg )
{
    CONTEXT *ctx           = (CONTEXT *)arg ;
    struct evbuffer *input = bufferevent_get_input( buff_ev );
    size_t buff_input_len  = evbuffer_get_length( input );

    if ( buff_input_len >= ctx->item_size )
    {
        char *buff_read = (char *)malloc( ctx->item_size + 1 );

        if ( buff_read )
        {
            while ( buff_input_len >= ctx->item_size )
            {
                size_t bytes_read = bufferevent_read( buff_ev, buff_read,
                                                      ctx->item_size );

                if ( bytes_read == ctx->item_size )
                {
                    buff_read[ ctx->item_size ] = 0 ;

                    hash_search_ret ret = (*ctx->hash_search)( ctx->hash_ctx, buff_read );

                    if ( ret == HASH_SEARCH_NOT_FOUND )
                        buff_read[ ctx->item_size ] = 1;
                    else
                    if ( ret == HASH_SEARCH_ERROR )
                        buff_read[ ctx->item_size ] = 2;

                    bufferevent_write( buff_ev, buff_read, ctx->item_size + 1 );
                }
                else
                {
                    evutil_socket_t sock = bufferevent_getfd( buff_ev );

                    fprintf( stderr, "ERROR!! sock [%d] read %ld != ITEM is %ld!!\n",
                            sock, bytes_read, ctx->item_size );
                    break;
                }

                buff_input_len = evbuffer_get_length( input );
            }
            free( buff_read );
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

static void listen_cb( struct evconnlistener *listener,
                       evutil_socket_t fd,
                       __attribute__((unused)) struct sockaddr *sa,
                       __attribute__((unused)) int socklen,
                       void *arg )
{
    struct event_base *base = evconnlistener_get_base( listener );
    struct bufferevent *buff_ev;

    buff_ev = bufferevent_socket_new( base, fd, BEV_OPT_CLOSE_ON_FREE );

    if (buff_ev)
    {
        CONTEXT *ctx = (CONTEXT *)arg ;

        evutil_socket_t sock = bufferevent_getfd( buff_ev );

        if ( sock != -1 )
            printf("socket %d CONNECTED\n", sock );

        bufferevent_setwatermark( buff_ev, EV_READ, ctx->item_size, 0 );

        bufferevent_enable( buff_ev, EV_READ|EV_WRITE);

        if ( ctx->socket_timeout )
        {
            struct timeval tv = { ctx->socket_timeout, 0 };

            bufferevent_set_timeouts( buff_ev, &tv, &tv );
        }

        bufferevent_setcb( buff_ev, net_read_callback, NULL, net_event_callback,
                           arg );
    }
    else
        fprintf( stderr, "bufferevent_socket_new() failed\n");
}

///////////////////////////////////////////////////////////////////////////////

struct evconnlistener *server_make_listener( CONTEXT *ctx,
                                             struct event_base *server_base )
{
    struct sockaddr_in server_addr ;

    memset( (void *)&server_addr, 0, sizeof(struct sockaddr_in) );

    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = ctx->ip;
    server_addr.sin_port        = htons( ctx->port );

    return evconnlistener_new_bind( server_base,
                                    listen_cb,
                                    (void *)ctx,
                                    LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
                                    -1,
                                    (struct sockaddr *)&server_addr,
                                    sizeof( server_addr ) );
}

///////////////////////////////////////////////////////////////////////////////

bool setup_signals( SIGNAL_CONTEXT *signal_ctx )
{
    signal_ctx->ev_sigint = evsignal_new( signal_ctx->server_base,
                                          SIGINT,
                                          sigterm_handler, signal_ctx );
    if ( signal_ctx->ev_sigint )
    {
        evsignal_add( signal_ctx->ev_sigint, NULL );

        signal_ctx->ev_sigterm = evsignal_new( signal_ctx->server_base,
                                               SIGTERM,
                                               sigterm_handler, signal_ctx );
        if ( signal_ctx->ev_sigterm )
        {
            evsignal_add( signal_ctx->ev_sigterm, NULL );

            signal_ctx->ev_sighup = evsignal_new( signal_ctx->server_base,
                                                  SIGHUP,
                                                  sighup_handler, signal_ctx );
            if ( signal_ctx->ev_sighup )
            {
                evsignal_add( signal_ctx->ev_sighup, NULL );

                return true;
            }

            event_free( signal_ctx->ev_sigterm );
        }

        event_free( signal_ctx->ev_sigint );
    }

    return false;
}

///////////////////////////////////////////////////////////////////////////////

void server_loop( CONTEXT *ctx, struct event_base *server_base,
                  struct evconnlistener *listener )
{
    SIGNAL_CONTEXT signal_ctx;

    printf("Server started at port %d...\n", ctx->port );

    signal_ctx.ctx         = ctx ;
    signal_ctx.server_base = server_base ;

    if ( setup_signals( &signal_ctx ) )
    {
        event_base_dispatch( server_base );

        event_free( signal_ctx.ev_sigint );
        event_free( signal_ctx.ev_sigterm );
        event_free( signal_ctx.ev_sighup );
    }
    else
    {
        fprintf(stderr, "Unable to setup signals. Exiting...\n");
    }

    evconnlistener_free( listener );

    event_base_free( server_base );

    printf("Server finished\n");
}

///////////////////////////////////////////////////////////////////////////////

bool server_start( CONTEXT *ctx )
{
    bool ret = false ;
    struct event_config *config;
    struct event_base *server_base;

    //event_enable_debug_logging(-1);

    config = event_config_new();

    event_config_set_flag( config, EVENT_BASE_FLAG_NO_CACHE_TIME );

    server_base = event_base_new_with_config( config );

    if (server_base)
    {
        if ( ctx->use_md5 )
            printf("Loading MD5 context...\n");
        else
            printf("Loading SHA256 context...\n");

        ctx->hash_ctx = (*ctx->hash_init_ctx)( ctx->hashes_file );

        if ( ctx->hash_ctx )
        {
            ctx->modif_time = util_get_modif_time( ctx->hashes_file );

            struct evconnlistener *listener = server_make_listener( ctx,
                                                                    server_base );
            if ( listener )
            {
                server_loop( ctx, server_base, listener );

                ret = true ;
            }
            else
                fprintf( stderr, "evconnlistener_new_bind() failed\n");

           (*ctx->hash_fini_ctx)( ctx->hash_ctx );
        }
    }
    else
        fprintf( stderr, "event_base_new() failed\n");

    return ret ;
}
