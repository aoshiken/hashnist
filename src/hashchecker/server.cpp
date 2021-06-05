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

enum hash_search_ret
{
    HASH_SEARCH_FOUND     = 0,
    HASH_SEARCH_NOT_FOUND = 1,
    HASH_SEARCH_ERROR     = 2
};

static struct event_base *g_server_base = NULL ;


///////////////////////////////////////////////////////////////////////////////

static void signal_handler( int signal )
{
    fprintf(stderr, "\nReceived signal %s. Exiting...\n", strsignal( signal ) );

    if ( g_server_base )
    {
        event_base_loopexit( g_server_base, NULL );
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

static hash_search_ret hash_search( CONTEXT *ctx, char *buff_read )
{
    hash_search_ret ret = HASH_SEARCH_ERROR ;

    if ( ctx->use_md5 )
    {
        md5_search_ret md5_ret = md5_search( ctx->md5_ctx, buff_read );

        switch( md5_ret )
        {
            case MD5_SEARCH_FOUND:
                ret = HASH_SEARCH_FOUND;
                break;
            case MD5_SEARCH_NOT_FOUND:
                ret = HASH_SEARCH_NOT_FOUND;
                break;
            case MD5_SEARCH_ERROR:
                ret = HASH_SEARCH_ERROR;
                break;
        }
    }
    else
    {
        sha_search_ret sha_ret = sha256_search( ctx->sha_ctx, buff_read );

        switch( sha_ret )
        {
            case SHA_SEARCH_FOUND:
                ret = HASH_SEARCH_FOUND;
                break;
            case SHA_SEARCH_NOT_FOUND:
                ret = HASH_SEARCH_NOT_FOUND;
                break;
            case SHA_SEARCH_ERROR:
                ret = HASH_SEARCH_ERROR;
                break;
        }
    }

    return ret;
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
                size_t bytes_read = bufferevent_read( buff_ev, buff_read, ctx->item_size );

                if ( bytes_read == ctx->item_size )
                {
                    buff_read[ ctx->item_size ] = 0 ;

                    hash_search_ret ret = hash_search( ctx, buff_read );

                    // 0 == HASH_SEARCH_FOUND
                    // 1 == HASH_SEARCH_NOT_FOUND
                    // 2 == HASH_SEARCH_ERROR

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

        bufferevent_setcb( buff_ev, net_read_callback, NULL, net_event_callback, arg );
    }
    else
        fprintf( stderr, "bufferevent_socket_new() failed\n");
}

///////////////////////////////////////////////////////////////////////////////

void server_signal_handlers( void )
{
     sigset_t sigset;
     struct sigaction act ;

     sigemptyset(&sigset);

     act.sa_handler = signal_handler,
     act.sa_mask    = sigset,
     act.sa_flags   = SA_RESTART,

     sigaction( SIGINT,  &act, NULL );
     sigaction( SIGTERM, &act, NULL );
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

void server_loop( CONTEXT *ctx, struct event_base *server_base,
                  struct evconnlistener *listener )
{
    printf("Server started at port %d...\n", ctx->port );

    g_server_base = server_base ;

    server_signal_handlers();

    event_base_dispatch( server_base );

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
        {
            printf("Loading MD5 context...\n");
            ctx->md5_ctx = md5_init_ctx( ctx->hashes_file );
        }
        else
        {
            printf("Loading SHA256 context...\n");
            ctx->sha_ctx = sha256_init_ctx( ctx->hashes_file );
        }

        if ( ctx->sha_ctx || ctx->md5_ctx )
        {
            struct evconnlistener *listener = server_make_listener( ctx,
                                                                    server_base );
            if ( listener )
            {
                server_loop( ctx, server_base, listener );

                ret = true ;
            }
            else
                fprintf( stderr, "evconnlistener_new_bind() failed\n");

            if ( ctx->use_md5 )
                md5_fini_ctx( ctx->md5_ctx );
            else
                sha256_fini_ctx( ctx->sha_ctx );
        }
    }
    else
        fprintf( stderr, "event_base_new() failed\n");

    return ret ;
}
