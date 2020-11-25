#define _REENTRANT

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <errno.h>


////////////////////////////////////////////////////////////////////////////////

bool util_to_uint64( const char *hex_str, uint64_t *num )
{
    char *end;

    errno = 0;

    *num = (uint64_t)strtoull( hex_str, &end, 16 );

    if ( *num == 0 && end == hex_str )
        /* str was not a number */
        return false ;

    if ( *num == ULLONG_MAX && errno )
        /* the value of str does not fit in unsigned long long */
        return false ;

    if (*end)
        /* str began with a number but has junk left over at the end */
        return false ;

    return true;
}

////////////////////////////////////////////////////////////////////////////////

void util_print_128( __uint128_t *n )
{
    uint64_t lo = *n;
    uint64_t hi = (*n >> 64);

    printf("%016" PRIX64 "%016" PRIX64, hi, lo);
}

////////////////////////////////////////////////////////////////////////////////

void util_print_buffer( const char *buffer, int size, int column )
{
    int i=1;
    while ( i <= size )
    {
        printf(" %02X ", buffer[i-1] & 0xFF );
        if ( i && !(i%column))
            printf("\n");
        i++;
    }
    printf("\n");
}
