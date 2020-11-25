#ifndef __SHA_256_INLINE__
#define __SHA_256_INLINE__

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include "sha256.h"


///////////////////////////////////////////////////////////////////////////////

static inline bool sha256_less( SHA_256 *sha256_left, SHA_256 *sha256_right )
{
    if ( sha256_left->num128.first < sha256_right->num128.first )

        return true ;

    if ( ( ! memcmp((void *)&sha256_left->num128.first, (void *)&sha256_right->num128.first, 16) ) &&
         ( sha256_left->num128.second < sha256_right->num128.second ) )

        return true ;

    return false ;
}

///////////////////////////////////////////////////////////////////////////////

static inline bool sha256_is_equal( SHA_256 *sha256_left, SHA_256 *sha256_right )
{
    return ! memcmp((void *)sha256_left, (void *)sha256_right, sizeof( SHA_256 ) );
}

///////////////////////////////////////////////////////////////////////////////

#endif
