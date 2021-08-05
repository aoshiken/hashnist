#ifndef __MD5_INLINE__
#define __MD5_INLINE__

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include "md5.h"


///////////////////////////////////////////////////////////////////////////////

static inline bool md5_less( MD5 *md5_left, MD5 *md5_right )
{
    if ( md5_left->num128 < md5_right->num128 )

        return true ;

    return false ;
}

///////////////////////////////////////////////////////////////////////////////

static inline bool md5_is_equal( MD5 *md5_left, MD5 *md5_right )
{
    return ! memcmp((void *)md5_left, (void *)md5_right, sizeof( MD5 ) );
}

///////////////////////////////////////////////////////////////////////////////

#endif
