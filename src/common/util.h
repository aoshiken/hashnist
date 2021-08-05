#ifndef __UTIL_H__
#define __UTIL_H__

bool util_to_uint64( const char *hex_str, uint64_t *num );
void util_print_buffer( const char *buffer, int size, int column );
void util_print_128( __uint128_t *n );
time_t util_get_modif_time( const char *full_path );

#endif
