#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include <regex.h>

#include "md5.h"

#define BUFFER_SIZE 64*256

typedef struct _CONTEXT {
    const char *hash_txt_path ; // File with all of the MD5 hashes in text
                                // format and ordered
    const char *hash_bin_path ; // File with all of the MD5 hashes in binary
                                // format
    char read_buffer[ BUFFER_SIZE + 1 ]; // Read buffer
    MD5 hash_obj;
    size_t bytes_read ;
    size_t bytes_written ;
    int file_src ;   // Source file handle
    int file_dst ;   // Destination file handle
    regex_t preg ;   // Regex handle

} CONTEXT ;


#endif
