#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include <regex.h>

#define BUFFER_SIZE 64*256

typedef struct _CONTEXT {
    const char *hash_txt_path ; // File with all of the SHA256 hashes in text
                                // format and ordered
    const char *hash_bin_path ; // File with all of the SHA256 hashes in binary
                                // format
    char read_buffer[ BUFFER_SIZE + 1 ]; // Read buffer
    char hash_bin[ 256 ];
    size_t bytes_read ;
    size_t bytes_written ;
    int file_src ;   // Source file handle
    int file_dst ;   // Destination file handle
    regex_t preg ;   // Regex handle
    bool use_md5 ;      // MD5 hashes instead of SHA256
    int hash_size ;     // Size of hash in binary format
    int hash_str_size ; // Size of hash string
    bool (*hash_from_hex)(char *, void *);
} CONTEXT ;


#endif
