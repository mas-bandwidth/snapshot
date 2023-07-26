/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_BASE64_H
#define SNAPSHOT_BASE64_H

#include "snapshot.h"

int snapshot_base64_encode_data( const uint8_t * input, size_t input_length, char * output, size_t output_size );

int snapshot_base64_decode_data( const char * input, uint8_t * output, size_t output_size );

int snapshot_base64_encode_string( const char * input, char * output, size_t output_size );

int snapshot_base64_decode_string( const char * input, char * output, size_t output_size );

#endif // #if SNAPSHOT_BASE64_H
