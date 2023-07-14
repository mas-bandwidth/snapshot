/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_CHALLENGE_TOKEN_H
#define SNAPSHOT_CHALLENGE_TOKEN_H

#include "snapshot.h"

#define SNAPSHOT_CHALLENGE_TOKEN_BYTES 300

struct snapshot_challenge_token_t
{
    uint64_t client_id;
    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
};

void snapshot_write_challenge_token( struct snapshot_challenge_token_t * challenge_token, uint8_t * buffer, int buffer_length );

int snapshot_encrypt_challenge_token( uint8_t * buffer, int buffer_length, uint64_t sequence, uint8_t * key );

int snapshot_decrypt_challenge_token( uint8_t * buffer, int buffer_length, uint64_t sequence, uint8_t * key );

int snapshot_read_challenge_token( const uint8_t * buffer, int buffer_length, struct snapshot_challenge_token_t * challenge_token );

#endif // #ifndef SNAPSHOT_CHALLENGE_TOKEN_H
