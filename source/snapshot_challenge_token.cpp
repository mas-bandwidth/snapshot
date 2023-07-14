/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_challenge_token.h"
#include "snapshot_read_write.h"
#include "snapshot_crypto.h"

void snapshot_write_challenge_token( struct snapshot_challenge_token_t * challenge_token, uint8_t * buffer, int buffer_length )
{
    (void) buffer_length;

    snapshot_assert( challenge_token );
    snapshot_assert( buffer );
    snapshot_assert( buffer_length >= SNAPSHOT_CHALLENGE_TOKEN_BYTES );

    memset( buffer, 0, SNAPSHOT_CHALLENGE_TOKEN_BYTES );

    uint8_t * start = buffer;

    (void) start;

    snapshot_write_uint64( &buffer, challenge_token->client_id );

    snapshot_write_bytes( &buffer, challenge_token->user_data, SNAPSHOT_USER_DATA_BYTES ); 

    snapshot_assert( buffer - start <= SNAPSHOT_CHALLENGE_TOKEN_BYTES - SNAPSHOT_MAC_BYTES );
}

int snapshot_encrypt_challenge_token( uint8_t * buffer, int buffer_length, uint64_t sequence, uint8_t * key )
{
    snapshot_assert( buffer );
    snapshot_assert( buffer_length >= SNAPSHOT_CHALLENGE_TOKEN_BYTES );
    snapshot_assert( key );

    (void) buffer_length;

    uint8_t nonce[12];
    {
        uint8_t * p = nonce;
        snapshot_write_uint32( &p, 0 );
        snapshot_write_uint64( &p, sequence );
    }

    return snapshot_crypto_encrypt_aead( buffer, SNAPSHOT_CHALLENGE_TOKEN_BYTES - SNAPSHOT_MAC_BYTES, NULL, 0, nonce, key );
}

int snapshot_decrypt_challenge_token( uint8_t * buffer, int buffer_length, uint64_t sequence, uint8_t * key )
{
    snapshot_assert( buffer );
    snapshot_assert( buffer_length >= SNAPSHOT_CHALLENGE_TOKEN_BYTES );
    snapshot_assert( key );

    (void) buffer_length;

    uint8_t nonce[12];
    {
        uint8_t * p = nonce;
        snapshot_write_uint32( &p, 0 );
        snapshot_write_uint64( &p, sequence );
    }

    return snapshot_crypto_decrypt_aead( buffer, SNAPSHOT_CHALLENGE_TOKEN_BYTES, NULL, 0, nonce, key );
}

int snapshot_read_challenge_token( const uint8_t * buffer, int buffer_length, struct snapshot_challenge_token_t * challenge_token )
{
    snapshot_assert( buffer );
    snapshot_assert( challenge_token );

    if ( buffer_length < SNAPSHOT_CHALLENGE_TOKEN_BYTES )
        return SNAPSHOT_ERROR;

    const uint8_t * start = buffer;

    (void) start;
    
    challenge_token->client_id = snapshot_read_uint64( &buffer );

    snapshot_read_bytes( &buffer, challenge_token->user_data, SNAPSHOT_USER_DATA_BYTES );

    snapshot_assert( buffer - start == 8 + SNAPSHOT_USER_DATA_BYTES );

    return SNAPSHOT_OK;
}
