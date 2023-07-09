/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_CHALLENGE_TOKEN_H
#define SNAPSHOT_CHALLENGE_TOKEN_H

#include "snapshot.h"
#include "snapshot_read_write.h"
#include "snapshot_crypto.h"

#define SNAPSHOT_CHALLENGE_TOKEN_BYTES 300

// todo: split into header and cpp

struct snapshot_challenge_token_t
{
    uint64_t client_id;
    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
};

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

int snapshot_encrypt_aead( uint8_t * message, uint64_t message_length, 
                           uint8_t * additional, uint64_t additional_length,
                           const uint8_t * nonce,
                           const uint8_t * key )
{
    unsigned long long encrypted_length;

    int result = snapshot_crypto_aead_chacha20poly1305_ietf_encrypt( message, &encrypted_length,
                                                                     message, (unsigned long long) message_length,
                                                                     additional, (unsigned long long) additional_length,
                                                                     NULL, nonce, key );
    
    if ( result != 0 )
        return SNAPSHOT_ERROR;

    snapshot_assert( encrypted_length == message_length + SNAPSHOT_MAC_BYTES );

    return SNAPSHOT_OK;
}

int snapshot_decrypt_aead( uint8_t * message, uint64_t message_length, 
                           uint8_t * additional, uint64_t additional_length,
                           uint8_t * nonce,
                           uint8_t * key )
{
    unsigned long long decrypted_length;

    int result = snapshot_crypto_aead_chacha20poly1305_ietf_decrypt( message, &decrypted_length,
                                                                     NULL,
                                                                     message, (unsigned long long) message_length,
                                                                     additional, (unsigned long long) additional_length,
                                                                     nonce, key );

    if ( result != 0 )
        return SNAPSHOT_ERROR;

    snapshot_assert( decrypted_length == message_length - SNAPSHOT_MAC_BYTES );

    return SNAPSHOT_OK;
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

    return snapshot_encrypt_aead( buffer, SNAPSHOT_CHALLENGE_TOKEN_BYTES - SNAPSHOT_MAC_BYTES, NULL, 0, nonce, key );
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

    return snapshot_decrypt_aead( buffer, SNAPSHOT_CHALLENGE_TOKEN_BYTES, NULL, 0, nonce, key );
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


#endif // #ifndef SNAPSHOT_CHALLENGE_TOKEN_H
