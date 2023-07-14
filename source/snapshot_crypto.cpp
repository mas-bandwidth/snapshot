/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_crypto.h"

#ifdef _MSC_VER
#pragma warning(disable:4996)
#pragma warning(push)
#pragma warning(disable:4324)
#endif // #ifdef _MSC_VER

#include <sodium.h>

#if SODIUM_LIBRARY_VERSION_MAJOR < 10 || ( SODIUM_LIBRARY_VERSION_MAJOR == 10 && SODIUM_LIBRARY_VERSION_MINOR < 2 )
#error please upgrade your libsodium to at least version 1.0.17
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif

int snapshot_crypto_init()
{
    return sodium_init();
}

void snapshot_crypto_random_bytes( uint8_t * buffer, int bytes )
{
    randombytes_buf( buffer, bytes );
}

int snapshot_crypto_generichash( unsigned char * out, size_t outlen, const unsigned char * in, unsigned long long inlen, const unsigned char * key, size_t keylen )
{
    return crypto_generichash( out, outlen, in, inlen, key, keylen );
}

int snapshot_crypto_sign_keypair( unsigned char * pk, unsigned char * sk )
{
    return crypto_sign_keypair( pk, sk );    
}

int snapshot_crypto_sign_init( struct snapshot_crypto_sign_state_t * state )
{
    return crypto_sign_init( (crypto_sign_state*) state );
}

int snapshot_crypto_sign_update( struct snapshot_crypto_sign_state_t * state, const unsigned char * m, unsigned long long mlen )
{
    return crypto_sign_update( (crypto_sign_state*) state, m, mlen );
}

int snapshot_crypto_sign_final_create( struct snapshot_crypto_sign_state_t * state, unsigned char * sig, unsigned long long * siglen_p, const unsigned char *sk )
{
    return crypto_sign_final_create( (crypto_sign_state*) state, sig, siglen_p, sk );
}

int snapshot_crypto_sign_final_verify( struct snapshot_crypto_sign_state_t * state, const unsigned char * sig, const unsigned char * pk )
{
    return crypto_sign_final_verify( (crypto_sign_state*) state, sig, pk );
}

void snapshot_crypto_secretbox_keygen( unsigned char * k )
{
    return crypto_secretbox_keygen( k );
}

int snapshot_crypto_secretbox_easy( unsigned char * c, const unsigned char * m, unsigned long long mlen, const unsigned char * n, const unsigned char * k )
{
    return crypto_secretbox_easy( c, m, mlen, n, k );
}

int snapshot_crypto_secretbox_open_easy( unsigned char * m, const unsigned char * c, unsigned long long clen, const unsigned char * n, const unsigned char * k )
{
    return crypto_secretbox_open_easy( m, c, clen, n, k );
}

void snapshot_crypto_aead_chacha20poly1305_keygen( unsigned char * k )
{
    crypto_aead_chacha20poly1305_keygen( k );
}

int snapshot_crypto_aead_chacha20poly1305_encrypt( unsigned char * c, unsigned long long * clen_p, const unsigned char * m, unsigned long long mlen, const unsigned char * ad, unsigned long long adlen, const unsigned char * nsec, const unsigned char * npub, const unsigned char * k )
{
    return crypto_aead_chacha20poly1305_encrypt( c, clen_p, m, mlen, ad, adlen, nsec, npub, k );   
}

int snapshot_crypto_aead_chacha20poly1305_decrypt( unsigned char * m, unsigned long long * mlen_p, unsigned char * nsec, const unsigned char * c, unsigned long long clen, const unsigned char * ad, unsigned long long adlen, const unsigned char * npub, const unsigned char * k )
{
    return crypto_aead_chacha20poly1305_decrypt( m, mlen_p, nsec, c, clen, ad, adlen, npub, k );
}

void snapshot_crypto_aead_chacha20poly1305_ietf_keygen( unsigned char * k )
{
    crypto_aead_chacha20poly1305_ietf_keygen( k );
}

int snapshot_crypto_aead_chacha20poly1305_ietf_encrypt( unsigned char * c, unsigned long long * clen_p, const unsigned char * m, unsigned long long mlen, const unsigned char * ad, unsigned long long adlen, const unsigned char * nsec, const unsigned char * npub, const unsigned char * k )
{
    return crypto_aead_chacha20poly1305_ietf_encrypt( c, clen_p, m, mlen, ad, adlen, nsec, npub, k );
}

int snapshot_crypto_aead_chacha20poly1305_ietf_decrypt( unsigned char * m, unsigned long long * mlen_p, unsigned char * nsec, const unsigned char * c, unsigned long long clen, const unsigned char * ad, unsigned long long adlen, const unsigned char * npub, const unsigned char * k )
{
    return crypto_aead_chacha20poly1305_ietf_decrypt( m, mlen_p, nsec, c, clen, ad, adlen, npub, k );
}

int snapshot_crypto_aead_xchacha20poly1305_ietf_encrypt( unsigned char * c, unsigned long long * clen_p, const unsigned char * m, unsigned long long mlen, const unsigned char * ad, unsigned long long adlen, const unsigned char * nsec, const unsigned char * npub, const unsigned char * k )
{
    return crypto_aead_xchacha20poly1305_ietf_encrypt( c, clen_p, m, mlen, ad, adlen, nsec, npub, k );
}

int snapshot_crypto_aead_xchacha20poly1305_ietf_decrypt( unsigned char * m, unsigned long long * mlen_p, unsigned char * nsec, const unsigned char * c, unsigned long long clen, const unsigned char * ad, unsigned long long adlen, const unsigned char * npub, const unsigned char * k )
{
    return crypto_aead_xchacha20poly1305_ietf_decrypt( m, mlen_p, nsec, c, clen, ad, adlen, npub, k );
}

int snapshot_crypto_kx_keypair( unsigned char * pk, unsigned char * sk )
{
    return crypto_kx_keypair( pk, sk );
}

int snapshot_crypto_kx_client_session_keys( unsigned char * rx, unsigned char * tx, const unsigned char * client_pk, const unsigned char * client_sk, const unsigned char * server_pk )
{
    return crypto_kx_client_session_keys( rx, tx, client_pk, client_sk, server_pk );
}

int snapshot_crypto_kx_server_session_keys( unsigned char * rx, unsigned char * tx, const unsigned char * server_pk, const unsigned char * server_sk, const unsigned char * client_pk )
{
    return crypto_kx_server_session_keys( rx, tx, server_pk, server_sk, client_pk );
}

int snapshot_crypto_box_keypair( unsigned char * pk, unsigned char * sk )
{
    return crypto_box_keypair( pk, sk );
}

int snapshot_crypto_box_easy( unsigned char * c, const unsigned char * m, unsigned long long mlen, const unsigned char * n, const unsigned char * pk, const unsigned char * sk )
{
    return crypto_box_easy( c, m, mlen, n, pk, sk );
}

int snapshot_crypto_box_open_easy( unsigned char * m, const unsigned char * c, unsigned long long clen, const unsigned char * n, const unsigned char * pk, const unsigned char * sk )
{
    return crypto_box_open_easy( m, c, clen, n, pk, sk );
}

int snapshot_crypto_encrypt_aead( uint8_t * message, uint64_t message_length, 
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

int snapshot_crypto_decrypt_aead( uint8_t * message, uint64_t message_length, 
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

int snapshot_crypto_encrypt_aead_bignonce( uint8_t * message, uint64_t message_length, 
                                           uint8_t * additional, uint64_t additional_length,
                                           const uint8_t * nonce,
                                           const uint8_t * key )
{
    unsigned long long encrypted_length;

    int result = snapshot_crypto_aead_xchacha20poly1305_ietf_encrypt( message, &encrypted_length,
                                                                      message, (unsigned long long) message_length,
                                                                      additional, (unsigned long long) additional_length,
                                                                      NULL, nonce, key );
    
    if ( result != 0 )
        return SNAPSHOT_ERROR;

    snapshot_assert( encrypted_length == message_length + SNAPSHOT_MAC_BYTES );

    return SNAPSHOT_OK;
}

int snapshot_crypto_decrypt_aead_bignonce( uint8_t * message, uint64_t message_length, 
                                           uint8_t * additional, uint64_t additional_length,
                                           uint8_t * nonce,
                                           uint8_t * key )
{
    unsigned long long decrypted_length;

    int result = snapshot_crypto_aead_xchacha20poly1305_ietf_decrypt( message, &decrypted_length,
                                                                      NULL,
                                                                      message, (unsigned long long) message_length,
                                                                      additional, (unsigned long long) additional_length,
                                                                      nonce, key );

    if ( result != 0 )
        return SNAPSHOT_ERROR;

    snapshot_assert( decrypted_length == message_length - SNAPSHOT_MAC_BYTES );

    return SNAPSHOT_OK;
}
