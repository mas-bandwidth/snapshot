/*
    Snapshot SDK Copyright © 2023 Network Next, Inc. This source code is licensed under GPL version 3 or any later version.
    Commercial licenses under different terms are available. Contact licensing@mas-bandwidth.com for details.
*/

#include "snapshot_common.h"

#ifndef SNAPSHOT_CRYPTO_H
#define SNAPSHOT_CRYPTO_H

// todo
#if 0

#define NEXT_CRYPTO_GENERICHASH_KEYBYTES                    32

#define NEXT_CRYPTO_SECRETBOX_KEYBYTES                      32
#define NEXT_CRYPTO_SECRETBOX_MACBYTES                      16
#define NEXT_CRYPTO_SECRETBOX_NONCEBYTES                    24

#define NEXT_CRYPTO_KX_PUBLICKEYBYTES                       32
#define NEXT_CRYPTO_KX_SECRETKEYBYTES                       32
#define NEXT_CRYPTO_KX_SESSIONKEYBYTES                      32

#define NEXT_CRYPTO_BOX_MACBYTES                            16
#define NEXT_CRYPTO_BOX_NONCEBYTES                          24
#define NEXT_CRYPTO_BOX_PUBLICKEYBYTES                      32
#define NEXT_CRYPTO_BOX_SECRETKEYBYTES                      32

#define NEXT_CRYPTO_SIGN_BYTES                              64
#define NEXT_CRYPTO_SIGN_PUBLICKEYBYTES                     32
#define NEXT_CRYPTO_SIGN_SECRETKEYBYTES                     64

#define NEXT_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES            16
#define NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES          32
#define NEXT_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES          8

#define NEXT_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES       16
#define NEXT_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES     32
#define NEXT_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES    12

int next_crypto_init();

void next_randombytes_buf( uint8_t * buffer, int bytes );

int next_crypto_generichash( unsigned char * out, size_t outlen, const unsigned char * in, unsigned long long inlen, const unsigned char * key, size_t keylen );

struct next_crypto_sign_state_t
{
    uint8_t dummy[1024];
};

int next_crypto_sign_keypair( unsigned char * pk, unsigned char * sk );

int next_crypto_sign_init( struct next_crypto_sign_state_t * state );

int next_crypto_sign_update( struct next_crypto_sign_state_t * state, const unsigned char * m, unsigned long long mlen );

int next_crypto_sign_final_create( struct next_crypto_sign_state_t * state, unsigned char * sig, unsigned long long * siglen_p, const unsigned char *sk );

int next_crypto_sign_final_verify( struct next_crypto_sign_state_t * state, const unsigned char * sig, const unsigned char * pk );

void next_crypto_secretbox_keygen( unsigned char * k );

int next_crypto_secretbox_easy( unsigned char * c, const unsigned char * m, unsigned long long mlen, const unsigned char * n, const unsigned char * k );

int next_crypto_secretbox_open_easy( unsigned char * m, const unsigned char * c, unsigned long long clen, const unsigned char * n, const unsigned char * k );

void next_crypto_aead_chacha20poly1305_keygen( unsigned char * k );

int next_crypto_aead_chacha20poly1305_encrypt( unsigned char * c, unsigned long long * clen_p, const unsigned char * m, unsigned long long mlen, const unsigned char * ad, unsigned long long adlen, const unsigned char * nsec, const unsigned char * npub, const unsigned char * k );

int next_crypto_aead_chacha20poly1305_decrypt( unsigned char * m, unsigned long long * mlen_p, unsigned char * nsec, const unsigned char * c, unsigned long long clen, const unsigned char * ad, unsigned long long adlen, const unsigned char * npub, const unsigned char * k );

void next_crypto_aead_chacha20poly1305_ietf_keygen( unsigned char * k );

int next_crypto_aead_chacha20poly1305_ietf_encrypt( unsigned char * c, unsigned long long * clen_p, const unsigned char * m, unsigned long long mlen, const unsigned char * ad, unsigned long long adlen, const unsigned char * nsec, const unsigned char * npub, const unsigned char * k );

int next_crypto_aead_chacha20poly1305_ietf_decrypt( unsigned char * m, unsigned long long * mlen_p, unsigned char * nsec, const unsigned char * c, unsigned long long clen, const unsigned char * ad, unsigned long long adlen, const unsigned char * npub, const unsigned char * k );

int next_crypto_kx_keypair( unsigned char * pk, unsigned char * sk );

int next_crypto_kx_client_session_keys( unsigned char * rx, unsigned char * tx, const unsigned char * client_pk, const unsigned char * client_sk, const unsigned char * server_pk );

int next_crypto_kx_server_session_keys( unsigned char * rx, unsigned char * tx, const unsigned char * server_pk, const unsigned char * server_sk, const unsigned char * client_pk );

int next_crypto_box_keypair( unsigned char * pk, unsigned char * sk );

int next_crypto_box_easy( unsigned char * c, const unsigned char * m, unsigned long long mlen, const unsigned char * n, const unsigned char * pk, const unsigned char * sk );

int next_crypto_box_open_easy( unsigned char * m, const unsigned char * c, unsigned long long clen, const unsigned char * n, const unsigned char * pk, const unsigned char * sk );

#endif // #ifndef NEXT_CRYPTO_H

#endif // todo
