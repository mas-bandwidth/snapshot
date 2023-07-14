/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_CONNECT_TOKEN_H
#define SNAPSHOT_CONNECT_TOKEN_H

#include "snapshot.h"
#include "snapshot_address.h"

// ---------------------------------------------------------------

struct snapshot_connect_token_t
{
    uint8_t version_info[SNAPSHOT_VERSION_INFO_BYTES];
    uint64_t protocol_id;
    uint64_t create_timestamp;
    uint64_t expire_timestamp;
    uint8_t nonce[SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES];
    uint8_t private_data[SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES];
    int timeout_seconds;
    int num_server_addresses;
    struct snapshot_address_t server_addresses[SNAPSHOT_MAX_SERVERS_PER_CONNECT];
    uint8_t client_to_server_key[SNAPSHOT_KEY_BYTES];
    uint8_t server_to_client_key[SNAPSHOT_KEY_BYTES];
};

int snapshot_generate_connect_token( int num_server_addresses, 
                                     const char ** server_addresses, 
                                     int expire_seconds, 
                                     int timeout_seconds,
                                     uint64_t client_id, 
                                     uint64_t protocol_id, 
                                     const uint8_t * private_key, 
                                     uint8_t * user_data, 
                                     uint8_t * output_buffer );

void snapshot_write_connect_token( struct snapshot_connect_token_t * connect_token, uint8_t * buffer, int buffer_length );

int snapshot_read_connect_token( const uint8_t * buffer, int buffer_length, struct snapshot_connect_token_t * connect_token );

// ---------------------------------------------------------------

struct snapshot_connect_token_private_t
{
    uint64_t client_id;
    int timeout_seconds;
    int num_server_addresses;
    struct snapshot_address_t server_addresses[SNAPSHOT_MAX_SERVERS_PER_CONNECT];
    uint8_t client_to_server_key[SNAPSHOT_KEY_BYTES];
    uint8_t server_to_client_key[SNAPSHOT_KEY_BYTES];
    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
};

void snapshot_generate_connect_token_private( struct snapshot_connect_token_private_t * connect_token, 
                                              uint64_t client_id, 
                                              int timeout_seconds,
                                              int num_server_addresses, 
                                              struct snapshot_address_t * server_addresses, 
                                              uint8_t * user_data );

void snapshot_write_connect_token_private( struct snapshot_connect_token_private_t * connect_token, uint8_t * buffer, int buffer_length );

int snapshot_encrypt_connect_token_private( uint8_t * buffer, 
                                            int buffer_length, 
                                            uint8_t * version_info, 
                                            uint64_t protocol_id, 
                                            uint64_t expire_timestamp, 
                                            const uint8_t * nonce, 
                                            const uint8_t * key );

int snapshot_decrypt_connect_token_private( uint8_t * buffer, 
                                            int buffer_length, 
                                            uint8_t * version_info, 
                                            uint64_t protocol_id, 
                                            uint64_t expire_timestamp, 
                                            uint8_t * nonce, 
                                            uint8_t * key );

int snapshot_read_connect_token_private( const uint8_t * buffer, int buffer_length, struct snapshot_connect_token_private_t * connect_token );

// ---------------------------------------------------------------

#endif // #ifndef SNAPSHOT_CONNECT_TOKEN_H
