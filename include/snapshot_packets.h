/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_PACKETS_H
#define SNAPSHOT_PACKETS_H

#include "snapshot.h"
#include "snapshot_challenge_token.h"

#define SNAPSHOT_MAX_PAYLOAD_BYTES                1024

#define SNAPSHOT_CONNECTION_REQUEST_PACKET           0
#define SNAPSHOT_CONNECTION_DENIED_PACKET            1
#define SNAPSHOT_CONNECTION_CHALLENGE_PACKET         2
#define SNAPSHOT_CONNECTION_RESPONSE_PACKET          3
#define SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET        4
#define SNAPSHOT_CONNECTION_PAYLOAD_PACKET           5
#define SNAPSHOT_CONNECTION_DISCONNECT_PACKET        6
#define SNAPSHOT_CONNECTION_NUM_PACKETS              7

inline int snapshot_sequence_number_bytes_required( uint64_t sequence )
{
    int i;
    uint64_t mask = 0xFF00000000000000UL;
    for ( i = 0; i < 7; ++i )
    {
        if ( sequence & mask )
            break;
        mask >>= 8;
    }
    return 8 - i;
}

struct snapshot_connection_request_packet_t
{
    uint8_t packet_type;
    uint8_t version_info[SNAPSHOT_VERSION_INFO_BYTES];
    uint64_t protocol_id;
    uint64_t connect_token_expire_timestamp;
    uint8_t connect_token_nonce[SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES];
    uint8_t connect_token_data[SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES];
};

struct snapshot_connection_denied_packet_t
{
    uint8_t packet_type;
};

struct snapshot_connection_challenge_packet_t
{
    uint8_t packet_type;
    uint64_t challenge_token_sequence;
    uint8_t challenge_token_data[SNAPSHOT_CHALLENGE_TOKEN_BYTES];
};

struct snapshot_connection_response_packet_t
{
    uint8_t packet_type;
    uint64_t challenge_token_sequence;
    uint8_t challenge_token_data[SNAPSHOT_CHALLENGE_TOKEN_BYTES];
};

struct snapshot_connection_keep_alive_packet_t
{
    uint8_t packet_type;
    int client_index;
    int max_clients;
};

struct snapshot_connection_payload_packet_t
{
    uint8_t packet_type;
    uint32_t payload_bytes;
    uint8_t payload_data[1];
};

struct snapshot_connection_disconnect_packet_t
{
    uint8_t packet_type;
};

struct snapshot_connection_payload_packet_t * snapshot_create_payload_packet( void * context, int payload_bytes );

void snapshot_destroy_payload_packet( void * context, snapshot_connection_payload_packet_t * packet );

struct snapshot_connection_payload_packet_t * snapshot_wrap_payload_packet( uint8_t * payload_data, int payload_bytes );

int snapshot_write_packet( void * packet, uint8_t * buffer, int buffer_length, uint64_t sequence, uint8_t * write_packet_key, uint64_t protocol_id );

void * snapshot_read_packet( uint8_t * buffer, 
                             int buffer_length, 
                             uint64_t * sequence, 
                             uint8_t * read_packet_key, 
                             uint64_t protocol_id, 
                             uint64_t current_timestamp, 
                             uint8_t * private_key, 
                             uint8_t * allowed_packets, 
                             uint8_t * out_packet_buffer,
                             struct snapshot_replay_protection_t * replay_protection );

#endif // #ifndef SNAPSHOT_PACKETS_H
