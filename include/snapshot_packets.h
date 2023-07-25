/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_PACKETS_H
#define SNAPSHOT_PACKETS_H

#include "snapshot.h"
#include "snapshot_challenge_token.h"

#define SNAPSHOT_PACKET_PREFIX_BYTES               256
#define SNAPSHOT_PACKET_POSTFIX_BYTES              256

#define SNAPSHOT_MAX_PAYLOAD_BYTES                4096

#define SNAPSHOT_MAX_PASSTHROUGH_BYTES            1500

#define SNAPSHOT_CONNECTION_REQUEST_PACKET           0
#define SNAPSHOT_CONNECTION_DENIED_PACKET            1
#define SNAPSHOT_CONNECTION_CHALLENGE_PACKET         2
#define SNAPSHOT_CONNECTION_RESPONSE_PACKET          3
#define SNAPSHOT_KEEP_ALIVE_PACKET                   4
#define SNAPSHOT_PAYLOAD_PACKET                      5
#define SNAPSHOT_PASSTHROUGH_PACKET                  6
#define SNAPSHOT_DISCONNECT_PACKET                   7
#define SNAPSHOT_NUM_PACKETS                         8

inline int snapshot_sequence_number_bytes_required( uint64_t sequence )
{
    uint64_t mask = 0xFF00000000000000UL;
    int i;
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

struct snapshot_keep_alive_packet_t
{
    uint8_t packet_type;
    int client_index;
    int max_clients;
};

struct snapshot_payload_packet_t
{
    uint8_t packet_type;
    uint32_t payload_bytes;
    uint8_t payload_data[1];
};

struct snapshot_passthrough_packet_t
{
    uint8_t packet_type;
    uint32_t passthrough_bytes;
    uint8_t passthrough_data[1];
};

struct snapshot_disconnect_packet_t
{
    uint8_t packet_type;
};

uint8_t * snapshot_create_packet( void * context, int packet_bytes );

void snapshot_destroy_packet( void * context, uint8_t * packet );

struct snapshot_payload_packet_t * snapshot_wrap_payload_packet( uint8_t * payload_data, int payload_bytes );

struct snapshot_passthrough_packet_t * snapshot_wrap_passthrough_packet( uint8_t * passthrough_data, int passthrough_bytes );

uint8_t * snapshot_write_packet( void * packet, uint8_t * buffer, int buffer_length, uint64_t sequence, uint8_t * write_packet_key, uint64_t protocol_id, int * out_bytes );

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

#if SNAPSHOT_DEVELOPMENT

#include "stdlib.h"

inline void snapshot_generate_packet_data( uint8_t * packet_data, int & packet_bytes, int max_size )
{
    packet_bytes = 1 + rand() % ( max_size - 1 );
    const int start = packet_bytes % 256;
    for ( int i = 0; i < packet_bytes; i++ )
    {
        packet_data[i] = (uint8_t) ( start + i ) % 256;
    }
}

inline void snapshot_verify_packet_data( const uint8_t * packet_data, int packet_bytes )
{
    const int start = packet_bytes % 256;
    for ( int i = 0; i < packet_bytes; i++ )
    {
        if ( packet_data[i] != (uint8_t) ( ( start + i ) % 256 ) )
        {
            printf( "packet data failed validation!\n" );
            fflush( stdout );
            exit( 1 );
        }
    }
}

#endif // #if SNAPSHOT_DEVELOPMENT

#endif // #ifndef SNAPSHOT_PACKETS_H
