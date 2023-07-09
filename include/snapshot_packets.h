/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_PACKETS_H
#define SNAPSHOT_PACKETS_H

#include "snapshot.h"
#include "snapshot_connect_token.h"
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

struct snapshot_connection_payload_packet_t * snapshot_create_payload_packet( void * context, int payload_bytes )
{
    snapshot_assert( payload_bytes >= 0 );
    snapshot_assert( payload_bytes <= SNAPSHOT_MAX_PAYLOAD_BYTES );

    struct snapshot_connection_payload_packet_t * packet = (struct snapshot_connection_payload_packet_t*) snapshot_malloc( context, sizeof( struct snapshot_connection_payload_packet_t ) + payload_bytes );

    if ( !packet )
        return NULL;
    
    packet->packet_type = SNAPSHOT_CONNECTION_PAYLOAD_PACKET;
    packet->payload_bytes = payload_bytes;

    return packet;
}

struct snapshot_context_t
{
    uint8_t write_packet_key[SNAPSHOT_KEY_BYTES];
    uint8_t read_packet_key[SNAPSHOT_KEY_BYTES];
};

int snapshot_write_packet( void * packet, uint8_t * buffer, int buffer_length, uint64_t sequence, uint8_t * write_packet_key, uint64_t protocol_id )
{
    snapshot_assert( packet );
    snapshot_assert( buffer );
    snapshot_assert( write_packet_key );

    (void) buffer_length;

    uint8_t packet_type = ((uint8_t*)packet)[0];

    if ( packet_type == SNAPSHOT_CONNECTION_REQUEST_PACKET )
    {
        // connection request packet: first byte is zero

        snapshot_assert( buffer_length >= 1 + SNAPSHOT_VERSION_INFO_BYTES + 8 + 8 + SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES + SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

        struct snapshot_connection_request_packet_t * p = (struct snapshot_connection_request_packet_t*) packet;

        uint8_t * start = buffer;

        snapshot_write_uint8( &buffer, SNAPSHOT_CONNECTION_REQUEST_PACKET );
        snapshot_write_bytes( &buffer, p->version_info, SNAPSHOT_VERSION_INFO_BYTES );
        snapshot_write_uint64( &buffer, p->protocol_id );
        snapshot_write_uint64( &buffer, p->connect_token_expire_timestamp );
        snapshot_write_bytes( &buffer, p->connect_token_nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );
        snapshot_write_bytes( &buffer, p->connect_token_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

        snapshot_assert( buffer - start == 1 + SNAPSHOT_VERSION_INFO_BYTES + 8 + 8 + SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES + SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

        return (int) ( buffer - start );
    }
    else
    {
        // *** encrypted packets ***

        // write the prefix byte (this is a combination of the packet type and number of sequence bytes)

        uint8_t * start = buffer;

        uint8_t sequence_bytes = (uint8_t) snapshot_sequence_number_bytes_required( sequence );

        snapshot_assert( sequence_bytes >= 1 );
        snapshot_assert( sequence_bytes <= 8 );

        snapshot_assert( packet_type <= 0xF );

        uint8_t prefix_byte = packet_type | ( sequence_bytes << 4 );

        snapshot_write_uint8( &buffer, prefix_byte );

        // write the variable length sequence number [1,8] bytes.

        uint64_t sequence_temp = sequence;

        int i;
        for ( i = 0; i < sequence_bytes; ++i )
        {
            snapshot_write_uint8( &buffer, (uint8_t) ( sequence_temp & 0xFF ) );
            sequence_temp >>= 8;
        }

        // write packet data according to type. this data will be encrypted.

        uint8_t * encrypted_start = buffer;

        switch ( packet_type )
        {
            case SNAPSHOT_CONNECTION_DENIED_PACKET:
            {
                // ...
            }
            break;

            case SNAPSHOT_CONNECTION_CHALLENGE_PACKET:
            {
                struct snapshot_connection_challenge_packet_t * p = (struct snapshot_connection_challenge_packet_t*) packet;
                snapshot_write_uint64( &buffer, p->challenge_token_sequence );
                snapshot_write_bytes( &buffer, p->challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES );
            }
            break;

            case SNAPSHOT_CONNECTION_RESPONSE_PACKET:
            {
                struct snapshot_connection_response_packet_t * p = (struct snapshot_connection_response_packet_t*) packet;
                snapshot_write_uint64( &buffer, p->challenge_token_sequence );
                snapshot_write_bytes( &buffer, p->challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES );
            }
            break;

            case SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET:
            {
                struct snapshot_connection_keep_alive_packet_t * p = (struct snapshot_connection_keep_alive_packet_t*) packet;
                snapshot_write_uint32( &buffer, p->client_index );
                snapshot_write_uint32( &buffer, p->max_clients );
            }
            break;

            case SNAPSHOT_CONNECTION_PAYLOAD_PACKET:
            {
                struct snapshot_connection_payload_packet_t * p = (struct snapshot_connection_payload_packet_t*) packet;

                snapshot_assert( p->payload_bytes <= SNAPSHOT_MAX_PAYLOAD_BYTES );

                snapshot_write_bytes( &buffer, p->payload_data, p->payload_bytes );
            }
            break;

            case SNAPSHOT_CONNECTION_DISCONNECT_PACKET:
            {
                // ...
            }
            break;

            default:
                snapshot_assert( 0 );
        }

        snapshot_assert( buffer - start <= buffer_length - SNAPSHOT_MAC_BYTES );

        uint8_t * encrypted_finish = buffer;

        // encrypt the per-packet packet written with the prefix byte, protocol id and version as the associated data. this must match to decrypt.

        uint8_t additional_data[SNAPSHOT_VERSION_INFO_BYTES+8+1];
        {
            uint8_t * p = additional_data;
            snapshot_write_bytes( &p, SNAPSHOT_VERSION_INFO, SNAPSHOT_VERSION_INFO_BYTES );
            snapshot_write_uint64( &p, protocol_id );
            snapshot_write_uint8( &p, prefix_byte );
        }

        uint8_t nonce[12];
        {
            uint8_t * p = nonce;
            snapshot_write_uint32( &p, 0 );
            snapshot_write_uint64( &p, sequence );
        }

        if ( snapshot_encrypt_aead( encrypted_start, 
                                    encrypted_finish - encrypted_start, 
                                    additional_data, sizeof( additional_data ), 
                                    nonce, write_packet_key ) != SNAPSHOT_OK )
        {
            return SNAPSHOT_ERROR;
        }

        buffer += SNAPSHOT_MAC_BYTES;

        snapshot_assert( buffer - start <= buffer_length );

        return (int) ( buffer - start );
    }
}

void * snapshot_read_packet( void * context, 
                             uint8_t * buffer, 
                             int buffer_length, 
                             uint64_t * sequence, 
                             uint8_t * read_packet_key, 
                             uint64_t protocol_id, 
                             uint64_t current_timestamp, 
                             uint8_t * private_key, 
                             uint8_t * allowed_packets, 
                             struct snapshot_replay_protection_t * replay_protection )
{
    snapshot_assert( sequence );
    snapshot_assert( allowed_packets );

    *sequence = 0;

    // todo
    (void) replay_protection;

    if ( buffer_length < 1 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored packet. buffer length is less than 1" );
        return NULL;
    }

    const uint8_t * start = buffer;

    const uint8_t * p = buffer;

    uint8_t prefix_byte = snapshot_read_uint8( &p );

    if ( prefix_byte == SNAPSHOT_CONNECTION_REQUEST_PACKET )
    {
        // connection request packet: first byte is zero

        if ( !allowed_packets[SNAPSHOT_CONNECTION_REQUEST_PACKET] )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection request packet. packet type is not allowed" );
            return NULL;
        }

        if ( buffer_length != 1 + SNAPSHOT_VERSION_INFO_BYTES + 8 + 8 + SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES + SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection request packet. bad packet length (expected %d, got %d)", 1 + SNAPSHOT_VERSION_INFO_BYTES + 8 + 8 + 8 + SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES, buffer_length );
            return NULL;
        }

        if ( !private_key )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection request packet. no private key" );
            return NULL;
        }

        uint8_t version_info[SNAPSHOT_VERSION_INFO_BYTES];
        snapshot_read_bytes( &p, version_info, SNAPSHOT_VERSION_INFO_BYTES );
        if ( version_info[0] != 'S' || 
             version_info[1] != 'N' || 
             version_info[2] != 'A' || 
             version_info[3] != 'P' || 
             version_info[4] != 'S' ||
             version_info[5] != 'H' ||
             version_info[6] != 'O' ||
             version_info[7] != 'T' || 
             version_info[8] != '\0' )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection request packet. bad version info" );
            return NULL;
        }

        uint64_t packet_protocol_id = snapshot_read_uint64( &p );
        if ( packet_protocol_id != protocol_id )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection request packet. wrong protocol id. expected %.16" PRIx64 ", got %.16" PRIx64, protocol_id, packet_protocol_id );
            return NULL;
        }

        uint64_t packet_connect_token_expire_timestamp = snapshot_read_uint64( &p );
        if ( packet_connect_token_expire_timestamp <= current_timestamp )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection request packet. connect token expired" );
            return NULL;
        }

        uint8_t packet_connect_token_nonce[SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES];
        snapshot_read_bytes( &p, packet_connect_token_nonce, sizeof(packet_connect_token_nonce) );

        snapshot_assert( p - start == 1 + SNAPSHOT_VERSION_INFO_BYTES + 8 + 8 + SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );

        if ( snapshot_decrypt_connect_token_private( (uint8_t*)p, 
                                                     SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES, 
                                                     version_info, 
                                                     protocol_id, 
                                                     packet_connect_token_expire_timestamp, 
                                                     packet_connect_token_nonce, 
                                                     private_key ) != SNAPSHOT_OK )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection request packet. connect token failed to decrypt" );
            return NULL;
        }

        struct snapshot_connection_request_packet_t * packet = (struct snapshot_connection_request_packet_t*) snapshot_malloc( context, sizeof( struct snapshot_connection_request_packet_t ) );

        if ( !packet )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection request packet. failed to allocate packet" );
            return NULL;
        }

        packet->packet_type = SNAPSHOT_CONNECTION_REQUEST_PACKET;
        memcpy( packet->version_info, version_info, SNAPSHOT_VERSION_INFO_BYTES );
        packet->protocol_id = packet_protocol_id;
        packet->connect_token_expire_timestamp = packet_connect_token_expire_timestamp;
        memcpy( packet->connect_token_nonce, packet_connect_token_nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );
        snapshot_read_bytes( &p, packet->connect_token_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

        snapshot_assert( p - start == 1 + SNAPSHOT_VERSION_INFO_BYTES + 8 + 8 + SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES + SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

        return packet;
    }
    else
    {
        // *** encrypted packets ***

        if ( !read_packet_key )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored encrypted packet. no read packet key for this address" );
            return NULL;
        }

        if ( buffer_length < 1 + 1 + SNAPSHOT_MAC_BYTES )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored encrypted packet. packet is too small to be valid (%d bytes)", buffer_length );
            return NULL;
        }

        // extract the packet type and number of sequence bytes from the prefix byte

        int packet_type = prefix_byte & 0xF;

        if ( packet_type >= SNAPSHOT_CONNECTION_NUM_PACKETS )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored encrypted packet. packet type %d is invalid", packet_type );
            return NULL;
        }

        if ( !allowed_packets[packet_type] )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored encrypted packet. packet type %d is not allowed", packet_type );
            return NULL;
        }

        int sequence_bytes = prefix_byte >> 4;

        if ( sequence_bytes < 1 || sequence_bytes > 8 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored encrypted packet. sequence bytes %d is out of range [1,8]", sequence_bytes );
            return NULL;
        }

        if ( buffer_length < 1 + sequence_bytes + SNAPSHOT_MAC_BYTES )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored encrypted packet. buffer is too small for sequence bytes + encryption mac" );
            return NULL;
        }

        // read variable length sequence number [1,8]

        int i;
        for ( i = 0; i < sequence_bytes; ++i )
        {
            uint8_t value = snapshot_read_uint8( &p );
            (*sequence) |= ( uint64_t) ( value ) << ( 8 * i );
        }

        // ignore the packet if it has already been received

        // todo
        /*
        if ( replay_protection && packet_type >= SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET )
        {
            if ( snapshot_replay_protection_already_received( replay_protection, *sequence ) )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored packet. sequence %.16" PRIx64 " already received (replay protection)", *sequence );
                return NULL;
            }
        }
        */

        // decrypt the per-packet type data

        uint8_t additional_data[SNAPSHOT_VERSION_INFO_BYTES+8+1];
        {
            uint8_t * q = additional_data;
            snapshot_write_bytes( &q, SNAPSHOT_VERSION_INFO, SNAPSHOT_VERSION_INFO_BYTES );
            snapshot_write_uint64( &q, protocol_id );
            snapshot_write_uint8( &q, prefix_byte );
        }

        // todo: we should probably add packet type to nonce

        uint8_t nonce[12];
        {
            uint8_t * p = nonce;
            snapshot_write_uint32( &p, 0 );
            snapshot_write_uint64( &p, *sequence );
        }

        int encrypted_bytes = (int) ( buffer_length - ( p - start ) );

        if ( encrypted_bytes < SNAPSHOT_MAC_BYTES )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored encrypted packet. encrypted payload is too small" );
            return NULL;
        }

        if ( snapshot_decrypt_aead( (uint8_t*)p, encrypted_bytes, additional_data, sizeof( additional_data ), nonce, read_packet_key ) != SNAPSHOT_OK )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored encrypted packet. failed to decrypt" );
            return NULL;
        }

        int decrypted_bytes = encrypted_bytes - SNAPSHOT_MAC_BYTES;

        // update the latest replay protection sequence #

        // todo
        /*
        if ( replay_protection && packet_type >= SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET )
        {
            snapshot_replay_protection_advance_sequence( replay_protection, *sequence );
        }
        */

        // process the per-packet type data that was just decrypted
        
        switch ( packet_type )
        {
            case SNAPSHOT_CONNECTION_DENIED_PACKET:
            {
                if ( decrypted_bytes != 0 )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection denied packet. decrypted packet data is wrong size" );
                    return NULL;
                }

                struct snapshot_connection_denied_packet_t * packet = (struct snapshot_connection_denied_packet_t*) snapshot_malloc( context, sizeof( struct snapshot_connection_denied_packet_t ) );

                if ( !packet )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection denied packet. could not allocate packet struct" );
                    return NULL;
                }
                
                packet->packet_type = SNAPSHOT_CONNECTION_DENIED_PACKET;
                
                return packet;
            }
            break;

            case SNAPSHOT_CONNECTION_CHALLENGE_PACKET:
            {
                if ( decrypted_bytes != 8 + SNAPSHOT_CHALLENGE_TOKEN_BYTES )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection challenge packet. decrypted packet data is wrong size" );
                    return NULL;
                }

                struct snapshot_connection_challenge_packet_t * packet = (struct snapshot_connection_challenge_packet_t*) snapshot_malloc( context, sizeof( struct snapshot_connection_challenge_packet_t ) );

                if ( !packet )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection challenge packet. could not allocate packet struct" );
                    return NULL;
                }
                
                packet->packet_type = SNAPSHOT_CONNECTION_CHALLENGE_PACKET;
                packet->challenge_token_sequence = snapshot_read_uint64( &p );
                snapshot_read_bytes( &p, packet->challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES );
                
                return packet;
            }
            break;

            case SNAPSHOT_CONNECTION_RESPONSE_PACKET:
            {
                if ( decrypted_bytes != 8 + SNAPSHOT_CHALLENGE_TOKEN_BYTES )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection response packet. decrypted packet data is wrong size" );
                    return NULL;
                }

                struct snapshot_connection_response_packet_t * packet = (struct snapshot_connection_response_packet_t*) snapshot_malloc( context, sizeof( struct snapshot_connection_response_packet_t ) );

                if ( !packet )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection response packet. could not allocate packet struct" );
                    return NULL;
                }
                
                packet->packet_type = SNAPSHOT_CONNECTION_RESPONSE_PACKET;
                packet->challenge_token_sequence = snapshot_read_uint64( &p );
                snapshot_read_bytes( &p, packet->challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES );
                
                return packet;
            }
            break;

            case SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET:
            {
                if ( decrypted_bytes != 8 )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection keep alive packet. decrypted packet data is wrong size" );
                    return NULL;
                }

                struct snapshot_connection_keep_alive_packet_t * packet = (struct snapshot_connection_keep_alive_packet_t*) snapshot_malloc( context, sizeof( struct snapshot_connection_keep_alive_packet_t ) );

                if ( !packet )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection keep alive packet. could not allocate packet struct" );
                    return NULL;
                }
                
                packet->packet_type = SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET;
                packet->client_index = snapshot_read_uint32( &p );
                packet->max_clients = snapshot_read_uint32( &p );
                
                return packet;
            }
            break;
            
            case SNAPSHOT_CONNECTION_PAYLOAD_PACKET:
            {
                if ( decrypted_bytes < 1 )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection payload packet. payload is too small" );
                    return NULL;
                }

                if ( decrypted_bytes > SNAPSHOT_MAX_PAYLOAD_BYTES )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection payload packet. payload is too large" );
                    return NULL;
                }

                // todo: i want this to become zero copy
                struct snapshot_connection_payload_packet_t * packet = snapshot_create_payload_packet( context, decrypted_bytes );

                if ( !packet )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection payload packet. could not allocate packet struct" );
                    return NULL;
                }
                
                memcpy( packet->payload_data, p, decrypted_bytes );
                
                return packet;
            }
            break;

            case SNAPSHOT_CONNECTION_DISCONNECT_PACKET:
            {
                if ( decrypted_bytes != 0 )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection disconnect packet. decrypted packet data is wrong size" );
                    return NULL;
                }

                struct snapshot_connection_disconnect_packet_t * packet = (struct snapshot_connection_disconnect_packet_t*) snapshot_malloc( context, sizeof( struct snapshot_connection_disconnect_packet_t ) );

                if ( !packet )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "ignored connection disconnect packet. could not allocate packet struct" );
                    return NULL;
                }
                
                packet->packet_type = SNAPSHOT_CONNECTION_DISCONNECT_PACKET;
                
                return packet;
            }
            break;

            default:
                return NULL;
        }
    }
}

#endif // #ifndef SNAPSHOT_PACKETS_H
