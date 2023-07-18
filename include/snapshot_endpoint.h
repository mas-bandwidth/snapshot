/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_ENDPOINT_H
#define SNAPSHOT_ENDPOINT_H

#include "snapshot_packets.h"
#include "snapshot_read_write.h"
#include "snapshot_packet_header.h"
#include "snapshot_sequence_buffer.h"

#define SNAPSHOT_ENDPOINT_FRAGMENT_HEADER_BYTES                             5

#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_SENT                          0
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED                      1
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_ACKED                         2
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_STALE                         3
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_INVALID                       4
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND             5
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE          6
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT                        7
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED                    8
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID                     9
#define SNAPSHOT_ENDPOINT_NUM_COUNTERS                                      10

struct snapshot_endpoint_config_t
{
    void * context;
    char name[256];
    int index;
    int max_packet_size;
    int fragment_above;
    int max_fragments;
    int fragment_size;
    int ack_buffer_size;
    int sent_packets_buffer_size;
    int received_packets_buffer_size;
    int fragment_reassembly_buffer_size;
    float rtt_smoothing_factor;
    float packet_loss_smoothing_factor;
    float bandwidth_smoothing_factor;
    int packet_header_size;
    void (*transmit_packet_function)(void*,int,uint16_t,uint8_t*,int);
    int (*process_packet_function)(void*,int,uint16_t,uint8_t*,int);
};

void snapshot_endpoint_default_config( struct snapshot_endpoint_config_t * config )
{
    snapshot_assert( config );
    memset( config, 0, sizeof( struct snapshot_endpoint_config_t ) );
    config->name[0] = 'e';
    config->name[1] = 'n';
    config->name[2] = 'd';
    config->name[3] = 'p';
    config->name[4] = 'o';
    config->name[5] = 'i';
    config->name[6] = 'n';
    config->name[7] = 't';
    config->name[8] = '\0';
    config->max_packet_size = 16 * 1024;
    config->fragment_above = 1024;
    config->max_fragments = 16;
    config->fragment_size = 1024;
    config->ack_buffer_size = 256;
    config->sent_packets_buffer_size = 256;
    config->received_packets_buffer_size = 256;
    config->fragment_reassembly_buffer_size = 64;
    config->rtt_smoothing_factor = 0.0025f;
    config->packet_loss_smoothing_factor = 0.1f;
    config->bandwidth_smoothing_factor = 0.1f;
    config->packet_header_size = 28;                        // note: UDP over IPv4 = 20 + 8 bytes, UDP over IPv6 = 40 + 8 bytes
}

struct snapshot_endpoint_t
{
    void * context;
    struct snapshot_endpoint_config_t config;
    double time;
    float rtt;
    float packet_loss;
    float sent_bandwidth_kbps;
    float received_bandwidth_kbps;
    float acked_bandwidth_kbps;
    int num_acks;
    uint16_t * acks;
    uint16_t sequence;
    struct snapshot_sequence_buffer_t * sent_packets;
    struct snapshot_sequence_buffer_t * received_packets;
    struct snapshot_sequence_buffer_t * fragment_reassembly;
    uint64_t counters[SNAPSHOT_ENDPOINT_NUM_COUNTERS];
};

struct snapshot_endpoint_sent_packet_data_t
{
    double time;
    uint32_t acked : 1;
    uint32_t packet_bytes : 31;
};

struct snapshot_endpoint_received_packet_data_t
{
    double time;
    uint32_t packet_bytes;
};

struct snapshot_endpoint_fragment_reassembly_data_t
{
    uint16_t sequence;
    uint16_t ack;
    uint32_t ack_bits;
    int num_fragments_received;
    int num_fragments_total;
    uint8_t * packet_data;
    int packet_bytes;
    int packet_header_bytes;
    uint8_t fragment_received[256];        // todo: magic number here. no likey.
};

void snapshot_endpoint_fragment_reassembly_data_cleanup( void * context, void * data )
{
    struct snapshot_endpoint_fragment_reassembly_data_t * reassembly_data = (struct snapshot_endpoint_fragment_reassembly_data_t*) data;
    if ( reassembly_data->packet_data )
    {
        snapshot_free( context, reassembly_data->packet_data );
        reassembly_data->packet_data = NULL;
    }
}

struct snapshot_endpoint_t * snapshot_endpoint_create( struct snapshot_endpoint_config_t * config, double time )
{
    snapshot_assert( config );
    snapshot_assert( config->max_packet_size > 0 );
    snapshot_assert( config->fragment_above > 0 );
    snapshot_assert( config->max_fragments > 0 );
    snapshot_assert( config->max_fragments <= 256 );
    snapshot_assert( config->fragment_size > 0 );
    snapshot_assert( config->ack_buffer_size > 0 );
    snapshot_assert( config->sent_packets_buffer_size > 0 );
    snapshot_assert( config->received_packets_buffer_size > 0 );
    snapshot_assert( config->transmit_packet_function != NULL );
    snapshot_assert( config->process_packet_function != NULL );

    struct snapshot_endpoint_t * endpoint = (struct snapshot_endpoint_t*) snapshot_malloc( config->context, sizeof( struct snapshot_endpoint_t ) );

    snapshot_assert( endpoint );

    memset( endpoint, 0, sizeof( struct snapshot_endpoint_t ) );

    endpoint->context = config->context;
    endpoint->config = *config;
    endpoint->time = time;

    endpoint->acks = (uint16_t*) snapshot_malloc( config->context, config->ack_buffer_size * sizeof( uint16_t ) );
    
    endpoint->sent_packets = snapshot_sequence_buffer_create( config->context, config->sent_packets_buffer_size, sizeof( struct snapshot_endpoint_sent_packet_data_t ) );

    endpoint->received_packets = snapshot_sequence_buffer_create( config->context, config->received_packets_buffer_size, sizeof( struct snapshot_endpoint_received_packet_data_t ) );

    // todo    
    // endpoint->fragment_reassembly = snapshot_sequence_buffer_create( config->context, config->fragment_reassembly_buffer_size, sizeof( struct snapshot_endpoint_fragment_reassembly_data_t ) );

    memset( endpoint->acks, 0, config->ack_buffer_size * sizeof( uint16_t ) );

    return endpoint;
}

void snapshot_endpoint_destroy( struct snapshot_endpoint_t * endpoint )
{
    snapshot_assert( endpoint );
    snapshot_assert( endpoint->acks );
    snapshot_assert( endpoint->sent_packets );
    snapshot_assert( endpoint->received_packets );

    for ( int i = 0; i < endpoint->config.fragment_reassembly_buffer_size; ++i )
    {
        struct snapshot_endpoint_fragment_reassembly_data_t * reassembly_data = (struct snapshot_endpoint_fragment_reassembly_data_t*) snapshot_sequence_buffer_at_index( endpoint->fragment_reassembly, i );

        if ( reassembly_data && reassembly_data->packet_data )
        {
            snapshot_free( endpoint->context, reassembly_data->packet_data );
            reassembly_data->packet_data = NULL;
        }
    }

    snapshot_free( endpoint->context, endpoint->acks );

    snapshot_sequence_buffer_destroy( endpoint->sent_packets );
    snapshot_sequence_buffer_destroy( endpoint->received_packets );
    snapshot_sequence_buffer_destroy( endpoint->fragment_reassembly );

    snapshot_free( endpoint->context, endpoint );
}

uint16_t snapshot_endpoint_next_packet_sequence( struct snapshot_endpoint_t * endpoint )
{
    snapshot_assert( endpoint );
    return endpoint->sequence;
}

// todo: we need to rework this to make it zero copy
void snapshot_endpoint_send_packet( struct snapshot_endpoint_t * endpoint, uint8_t * packet_data, int packet_bytes )
{
    snapshot_assert( endpoint );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes > 0 );

    if ( packet_bytes > endpoint->config.max_packet_size )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "[%s] packet too large to send. packet is %d bytes, maximum is %d\n", endpoint->config.name, packet_bytes, endpoint->config.max_packet_size );
        endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND]++;
        return;
    }

    uint16_t sequence = endpoint->sequence++;
    uint16_t ack;
    uint32_t ack_bits;

    snapshot_sequence_buffer_generate_ack_bits( endpoint->received_packets, &ack, &ack_bits );

    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] sending packet %d\n", endpoint->config.name, sequence );

    struct snapshot_endpoint_sent_packet_data_t * sent_packet_data = (struct snapshot_endpoint_sent_packet_data_t*) snapshot_sequence_buffer_insert( endpoint->sent_packets, sequence );

    snapshot_assert( sent_packet_data );

    sent_packet_data->time = endpoint->time;
    sent_packet_data->packet_bytes = endpoint->config.packet_header_size + packet_bytes;
    sent_packet_data->acked = 0;

    if ( packet_bytes <= endpoint->config.fragment_above )
    {
        // regular packet

        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] sending packet %d without fragmentation\n", endpoint->config.name, sequence );

        uint8_t * transmit_packet_data = snapshot_create_packet( endpoint->context, packet_bytes + SNAPSHOT_MAX_PACKET_HEADER_BYTES );

        int packet_header_bytes = snapshot_write_packet_header( transmit_packet_data, sequence, ack, ack_bits );

        memcpy( transmit_packet_data + packet_header_bytes, packet_data, packet_bytes );

        endpoint->config.transmit_packet_function( endpoint->config.context, endpoint->config.index, sequence, transmit_packet_data, packet_header_bytes + packet_bytes );

        snapshot_destroy_packet( endpoint->context, transmit_packet_data );
    }
    else
    {
        // fragmented packet

        uint8_t packet_header[SNAPSHOT_MAX_PACKET_HEADER_BYTES];

        memset( packet_header, 0, SNAPSHOT_MAX_PACKET_HEADER_BYTES );

        int packet_header_bytes = snapshot_write_packet_header( packet_header, sequence, ack, ack_bits );        

        int num_fragments = ( packet_bytes / endpoint->config.fragment_size ) + ( ( packet_bytes % endpoint->config.fragment_size ) != 0 ? 1 : 0 );

        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] sending packet %d as %d fragments\n", endpoint->config.name, sequence, num_fragments );

        snapshot_assert( num_fragments >= 1 );
        snapshot_assert( num_fragments <= endpoint->config.max_fragments );

        int fragment_buffer_size = SNAPSHOT_ENDPOINT_FRAGMENT_HEADER_BYTES + SNAPSHOT_MAX_PACKET_HEADER_BYTES + endpoint->config.fragment_size;

        uint8_t * fragment_packet_data = snapshot_create_packet( endpoint->context, fragment_buffer_size );

        uint8_t * q = packet_data;

        uint8_t * end = q + packet_bytes;

        int fragment_id;
        for ( fragment_id = 0; fragment_id < num_fragments; ++fragment_id )
        {
            uint8_t * p = fragment_packet_data;

            snapshot_write_uint8( &p, 1 );
            snapshot_write_uint16( &p, sequence );
            snapshot_write_uint8( &p, (uint8_t) fragment_id );
            snapshot_write_uint8( &p, (uint8_t) ( num_fragments - 1 ) );

            if ( fragment_id == 0 )
            {
                memcpy( p, packet_header, packet_header_bytes );
                p += packet_header_bytes;
            }

            int bytes_to_copy = endpoint->config.fragment_size;
            if ( q + bytes_to_copy > end )
            {
                bytes_to_copy = (int) ( end - q );
            }

            memcpy( p, q, bytes_to_copy );

            p += bytes_to_copy;
            q += bytes_to_copy;

            int fragment_packet_bytes = (int) ( p - fragment_packet_data );

            endpoint->config.transmit_packet_function( endpoint->config.context, endpoint->config.index, sequence, fragment_packet_data, fragment_packet_bytes );

            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT]++;
        }

        snapshot_destroy_packet( endpoint->context, fragment_packet_data );
    }

    endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_SENT]++;
}

#endif // #ifndef SNAPSHOT_ENDPOINT_H
