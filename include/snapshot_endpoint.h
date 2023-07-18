/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_ENDPOINT_H
#define SNAPSHOT_ENDPOINT_H

#include "snapshot_sequence_buffer.h"

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

/*
void snapshot_endpoint_destroy( struct reliable_endpoint_t * endpoint )
{
    reliable_assert( endpoint );
    reliable_assert( endpoint->acks );
    reliable_assert( endpoint->sent_packets );
    reliable_assert( endpoint->received_packets );

    int i;
    for ( i = 0; i < endpoint->config.fragment_reassembly_buffer_size; ++i )
    {
        struct reliable_fragment_reassembly_data_t * reassembly_data = (struct reliable_fragment_reassembly_data_t*) 
            reliable_sequence_buffer_at_index( endpoint->fragment_reassembly, i );

        if ( reassembly_data && reassembly_data->packet_data )
        {
            endpoint->free_function( endpoint->allocator_context, reassembly_data->packet_data );
            reassembly_data->packet_data = NULL;
        }
    }

    endpoint->free_function( endpoint->allocator_context, endpoint->acks );

    reliable_sequence_buffer_destroy( endpoint->sent_packets );
    reliable_sequence_buffer_destroy( endpoint->received_packets );
    reliable_sequence_buffer_destroy( endpoint->fragment_reassembly );

    endpoint->free_function( endpoint->allocator_context, endpoint );
}

uint16_t reliable_endpoint_next_packet_sequence( struct reliable_endpoint_t * endpoint )
{
    reliable_assert( endpoint );
    return endpoint->sequence;
}

int reliable_write_packet_header( uint8_t * packet_data, uint16_t sequence, uint16_t ack, uint32_t ack_bits )
{
    uint8_t * p = packet_data;

    uint8_t prefix_byte = 0;

    if ( ( ack_bits & 0x000000FF ) != 0x000000FF )
    {
        prefix_byte |= (1<<1);
    }

    if ( ( ack_bits & 0x0000FF00 ) != 0x0000FF00 )
    {
        prefix_byte |= (1<<2);
    }

    if ( ( ack_bits & 0x00FF0000 ) != 0x00FF0000 )
    {
        prefix_byte |= (1<<3);
    }

    if ( ( ack_bits & 0xFF000000 ) != 0xFF000000 )
    {
        prefix_byte |= (1<<4);
    }

    int sequence_difference = sequence - ack;
    if ( sequence_difference < 0 )
        sequence_difference += 65536;
    if ( sequence_difference <= 255 )
        prefix_byte |= (1<<5);

    reliable_write_uint8( &p, prefix_byte );

    reliable_write_uint16( &p, sequence );

    if ( sequence_difference <= 255 )
    {
        reliable_write_uint8( &p, (uint8_t) sequence_difference );
    }
    else
    {
        reliable_write_uint16( &p, ack );
    }

    if ( ( ack_bits & 0x000000FF ) != 0x000000FF )
    {
        reliable_write_uint8( &p, (uint8_t) ( ack_bits & 0x000000FF ) );
    }

    if ( ( ack_bits & 0x0000FF00 ) != 0x0000FF00 )
    {
        reliable_write_uint8( &p, (uint8_t) ( ( ack_bits & 0x0000FF00 ) >> 8 ) );
    }

    if ( ( ack_bits & 0x00FF0000 ) != 0x00FF0000 )
    {
        reliable_write_uint8( &p, (uint8_t) ( ( ack_bits & 0x00FF0000 ) >> 16 ) );
    }

    if ( ( ack_bits & 0xFF000000 ) != 0xFF000000 )
    {
        reliable_write_uint8( &p, (uint8_t) ( ( ack_bits & 0xFF000000 ) >> 24 ) );
    }

    reliable_assert( p - packet_data <= RELIABLE_MAX_PACKET_HEADER_BYTES );

    return (int) ( p - packet_data );
}

void reliable_endpoint_send_packet( struct reliable_endpoint_t * endpoint, uint8_t * packet_data, int packet_bytes )
{
    reliable_assert( endpoint );
    reliable_assert( packet_data );
    reliable_assert( packet_bytes > 0 );

    if ( packet_bytes > endpoint->config.max_packet_size )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] packet too large to send. packet is %d bytes, maximum is %d\n", 
            endpoint->config.name, packet_bytes, endpoint->config.max_packet_size );
        endpoint->counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND]++;
        return;
    }

    uint16_t sequence = endpoint->sequence++;
    uint16_t ack;
    uint32_t ack_bits;

    reliable_sequence_buffer_generate_ack_bits( endpoint->received_packets, &ack, &ack_bits );

    reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] sending packet %d\n", endpoint->config.name, sequence );

    struct reliable_sent_packet_data_t * sent_packet_data = (struct reliable_sent_packet_data_t*) reliable_sequence_buffer_insert( endpoint->sent_packets, sequence );

    reliable_assert( sent_packet_data );

    sent_packet_data->time = endpoint->time;
    sent_packet_data->packet_bytes = endpoint->config.packet_header_size + packet_bytes;
    sent_packet_data->acked = 0;

    if ( packet_bytes <= endpoint->config.fragment_above )
    {
        // regular packet

        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] sending packet %d without fragmentation\n", endpoint->config.name, sequence );

        uint8_t * transmit_packet_data = (uint8_t*) endpoint->allocate_function( endpoint->allocator_context, packet_bytes + RELIABLE_MAX_PACKET_HEADER_BYTES );

        int packet_header_bytes = reliable_write_packet_header( transmit_packet_data, sequence, ack, ack_bits );

        memcpy( transmit_packet_data + packet_header_bytes, packet_data, packet_bytes );

        endpoint->config.transmit_packet_function( endpoint->config.context, endpoint->config.index, sequence, transmit_packet_data, packet_header_bytes + packet_bytes );

        endpoint->free_function( endpoint->allocator_context, transmit_packet_data );
    }
    else
    {
        // fragmented packet

        uint8_t packet_header[RELIABLE_MAX_PACKET_HEADER_BYTES];

        memset( packet_header, 0, RELIABLE_MAX_PACKET_HEADER_BYTES );

        int packet_header_bytes = reliable_write_packet_header( packet_header, sequence, ack, ack_bits );        

        int num_fragments = ( packet_bytes / endpoint->config.fragment_size ) + ( ( packet_bytes % endpoint->config.fragment_size ) != 0 ? 1 : 0 );

        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] sending packet %d as %d fragments\n", endpoint->config.name, sequence, num_fragments );

        reliable_assert( num_fragments >= 1 );
        reliable_assert( num_fragments <= endpoint->config.max_fragments );

        int fragment_buffer_size = RELIABLE_FRAGMENT_HEADER_BYTES + RELIABLE_MAX_PACKET_HEADER_BYTES + endpoint->config.fragment_size;

        uint8_t * fragment_packet_data = (uint8_t*) endpoint->allocate_function( endpoint->allocator_context, fragment_buffer_size );

        uint8_t * q = packet_data;

        uint8_t * end = q + packet_bytes;

        int fragment_id;
        for ( fragment_id = 0; fragment_id < num_fragments; ++fragment_id )
        {
            uint8_t * p = fragment_packet_data;

            reliable_write_uint8( &p, 1 );
            reliable_write_uint16( &p, sequence );
            reliable_write_uint8( &p, (uint8_t) fragment_id );
            reliable_write_uint8( &p, (uint8_t) ( num_fragments - 1 ) );

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

            endpoint->counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT]++;
        }

        endpoint->free_function( endpoint->allocator_context, fragment_packet_data );
    }

    endpoint->counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT]++;
}
*/

#endif // #ifndef SNAPSHOT_ENDPOINT_H
