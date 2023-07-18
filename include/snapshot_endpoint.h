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

#include <math.h>

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

// todo: we need to rework this a bit to make it zero copy
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

void snapshot_endpoint_receive_packet( struct snapshot_endpoint_t * endpoint, uint8_t * packet_data, int packet_bytes )
{
    snapshot_assert( endpoint );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes > 0 );

    if ( packet_bytes > endpoint->config.max_packet_size + SNAPSHOT_MAX_PACKET_HEADER_BYTES + SNAPSHOT_ENDPOINT_FRAGMENT_HEADER_BYTES )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] packet too large to receive. packet is at least %d bytes, maximum is %d\n", endpoint->config.name, packet_bytes - ( SNAPSHOT_MAX_PACKET_HEADER_BYTES + SNAPSHOT_ENDPOINT_FRAGMENT_HEADER_BYTES ), endpoint->config.max_packet_size );
        endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE]++;
        return;
    }

    uint8_t prefix_byte = packet_data[0];

    if ( ( prefix_byte & 1 ) == 0 )
    {
        // regular packet

        endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED]++;

        uint16_t sequence;
        uint16_t ack;
        uint32_t ack_bits;

        int packet_header_bytes = snapshot_read_packet_header( endpoint->config.name, packet_data, packet_bytes, &sequence, &ack, &ack_bits );
        if ( packet_header_bytes < 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] ignoring invalid packet. could not read packet header\n", endpoint->config.name );
            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_INVALID]++;
            return;
        }

        snapshot_assert( packet_header_bytes <= packet_bytes );

        int packet_payload_bytes = packet_bytes - packet_header_bytes;

        if ( packet_payload_bytes > endpoint->config.max_packet_size )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "[%s] packet too large to receive. packet is at %d bytes, maximum is %d\n", endpoint->config.name, packet_payload_bytes, endpoint->config.max_packet_size );
            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE]++;
            return;
        }

        if ( !snapshot_sequence_buffer_test_insert( endpoint->received_packets, sequence ) )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] ignoring stale packet %d\n", endpoint->config.name, sequence );
            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_STALE]++;
            return;
        }

        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] processing packet %d\n", endpoint->config.name, sequence );

        if ( endpoint->config.process_packet_function( endpoint->config.context, 
                                                       endpoint->config.index, 
                                                       sequence, 
                                                       packet_data + packet_header_bytes, 
                                                       packet_bytes - packet_header_bytes ) )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] process packet %d successful\n", endpoint->config.name, sequence );

            struct snapshot_endpoint_received_packet_data_t * received_packet_data = (struct snapshot_endpoint_received_packet_data_t*) snapshot_sequence_buffer_insert( endpoint->received_packets, sequence );

            snapshot_sequence_buffer_advance_with_cleanup( endpoint->fragment_reassembly, sequence, snapshot_endpoint_fragment_reassembly_data_cleanup );

            snapshot_assert( received_packet_data );

            received_packet_data->time = endpoint->time;
            received_packet_data->packet_bytes = endpoint->config.packet_header_size + packet_bytes;

            int i;
            for ( i = 0; i < 32; ++i )
            {
                if ( ack_bits & 1 )
                {                    
                    uint16_t ack_sequence = ack - ((uint16_t)i);
                    
                    struct snapshot_endpoint_sent_packet_data_t * sent_packet_data = (struct snapshot_endpoint_sent_packet_data_t*) snapshot_sequence_buffer_find( endpoint->sent_packets, ack_sequence );

                    if ( sent_packet_data && !sent_packet_data->acked && endpoint->num_acks < endpoint->config.ack_buffer_size )
                    {
                        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] acked packet %d\n", endpoint->config.name, ack_sequence );
                        endpoint->acks[endpoint->num_acks++] = ack_sequence;
                        endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_ACKED]++;
                        sent_packet_data->acked = 1;

                        float rtt = (float) ( endpoint->time - sent_packet_data->time ) * 1000.0f;
                        snapshot_assert( rtt >= 0.0 );
                        if ( ( endpoint->rtt == 0.0f && rtt > 0.0f ) || fabs( endpoint->rtt - rtt ) < 0.00001 )
                        {
                            endpoint->rtt = rtt;
                        }
                        else
                        {
                            endpoint->rtt += ( rtt - endpoint->rtt ) * endpoint->config.rtt_smoothing_factor;
                        }
                    }
                }
                ack_bits >>= 1;
            }
        }
        else
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "[%s] process packet failed\n", endpoint->config.name );
        }
    }
    else
    {
        // fragment packet

        int fragment_id;
        int num_fragments;
        int fragment_bytes;

        uint16_t sequence;
        uint16_t ack;
        uint32_t ack_bits;

        int fragment_header_bytes = snapshot_read_fragment_header( endpoint->config.name, 
                                                                   packet_data, 
                                                                   packet_bytes, 
                                                                   endpoint->config.max_fragments, 
                                                                   endpoint->config.fragment_size,
                                                                   &fragment_id, 
                                                                   &num_fragments, 
                                                                   &fragment_bytes, 
                                                                   &sequence, 
                                                                   &ack, 
                                                                   &ack_bits );

        if ( fragment_header_bytes < 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] ignoring invalid fragment. could not read fragment header\n", endpoint->config.name );
            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
            return;
        }

        struct snapshot_endpoint_fragment_reassembly_data_t * reassembly_data = (struct snapshot_endpoint_fragment_reassembly_data_t*)  snapshot_sequence_buffer_find( endpoint->fragment_reassembly, sequence );

        if ( !reassembly_data )
        {
            reassembly_data = (struct snapshot_endpoint_fragment_reassembly_data_t*) snapshot_sequence_buffer_insert_with_cleanup( endpoint->fragment_reassembly, sequence, snapshot_fragment_reassembly_data_cleanup );

            if ( !reassembly_data )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "[%s] ignoring invalid fragment. could not insert in reassembly buffer (stale)\n", endpoint->config.name );
                endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
                return;
            }

            snapshot_sequence_buffer_advance( endpoint->received_packets, sequence );

            int packet_buffer_size = SNAPSHOT_MAX_PACKET_HEADER_BYTES + num_fragments * endpoint->config.fragment_size;

            reassembly_data->sequence = sequence;
            reassembly_data->ack = 0;
            reassembly_data->ack_bits = 0;
            reassembly_data->num_fragments_received = 0;
            reassembly_data->num_fragments_total = num_fragments;
            reassembly_data->packet_data = (uint8_t*) endpoint->allocate_function( endpoint->allocator_context, packet_buffer_size );
            reassembly_data->packet_bytes = 0;
            memset( reassembly_data->fragment_received, 0, sizeof( reassembly_data->fragment_received ) );
        }

        if ( num_fragments != (int) reassembly_data->num_fragments_total )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "[%s] ignoring invalid fragment. fragment count mismatch. expected %d, got %d\n", endpoint->config.name, (int) reassembly_data->num_fragments_total, num_fragments );
            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
            return;
        }

        if ( reassembly_data->fragment_received[fragment_id] )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "[%s] ignoring fragment %d of packet %d. fragment already received\n", endpoint->config.name, fragment_id, sequence );
            return;
        }

        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] received fragment %d of packet %d (%d/%d)\n", endpoint->config.name, fragment_id, sequence, reassembly_data->num_fragments_received+1, num_fragments );

        reassembly_data->num_fragments_received++;
        reassembly_data->fragment_received[fragment_id] = 1;

        snapshot_store_fragment_data( reassembly_data, 
                                      sequence, 
                                      ack, 
                                      ack_bits, 
                                      fragment_id, 
                                      endpoint->config.fragment_size, 
                                      packet_data + fragment_header_bytes, 
                                      packet_bytes - fragment_header_bytes );

        if ( reassembly_data->num_fragments_received == reassembly_data->num_fragments_total )
        {
            snapshto_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] completed reassembly of packet %d\n", endpoint->config.name, sequence );

            snapshot_endpoint_receive_packet( endpoint, 
                                              reassembly_data->packet_data + SNAPSHOT_MAX_PACKET_HEADER_BYTES - reassembly_data->packet_header_bytes, 
                                              reassembly_data->packet_header_bytes + reassembly_data->packet_bytes );

            snapshot_sequence_buffer_remove_with_cleanup( endpoint->fragment_reassembly, sequence, snapshot_fragment_reassembly_data_cleanup );
        }

        endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED]++;
    }
}

uint16_t * snapshot_endpoint_get_acks( struct snapshot_endpoint_t * endpoint, int * num_acks )
{
    snapshto_assert( endpoint );
    snapshot_assert( num_acks );
    *num_acks = endpoint->num_acks;
    return endpoint->acks;
}

void snapshot_endpoint_clear_acks( struct snapshot_endpoint_t * endpoint )
{
    snapshot_assert( endpoint );
    endpoint->num_acks = 0;
}

void snapshot_endpoint_reset( struct snapshot_endpoint_t * endpoint )
{
    snapshot_assert( endpoint );

    endpoint->num_acks = 0;
    endpoint->sequence = 0;

    memset( endpoint->acks, 0, endpoint->config.ack_buffer_size * sizeof( uint16_t ) );
    memset( endpoint->counters, 0, SNAPSHOT_ENDPOINT_NUM_COUNTERS * sizeof( uint64_t ) );

    int i;
    for ( i = 0; i < endpoint->config.fragment_reassembly_buffer_size; ++i )
    {
        struct snapshot_fragment_reassembly_data_t * reassembly_data = (struct snapshot_fragment_reassembly_data_t*) snapshot_sequence_buffer_at_index( endpoint->fragment_reassembly, i );

        if ( reassembly_data && reassembly_data->packet_data )
        {
            endpoint->free_function( endpoint->allocator_context, reassembly_data->packet_data );
            reassembly_data->packet_data = NULL;
        }
    }

    snapshot_sequence_buffer_reset( endpoint->sent_packets );
    snapshot_sequence_buffer_reset( endpoint->received_packets );
    snapshot_sequence_buffer_reset( endpoint->fragment_reassembly );
}

void snapshot_endpoint_update( struct snapshot_endpoint_t * endpoint, double time )
{
    snapshot_assert( endpoint );

    endpoint->time = time;
    
    // calculate packet loss
    {
        uint32_t base_sequence = ( endpoint->sent_packets->sequence - endpoint->config.sent_packets_buffer_size + 1 ) + 0xFFFF;
        int i;
        int num_dropped = 0;
        int num_samples = endpoint->config.sent_packets_buffer_size / 2;
        for ( i = 0; i < num_samples; ++i )
        {
            uint16_t sequence = (uint16_t) ( base_sequence + i );
            struct snapshot_sent_packet_data_t * sent_packet_data = (struct snapshot_sent_packet_data_t*) snapshot_sequence_buffer_find( endpoint->sent_packets, sequence );
            if ( sent_packet_data && !sent_packet_data->acked )
            {
                num_dropped++;
            }
        }
        float packet_loss = ( (float) num_dropped ) / ( (float) num_samples ) * 100.0f;
        if ( fabs( endpoint->packet_loss - packet_loss ) > 0.00001 )
        {
            endpoint->packet_loss += ( packet_loss - endpoint->packet_loss ) * endpoint->config.packet_loss_smoothing_factor;
        }
        else
        {
            endpoint->packet_loss = packet_loss;
        }
    }

    // calculate sent bandwidth
    {
        uint32_t base_sequence = ( endpoint->sent_packets->sequence - endpoint->config.sent_packets_buffer_size + 1 ) + 0xFFFF;
        int i;
        int bytes_sent = 0;
        double start_time = FLT_MAX;
        double finish_time = 0.0;
        int num_samples = endpoint->config.sent_packets_buffer_size / 2;
        for ( i = 0; i < num_samples; ++i )
        {
            uint16_t sequence = (uint16_t) ( base_sequence + i );
            struct snapshot_sent_packet_data_t * sent_packet_data = (struct snapshot_sent_packet_data_t*) snapshot_sequence_buffer_find( endpoint->sent_packets, sequence );
            if ( !sent_packet_data )
            {
                continue;
            }
            bytes_sent += sent_packet_data->packet_bytes;
            if ( sent_packet_data->time < start_time )
            {
                start_time = sent_packet_data->time;
            }
            if ( sent_packet_data->time > finish_time )
            {
                finish_time = sent_packet_data->time;
            }
        }
        if ( start_time != FLT_MAX && finish_time != 0.0 )
        {
            float sent_bandwidth_kbps = (float) ( ( (double) bytes_sent ) / ( finish_time - start_time ) * 8.0f / 1000.0f );
            if ( fabs( endpoint->sent_bandwidth_kbps - sent_bandwidth_kbps ) > 0.00001 )
            {
                endpoint->sent_bandwidth_kbps += ( sent_bandwidth_kbps - endpoint->sent_bandwidth_kbps ) * endpoint->config.bandwidth_smoothing_factor;
            }
            else
            {
                endpoint->sent_bandwidth_kbps = sent_bandwidth_kbps;
            }
        }
    }

    // calculate received bandwidth
    {
        uint32_t base_sequence = ( endpoint->received_packets->sequence - endpoint->config.received_packets_buffer_size + 1 ) + 0xFFFF;
        int i;
        int bytes_sent = 0;
        double start_time = FLT_MAX;
        double finish_time = 0.0;
        int num_samples = endpoint->config.received_packets_buffer_size / 2;
        for ( i = 0; i < num_samples; ++i )
        {
            uint16_t sequence = (uint16_t) ( base_sequence + i );
            struct snapshot_received_packet_data_t * received_packet_data = (struct snapshot_received_packet_data_t*) snapshot_sequence_buffer_find( endpoint->received_packets, sequence );
            if ( !received_packet_data )
            {
                continue;
            }
            bytes_sent += received_packet_data->packet_bytes;
            if ( received_packet_data->time < start_time )
            {
                start_time = received_packet_data->time;
            }
            if ( received_packet_data->time > finish_time )
            {
                finish_time = received_packet_data->time;
            }
        }
        if ( start_time != FLT_MAX && finish_time != 0.0 )
        {
            float received_bandwidth_kbps = (float) ( ( (double) bytes_sent ) / ( finish_time - start_time ) * 8.0f / 1000.0f );
            if ( fabs( endpoint->received_bandwidth_kbps - received_bandwidth_kbps ) > 0.00001 )
            {
                endpoint->received_bandwidth_kbps += ( received_bandwidth_kbps - endpoint->received_bandwidth_kbps ) * endpoint->config.bandwidth_smoothing_factor;
            }
            else
            {
                endpoint->received_bandwidth_kbps = received_bandwidth_kbps;
            }
        }
    }

    // calculate acked bandwidth
    {
        uint32_t base_sequence = ( endpoint->sent_packets->sequence - endpoint->config.sent_packets_buffer_size + 1 ) + 0xFFFF;
        int i;
        int bytes_sent = 0;
        double start_time = FLT_MAX;
        double finish_time = 0.0;
        int num_samples = endpoint->config.sent_packets_buffer_size / 2;
        for ( i = 0; i < num_samples; ++i )
        {
            uint16_t sequence = (uint16_t) ( base_sequence + i );
            struct snapshot_sent_packet_data_t * sent_packet_data = (struct snapshot_sent_packet_data_t*) snapshot_sequence_buffer_find( endpoint->sent_packets, sequence );
            if ( !sent_packet_data || !sent_packet_data->acked )
            {
                continue;
            }
            bytes_sent += sent_packet_data->packet_bytes;
            if ( sent_packet_data->time < start_time )
            {
                start_time = sent_packet_data->time;
            }
            if ( sent_packet_data->time > finish_time )
            {
                finish_time = sent_packet_data->time;
            }
        }
        if ( start_time != FLT_MAX && finish_time != 0.0 )
        {
            float acked_bandwidth_kbps = (float) ( ( (double) bytes_sent ) / ( finish_time - start_time ) * 8.0f / 1000.0f );
            if ( fabs( endpoint->acked_bandwidth_kbps - acked_bandwidth_kbps ) > 0.00001 )
            {
                endpoint->acked_bandwidth_kbps += ( acked_bandwidth_kbps - endpoint->acked_bandwidth_kbps ) * endpoint->config.bandwidth_smoothing_factor;
            }
            else
            {
                endpoint->acked_bandwidth_kbps = acked_bandwidth_kbps;
            }
        }
    }
}

float snapshot_endpoint_rtt( struct snapshot_endpoint_t * endpoint )
{
    snapshot_assert( endpoint );
    return endpoint->rtt;
}

float snapshot_endpoint_packet_loss( struct snapshot_endpoint_t * endpoint )
{
    snapshot_assert( endpoint );
    return endpoint->packet_loss;
}

void snapshot_endpoint_bandwidth( struct snapshot_endpoint_t * endpoint, float * sent_bandwidth_kbps, float * received_bandwidth_kbps, float * acked_bandwidth_kbps )
{
    snapshot_assert( endpoint );
    snapshot_assert( sent_bandwidth_kbps );
    snapshot_assert( acked_bandwidth_kbps );
    snapshot_assert( received_bandwidth_kbps );
    *sent_bandwidth_kbps = endpoint->sent_bandwidth_kbps;
    *received_bandwidth_kbps = endpoint->received_bandwidth_kbps;
    *acked_bandwidth_kbps = endpoint->acked_bandwidth_kbps;
}

const uint64_t * snapshot_endpoint_counters( struct snapshot_endpoint_t * endpoint )
{
    snapshot_assert( endpoint );
    return endpoint->counters;
}

#endif // #ifndef SNAPSHOT_ENDPOINT_H
