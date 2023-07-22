/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_endpoint.h"
#include "snapshot_packets.h"
#include "snapshot_read_write.h"
#include "snapshot_packet_header.h"
#include "snapshot_sequence_buffer.h"

#include <math.h>
#include <float.h>

// -----------------------------------------------------------------------------------------

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
    int num_fragments_received;
    int num_fragments_total;
    uint16_t payload_sequence;
    uint16_t payload_ack;
    uint32_t payload_ack_bits;
    uint8_t * payload_data;
    int payload_bytes;
    uint8_t fragment_received[SNAPSHOT_MAX_FRAGMENTS];
};

void snapshot_fragment_reassembly_data_cleanup( void * context, void * data )
{
    struct snapshot_endpoint_fragment_reassembly_data_t * reassembly_data = (struct snapshot_endpoint_fragment_reassembly_data_t*) data;
    if ( reassembly_data->payload_data )
    {
        snapshot_destroy_packet( context, reassembly_data->payload_data );
        reassembly_data->payload_data = NULL;
    }
}

int snapshot_read_fragment_header( char * name, 
                                   const uint8_t * packet_data, 
                                   int packet_bytes, 
                                   int max_fragments, 
                                   int fragment_size, 
                                   int * fragment_id, 
                                   int * num_fragments, 
                                   int * fragment_bytes, 
                                   uint16_t * sequence, 
                                   uint16_t * ack, 
                                   uint32_t * ack_bits )
{
    if ( packet_bytes < SNAPSHOT_FRAGMENT_HEADER_BYTES )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] packet is too small to read fragment header", name );
        return -1;
    }

    const uint8_t * p = packet_data;

    uint8_t prefix_byte = snapshot_read_uint8( &p );
    if ( prefix_byte != 1 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] prefix byte is not a fragment", name );
        return -1;
    }
    
    *sequence = snapshot_read_uint16( &p );
    *fragment_id = (int) snapshot_read_uint8( &p );
    *num_fragments = ( (int) snapshot_read_uint8( &p ) ) + 1;

    if ( *num_fragments > max_fragments )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] num fragments %d outside of range of max fragments %d", name, *num_fragments, max_fragments );
        return -1;
    }

    if ( *fragment_id >= *num_fragments )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] fragment id %d outside of range of num fragments %d", name, *fragment_id, *num_fragments );
        return -1;
    }

    *fragment_bytes = packet_bytes - SNAPSHOT_FRAGMENT_HEADER_BYTES;

    if ( *fragment_id == 0 )
    {
        uint16_t packet_sequence = 0;
        uint16_t packet_ack = 0;
        uint32_t packet_ack_bits = 0;

        int packet_header_bytes = snapshot_read_packet_header( name, 
                                                               packet_data + SNAPSHOT_FRAGMENT_HEADER_BYTES, 
                                                               packet_bytes, 
                                                               &packet_sequence, 
                                                               &packet_ack, 
                                                               &packet_ack_bits );

        if ( packet_header_bytes < 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] bad packet header in fragment", name );
            return -1;
        }

        if ( packet_sequence != *sequence )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] bad packet sequence in fragment. expected %d, got %d", name, *sequence, packet_sequence );
            return -1;
        }

        *ack = packet_ack;
        *ack_bits = packet_ack_bits;
        *fragment_bytes -= packet_header_bytes;

        p += packet_header_bytes;
    }
    else
    {
        *ack = 0;
        *ack_bits = 0;
    }

    if ( *fragment_bytes > fragment_size )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] fragment bytes %d > fragment size %d", name, *fragment_bytes, fragment_size );
        return - 1;
    }

    if ( *fragment_id != *num_fragments - 1 && *fragment_bytes != fragment_size )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] fragment %d is %d bytes, which is not the expected fragment size %d", name, *fragment_id, *fragment_bytes, fragment_size );
        return -1;
    }

    return (int) ( p - packet_data );
}

void snapshot_store_fragment_data( struct snapshot_endpoint_fragment_reassembly_data_t * reassembly_data, 
                                   int fragment_id, 
                                   int fragment_size, 
                                   uint8_t * fragment_data, 
                                   int fragment_bytes,
                                   uint16_t payload_sequence,
                                   uint16_t payload_ack,
                                   uint32_t payload_ack_bits )
{
    snapshot_assert( reassembly_data );
    snapshot_assert( fragment_id >= 0 );
    snapshot_assert( fragment_id < SNAPSHOT_MAX_FRAGMENTS );
    snapshot_assert( fragment_id < reassembly_data->num_fragments_total );
    snapshot_assert( fragment_data );
    snapshot_assert( fragment_bytes > 0 );
    snapshot_assert( fragment_bytes <= fragment_size );

    memcpy( reassembly_data->payload_data + fragment_id * fragment_size, fragment_data, fragment_bytes );

    if ( fragment_id == 0 )
    {
        reassembly_data->payload_sequence = payload_sequence;
        reassembly_data->payload_ack = payload_ack;
        reassembly_data->payload_ack_bits = payload_ack_bits;
    }

    if ( fragment_id == reassembly_data->num_fragments_total - 1 )
    {
        reassembly_data->payload_bytes = ( reassembly_data->num_fragments_total - 1 ) * fragment_size + fragment_bytes;
    }
}

// -----------------------------------------------------------------------------------------

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

struct snapshot_endpoint_t * snapshot_endpoint_create( struct snapshot_endpoint_config_t * config, double time )
{
    snapshot_assert( config );
    snapshot_assert( config->fragment_above > 0 );
    snapshot_assert( config->max_fragments > 0 );
    snapshot_assert( config->max_fragments <= 256 );
    snapshot_assert( config->max_fragments <= SNAPSHOT_MAX_FRAGMENTS );
    snapshot_assert( config->fragment_size > 0 );
    snapshot_assert( config->ack_buffer_size > 0 );
    snapshot_assert( config->sent_packets_buffer_size > 0 );
    snapshot_assert( config->received_packets_buffer_size > 0 );

    struct snapshot_endpoint_t * endpoint = (struct snapshot_endpoint_t*) snapshot_malloc( config->context, sizeof( struct snapshot_endpoint_t ) );

    snapshot_assert( endpoint );

    memset( endpoint, 0, sizeof( struct snapshot_endpoint_t ) );

    endpoint->context = config->context;
    endpoint->config = *config;
    endpoint->time = time;

    endpoint->acks = (uint16_t*) snapshot_malloc( config->context, config->ack_buffer_size * sizeof( uint16_t ) );
    
    endpoint->sent_packets = snapshot_sequence_buffer_create( config->context, config->sent_packets_buffer_size, sizeof( struct snapshot_endpoint_sent_packet_data_t ) );

    endpoint->received_packets = snapshot_sequence_buffer_create( config->context, config->received_packets_buffer_size, sizeof( struct snapshot_endpoint_received_packet_data_t ) );

    endpoint->fragment_reassembly = snapshot_sequence_buffer_create( config->context, config->fragment_reassembly_buffer_size, sizeof( struct snapshot_endpoint_fragment_reassembly_data_t ) );

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

        if ( reassembly_data && reassembly_data->payload_data )
        {
            snapshot_destroy_packet( endpoint->context, reassembly_data->payload_data );
            reassembly_data->payload_data = NULL;
        }
    }

    snapshot_free( endpoint->context, endpoint->acks );

    snapshot_sequence_buffer_destroy( endpoint->sent_packets );
    snapshot_sequence_buffer_destroy( endpoint->received_packets );
    snapshot_sequence_buffer_destroy( endpoint->fragment_reassembly );

    snapshot_free( endpoint->context, endpoint );
}

uint16_t snapshot_endpoint_sequence( struct snapshot_endpoint_t * endpoint )
{
    snapshot_assert( endpoint );
    return endpoint->sequence;
}

void snapshot_endpoint_write_packets( struct snapshot_endpoint_t * endpoint, uint8_t * payload_data, int payload_bytes, int * num_packets, uint8_t ** packet_data, int * packet_bytes )
{
    snapshot_assert( endpoint );
    snapshot_assert( payload_data );
    snapshot_assert( payload_bytes > 0 );
    snapshot_assert( payload_bytes <= SNAPSHOT_MAX_PAYLOAD_BYTES );
    snapshot_assert( num_packets );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes );

    if ( payload_bytes > SNAPSHOT_MAX_PAYLOAD_BYTES )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "[%s] packet too large to send. payload is %d bytes, maximum is %d", endpoint->config.name, payload_bytes, SNAPSHOT_MAX_PAYLOAD_BYTES );
        endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND]++;
        return;
    }

    uint16_t sequence = endpoint->sequence++;
    uint16_t ack;
    uint32_t ack_bits;

    snapshot_sequence_buffer_generate_ack_bits( endpoint->received_packets, &ack, &ack_bits );

    struct snapshot_endpoint_sent_packet_data_t * sent_packet_data = (struct snapshot_endpoint_sent_packet_data_t*) snapshot_sequence_buffer_insert( endpoint->sent_packets, sequence );

    snapshot_assert( sent_packet_data );

    sent_packet_data->time = endpoint->time;
    sent_packet_data->packet_bytes = endpoint->config.packet_header_size + payload_bytes;
    sent_packet_data->acked = 0;

    if ( payload_bytes <= endpoint->config.fragment_above )
    {
        // regular packet

        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] sending payload %d without fragmentation", endpoint->config.name, sequence );

        uint8_t header[SNAPSHOT_MAX_PACKET_HEADER_BYTES];

        memset( header, 0, SNAPSHOT_MAX_PACKET_HEADER_BYTES );

        int header_bytes = snapshot_write_packet_header( header, sequence, ack, ack_bits );

        *num_packets = 1;
        packet_data[0] = payload_data - header_bytes;
        packet_bytes[0] = payload_bytes + header_bytes;

        memcpy( packet_data[0], header, header_bytes );
    }
    else
    {
        // fragmented packet

        int num_fragments = ( payload_bytes / endpoint->config.fragment_size ) + ( ( payload_bytes % endpoint->config.fragment_size ) != 0 ? 1 : 0 );

        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] sending packet %d as %d fragments", endpoint->config.name, sequence, num_fragments );

        snapshot_assert( num_fragments >= 1 );
        snapshot_assert( num_fragments <= endpoint->config.max_fragments );

        int fragment_buffer_size = SNAPSHOT_FRAGMENT_HEADER_BYTES + SNAPSHOT_MAX_PACKET_HEADER_BYTES + endpoint->config.fragment_size;

        uint8_t * q = payload_data;

        uint8_t * end = q + payload_bytes;

        for ( int fragment_id = 0; fragment_id < num_fragments; ++fragment_id )
        {
            uint8_t * fragment_packet_data = snapshot_create_packet( endpoint->context, fragment_buffer_size );

            uint8_t * p = fragment_packet_data;

            snapshot_write_uint8( &p, 1 ); // fragment
            snapshot_write_uint16( &p, sequence );
            snapshot_write_uint8( &p, (uint8_t) fragment_id );
            snapshot_write_uint8( &p, (uint8_t) ( num_fragments - 1 ) );

            if ( fragment_id == 0 )
            {
                uint8_t header[SNAPSHOT_MAX_PACKET_HEADER_BYTES];
                memset( header, 0, SNAPSHOT_MAX_PACKET_HEADER_BYTES );
                int header_bytes = snapshot_write_packet_header( header, sequence, ack, ack_bits );
                memcpy( p, header, header_bytes );
                p += header_bytes;
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

            packet_data[fragment_id] = fragment_packet_data;
            packet_bytes[fragment_id] = fragment_packet_bytes;

            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT]++;
        }

        *num_packets = num_fragments;
    }

    endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_SENT]++;
}

void snapshot_endpoint_process_packet( struct snapshot_endpoint_t * endpoint, uint8_t * packet_data, int packet_bytes, uint8_t * payload_buffer, uint8_t ** out_payload_data, int * out_payload_bytes, uint16_t * out_payload_sequence, uint16_t * out_payload_ack, uint32_t * out_payload_ack_bits )
{
    snapshot_assert( endpoint );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes > 0 );
    snapshot_assert( payload_buffer );
    snapshot_assert( out_payload_data );
    snapshot_assert( out_payload_sequence );
    snapshot_assert( out_payload_ack );
    snapshot_assert( out_payload_ack_bits );

    *out_payload_data = NULL;
    *out_payload_bytes = 0;
    *out_payload_sequence = 0;

    if ( packet_bytes > SNAPSHOT_MAX_PACKET_BYTES + SNAPSHOT_MAX_PACKET_HEADER_BYTES + SNAPSHOT_FRAGMENT_HEADER_BYTES )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] packet too large to receive. packet is at least %d bytes, maximum is %d", endpoint->config.name, packet_bytes - ( SNAPSHOT_MAX_PACKET_HEADER_BYTES + SNAPSHOT_FRAGMENT_HEADER_BYTES ), SNAPSHOT_MAX_PACKET_BYTES );
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
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] ignoring invalid packet. could not read packet header", endpoint->config.name );
            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_INVALID]++;
            return;
        }

        snapshot_assert( packet_header_bytes <= packet_bytes );

        int packet_payload_bytes = packet_bytes - packet_header_bytes;

        if ( packet_payload_bytes > SNAPSHOT_MAX_PAYLOAD_BYTES )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "[%s] payload too large to receive. payload is at %d bytes, maximum is %d", endpoint->config.name, packet_payload_bytes, SNAPSHOT_MAX_PAYLOAD_BYTES );
            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE]++;
            return;
        }

        if ( !snapshot_sequence_buffer_test_insert( endpoint->received_packets, sequence ) )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] ignoring stale packet %d", endpoint->config.name, sequence );
            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_STALE]++;
            return;
        }

        *out_payload_data = packet_data + packet_header_bytes;
        *out_payload_bytes = packet_bytes - packet_header_bytes;
        *out_payload_sequence = sequence;
        *out_payload_ack = ack;
        *out_payload_ack_bits = ack_bits;
    }
    else
    {
        // fragment

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
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] ignoring invalid fragment. could not read fragment header", endpoint->config.name );
            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
            return;
        }

        struct snapshot_endpoint_fragment_reassembly_data_t * reassembly_data = (struct snapshot_endpoint_fragment_reassembly_data_t*)  snapshot_sequence_buffer_find( endpoint->fragment_reassembly, sequence );

        if ( !reassembly_data )
        {
            reassembly_data = (struct snapshot_endpoint_fragment_reassembly_data_t*) snapshot_sequence_buffer_insert_with_cleanup( endpoint->fragment_reassembly, sequence, snapshot_fragment_reassembly_data_cleanup );

            if ( !reassembly_data )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "[%s] ignoring invalid fragment. could not insert in reassembly buffer (stale)", endpoint->config.name );
                endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
                return;
            }

            snapshot_sequence_buffer_advance( endpoint->received_packets, sequence );

            int payload_buffer_size = num_fragments * endpoint->config.fragment_size;

            reassembly_data->num_fragments_received = 0;
            reassembly_data->num_fragments_total = num_fragments;
            reassembly_data->payload_data = snapshot_create_packet( endpoint->context, payload_buffer_size );
            reassembly_data->payload_bytes = 0;
            memset( reassembly_data->fragment_received, 0, sizeof( reassembly_data->fragment_received ) );
        }

        if ( num_fragments != (int) reassembly_data->num_fragments_total )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "[%s] ignoring invalid fragment. fragment count mismatch. expected %d, got %d", endpoint->config.name, (int) reassembly_data->num_fragments_total, num_fragments );
            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
            return;
        }

        if ( reassembly_data->fragment_received[fragment_id] )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "[%s] ignoring fragment %d of payload %d. fragment already received", endpoint->config.name, fragment_id, sequence );
            return;
        }

        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] received fragment %d of payload %d (%d/%d)", endpoint->config.name, fragment_id, sequence, reassembly_data->num_fragments_received+1, num_fragments );

        reassembly_data->num_fragments_received++;
        reassembly_data->fragment_received[fragment_id] = 1;

        snapshot_store_fragment_data( reassembly_data, 
                                      fragment_id, 
                                      endpoint->config.fragment_size, 
                                      packet_data + fragment_header_bytes, 
                                      packet_bytes - fragment_header_bytes,
                                      sequence, 
                                      ack, 
                                      ack_bits );

        endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED]++;

        if ( reassembly_data->num_fragments_received == reassembly_data->num_fragments_total )
        {
            snapshot_assert( reassembly_data->payload_data );

            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] completed reassembly of payload %d", endpoint->config.name, sequence );

            int payload_bytes = reassembly_data->payload_bytes;

            if ( payload_bytes > SNAPSHOT_MAX_PAYLOAD_BYTES )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "[%s] payload too large to receive. payload is at %d bytes, maximum is %d", endpoint->config.name, payload_bytes, SNAPSHOT_MAX_PAYLOAD_BYTES );
                endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE]++;
                return;
            }

            memcpy( payload_buffer, reassembly_data->payload_data, payload_bytes );

            snapshot_sequence_buffer_remove_with_cleanup( endpoint->fragment_reassembly, sequence, snapshot_fragment_reassembly_data_cleanup );

            if ( !snapshot_sequence_buffer_test_insert( endpoint->received_packets, sequence ) )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] ignoring stale packet %d", endpoint->config.name, sequence );
                endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_STALE]++;
                return;
            }

            *out_payload_data = payload_buffer;
            *out_payload_bytes = payload_bytes;
            *out_payload_sequence = reassembly_data->payload_sequence;
            *out_payload_ack = reassembly_data->payload_ack;
            *out_payload_ack_bits = reassembly_data->payload_ack_bits;

            endpoint->counters[SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED]++;
        }
    }
}

void snapshot_endpoint_mark_payload_processed( snapshot_endpoint_t * endpoint, uint16_t sequence, uint16_t ack, uint32_t ack_bits, int payload_bytes )
{
    snapshot_assert( endpoint );

    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] marking packet %d as processed", endpoint->config.name, sequence );

    struct snapshot_endpoint_received_packet_data_t * received_packet_data = (struct snapshot_endpoint_received_packet_data_t*) snapshot_sequence_buffer_insert( endpoint->received_packets, sequence );

    snapshot_assert( received_packet_data );

    received_packet_data->time = endpoint->time;
    received_packet_data->packet_bytes = endpoint->config.packet_header_size + payload_bytes;

    snapshot_sequence_buffer_advance_with_cleanup( endpoint->fragment_reassembly, sequence, snapshot_fragment_reassembly_data_cleanup );

    for ( int i = 0; i < 32; ++i )
    {
        if ( ack_bits & 1 )
        {                    
            uint16_t ack_sequence = ack - ((uint16_t)i);
            
            struct snapshot_endpoint_sent_packet_data_t * sent_packet_data = (struct snapshot_endpoint_sent_packet_data_t*) snapshot_sequence_buffer_find( endpoint->sent_packets, ack_sequence );

            if ( sent_packet_data && !sent_packet_data->acked && endpoint->num_acks < endpoint->config.ack_buffer_size )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] acked packet %d", endpoint->config.name, ack_sequence );
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

uint16_t * snapshot_endpoint_get_acks( struct snapshot_endpoint_t * endpoint, int * num_acks )
{
    snapshot_assert( endpoint );
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

    for ( int i = 0; i < endpoint->config.fragment_reassembly_buffer_size; ++i )
    {
        struct snapshot_endpoint_fragment_reassembly_data_t * reassembly_data = (struct snapshot_endpoint_fragment_reassembly_data_t*) snapshot_sequence_buffer_at_index( endpoint->fragment_reassembly, i );

        if ( reassembly_data && reassembly_data->payload_data )
        {
            snapshot_destroy_packet( endpoint->context, reassembly_data->payload_data );
            reassembly_data->payload_data = NULL;
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
        int num_dropped = 0;
        int num_samples = endpoint->config.sent_packets_buffer_size / 2;
        for ( int i = 0; i < num_samples; ++i )
        {
            uint16_t sequence = (uint16_t) ( base_sequence + i );
            struct snapshot_endpoint_sent_packet_data_t * sent_packet_data = (struct snapshot_endpoint_sent_packet_data_t*) snapshot_sequence_buffer_find( endpoint->sent_packets, sequence );
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
        int bytes_sent = 0;
        double start_time = FLT_MAX;
        double finish_time = 0.0;
        int num_samples = endpoint->config.sent_packets_buffer_size / 2;
        for ( int i = 0; i < num_samples; ++i )
        {
            uint16_t sequence = (uint16_t) ( base_sequence + i );
            struct snapshot_endpoint_sent_packet_data_t * sent_packet_data = (struct snapshot_endpoint_sent_packet_data_t*) snapshot_sequence_buffer_find( endpoint->sent_packets, sequence );
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
        int bytes_sent = 0;
        double start_time = FLT_MAX;
        double finish_time = 0.0;
        int num_samples = endpoint->config.received_packets_buffer_size / 2;
        for ( int i = 0; i < num_samples; ++i )
        {
            uint16_t sequence = (uint16_t) ( base_sequence + i );
            struct snapshot_endpoint_received_packet_data_t * received_packet_data = (struct snapshot_endpoint_received_packet_data_t*) snapshot_sequence_buffer_find( endpoint->received_packets, sequence );
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
        int bytes_sent = 0;
        double start_time = FLT_MAX;
        double finish_time = 0.0;
        int num_samples = endpoint->config.sent_packets_buffer_size / 2;
        for ( int i = 0; i < num_samples; ++i )
        {
            uint16_t sequence = (uint16_t) ( base_sequence + i );
            struct snapshot_endpoint_sent_packet_data_t * sent_packet_data = (struct snapshot_endpoint_sent_packet_data_t*) snapshot_sequence_buffer_find( endpoint->sent_packets, sequence );
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
