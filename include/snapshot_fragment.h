/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_FRAGMENT_H
#define SNAPSHOT_FRAGMENT_H

#include "snapshot.h"
#include "snapshot_packets.h"
#include "snapshot_read_write.h"

#define SNAPSHOT_FRAGMENT_HEADER_BYTES           5
#define SNAPSHOT_MAX_FRAGMENTS                 256

struct snapshot_fragment_reassembly_data_t
{
    uint16_t sequence;
    uint16_t ack;
    uint32_t ack_bits;
    int num_fragments_received;
    int num_fragments_total;
    uint8_t * packet_data;
    int packet_bytes;
    int packet_header_bytes;
    uint8_t fragment_received[SNAPSHOT_MAX_FRAGMENTS];
};

void snapshot_fragment_reassembly_data_cleanup( void * context, void * data )
{
    struct snapshot_fragment_reassembly_data_t * reassembly_data = (struct snapshot_fragment_reassembly_data_t*) data;
    if ( reassembly_data->packet_data )
    {
        snapshot_destroy_packet( context, reassembly_data->packet_data );
        reassembly_data->packet_data = NULL;
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
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] packet is too small to read fragment header\n", name );
        return -1;
    }

    const uint8_t * p = packet_data;

    uint8_t prefix_byte = snapshot_read_uint8( &p );
    if ( prefix_byte != 1 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] prefix byte is not a fragment\n", name );
        return -1;
    }
    
    *sequence = snapshot_read_uint16( &p );
    *fragment_id = (int) snapshot_read_uint8( &p );
    *num_fragments = ( (int) snapshot_read_uint8( &p ) ) + 1;

    if ( *num_fragments > max_fragments )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] num fragments %d outside of range of max fragments %d\n", name, *num_fragments, max_fragments );
        return -1;
    }

    if ( *fragment_id >= *num_fragments )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] fragment id %d outside of range of num fragments %d\n", name, *fragment_id, *num_fragments );
        return -1;
    }

    *fragment_bytes = packet_bytes - SNAPSHOT_FRAGMENT_HEADER_BYTES;

    uint16_t packet_sequence = 0;
    uint16_t packet_ack = 0;
    uint32_t packet_ack_bits = 0;

    if ( *fragment_id == 0 )
    {
        int packet_header_bytes = snapshot_read_packet_header( name, 
                                                               packet_data + SNAPSHOT_FRAGMENT_HEADER_BYTES, 
                                                               packet_bytes, 
                                                               &packet_sequence, 
                                                               &packet_ack, 
                                                               &packet_ack_bits );

        if ( packet_header_bytes < 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] bad packet header in fragment\n", name );
            return -1;
        }

        if ( packet_sequence != *sequence )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] bad packet sequence in fragment. expected %d, got %d\n", name, *sequence, packet_sequence );
            return -1;
        }

        *fragment_bytes = packet_bytes - packet_header_bytes - SNAPSHOT_FRAGMENT_HEADER_BYTES;
    }

    *ack = packet_ack;
    *ack_bits = packet_ack_bits;

    if ( *fragment_bytes > fragment_size )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] fragment bytes %d > fragment size %d\n", name, *fragment_bytes, fragment_size );
        return - 1;
    }

    if ( *fragment_id != *num_fragments - 1 && *fragment_bytes != fragment_size )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] fragment %d is %d bytes, which is not the expected fragment size %d\n", name, *fragment_id, *fragment_bytes, fragment_size );
        return -1;
    }

    return (int) ( p - packet_data );
}

void snapshot_store_fragment_data( struct snapshot_fragment_reassembly_data_t * reassembly_data, 
                                   uint16_t sequence, 
                                   uint16_t ack, 
                                   uint32_t ack_bits, 
                                   int fragment_id, 
                                   int fragment_size, 
                                   uint8_t * fragment_data, 
                                   int fragment_bytes )
{
    if ( fragment_id == 0 )
    {
        uint8_t packet_header[SNAPSHOT_MAX_PACKET_HEADER_BYTES];

        memset( packet_header, 0, SNAPSHOT_MAX_PACKET_HEADER_BYTES );

        reassembly_data->packet_header_bytes = snapshot_write_packet_header( packet_header, sequence, ack, ack_bits );

        memcpy( reassembly_data->packet_data + SNAPSHOT_MAX_PACKET_HEADER_BYTES - reassembly_data->packet_header_bytes, 
                packet_header, 
                reassembly_data->packet_header_bytes );

        fragment_data += reassembly_data->packet_header_bytes;
        fragment_bytes -= reassembly_data->packet_header_bytes;
    }

    if ( fragment_id == reassembly_data->num_fragments_total - 1 )
    {
        reassembly_data->packet_bytes = ( reassembly_data->num_fragments_total - 1 ) * fragment_size + fragment_bytes;
    }

    memcpy( reassembly_data->packet_data + SNAPSHOT_MAX_PACKET_HEADER_BYTES + fragment_id * fragment_size, fragment_data, fragment_bytes );
}

#endif // #ifndef SNAPSHOT_FRAGMENT_H
