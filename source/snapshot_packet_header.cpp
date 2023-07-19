/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_packet_header.h"
#include "snapshot_read_write.h"

int snapshot_write_packet_header( uint8_t * packet_data, uint16_t sequence, uint16_t ack, uint32_t ack_bits )
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

    snapshot_write_uint8( &p, prefix_byte );

    snapshot_write_uint16( &p, sequence );

    if ( sequence_difference <= 255 )
    {
        snapshot_write_uint8( &p, (uint8_t) sequence_difference );
    }
    else
    {
        snapshot_write_uint16( &p, ack );
    }

    if ( ( ack_bits & 0x000000FF ) != 0x000000FF )
    {
        snapshot_write_uint8( &p, (uint8_t) ( ack_bits & 0x000000FF ) );
    }

    if ( ( ack_bits & 0x0000FF00 ) != 0x0000FF00 )
    {
        snapshot_write_uint8( &p, (uint8_t) ( ( ack_bits & 0x0000FF00 ) >> 8 ) );
    }

    if ( ( ack_bits & 0x00FF0000 ) != 0x00FF0000 )
    {
        snapshot_write_uint8( &p, (uint8_t) ( ( ack_bits & 0x00FF0000 ) >> 16 ) );
    }

    if ( ( ack_bits & 0xFF000000 ) != 0xFF000000 )
    {
        snapshot_write_uint8( &p, (uint8_t) ( ( ack_bits & 0xFF000000 ) >> 24 ) );
    }

    snapshot_assert( p - packet_data <= SNAPSHOT_MAX_PACKET_HEADER_BYTES );

    return (int) ( p - packet_data );
}

int snapshot_read_packet_header( const char * name, const uint8_t * packet_data, int packet_bytes, uint16_t * sequence, uint16_t * ack, uint32_t * ack_bits )
{
    if ( packet_bytes < 3 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] packet too small for packet header (1)\n", name );
        return -1;
    }

    const uint8_t * p = packet_data;

    uint8_t prefix_byte = snapshot_read_uint8( &p );

    if ( ( prefix_byte & 1 ) != 0 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] prefix byte does not indicate a regular packet\n", name );
        return -1;
    }

    *sequence = snapshot_read_uint16( &p );

    if ( prefix_byte & (1<<5) )
    {
        if ( packet_bytes < 3 + 1 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] packet too small for packet header (2)\n", name );
            return -1;
        }
        uint8_t sequence_difference = snapshot_read_uint8( &p );
        *ack = *sequence - sequence_difference;
    }
    else
    {
        if ( packet_bytes < 3 + 2 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] packet too small for packet header (3)\n", name );
            return -1;
        }
        *ack = snapshot_read_uint16( &p );
    }

    int expected_bytes = 0;
    int i;
    for ( i = 1; i <= 4; ++i )
    {
        if ( prefix_byte & (1<<i) )
        {
            expected_bytes++;
        }
    }
    if ( packet_bytes < ( p - packet_data ) + expected_bytes )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "[%s] packet too small for packet header (4)\n", name );
        return -1;
    }

    *ack_bits = 0xFFFFFFFF;

    if ( prefix_byte & (1<<1) )
    {
        *ack_bits &= 0xFFFFFF00;
        *ack_bits |= (uint32_t) ( snapshot_read_uint8( &p ) );
    }

    if ( prefix_byte & (1<<2) )
    {
        *ack_bits &= 0xFFFF00FF;
        *ack_bits |= (uint32_t) ( snapshot_read_uint8( &p ) ) << 8;
    }

    if ( prefix_byte & (1<<3) )
    {
        *ack_bits &= 0xFF00FFFF;
        *ack_bits |= (uint32_t) ( snapshot_read_uint8( &p ) ) << 16;
    }

    if ( prefix_byte & (1<<4) )
    {
        *ack_bits &= 0x00FFFFFF;
        *ack_bits |= (uint32_t) ( snapshot_read_uint8( &p ) ) << 24;
    }

    return (int) ( p - packet_data );
}
