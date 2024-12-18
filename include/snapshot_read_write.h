/*
    Snapshot 

    Copyright © 2024 Más Bandwidth LLC. 

    This source code is licensed under GPL version 3 or any later version.

    Commercial licensing under different terms is available. Email licensing@mas-bandwidth.com for details
*/

#ifndef SNAPSHOT_READ_WRITE_H
#define SNAPSHOT_READ_WRITE_H

#include "snapshot_address.h"

// ----------------------------------------------------------------------

static inline void snapshot_write_uint8( uint8_t ** p, uint8_t value )
{
    **p = value;
    ++(*p);
}

static inline void snapshot_write_uint16( uint8_t ** p, uint16_t value )
{
    (*p)[0] = value & 0xFF;
    (*p)[1] = value >> 8;
    *p += 2;
}

static inline void snapshot_write_uint32( uint8_t ** p, uint32_t value )
{
    (*p)[0] = value & 0xFF;
    (*p)[1] = ( value >> 8  ) & 0xFF;
    (*p)[2] = ( value >> 16 ) & 0xFF;
    (*p)[3] = value >> 24;
    *p += 4;
}

static inline void snapshot_write_uint64( uint8_t ** p, uint64_t value )
{
    (*p)[0] = value & 0xFF;
    (*p)[1] = ( value >> 8  ) & 0xFF;
    (*p)[2] = ( value >> 16 ) & 0xFF;
    (*p)[3] = ( value >> 24 ) & 0xFF;
    (*p)[4] = ( value >> 32 ) & 0xFF;
    (*p)[5] = ( value >> 40 ) & 0xFF;
    (*p)[6] = ( value >> 48 ) & 0xFF;
    (*p)[7] = value >> 56;
    *p += 8;
}

static inline void snapshot_write_float32( uint8_t ** p, float value )
{
    uint32_t value_int = 0;
    char * p_value = (char*)(&value);
    char * p_value_int = (char*)(&value_int);
    memcpy(p_value_int, p_value, sizeof(uint32_t));
    snapshot_write_uint32( p, value_int);
}

static inline void snapshot_write_float64( uint8_t ** p, double value )
{
    uint64_t value_int = 0;
    char * p_value = (char *)(&value);
    char * p_value_int = (char *)(&value_int);
    memcpy(p_value_int, p_value, sizeof(uint64_t));
    snapshot_write_uint64( p, value_int);
}

static inline void snapshot_write_bytes( uint8_t ** p, const uint8_t * byte_array, int num_bytes )
{
    for ( int i = 0; i < num_bytes; ++i )
    {
        snapshot_write_uint8( p, byte_array[i] );
    }
}

static inline void snapshot_write_address( uint8_t ** buffer, const struct snapshot_address_t * address )
{
    snapshot_assert( buffer );
    snapshot_assert( *buffer );
    snapshot_assert( address );

    if ( address->type == SNAPSHOT_ADDRESS_IPV4 )
    {
        snapshot_write_uint8( buffer, SNAPSHOT_ADDRESS_IPV4 );
        for ( int i = 0; i < 4; ++i )
        {
            snapshot_write_uint8( buffer, address->data.ipv4[i] );
        }
        snapshot_write_uint16( buffer, address->port );
    }
    else if ( address->type == SNAPSHOT_ADDRESS_IPV6 )
    {
        snapshot_write_uint8( buffer, SNAPSHOT_ADDRESS_IPV6 );
        for ( int i = 0; i < 8; ++i )
        {
            snapshot_write_uint16( buffer, address->data.ipv6[i] );
        }
        snapshot_write_uint16( buffer, address->port );
    }
    else
    {
        snapshot_write_uint8( buffer, SNAPSHOT_ADDRESS_NONE );    
    }
}

// ----------------------------------------------------------------------

static inline uint8_t snapshot_read_uint8( const uint8_t ** p )
{
    uint8_t value = **p;
    ++(*p);
    return value;
}

static inline uint16_t snapshot_read_uint16( const uint8_t ** p )
{
    uint16_t value;
    value = (*p)[0];
    value |= ( ( (uint16_t)( (*p)[1] ) ) << 8 );
    *p += 2;
    return value;
}

static inline uint32_t snapshot_read_uint32( const uint8_t ** p )
{
    uint32_t value;
    value  = (*p)[0];
    value |= ( ( (uint32_t)( (*p)[1] ) ) << 8 );
    value |= ( ( (uint32_t)( (*p)[2] ) ) << 16 );
    value |= ( ( (uint32_t)( (*p)[3] ) ) << 24 );
    *p += 4;
    return value;
}

static inline uint64_t snapshot_read_uint64( const uint8_t ** p )
{
    uint64_t value;
    value  = (*p)[0];
    value |= ( ( (uint64_t)( (*p)[1] ) ) << 8  );
    value |= ( ( (uint64_t)( (*p)[2] ) ) << 16 );
    value |= ( ( (uint64_t)( (*p)[3] ) ) << 24 );
    value |= ( ( (uint64_t)( (*p)[4] ) ) << 32 );
    value |= ( ( (uint64_t)( (*p)[5] ) ) << 40 );
    value |= ( ( (uint64_t)( (*p)[6] ) ) << 48 );
    value |= ( ( (uint64_t)( (*p)[7] ) ) << 56 );
    *p += 8;
    return value;
}

static inline float snapshot_read_float32( const uint8_t ** p )
{
    uint32_t value_int = snapshot_read_uint32( p );
    float value_float = 0.0f;
    uint8_t * pointer_int = (uint8_t *)( &value_int );
    uint8_t * pointer_float = (uint8_t *)( &value_float );
    memcpy( pointer_float, pointer_int, sizeof( value_int ) );
    return value_float;
}

static inline double snapshot_read_float64( const uint8_t ** p )
{
    uint64_t value_int = snapshot_read_uint64( p );
    double value_float = 0.0;
    uint8_t * pointer_int = (uint8_t *)( &value_int );
    uint8_t * pointer_float = (uint8_t *)( &value_float );
    memcpy( pointer_float, pointer_int, sizeof( value_int ) );
    return value_float;
}

static inline void snapshot_read_bytes( const uint8_t ** p, uint8_t * byte_array, int num_bytes )
{
    for ( int i = 0; i < num_bytes; ++i )
    {
        byte_array[i] = snapshot_read_uint8( p );
    }
}

static inline void snapshot_read_address( const uint8_t ** buffer, struct snapshot_address_t * address )
{
    memset( address, 0, sizeof(struct snapshot_address_t) );

    address->type = snapshot_read_uint8( buffer );

    if ( address->type == SNAPSHOT_ADDRESS_IPV4 )
    {
        for ( int j = 0; j < 4; ++j )
        {
            address->data.ipv4[j] = snapshot_read_uint8( buffer );
        }
        address->port = snapshot_read_uint16( buffer );
    }
    else if ( address->type == SNAPSHOT_ADDRESS_IPV6 )
    {
        for ( int j = 0; j < 8; ++j )
        {
            address->data.ipv6[j] = snapshot_read_uint16( buffer );
        }
        address->port = snapshot_read_uint16( buffer );
    }
}

// ----------------------------------------------------------------------

#endif // #ifndef SNAPSHOT_READ_WRITE_H
