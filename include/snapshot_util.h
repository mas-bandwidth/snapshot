 /*
    Snapshot 

    Copyright © 2024 Más Bandwidth LLC. 

    This source code is licensed under GPL version 3 or any later version.

    Commercial licensing under different terms is available. Email licensing@mas-bandwidth.com for details
*/

#ifndef SNAPSHOT_UTIL_H
#define SNAPSHOT_UTIL_H

#include "snapshot.h"

inline uint32_t snapshot_popcount( uint32_t x )
{
#ifdef __GNUC__
    return __builtin_popcount( x );
#else // #ifdef __GNUC__
    const uint32_t a = x - ( ( x >> 1 )       & 0x55555555 );
    const uint32_t b =   ( ( ( a >> 2 )       & 0x33333333 ) + ( a & 0x33333333 ) );
    const uint32_t c =   ( ( ( b >> 4 ) + b ) & 0x0f0f0f0f );
    const uint32_t d =   c + ( c >> 8 );
    const uint32_t e =   d + ( d >> 16 );
    const uint32_t result = e & 0x0000003f;
    return result;
#endif // #ifdef __GNUC__
}

inline uint32_t snapshot_log2( uint32_t x )
{
    const uint32_t a = x | ( x >> 1 );
    const uint32_t b = a | ( a >> 2 );
    const uint32_t c = b | ( b >> 4 );
    const uint32_t d = c | ( c >> 8 );
    const uint32_t e = d | ( d >> 16 );
    const uint32_t f = e >> 1;
    return snapshot_popcount( f );
}

static inline int snapshot_bits_required( uint32_t min, uint32_t max )
{
#ifdef __GNUC__
    return ( min == max ) ? 0 : 32 - __builtin_clz( max - min );
#else // #ifdef __GNUC__
    return ( min == max ) ? 0 : log2( max - min ) + 1;
#endif // #ifdef __GNUC__
}

inline uint64_t snapshot_bswap_uint64( uint64_t value )
{
#ifdef __GNUC__
    return __builtin_bswap64( value );
#else // #ifdef __GNUC__
    value = ( value & 0x00000000FFFFFFFF ) << 32 | ( value & 0xFFFFFFFF00000000 ) >> 32;
    value = ( value & 0x0000FFFF0000FFFF ) << 16 | ( value & 0xFFFF0000FFFF0000 ) >> 16;
    value = ( value & 0x00FF00FF00FF00FF ) << 8  | ( value & 0xFF00FF00FF00FF00 ) >> 8;
    return value;
#endif // #ifdef __GNUC__
}

inline uint32_t snapshot_bswap_uint32( uint32_t value )
{
#ifdef __GNUC__
    return __builtin_bswap32( value );
#else // #ifdef __GNUC__
    return ( value & 0x000000ff ) << 24 | ( value & 0x0000ff00 ) << 8 | ( value & 0x00ff0000 ) >> 8 | ( value & 0xff000000 ) >> 24;
#endif // #ifdef __GNUC__
}

inline uint16_t snapshot_bswap_uint16( uint16_t value )
{
    return ( value & 0x00ff ) << 8 | ( value & 0xff00 ) >> 8;
}

inline SNAPSHOT_BOOL snapshot_sequence_greater_than( uint16_t s1, uint16_t s2 )
{
    return ( ( ( s1 > s2 ) && ( s1 - s2 <= 32768 ) ) || ( ( s1 < s2 ) && ( s2 - s1  > 32768 ) ) ) ? SNAPSHOT_TRUE : SNAPSHOT_FALSE;
}

inline SNAPSHOT_BOOL snapshot_sequence_less_than( uint16_t s1, uint16_t s2 )
{
    return snapshot_sequence_greater_than( s2, s1 );
}

#endif // #ifndef SNAPSHOT_UTIL_H
