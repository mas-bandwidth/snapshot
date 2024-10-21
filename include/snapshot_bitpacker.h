/*
    Snapshot 

    Copyright © 2024 Más Bandwidth LLC. 

    This source code is licensed under GPL version 3 or any later version.

    Commercial licensing under different terms is available. Email licensing@mas-bandwidth.com for details
*/

#ifndef SNAPSHOT_BITPACKER_H
#define SNAPSHOT_BITPACKER_H

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

inline int snapshot_bits_required( uint32_t min, uint32_t max )
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

inline bool snapshot_sequence_greater_than( uint16_t s1, uint16_t s2 )
{
    return ( ( s1 > s2 ) && ( s1 - s2 <= 32768 ) ) ||
           ( ( s1 < s2 ) && ( s2 - s1  > 32768 ) );
}

inline bool snapshot_sequence_less_than( uint16_t s1, uint16_t s2 )
{
    return snapshot_sequence_greater_than( s2, s1 );
}

// todo: convert code below to C style. I don't want to use C++ anymore

namespace snapshot
{
    class BitWriter
    {
    public:

        BitWriter( void * data, int bytes ) : m_data( (uint32_t*) data ), m_numWords( bytes / 4 )
        {
            snapshot_assert( data );
            snapshot_assert( ( bytes % 4 ) == 0 );                // IMPORTANT: buffer length should be a multiple of 4 bytes
            m_numBits = m_numWords * 32;
            m_bitsWritten = 0;
            m_wordIndex = 0;
            m_scratch = 0;
            m_scratchBits = 0;
        }

        void WriteBits( uint32_t value, int bits )
        {
            snapshot_assert( bits > 0 );
            snapshot_assert( bits <= 32 );
            snapshot_assert( m_bitsWritten + bits <= m_numBits );
            snapshot_assert( uint64_t( value ) <= ( ( 1ULL << bits ) - 1 ) );

            m_scratch |= uint64_t( value ) << m_scratchBits;

            m_scratchBits += bits;

            if ( m_scratchBits >= 32 )
            {
                snapshot_assert( m_wordIndex < m_numWords );
#if SNAPSHOT_LITTLE_ENDIAN
                m_data[m_wordIndex] = uint32_t( m_scratch & 0xFFFFFFFF );
#else // #if SNAPSHOT_LITTLE_ENDIAN
               m_data[m_wordIndex] = bswap_uint32( uint32_t( m_scratch & 0xFFFFFFFF ) );
#endif // #if SNAPSHOT_LITTLE_ENDIAN
                m_scratch >>= 32;
                m_scratchBits -= 32;
                m_wordIndex++;
            }

            m_bitsWritten += bits;
        }

        void WriteAlign()
        {
            const int remainderBits = m_bitsWritten % 8;

            if ( remainderBits != 0 )
            {
                uint32_t zero = 0;
                WriteBits( zero, 8 - remainderBits );
                snapshot_assert( ( m_bitsWritten % 8 ) == 0 );
            }
        }

        void WriteBytes( const uint8_t * data, int bytes )
        {
            snapshot_assert( GetAlignBits() == 0 );
            snapshot_assert( m_bitsWritten + bytes * 8 <= m_numBits );
            snapshot_assert( ( m_bitsWritten % 32 ) == 0 || ( m_bitsWritten % 32 ) == 8 || ( m_bitsWritten % 32 ) == 16 || ( m_bitsWritten % 32 ) == 24 );

            int headBytes = ( 4 - ( m_bitsWritten % 32 ) / 8 ) % 4;
            if ( headBytes > bytes )
                headBytes = bytes;
            for ( int i = 0; i < headBytes; ++i )
                WriteBits( data[i], 8 );
            if ( headBytes == bytes )
                return;

            FlushBits();

            snapshot_assert( GetAlignBits() == 0 );

            int numWords = ( bytes - headBytes ) / 4;
            if ( numWords > 0 )
            {
                snapshot_assert( ( m_bitsWritten % 32 ) == 0 );
                memcpy( &m_data[m_wordIndex], data + headBytes, size_t(numWords) * 4 );
                m_bitsWritten += numWords * 32;
                m_wordIndex += numWords;
                m_scratch = 0;
            }

            snapshot_assert( GetAlignBits() == 0 );

            int tailStart = headBytes + numWords * 4;
            int tailBytes = bytes - tailStart;
            snapshot_assert( tailBytes >= 0 && tailBytes < 4 );
            for ( int i = 0; i < tailBytes; ++i )
                WriteBits( data[tailStart+i], 8 );

            snapshot_assert( GetAlignBits() == 0 );

            snapshot_assert( headBytes + numWords * 4 + tailBytes == bytes );
        }

        void FlushBits()
        {
            if ( m_scratchBits != 0 )
            {
                snapshot_assert( m_scratchBits <= 32 );
                snapshot_assert( m_wordIndex < m_numWords );
#if SNAPSHOT_LITTLE_ENDIAN
                m_data[m_wordIndex] = uint32_t( m_scratch & 0xFFFFFFFF );
#else // #if SNAPSHOT_LITTLE_ENDIAN
               m_data[m_wordIndex] = bswap_uint32( uint32_t( m_scratch & 0xFFFFFFFF ) );
#endif // #if SNAPSHOT_LITTLE_ENDIAN
                m_scratch >>= 32;
                m_scratchBits = 0;
                m_wordIndex++;
            }
        }

        int GetAlignBits() const
        {
            return ( 8 - ( m_bitsWritten % 8 ) ) % 8;
        }

        int GetBitsWritten() const
        {
            return m_bitsWritten;
        }

        int GetBitsAvailable() const
        {
            return m_numBits - m_bitsWritten;
        }

        const uint8_t * GetData() const
        {
            return (uint8_t*) m_data;
        }

        int GetBytesWritten() const
        {
            return ( m_bitsWritten + 7 ) / 8;
        }

    private:

        uint32_t * m_data;
        uint64_t m_scratch;
        int m_numBits;
        int m_numWords;
        int m_bitsWritten;
        int m_wordIndex;
        int m_scratchBits;
    };

    class BitReader
    {
    public:

#if SNAPSHOT_ASSERTS
        BitReader( const void * data, int bytes ) : m_data( (const uint32_t*) data ), m_numBytes( bytes ), m_numWords( ( bytes + 3 ) / 4)
#else // #if SNAPSHOT_ASSERTS
        BitReader( const void * data, int bytes ) : m_data( (const uint32_t*) data ), m_numBytes( bytes )
#endif // #if SNAPSHOT_ASSERTS
        {
            snapshot_assert( data );
            m_numBits = m_numBytes * 8;
            m_bitsRead = 0;
            m_scratch = 0;
            m_scratchBits = 0;
            m_wordIndex = 0;
        }

        bool WouldReadPastEnd( int bits ) const
        {
            return m_bitsRead + bits > m_numBits;
        }

        uint32_t ReadBits( int bits )
        {
            snapshot_assert( bits > 0 );
            snapshot_assert( bits <= 32 );
            snapshot_assert( m_bitsRead + bits <= m_numBits );

            m_bitsRead += bits;

            snapshot_assert( m_scratchBits >= 0 && m_scratchBits <= 64 );

            if ( m_scratchBits < bits )
            {
                snapshot_assert( m_wordIndex < m_numWords );
#if SNAPSHOT_LITTLE_ENDIAN
                m_scratch |= uint64_t( m_data[m_wordIndex] ) << m_scratchBits;
#else // #if SNAPSHOT_LITTLE_ENDIAN
                m_scratch |= uint64_t( bswap_uint32( m_data[m_wordIndex] ) ) << m_scratchBits;
#endif // #if SNAPSHOT_LITTLE_ENDIAN
                m_scratchBits += 32;
                m_wordIndex++;
            }

            snapshot_assert( m_scratchBits >= bits );

            const uint32_t output = m_scratch & ( (uint64_t(1)<<bits) - 1 );

            m_scratch >>= bits;
            m_scratchBits -= bits;

            return output;
        }

        bool ReadAlign()
        {
            const int remainderBits = m_bitsRead % 8;
            if ( remainderBits != 0 )
            {
                uint32_t value = ReadBits( 8 - remainderBits );
                snapshot_assert( m_bitsRead % 8 == 0 );
                if ( value != 0 )
                    return false;
            }
            return true;
        }

        void ReadBytes( uint8_t * data, int bytes )
        {
            snapshot_assert( GetAlignBits() == 0 );
            snapshot_assert( m_bitsRead + bytes * 8 <= m_numBits );
            snapshot_assert( ( m_bitsRead % 32 ) == 0 || ( m_bitsRead % 32 ) == 8 || ( m_bitsRead % 32 ) == 16 || ( m_bitsRead % 32 ) == 24 );

            int headBytes = ( 4 - ( m_bitsRead % 32 ) / 8 ) % 4;
            if ( headBytes > bytes )
                headBytes = bytes;
            for ( int i = 0; i < headBytes; ++i )
                data[i] = (uint8_t) ReadBits( 8 );
            if ( headBytes == bytes )
                return;

            snapshot_assert( GetAlignBits() == 0 );

            int numWords = ( bytes - headBytes ) / 4;
            if ( numWords > 0 )
            {
                snapshot_assert( ( m_bitsRead % 32 ) == 0 );
                memcpy( data + headBytes, &m_data[m_wordIndex], size_t(numWords) * 4 );
                m_bitsRead += numWords * 32;
                m_wordIndex += numWords;
                m_scratchBits = 0;
            }

            snapshot_assert( GetAlignBits() == 0 );

            int tailStart = headBytes + numWords * 4;
            int tailBytes = bytes - tailStart;
            snapshot_assert( tailBytes >= 0 && tailBytes < 4 );
            for ( int i = 0; i < tailBytes; ++i )
                data[tailStart+i] = (uint8_t) ReadBits( 8 );

            snapshot_assert( GetAlignBits() == 0 );

            snapshot_assert( headBytes + numWords * 4 + tailBytes == bytes );
        }

        int GetAlignBits() const
        {
            return ( 8 - m_bitsRead % 8 ) % 8;
        }

        int GetBitsRead() const
        {
            return m_bitsRead;
        }

        int GetBitsRemaining() const
        {
            return m_numBits - m_bitsRead;
        }

    private:

        const uint32_t * m_data;
        uint64_t m_scratch;
        int m_numBits;
        int m_numBytes;
#if SNAPSHOT_ASSERTS
        int m_numWords;
#endif // #if SNAPSHOT_ASSERTS
        int m_bitsRead;
        int m_scratchBits;
        int m_wordIndex;
    };
}

#endif // #ifndef SNAPSHOT_BITPACKER_H
