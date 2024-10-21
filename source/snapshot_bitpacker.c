 /*
    Snapshot 

    Copyright © 2024 Más Bandwidth LLC. 

    This source code is licensed under GPL version 3 or any later version.

    Commercial licensing under different terms is available. Email licensing@mas-bandwidth.com for details
*/

#include "snapshot_bitpacker.h"

// -----------------------------------------------------------------------------------------------------------------------

// todo
/*
void snapshot_bit_writer_init( struct snapshot_bit_writer_t * writer, void * data, int bytes )
{
    snapshot_assert( writer );
    snapshot_assert( data );
    snapshot_assert( ( bytes % 4 ) == 0 );                // IMPORTANT: buffer length must be a multiple of 4 bytes
    writer->data = (uint32_t*) data;
    writer->num_words = bytes / 4;
    writer->num_bits = writer->num_words * 32;
    writer->bits_written = 0;
    writer->word_index = 0;
    writer->scratch = 0;
    writer->scratch_bits = 0;
}

void snapshot_write_bits( struct snapshot_bit_writer_t * writer, uint32_t value, int bits )
{
    snapshot_assert( writer );
    snapshot_assert( bits > 0 );
    snapshot_assert( bits <= 32 );
    snapshot_assert( writer->bits_written + bits <= writer->num_bits );
    snapshot_assert( (uint64_t)value <= ( ( 1ULL << bits ) - 1 ) );

    writer->scratch |= (uint64_t)value << writer->scratch_bits;

    writer->scratch_bits += bits;

    if ( writer->scratch_bits >= 32 )
    {
        snapshot_assert( writer->word_index < writer->num_words );
#if SNAPSHOT_LITTLE_ENDIAN
        writer->data[writer->word_index] = (uint32_t) ( writer->scratch & 0xFFFFFFFF );
#else // #if SNAPSHOT_LITTLE_ENDIAN
        writer->data[writer->word_index] = bswap_uint32( (uint32_t) ( writer->scratch & 0xFFFFFFFF ) );
#endif // #if SNAPSHOT_LITTLE_ENDIAN
        writer->scratch >>= 32;
        writer->scratch_bits -= 32;
        writer->word_index++;
    }

    writer->bits_written += bits;
}

void snapshot_write_align( struct snapshot_bit_writer_t * writer )
{
    snapshot_assert( writer );
    const int remainder_bits = writer->bits_written % 8;
    if ( remainder_bits != 0 )
    {
        uint32_t zero = 0;
        snapshot_write_bits( writer, zero, 8 - remainder_bits );
        snapshot_assert( ( writer->bits_written % 8 ) == 0 );
    }
}

void snapshot_write_bytes( struct snapshot_bit_writer_t * writer, const uint8_t * data, int bytes )
{
    snapshot_assert( writer );
    snapshot_assert( snapshot_get_write_align_bits( writer ) == 0 );
    snapshot_assert( writer->bits_written + bytes * 8 <= writer->num_bits );
    snapshot_assert( ( writer->bits_written % 32 ) == 0 || ( writer->bits_written % 32 ) == 8 || ( writer->bits_written % 32 ) == 16 || ( writer->bits_written % 32 ) == 24 );

    int head_bytes = ( 4 - ( writer->bits_written % 32 ) / 8 ) % 4;
    if ( head_bytes > bytes )
        head_bytes = bytes;
    for ( int i = 0; i < head_bytes; ++i )
        snapshot_write_bits( writer, data[i], 8 );
    if ( head_bytes == bytes )
        return;

    snapshot_flush_bits( writer );

    snapshot_assert( snapshot_get_write_align_bits( writer ) == 0 );

    int num_words = ( bytes - head_bytes ) / 4;
    if ( num_words > 0 )
    {
        snapshot_assert( ( writer->bits_written % 32 ) == 0 );
        memcpy( &writer->data[writer->word_index], data + head_bytes, num_words * 4 );
        writer->bits_written += num_words * 32;
        writer->word_index += num_words;
        writer->scratch = 0;
    }

    snapshot_assert( snapshot_get_write_align_bits( writer ) == 0 );

    int tail_start = head_bytes + num_words * 4;
    int tail_bytes = bytes - tail_start;
    snapshot_assert( tail_bytes >= 0 && tail_bytes < 4 );
    for ( int i = 0; i < tail_bytes; ++i )
        snapshot_write_bits( writer, data[tail_start+i], 8 );

    snapshot_assert( snapshot_get_write_align_bits( writer ) == 0 );

    snapshot_assert( head_bytes + num_words * 4 + tail_bytes == bytes );
}

void snapshot_flush_bits( struct snapshot_bit_writer_t * writer )
{
    snapshot_assert( writer );
    if ( writer->scratch_bits != 0 )
    {
        snapshot_assert( writer->scratch_bits <= 32 );
        snapshot_assert( writer->word_index < writer->num_words );
#if SNAPSHOT_LITTLE_ENDIAN
        writer->data[writer->word_index] = (uint32_t) ( writer->scratch & 0xFFFFFFFF );
#else // #if SNAPSHOT_LITTLE_ENDIAN
       writer->data[writer->word_index] = bswap_uint32( (uint32_t) ( writer->scratch & 0xFFFFFFFF ) );
#endif // #if SNAPSHOT_LITTLE_ENDIAN
        writer->scratch >>= 32;
        writer->scratch_bits = 0;
        writer->word_index++;
    }
}

int snapshot_get_write_align_bits( struct snapshot_bit_writer_t * writer )
{
    snapshot_assert( writer );
    return ( 8 - ( writer->bits_written % 8 ) ) % 8;
}

int snapshot_get_bytes_written( struct snapshot_bit_writer_t * writer )
{
    snapshot_assert( writer );
    return ( writer->bits_written + 7 ) / 8;
}

// -----------------------------------------------------------------------------------------------------------------------

void snapshot_bit_reader_init( struct snapshot_bit_reader_t * reader, void * data, int bytes )
{
    snapshot_assert( reader );
    snapshot_assert( data );
    reader->data = (uint32_t*) data;
    reader->num_bytes = bytes;
#if SNAPSHOT_ASSERTS
    reader->num_words = ( bytes + 3 ) / 4;
#endif // #if SNAPSHOT_ASSERTS
    reader->num_bits = reader->num_bytes * 8;
    reader->bits_read = 0;
    reader->scratch = 0;
    reader->scratch_bits = 0;
    reader->word_index = 0;
}

SNAPSHOT_BOOL snapshot_would_read_past_end( struct snapshot_bit_reader_t * reader, int bits )
{
    snapshot_assert( reader );
    return reader->bits_read + bits > reader->num_bits;
}

uint32_t snapshot_read_bits( struct snapshot_bit_reader_t * reader, int bits )
{
    snapshot_assert( reader );
    snapshot_assert( bits > 0 );
    snapshot_assert( bits <= 32 );
    snapshot_assert( reader->bits_read + bits <= reader->num_bits );

    reader->bits_read += bits;

    snapshot_assert( reader->scratch_bits >= 0 && reader->scratch_bits <= 64 );

    if ( reader->scratch_bits < bits )
    {
        snapshot_assert( reader->word_index < reader->num_words );
#if SNAPSHOT_LITTLE_ENDIAN
        reader->scratch |= (uint64_t) ( reader->data[reader->word_index] ) << reader->scratch_bits;
#else // #if SNAPSHOT_LITTLE_ENDIAN
        reader->scratch |= (uint64_t) ( bswap_uint32( reader->data[reader->word_index] ) ) << reader->scratch_bits;
#endif // #if SNAPSHOT_LITTLE_ENDIAN
        reader->scratch_bits += 32;
        reader->word_index++;
    }

    snapshot_assert( reader->scratch_bits >= bits );

    const uint32_t output = reader->scratch & ( ( ( (uint64_t)1 ) << bits ) - 1 );

    reader->scratch >>= bits;
    reader->scratch_bits -= bits;

    return output;
}

SNAPSHOT_BOOL snapshot_read_align( struct snapshot_bit_reader_t * reader )
{
    snapshot_assert( reader );
    int remainder_bits = reader->bits_read % 8;
    if ( remainder_bits != 0 )
    {
        uint32_t value = snapshot_read_bits( reader, 8 - remainder_bits );
        snapshot_assert( reader->bits_read % 8 == 0 );
        if ( value != 0 )
        {
            return SNAPSHOT_FALSE;
        }
    }
    return SNAPSHOT_TRUE;
}

int snapshot_get_read_align_bits( struct snapshot_bit_reader_t * reader )
{
    snapshot_assert( reader );
    return ( 8 - reader->bits_read % 8 ) % 8;
}

void snapshot_read_bytes( struct snapshot_bit_reader_t * reader, uint8_t * data, int bytes )
{
    snapshot_assert( reader );
    snapshot_assert( snapshot_get_read_align_bits( reader ) == 0 );
    snapshot_assert( reader->bits_read + bytes * 8 <= reader->num_bits );
    snapshot_assert( ( reader->bits_read % 32 ) == 0 || ( reader->bits_read % 32 ) == 8 || ( reader->bits_read % 32 ) == 16 || ( reader->bits_read % 32 ) == 24 );

    int head_bytes = ( 4 - ( reader->bits_read % 32 ) / 8 ) % 4;
    if ( head_bytes > bytes )
        head_bytes = bytes;
    for ( int i = 0; i < head_bytes; ++i )
        data[i] = (uint8_t) snapshot_read_bits( reader, 8 );
    if ( head_bytes == bytes )
        return;

    snapshot_assert( snapshot_get_read_align_bits( reader ) == 0 );

    int num_words = ( bytes - head_bytes ) / 4;
    if ( num_words > 0 )
    {
        snapshot_assert( ( reader->bits_read % 32 ) == 0 );
        memcpy( data + head_bytes, &reader->data[reader->word_index], num_words * 4 );
        reader->bits_read += num_words * 32;
        reader->word_index += num_words;
        reader->scratch_bits = 0;
    }

    snapshot_assert( snapshot_get_read_align_bits( reader ) == 0 );

    int tail_start = head_bytes + num_words * 4;
    int tail_bytes = bytes - tail_start;
    snapshot_assert( tail_bytes >= 0 && tail_bytes < 4 );
    for ( int i = 0; i < tail_bytes; ++i )
        data[tail_start+i] = (uint8_t) snapshot_read_bits( reader, 8 );

    snapshot_assert( snapshot_get_read_align_bits( reader ) == 0 );

    snapshot_assert( head_bytes + num_words * 4 + tail_bytes == bytes );
}

// -----------------------------------------------------------------------------------------------------------------------
*/