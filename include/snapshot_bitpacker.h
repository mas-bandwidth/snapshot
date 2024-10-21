 /*
    Snapshot 

    Copyright © 2024 Más Bandwidth LLC. 

    This source code is licensed under GPL version 3 or any later version.

    Commercial licensing under different terms is available. Email licensing@mas-bandwidth.com for details
*/

#ifndef SNAPSHOT_BITPACKER_H
#define SNAPSHOT_BITPACKER_H

#include "snapshot.h"
#include "snapshot_util.h"

// -------------------------------------------------------------------------------------------------------------------------

struct snapshot_bit_writer_t
{
    uint32_t * data;
    uint64_t scratch;
    int num_bits;
    int num_words;
    int bits_written;
    int word_index;
    int scratch_bits;
};

void snapshot_bit_writer_init( struct snapshot_bit_writer_t * writer, void * data, int bytes );

void snapshot_write_bits( struct snapshot_bit_writer_t * writer, uint32_t value, int bits );

void snapshot_write_align( struct snapshot_bit_writer_t * writer );

void snapshot_write_bytes( struct snapshot_bit_writer_t * writer, const uint8_t * data, int bytes );

void snapshot_flush_bits( struct snapshot_bit_writer_t * writer );

int snapshot_get_write_align_bits( struct snapshot_bit_writer_t * writer );

int snapshot_get_bytes_written( struct snapshot_bit_writer_t * writer );

// -------------------------------------------------------------------------------------------------------------------------

struct snapshot_bit_reader_t
{
    uint32_t * data;
    uint64_t scratch;
    int num_bits;
    int num_bytes;
#if SNAPSHOT_ASSERTS
    int num_words;
#endif // #if SNAPSHOT_ASSERTS
    int bits_read;
    int scratch_bits;
    int word_index;
};

void snapshot_bit_reader_init( struct snapshot_bit_reader_t * reader, void * data, int bytes );

SNAPSHOT_BOOL snapshot_would_read_past_end( struct snapshot_bit_reader_t * reader, int bits );

uint32_t snapshot_read_bits( struct snapshot_bit_reader_t * reader, int bits );

SNAPSHOT_BOOL snapshot_read_align( struct snapshot_bit_reader_t * reader );

void snapshot_read_bytes( struct snapshot_bit_reader_t * reader, uint8_t * data, int bytes );

int snapshot_get_read_align_bits( struct snapshot_bit_reader_t * reader );

// -------------------------------------------------------------------------------------------------------------------------

#endif // #ifndef SNAPSHOT_BITPACKER_H
