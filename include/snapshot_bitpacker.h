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

struct snapshot_bitwriter_t
{
    uint32_t * data;
    uint64_t scratch;
    int num_bits;
    int num_words;
    int bits_written;
    int word_index;
    int scratch_bits;
};

extern void snapshot_bitwriter_init( struct snapshot_bitwriter_t * writer, void * data, int bytes );

extern void snapshot_bitwriter_write_bits( struct snapshot_bitwriter_t * writer, uint32_t value, int bits );

extern void snapshot_bitwriter_write_align( struct snapshot_bitwriter_t * writer );

extern void snapshot_bitwriter_write_bytes( struct snapshot_bitwriter_t * writer, const uint8_t * data, int bytes );

extern void snapshot_bitwriter_flush_bits( struct snapshot_bitwriter_t * writer );

extern int snapshot_bitwriter_get_align_bits( struct snapshot_bitwriter_t * writer );

extern int snapshot_bitwriter_get_bytes_written( struct snapshot_bitwriter_t * writer );

// -------------------------------------------------------------------------------------------------------------------------

struct snapshot_bitreader_t
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

extern void snapshot_bitreader_init( struct snapshot_bitreader_t * reader, void * data, int bytes );

extern SNAPSHOT_BOOL snapshot_bitreader_would_read_past_end( struct snapshot_bitreader_t * reader, int bits );

extern uint32_t snapshot_bitreader_read_bits( struct snapshot_bitreader_t * reader, int bits );

extern SNAPSHOT_BOOL snapshot_bitreader_read_align( struct snapshot_bitreader_t * reader );

extern void snapshot_bitreader_read_bytes( struct snapshot_bitreader_t * reader, uint8_t * data, int bytes );

extern int snapshot_bitreader_get_read_align_bits( struct snapshot_bitreader_t * reader );

// -------------------------------------------------------------------------------------------------------------------------

#endif // #ifndef SNAPSHOT_BITPACKER_H
