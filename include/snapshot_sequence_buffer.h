/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_SEQUENCE_BUFFER_H
#define SNAPSHOT_SEQUENCE_BUFFER_H

#include "snapshot.h"

struct snapshot_sequence_buffer_t
{
    void * context;
    uint16_t sequence;
    int num_entries;
    int entry_stride;
    uint32_t * entry_sequence;
    uint8_t * entry_data;
};

struct snapshot_sequence_buffer_t * snapshot_sequence_buffer_create( void * context, int num_entries, int entry_stride );

void snapshot_sequence_buffer_destroy( struct snapshot_sequence_buffer_t * sequence_buffer );

void snapshot_sequence_buffer_reset( struct snapshot_sequence_buffer_t * sequence_buffer );

void snapshot_sequence_buffer_remove_entries( struct snapshot_sequence_buffer_t * sequence_buffer, int start_sequence, int finish_sequence, void (*cleanup_function)(void*,void*) );

int snapshot_sequence_buffer_test_insert( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence );

void * snapshot_sequence_buffer_insert( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence );

void snapshot_sequence_buffer_advance( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence );

void * snapshot_sequence_buffer_insert_with_cleanup( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence, void (*cleanup_function)(void*,void*) );

void snapshot_sequence_buffer_advance_with_cleanup( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence, void (*cleanup_function)(void*,void*) );

void snapshot_sequence_buffer_remove( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence );

void snapshot_sequence_buffer_remove_with_cleanup( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence, void (*cleanup_function)(void*,void*) );

int snapshot_sequence_buffer_available( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence );

int snapshot_sequence_buffer_exists( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence );

void * snapshot_sequence_buffer_find( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence );

void * snapshot_sequence_buffer_at_index( struct snapshot_sequence_buffer_t * sequence_buffer, int index );

void snapshot_sequence_buffer_generate_ack_bits( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t * ack, uint32_t * ack_bits );

#endif // #ifndef SNAPSHOT_SEQUENCE_BUFFER_H
