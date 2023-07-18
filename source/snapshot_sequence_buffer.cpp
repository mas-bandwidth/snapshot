/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_sequence_buffer.h"

struct snapshot_sequence_buffer_t * snapshot_sequence_buffer_create( void * context, int num_entries, int entry_stride )
{
    snapshot_assert( num_entries > 0 );
    snapshot_assert( entry_stride > 0 );

    struct snapshot_sequence_buffer_t * sequence_buffer = (struct snapshot_sequence_buffer_t*) snapshot_malloc( context, sizeof( struct snapshot_sequence_buffer_t ) );

    sequence_buffer->context = context;
    sequence_buffer->sequence = 0;
    sequence_buffer->num_entries = num_entries;
    sequence_buffer->entry_stride = entry_stride;
    sequence_buffer->entry_sequence = (uint32_t*) snapshot_malloc( context, num_entries * sizeof( uint32_t ) );
    sequence_buffer->entry_data = (uint8_t*) snapshot_malloc( context, num_entries * entry_stride );
    snapshot_assert( sequence_buffer->entry_sequence );
    snapshot_assert( sequence_buffer->entry_data );
    memset( sequence_buffer->entry_sequence, 0xFF, sizeof( uint32_t) * sequence_buffer->num_entries );
    memset( sequence_buffer->entry_data, 0, num_entries * entry_stride );

    return sequence_buffer;
}

void snapshot_sequence_buffer_destroy( struct snapshot_sequence_buffer_t * sequence_buffer )
{
    snapshot_assert( sequence_buffer );
    snapshot_free( sequence_buffer->context, sequence_buffer->entry_sequence );
    snapshot_free( sequence_buffer->context, sequence_buffer->entry_data );
    snapshot_free( sequence_buffer->context, sequence_buffer );
}

void snapshot_sequence_buffer_reset( struct snapshot_sequence_buffer_t * sequence_buffer )
{
    snapshot_assert( sequence_buffer );
    sequence_buffer->sequence = 0;
    memset( sequence_buffer->entry_sequence, 0xFF, sizeof( uint32_t) * sequence_buffer->num_entries );
}

void snapshot_sequence_buffer_remove_entries( struct snapshot_sequence_buffer_t * sequence_buffer, 
                                              int start_sequence, 
                                              int finish_sequence, 
                                              void (*cleanup_function)(void*,void*) )
{
    snapshot_assert( sequence_buffer );

    if ( finish_sequence < start_sequence ) 
    {
        finish_sequence += 65536;
    }
    if ( finish_sequence - start_sequence < sequence_buffer->num_entries )
    {
        int sequence;
        for ( sequence = start_sequence; sequence <= finish_sequence; ++sequence )
        {
            if ( cleanup_function )
            {
                cleanup_function( sequence_buffer->context, sequence_buffer->entry_data + sequence_buffer->entry_stride * ( sequence % sequence_buffer->num_entries ) );
            }
            sequence_buffer->entry_sequence[ sequence % sequence_buffer->num_entries ] = 0xFFFFFFFF;
        }
    }
    else
    {
        int i;
        for ( i = 0; i < sequence_buffer->num_entries; ++i )
        {
            if ( cleanup_function )
            {
                cleanup_function( sequence_buffer->context, sequence_buffer->entry_data + sequence_buffer->entry_stride * i );
            }
            sequence_buffer->entry_sequence[i] = 0xFFFFFFFF;
        }
    }
}

int snapshot_sequence_greater_than( uint16_t s1, uint16_t s2 )
{
    return ( ( s1 > s2 ) && ( s1 - s2 <= 32768 ) ) || 
           ( ( s1 < s2 ) && ( s2 - s1  > 32768 ) );
}

int snapshot_sequence_less_than( uint16_t s1, uint16_t s2 )
{
    return snapshot_sequence_greater_than( s2, s1 );
}

int snapshot_sequence_buffer_test_insert( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence )
{
    return snapshot_sequence_less_than( sequence, sequence_buffer->sequence - ((uint16_t)sequence_buffer->num_entries) ) ? ((uint16_t)0) : ((uint16_t)1);
}

void * snapshot_sequence_buffer_insert( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence )
{
    snapshot_assert( sequence_buffer );

    if ( snapshot_sequence_less_than( sequence, sequence_buffer->sequence - ((uint16_t)sequence_buffer->num_entries) ) )
    {
        return NULL;
    }

    if ( snapshot_sequence_greater_than( sequence + 1, sequence_buffer->sequence ) )
    {
        snapshot_sequence_buffer_remove_entries( sequence_buffer, sequence_buffer->sequence, sequence, NULL );
        sequence_buffer->sequence = sequence + 1;
    }

    int index = sequence % sequence_buffer->num_entries;

    sequence_buffer->entry_sequence[index] = sequence;

    return sequence_buffer->entry_data + index * sequence_buffer->entry_stride;
}

void snapshot_sequence_buffer_advance( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence )
{
    snapshot_assert( sequence_buffer );

    if ( snapshot_sequence_greater_than( sequence + 1, sequence_buffer->sequence ) )
    {
        snapshot_sequence_buffer_remove_entries( sequence_buffer, sequence_buffer->sequence, sequence, NULL );
        sequence_buffer->sequence = sequence + 1;
    }
}

void * snapshot_sequence_buffer_insert_with_cleanup( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence, void (*cleanup_function)(void*,void*) )
{
    snapshot_assert( sequence_buffer );

    if ( snapshot_sequence_greater_than( sequence + 1, sequence_buffer->sequence ) )
    {
        snapshot_sequence_buffer_remove_entries( sequence_buffer, sequence_buffer->sequence, sequence, cleanup_function );
        sequence_buffer->sequence = sequence + 1;
    }
    else if ( snapshot_sequence_less_than( sequence, sequence_buffer->sequence - ((uint16_t)sequence_buffer->num_entries) ) )
    {
        return NULL;
    }

    int index = sequence % sequence_buffer->num_entries;

    if ( sequence_buffer->entry_sequence[index] != 0xFFFFFFFF )
    {
        cleanup_function( sequence_buffer->context, sequence_buffer->entry_data + sequence_buffer->entry_stride * ( sequence % sequence_buffer->num_entries ) );
    }

    sequence_buffer->entry_sequence[index] = sequence;

    return sequence_buffer->entry_data + index * sequence_buffer->entry_stride;
}

void snapshot_sequence_buffer_advance_with_cleanup( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence, void (*cleanup_function)(void*,void*) )
{
    snapshot_assert( sequence_buffer );
    if ( snapshot_sequence_greater_than( sequence + 1, sequence_buffer->sequence ) )
    {
        snapshot_sequence_buffer_remove_entries( sequence_buffer, sequence_buffer->sequence, sequence, cleanup_function );
        sequence_buffer->sequence = sequence + 1;
    }
}

void snapshot_sequence_buffer_remove( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence )
{
    snapshot_assert( sequence_buffer );
    sequence_buffer->entry_sequence[ sequence % sequence_buffer->num_entries ] = 0xFFFFFFFF;
}

void snapshot_sequence_buffer_remove_with_cleanup( struct snapshot_sequence_buffer_t * sequence_buffer, 
                                                   uint16_t sequence, 
                                                   void (*cleanup_function)(void*,void*) )
{
    snapshot_assert( sequence_buffer );

    int index = sequence % sequence_buffer->num_entries;

    if ( sequence_buffer->entry_sequence[index] != 0xFFFFFFFF )
    {
        sequence_buffer->entry_sequence[index] = 0xFFFFFFFF;
        cleanup_function( sequence_buffer->context, sequence_buffer->entry_data + sequence_buffer->entry_stride * index );
    }
}

int snapshot_sequence_buffer_available( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence )
{
    snapshot_assert( sequence_buffer );
    return sequence_buffer->entry_sequence[ sequence % sequence_buffer->num_entries ] == 0xFFFFFFFF;
}

int snapshot_sequence_buffer_exists( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence )
{
    snapshot_assert( sequence_buffer );

    return sequence_buffer->entry_sequence[ sequence % sequence_buffer->num_entries ] == (uint32_t) sequence;
}

void * snapshot_sequence_buffer_find( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t sequence )
{
    snapshot_assert( sequence_buffer );

    int index = sequence % sequence_buffer->num_entries;

    return ( ( sequence_buffer->entry_sequence[index] == (uint32_t) sequence ) ) ? ( sequence_buffer->entry_data + index * sequence_buffer->entry_stride ) : NULL;

}

void * snapshot_sequence_buffer_at_index( struct snapshot_sequence_buffer_t * sequence_buffer, int index )
{
    snapshot_assert( sequence_buffer );
    snapshot_assert( index >= 0 );
    snapshot_assert( index < sequence_buffer->num_entries );

    return sequence_buffer->entry_sequence[index] != 0xFFFFFFFF ? ( sequence_buffer->entry_data + index * sequence_buffer->entry_stride ) : NULL;
}

void snapshot_sequence_buffer_generate_ack_bits( struct snapshot_sequence_buffer_t * sequence_buffer, uint16_t * ack, uint32_t * ack_bits )
{
    snapshot_assert( sequence_buffer );
    snapshot_assert( ack );
    snapshot_assert( ack_bits );

    *ack = sequence_buffer->sequence - 1;
    *ack_bits = 0;
    uint32_t mask = 1;
    
    for ( int i = 0; i < 32; ++i )
    {
        uint16_t sequence = *ack - ((uint16_t)i);
        if ( snapshot_sequence_buffer_exists( sequence_buffer, sequence ) )
            *ack_bits |= mask;
        mask <<= 1;
    }
}
