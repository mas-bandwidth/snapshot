/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_network_simulator.h"

#if SNAPSHOT_DEVELOPMENT

#include "snapshot_address.h"
#include "snapshot_packets.h"
#include <stdlib.h>
#include <math.h>

#define SNAPSHOT_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES ( SNAPSHOT_MAX_CLIENTS * 256 )
#define SNAPSHOT_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS ( SNAPSHOT_MAX_CLIENTS * 64 )

struct snapshot_network_simulator_packet_entry_t
{
    struct snapshot_address_t from;
    struct snapshot_address_t to;
    double delivery_time;
    uint8_t * packet_data;
    int packet_bytes;
};

struct snapshot_network_simulator_t
{
    void * context;
    float latency_milliseconds;
    float jitter_milliseconds;
    float packet_loss_percent;
    float duplicate_percent;
    double time;
    int current_index;
    int num_pending_receive_packets;
    struct snapshot_network_simulator_packet_entry_t packet_entries[SNAPSHOT_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES];
    struct snapshot_network_simulator_packet_entry_t pending_receive_packets[SNAPSHOT_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS];
};

struct snapshot_network_simulator_t * snapshot_network_simulator_create( void * context )
{
    struct snapshot_network_simulator_t * network_simulator = (struct snapshot_network_simulator_t*) snapshot_malloc( context, sizeof( struct snapshot_network_simulator_t ) );

    snapshot_assert( network_simulator );

    memset( network_simulator, 0, sizeof( struct snapshot_network_simulator_t ) );

    network_simulator->context = context;

    return network_simulator;
}

void snapshot_network_simulator_set( struct snapshot_network_simulator_t * network_simulator, float latency_milliseconds, float jitter_milliseconds, float packet_loss_percent, float duplicate_percent )
{
    snapshot_assert( network_simulator );

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "network simulator set: latency = %.1f (ms), jitter = %.1f (ms), packet loss = %.1f%%, duplicate = %.1f%%", latency_milliseconds, jitter_milliseconds, packet_loss_percent, duplicate_percent );

    network_simulator->latency_milliseconds = latency_milliseconds;
    network_simulator->jitter_milliseconds = jitter_milliseconds;
    network_simulator->packet_loss_percent = packet_loss_percent;
    network_simulator->duplicate_percent = duplicate_percent;
}

void snapshot_network_simulator_reset( struct snapshot_network_simulator_t * network_simulator )
{
    snapshot_assert( network_simulator );

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "network simulator reset" );

    int i;
    for ( i = 0; i < SNAPSHOT_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES; ++i )
    {
        if ( network_simulator->packet_entries[i].packet_data != NULL )
        {
            snapshot_destroy_packet( network_simulator->context, network_simulator->packet_entries[i].packet_data );
        }
        memset( &network_simulator->packet_entries[i], 0, sizeof( struct snapshot_network_simulator_packet_entry_t ) );
    }

    for ( i = 0; i < network_simulator->num_pending_receive_packets; ++i )
    {
        if ( network_simulator->pending_receive_packets[i].packet_data != NULL )
        {
            snapshot_destroy_packet( network_simulator->context, network_simulator->pending_receive_packets[i].packet_data );
        }
        memset( &network_simulator->pending_receive_packets[i], 0, sizeof( struct snapshot_network_simulator_packet_entry_t ) );
    }

    network_simulator->current_index = 0;
    network_simulator->num_pending_receive_packets = 0;

    network_simulator->latency_milliseconds = 0.0f;
    network_simulator->jitter_milliseconds = 0.0f;
    network_simulator->packet_loss_percent = 0.0f;
    network_simulator->duplicate_percent = 0.0f;
}

void snapshot_network_simulator_destroy( struct snapshot_network_simulator_t * network_simulator )
{
    snapshot_assert( network_simulator );
    snapshot_network_simulator_reset( network_simulator );
    snapshot_free( network_simulator->context, network_simulator );
}

float snapshot_random_float( float a, float b )
{
    snapshot_assert( a < b );
    float random = ( (float) rand() ) / (float) RAND_MAX;
    float diff = b - a;
    float r = random * diff;
    return a + r;
}

void snapshot_network_simulator_queue_packet( struct snapshot_network_simulator_t * network_simulator, 
                                              const struct snapshot_address_t * from, 
                                              const struct snapshot_address_t * to, 
                                              uint8_t * packet_data, 
                                              int packet_bytes, 
                                              float delay )
{
    snapshot_assert( network_simulator );
    snapshot_assert( from );
    snapshot_assert( to );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes > 0 );

    network_simulator->packet_entries[network_simulator->current_index].from = *from;
    network_simulator->packet_entries[network_simulator->current_index].to = *to;
    network_simulator->packet_entries[network_simulator->current_index].packet_data = snapshot_create_packet( network_simulator->context, packet_bytes );
    memcpy( network_simulator->packet_entries[network_simulator->current_index].packet_data, packet_data, packet_bytes );
    network_simulator->packet_entries[network_simulator->current_index].packet_bytes = packet_bytes;
    network_simulator->packet_entries[network_simulator->current_index].delivery_time = network_simulator->time + delay;
    network_simulator->current_index++;
    network_simulator->current_index %= SNAPSHOT_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES;
}

void snapshot_network_simulator_send_packet( struct snapshot_network_simulator_t * network_simulator, 
                                             const struct snapshot_address_t * from, 
                                             const struct snapshot_address_t * to, 
                                             uint8_t * packet_data, 
                                             int packet_bytes )
{
    snapshot_assert( network_simulator );
    snapshot_assert( from );
    snapshot_assert( from->type != 0 );
    snapshot_assert( to );
    snapshot_assert( to->type != 0 );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes > 0 );
    snapshot_assert( packet_bytes <= SNAPSHOT_MAX_PACKET_BYTES );

    if ( snapshot_random_float( 0.0f, 100.0f ) <= network_simulator->packet_loss_percent )
        return;

    if ( network_simulator->packet_entries[network_simulator->current_index].packet_data )
    {
        snapshot_destroy_packet( network_simulator->context, network_simulator->packet_entries[network_simulator->current_index].packet_data );
        network_simulator->packet_entries[network_simulator->current_index].packet_data = NULL;
    }

    float delay = network_simulator->latency_milliseconds / 1000.0f;

    if ( network_simulator->jitter_milliseconds > 0.0 )
        delay += snapshot_random_float( -network_simulator->jitter_milliseconds, +network_simulator->jitter_milliseconds ) / 1000.0f;

    snapshot_network_simulator_queue_packet( network_simulator, from, to, packet_data, packet_bytes, delay );

    if ( snapshot_random_float( 0.0f, 100.0f ) <= network_simulator->duplicate_percent )
    {
        snapshot_network_simulator_queue_packet( network_simulator, from, to, packet_data, packet_bytes, delay + snapshot_random_float( 0, 1.0 ) );
    }
}

int snapshot_network_simulator_receive_packets( struct snapshot_network_simulator_t * network_simulator, 
                                                const struct snapshot_address_t * to, 
                                                int max_packets, 
                                                uint8_t ** packet_data, 
                                                int * packet_bytes, 
                                                struct snapshot_address_t * from )
{
    snapshot_assert( network_simulator );
    snapshot_assert( max_packets >= 0 );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes );
    snapshot_assert( from );
    snapshot_assert( to );

    int num_packets = 0;

    int i;
    for ( i = 0; i < network_simulator->num_pending_receive_packets; ++i )
    {
        if ( num_packets == max_packets )
            break;

        if ( !network_simulator->pending_receive_packets[i].packet_data )
            continue;

        if ( !snapshot_address_equal( &network_simulator->pending_receive_packets[i].to, to ) )
            continue;

        packet_data[num_packets] = network_simulator->pending_receive_packets[i].packet_data;
        packet_bytes[num_packets] = network_simulator->pending_receive_packets[i].packet_bytes;
        from[num_packets] = network_simulator->pending_receive_packets[i].from;

        network_simulator->pending_receive_packets[i].packet_data = NULL;

        num_packets++;
    }

    snapshot_assert( num_packets <= max_packets );

    return num_packets;
}

void snapshot_network_simulator_update( struct snapshot_network_simulator_t * network_simulator, double time )
{   
    snapshot_assert( network_simulator );

    network_simulator->time = time;

    // discard any pending receive packets that are still in the buffer

    int i;
    for ( i = 0; i < network_simulator->num_pending_receive_packets; ++i )
    {
        if ( network_simulator->pending_receive_packets[i].packet_data )
        {
            snapshot_destroy_packet( network_simulator->context, network_simulator->pending_receive_packets[i].packet_data );
            network_simulator->pending_receive_packets[i].packet_data = NULL;
        }
    }

    network_simulator->num_pending_receive_packets = 0;

    // walk across packet entries and move any that are ready to be received into the pending receive buffer

    for ( i = 0; i < SNAPSHOT_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES; ++i )
    {
        if ( !network_simulator->packet_entries[i].packet_data )
            continue;

        if ( network_simulator->num_pending_receive_packets == SNAPSHOT_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS )
            break;

        if ( network_simulator->packet_entries[i].packet_data && network_simulator->packet_entries[i].delivery_time <= time )
        {
            network_simulator->pending_receive_packets[network_simulator->num_pending_receive_packets] = network_simulator->packet_entries[i];
            network_simulator->num_pending_receive_packets++;
            network_simulator->packet_entries[i].packet_data = NULL;
        }
    }
}

#else // #if SNAPSHOT_DEVELOPMENT

int snapshot_network_simulator_dummy = 0;

#endif // #if SNAPSHOT_DEVELOPMENT
