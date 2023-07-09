/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_NETWORK_SIMULATOR_H
#define SNAPSHOT_NETWORK_SIMULATOR_H

#include "snapshot.h"

// todo: clean up

/*
#define NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES ( NETCODE_MAX_CLIENTS * 256 )
#define NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS ( NETCODE_MAX_CLIENTS * 64 )

struct netcode_network_simulator_packet_entry_t
{
    struct netcode_address_t from;
    struct netcode_address_t to;
    double delivery_time;
    uint8_t * packet_data;
    int packet_bytes;
};

struct netcode_network_simulator_t
{
    void * allocator_context;
    void * (*allocate_function)(void*,uint64_t);
    void (*free_function)(void*,void*);
    float latency_milliseconds;
    float jitter_milliseconds;
    float packet_loss_percent;
    float duplicate_packet_percent;
    double time;
    int current_index;
    int num_pending_receive_packets;
    struct netcode_network_simulator_packet_entry_t packet_entries[NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES];
    struct netcode_network_simulator_packet_entry_t pending_receive_packets[NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS];
};

struct netcode_network_simulator_t * netcode_network_simulator_create( void * allocator_context, 
                                                                       void * (*allocate_function)(void*,uint64_t), 
                                                                       void (*free_function)(void*,void*) )
{
    if ( allocate_function == NULL )
    {
        allocate_function = netcode_default_allocate_function;
    }

    if ( free_function == NULL )
    {
        free_function = netcode_default_free_function;
    }

    struct netcode_network_simulator_t * network_simulator = (struct netcode_network_simulator_t*) 
        allocate_function( allocator_context, sizeof( struct netcode_network_simulator_t ) );

    netcode_assert( network_simulator );

    memset( network_simulator, 0, sizeof( struct netcode_network_simulator_t ) );

    network_simulator->allocator_context = allocator_context;
    network_simulator->allocate_function = allocate_function;
    network_simulator->free_function = free_function;

    return network_simulator;
}

void netcode_network_simulator_reset( struct netcode_network_simulator_t * network_simulator )
{
    netcode_assert( network_simulator );

    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "network simulator reset\n" );

    int i;
    for ( i = 0; i < NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES; ++i )
    {
        network_simulator->free_function( network_simulator->allocator_context, network_simulator->packet_entries[i].packet_data );
        memset( &network_simulator->packet_entries[i], 0, sizeof( struct netcode_network_simulator_packet_entry_t ) );
    }

    for ( i = 0; i < network_simulator->num_pending_receive_packets; ++i )
    {
        network_simulator->free_function( network_simulator->allocator_context, network_simulator->pending_receive_packets[i].packet_data );
        memset( &network_simulator->pending_receive_packets[i], 0, sizeof( struct netcode_network_simulator_packet_entry_t ) );
    }

    network_simulator->current_index = 0;
    network_simulator->num_pending_receive_packets = 0;
}

void netcode_network_simulator_destroy( struct netcode_network_simulator_t * network_simulator )
{
    netcode_assert( network_simulator );
    netcode_network_simulator_reset( network_simulator );
    network_simulator->free_function( network_simulator->allocator_context, network_simulator );
}

float netcode_random_float( float a, float b )
{
    netcode_assert( a < b );
    float random = ( (float) rand() ) / (float) RAND_MAX;
    float diff = b - a;
    float r = random * diff;
    return a + r;
}

void netcode_network_simulator_queue_packet( struct netcode_network_simulator_t * network_simulator, 
                                             struct netcode_address_t * from, 
                                             struct netcode_address_t * to, 
                                             uint8_t * packet_data, 
                                             int packet_bytes, 
                                             float delay )
{
    network_simulator->packet_entries[network_simulator->current_index].from = *from;
    network_simulator->packet_entries[network_simulator->current_index].to = *to;
    network_simulator->packet_entries[network_simulator->current_index].packet_data = 
        (uint8_t*) network_simulator->allocate_function( network_simulator->allocator_context, packet_bytes );
    memcpy( network_simulator->packet_entries[network_simulator->current_index].packet_data, packet_data, packet_bytes );
    network_simulator->packet_entries[network_simulator->current_index].packet_bytes = packet_bytes;
    network_simulator->packet_entries[network_simulator->current_index].delivery_time = network_simulator->time + delay;
    network_simulator->current_index++;
    network_simulator->current_index %= NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES;
}

void netcode_network_simulator_send_packet( struct netcode_network_simulator_t * network_simulator, 
                                            struct netcode_address_t * from, 
                                            struct netcode_address_t * to, 
                                            uint8_t * packet_data, 
                                            int packet_bytes )
{
    netcode_assert( network_simulator );
    netcode_assert( from );
    netcode_assert( from->type != 0 );
    netcode_assert( to );
    netcode_assert( to->type != 0 );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );
    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_BYTES );

    if ( netcode_random_float( 0.0f, 100.0f ) <= network_simulator->packet_loss_percent )
        return;

    if ( network_simulator->packet_entries[network_simulator->current_index].packet_data )
    {
        network_simulator->free_function( network_simulator->allocator_context, network_simulator->packet_entries[network_simulator->current_index].packet_data );
        network_simulator->packet_entries[network_simulator->current_index].packet_data = NULL;
    }

    float delay = network_simulator->latency_milliseconds / 1000.0f;

    if ( network_simulator->jitter_milliseconds > 0.0 )
        delay += netcode_random_float( -network_simulator->jitter_milliseconds, +network_simulator->jitter_milliseconds ) / 1000.0f;

    netcode_network_simulator_queue_packet( network_simulator, from, to, packet_data, packet_bytes, delay );

    if ( netcode_random_float( 0.0f, 100.0f ) <= network_simulator->duplicate_packet_percent )
    {
        netcode_network_simulator_queue_packet( network_simulator, from, to, packet_data, packet_bytes, delay + netcode_random_float( 0, 1.0 ) );
    }
}

int netcode_network_simulator_receive_packets( struct netcode_network_simulator_t * network_simulator, 
                                               struct netcode_address_t * to, 
                                               int max_packets, 
                                               uint8_t ** packet_data, 
                                               int * packet_bytes, 
                                               struct netcode_address_t * from )
{
    netcode_assert( network_simulator );
    netcode_assert( max_packets >= 0 );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes );
    netcode_assert( from );
    netcode_assert( to );

    int num_packets = 0;

    int i;
    for ( i = 0; i < network_simulator->num_pending_receive_packets; ++i )
    {
        if ( num_packets == max_packets )
            break;

        if ( !network_simulator->pending_receive_packets[i].packet_data )
            continue;

        if ( !netcode_address_equal( &network_simulator->pending_receive_packets[i].to, to ) )
            continue;

        packet_data[num_packets] = network_simulator->pending_receive_packets[i].packet_data;
        packet_bytes[num_packets] = network_simulator->pending_receive_packets[i].packet_bytes;
        from[num_packets] = network_simulator->pending_receive_packets[i].from;

        network_simulator->pending_receive_packets[i].packet_data = NULL;

        num_packets++;
    }

    netcode_assert( num_packets <= max_packets );

    return num_packets;
}

void netcode_network_simulator_update( struct netcode_network_simulator_t * network_simulator, double time )
{   
    netcode_assert( network_simulator );

    network_simulator->time = time;

    // discard any pending receive packets that are still in the buffer

    int i;
    for ( i = 0; i < network_simulator->num_pending_receive_packets; ++i )
    {
        if ( network_simulator->pending_receive_packets[i].packet_data )
        {
            network_simulator->free_function( network_simulator->allocator_context, network_simulator->pending_receive_packets[i].packet_data );
            network_simulator->pending_receive_packets[i].packet_data = NULL;
        }
    }

    network_simulator->num_pending_receive_packets = 0;

    // walk across packet entries and move any that are ready to be received into the pending receive buffer

    for ( i = 0; i < NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES; ++i )
    {
        if ( !network_simulator->packet_entries[i].packet_data )
            continue;

        if ( network_simulator->num_pending_receive_packets == NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS )
            break;

        if ( network_simulator->packet_entries[i].packet_data && network_simulator->packet_entries[i].delivery_time <= time )
        {
            network_simulator->pending_receive_packets[network_simulator->num_pending_receive_packets] = network_simulator->packet_entries[i];
            network_simulator->num_pending_receive_packets++;
            network_simulator->packet_entries[i].packet_data = NULL;
        }
    }
}
*/

#endif // #ifndef SNAPSHOT_NETWORK_SIMULATOR_H
