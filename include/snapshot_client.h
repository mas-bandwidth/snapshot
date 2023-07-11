/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_CLIENT_H
#define SNAPSHOT_CLIENT_H

#include "snapshot.h"

struct snapshot_client_config_t
{
    void * context;
    struct snapshot_network_simulator_t * network_simulator;
    void (*state_change_callback)(void*,int,int);
    void (*send_loopback_packet_callback)(void*,int,const uint8_t*,int,uint64_t);
};

void snapshot_default_client_config( struct snapshot_client_config_t * config );

struct snapshot_client_t * snapshot_client_create( const char * bind_address, const struct snapshot_client_config_t * config, double time );

void snapshot_client_destroy( struct snapshot_client_t * client );

void snapshot_client_connect( struct snapshot_client_t * client, uint8_t * connect_token );

void snapshot_client_update( struct snapshot_client_t * client, double time );

uint64_t snapshot_client_next_packet_sequence( struct snapshot_client_t * client );

void snapshot_client_send_packet( struct snapshot_client_t * client, const uint8_t * packet_data, int packet_bytes );

uint8_t * snapshot_client_receive_packet( struct snapshot_client_t * client, int * packet_bytes, uint64_t * packet_sequence );

void snapshot_client_free_packet( struct snapshot_client_t * client, void * packet );

void snapshot_client_disconnect( struct snapshot_client_t * client );

int snapshot_client_state( struct snapshot_client_t * client );

int snapshot_client_index( struct snapshot_client_t * client );

int snapshot_client_max_clients( struct snapshot_client_t * client );

void snapshot_client_connect_loopback( struct snapshot_client_t * client, struct snapshot_address_t * server_address, int client_index, int max_clients );

void snapshot_client_disconnect_loopback( struct snapshot_client_t * client );

void snapshot_client_process_packet( struct snapshot_client_t * client, struct snapshot_address_t * from, uint8_t * packet_data, int packet_bytes );

int snapshot_client_loopback( struct snapshot_client_t * client );

void snapshot_client_process_loopback_packet( struct snapshot_client_t * client, const uint8_t * packet_data, int packet_bytes, uint64_t packet_sequence );

uint16_t snapshot_client_port( struct snapshot_client_t * client );

const struct snapshot_address_t * snapshot_client_server_address( struct snapshot_client_t * client );

const char * snapshot_client_state_name( int client_state );

#endif // #ifndef SNAPSHOT_CLIENT_H
