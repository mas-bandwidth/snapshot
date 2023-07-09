/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_SERVER_H
#define SNAPSHOT_SERVER_H

#include "snapshot.h"

// todo
/*
struct snapshot_server_config_t
{
    uint64_t protocol_id;
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    void * allocator_context;
    void * (*allocate_function)(void*,uint64_t);
    void (*free_function)(void*,void*);
    struct snapshot_network_simulator_t * network_simulator;
    void * callback_context;
    void (*connect_disconnect_callback)(void*,int,int);
    void (*send_loopback_packet_callback)(void*,int,const uint8_t*,int,uint64_t);
    int override_send_and_receive;
    void (*send_packet_override)(void*,struct snapshot_address_t*,const uint8_t*,int);
    int (*receive_packet_override)(void*,struct snapshot_address_t*,uint8_t*,int);
};

void snapshot_default_server_config( struct snapshot_server_config_t * config );

struct snapshot_server_t * snapshot_server_create( const char * server_address, const struct snapshot_server_config_t * config, double time );

void snapshot_server_destroy( struct snapshot_server_t * server );

void snapshot_server_start( struct snapshot_server_t * server, int max_clients );

void snapshot_server_stop( struct snapshot_server_t * server );

int snapshot_server_running( struct snapshot_server_t * server );

int snapshot_server_max_clients( struct snapshot_server_t * server );

void snapshot_server_update( struct snapshot_server_t * server, double time );

int snapshot_server_client_connected( struct snapshot_server_t * server, int client_index );

uint64_t snapshot_server_client_id( struct snapshot_server_t * server, int client_index );

struct snapshot_address_t * snapshot_server_client_address( struct snapshot_server_t * server, int client_index );

void snapshot_server_disconnect_client( struct snapshot_server_t * server, int client_index );

void snapshot_server_disconnect_all_clients( struct snapshot_server_t * server );

uint64_t snapshot_server_next_packet_sequence( struct snapshot_server_t * server, int client_index );

void snapshot_server_send_packet( struct snapshot_server_t * server, int client_index, const * packet_data, int packet_bytes );

uint8_t * snapshot_server_receive_packet( struct snapshot_server_t * server, int client_index, int * packet_bytes, uint64_t * packet_sequence );

void snapshot_server_free_packet( struct snapshot_server_t * server, void * packet );

int snapshot_server_num_connected_clients( struct snapshot_server_t * server );

void * snapshot_server_client_user_data( struct snapshot_server_t * server, int client_index );

void snapshot_server_process_packet( struct snapshot_server_t * server, struct snapshot_address_t * from, uint8_t * packet_data, int packet_bytes );

void snapshot_server_connect_loopback_client( struct snapshot_server_t * server, int client_index, uint64_t client_id, const uint8_t * user_data );

void snapshot_server_disconnect_loopback_client( struct snapshot_server_t * server, int client_index );

int snapshot_server_client_loopback( struct snapshot_server_t * server, int client_index );

void snapshot_server_process_loopback_packet( struct snapshot_server_t * server, int client_index, const uint8_t * packet_data, int packet_bytes, uint64_t packet_sequence );

uint16_t snapshot_server_get_port( struct snapshot_server_t * server );
*/

#endif // #ifndef SNAPSHOT_SERVER_H
