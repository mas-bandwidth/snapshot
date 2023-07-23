/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_SERVER_H
#define SNAPSHOT_SERVER_H

#include "snapshot.h"

#define SNAPSHOT_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS           1
#define SNAPSHOT_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS     (1<<1)

#define SNAPSHOT_SERVER_COUNTER_PAYLOADS_SENT                            0
#define SNAPSHOT_SERVER_COUNTER_PAYLOADS_RECEIVED                        1
#define SNAPSHOT_SERVER_NUM_COUNTERS                                   256

struct snapshot_server_config_t
{
    void * context;
    uint64_t protocol_id;
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    struct snapshot_network_simulator_t * network_simulator;
    void (*connect_disconnect_callback)(void*,int,int);
    void (*send_loopback_packet_callback)(void*,struct snapshot_address_t*,uint8_t*,int);
    void (*process_passthrough_callback)(void*,int,const uint8_t*,int);
};

void snapshot_default_server_config( struct snapshot_server_config_t * config );

struct snapshot_server_t * snapshot_server_create( const char * server_address, const struct snapshot_server_config_t * config, double time );

void snapshot_server_destroy( struct snapshot_server_t * server );

void snapshot_server_start( struct snapshot_server_t * server, int max_clients );

void snapshot_server_stop( struct snapshot_server_t * server );

int snapshot_server_running( struct snapshot_server_t * server );

int snapshot_server_max_clients( struct snapshot_server_t * server );

void snapshot_server_update( struct snapshot_server_t * server, double time );

bool snapshot_server_process_packet( struct snapshot_server_t * server, struct snapshot_address_t * from, uint8_t * packet_data, int packet_bytes );

int snapshot_server_client_connected( struct snapshot_server_t * server, int client_index );

uint64_t snapshot_server_client_id( struct snapshot_server_t * server, int client_index );

struct snapshot_address_t * snapshot_server_client_address( struct snapshot_server_t * server, int client_index );

void snapshot_server_disconnect_client( struct snapshot_server_t * server, int client_index );

void snapshot_server_disconnect_all_clients( struct snapshot_server_t * server );

int snapshot_server_num_connected_clients( struct snapshot_server_t * server );

void * snapshot_server_client_user_data( struct snapshot_server_t * server, int client_index );

void snapshot_server_connect_loopback_client( struct snapshot_server_t * server, int client_index, uint64_t client_id, const uint8_t * user_data );

void snapshot_server_disconnect_loopback_client( struct snapshot_server_t * server, int client_index );

void snapshot_server_send_passthrough_packet( struct snapshot_server_t * server, int client_index, const uint8_t * passthrough_data, int passthrough_bytes );

int snapshot_server_client_loopback( struct snapshot_server_t * server, int client_index );

uint16_t snapshot_server_port( struct snapshot_server_t * server );

void snapshot_server_set_flags( struct snapshot_server_t * server, uint64_t flags );

#if SNAPSHOT_DEVELOPMENT
void snapshot_server_set_development_flags( struct snapshot_server_t * server, uint64_t flags );
#endif // #if SNAPSHOT_DEVELOPMENT

const uint64_t * snapshot_server_counters( struct snapshot_server_t * server );

#endif // #ifndef SNAPSHOT_SERVER_H
