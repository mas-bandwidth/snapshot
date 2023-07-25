/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_SERVER_H
#define SNAPSHOT_SERVER_H

#include "snapshot.h"

#define SNAPSHOT_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS                       1
#define SNAPSHOT_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS                 (1<<1)

#define SNAPSHOT_SERVER_COUNTER_PAYLOADS_SENT                                        0
#define SNAPSHOT_SERVER_COUNTER_PAYLOADS_RECEIVED                                    1
#define SNAPSHOT_SERVER_COUNTER_STARTS                                               2
#define SNAPSHOT_SERVER_COUNTER_STOPS                                                3
#define SNAPSHOT_SERVER_COUNTER_CLIENT_CONNECTS                                      4
#define SNAPSHOT_SERVER_COUNTER_CLIENT_DISCONNECTS                                   5
#define SNAPSHOT_SERVER_COUNTER_CLIENT_LOOPBACK_CONNECTS                             6
#define SNAPSHOT_SERVER_COUNTER_CLIENT_LOOPBACK_DISCONNECTS                          7
#define SNAPSHOT_SERVER_COUNTER_CONNECTION_DENIED_PACKETS_SENT                       8
#define SNAPSHOT_SERVER_COUNTER_CONNECTION_CHALLENGE_PACKETS_SENT                    9
#define SNAPSHOT_SERVER_COUNTER_KEEP_ALIVE_PACKETS_SENT                             10
#define SNAPSHOT_SERVER_COUNTER_PAYLOAD_PACKETS_SENT                                11
#define SNAPSHOT_SERVER_COUNTER_PASSTHROUGH_PACKETS_SENT                            12
#define SNAPSHOT_SERVER_COUNTER_DISCONNECT_PACKETS_SENT                             13
#define SNAPSHOT_SERVER_COUNTER_CONNECTION_REQUEST_PACKETS_RECEIVED                 14
#define SNAPSHOT_SERVER_COUNTER_CONNECTION_RESPONSE_PACKETS_RECEIVED                15
#define SNAPSHOT_SERVER_COUNTER_KEEP_ALIVE_PACKETS_RECEIVED                         16
#define SNAPSHOT_SERVER_COUNTER_PAYLOAD_PACKETS_RECEIVED                            17
#define SNAPSHOT_SERVER_COUNTER_PASSTHROUGH_PACKETS_RECEIVED                        18
#define SNAPSHOT_SERVER_COUNTER_DISCONNECT_PACKETS_RECEIVED                         19
#define SNAPSHOT_SERVER_COUNTER_PACKETS_PROCESSED                                   20
#define SNAPSHOT_SERVER_COUNTER_PACKETS_RECEIVED                                    21
#define SNAPSHOT_SERVER_COUNTER_PACKETS_RECEIVED_SIMULATOR                          22
#define SNAPSHOT_SERVER_COUNTER_READ_PACKET_FAILURES                                23
#define SNAPSHOT_SERVER_COUNTER_PACKETS_SENT                                        24
#define SNAPSHOT_SERVER_COUNTER_PACKETS_SENT_LOOPBACK                               25
#define SNAPSHOT_SERVER_COUNTER_PACKETS_SENT_SIMULATOR                              26

#define SNAPSHOT_SERVER_NUM_COUNTERS                                                27

struct snapshot_server_config_t
{
    void * context;
    int max_clients;
    uint64_t protocol_id;
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    struct snapshot_network_simulator_t * network_simulator;
    void (*connect_disconnect_callback)(void*,int,int);
    void (*send_loopback_packet_callback)(void*,const struct snapshot_address_t*,uint8_t*,int);
    void (*process_passthrough_callback)(void*,const struct snapshot_address_t*,int,const uint8_t*,int);
};

void snapshot_default_server_config( struct snapshot_server_config_t * config );

struct snapshot_server_t * snapshot_server_create( const char * server_address, const struct snapshot_server_config_t * config, double time );

void snapshot_server_destroy( struct snapshot_server_t * server );

void snapshot_server_update( struct snapshot_server_t * server, double time );

int snapshot_server_connected_clients( struct snapshot_server_t * server );

int snapshot_server_max_clients( struct snapshot_server_t * server );

bool snapshot_server_process_packet( struct snapshot_server_t * server, const struct snapshot_address_t * from, uint8_t * packet_data, int packet_bytes );

int snapshot_server_client_connected( struct snapshot_server_t * server, int client_index );

uint64_t snapshot_server_client_id( struct snapshot_server_t * server, int client_index );

struct snapshot_address_t * snapshot_server_client_address( struct snapshot_server_t * server, int client_index );

void snapshot_server_disconnect_client( struct snapshot_server_t * server, int client_index );

void snapshot_server_disconnect_all_clients( struct snapshot_server_t * server );

int snapshot_server_num_connected_clients( struct snapshot_server_t * server );

void * snapshot_server_client_user_data( struct snapshot_server_t * server, int client_index );

void snapshot_server_connect_loopback_client( struct snapshot_server_t * server, int client_index, uint64_t client_id, const uint8_t * user_data );

void snapshot_server_disconnect_loopback_client( struct snapshot_server_t * server, int client_index );

int snapshot_server_find_client_index_by_address( struct snapshot_server_t * server, const struct snapshot_address_t * address );

void snapshot_server_send_passthrough_packet( struct snapshot_server_t * server, int client_index, const uint8_t * passthrough_data, int passthrough_bytes );

int snapshot_server_client_loopback( struct snapshot_server_t * server, int client_index );

uint16_t snapshot_server_port( struct snapshot_server_t * server );

void snapshot_server_set_flags( struct snapshot_server_t * server, uint64_t flags );

#if SNAPSHOT_DEVELOPMENT
void snapshot_server_set_development_flags( struct snapshot_server_t * server, uint64_t flags );
#endif // #if SNAPSHOT_DEVELOPMENT

const uint64_t * snapshot_server_counters( struct snapshot_server_t * server );

#endif // #ifndef SNAPSHOT_SERVER_H
