/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_CLIENT_H
#define SNAPSHOT_CLIENT_H

#include "snapshot.h"

#define SNAPSHOT_CLIENT_STATE_CONNECT_TOKEN_EXPIRED                     -6
#define SNAPSHOT_CLIENT_STATE_INVALID_CONNECT_TOKEN                     -5
#define SNAPSHOT_CLIENT_STATE_CONNECTION_TIMED_OUT                      -4
#define SNAPSHOT_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT             -3
#define SNAPSHOT_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT              -2
#define SNAPSHOT_CLIENT_STATE_CONNECTION_DENIED                         -1
#define SNAPSHOT_CLIENT_STATE_DISCONNECTED                               0
#define SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST                 1
#define SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_RESPONSE                2
#define SNAPSHOT_CLIENT_STATE_CONNECTED                                  3

#define SNAPSHOT_CLIENT_COUNTER_PAYLOADS_SENT                            0
#define SNAPSHOT_CLIENT_COUNTER_PAYLOADS_RECEIVED                        1
#define SNAPSHOT_CLIENT_COUNTER_CONNECT_CALLS                            2
#define SNAPSHOT_CLIENT_COUNTER_DISCONNECT_CALLS                         3
#define SNAPSHOT_CLIENT_COUNTER_CONNECT_LOOPBACK_CALLS                   4
#define SNAPSHOT_CLIENT_COUNTER_DISCONNECT_LOOPBACK_CALLS                5
#define SNAPSHOT_CLIENT_COUNTER_CONNECTION_REQUEST_PACKETS_SENT          6
#define SNAPSHOT_CLIENT_COUNTER_CONNECTION_RESPONSE_PACKETS_SENT         7
#define SNAPSHOT_CLIENT_COUNTER_KEEP_ALIVE_PACKETS_SENT                  8
#define SNAPSHOT_CLIENT_COUNTER_PAYLOAD_PACKETS_SENT                     9
#define SNAPSHOT_CLIENT_COUNTER_PASSTHROUGH_PACKETS_SENT                10
#define SNAPSHOT_CLIENT_COUNTER_DISCONNECT_PACKETS_SENT                 11
#define SNAPSHOT_CLIENT_COUNTER_CONNECTION_DENIED_PACKETS_RECEIVED      12
#define SNAPSHOT_CLIENT_COUNTER_CONNECTION_CHALLENGE_PACKETS_RECEIVED   13
#define SNAPSHOT_CLIENT_COUNTER_KEEP_ALIVE_PACKETS_RECEIVED             14
#define SNAPSHOT_CLIENT_COUNTER_PAYLOAD_PACKETS_RECEIVED                15
#define SNAPSHOT_CLIENT_COUNTER_PASSTHROUGH_PACKETS_RECEIVED            16
#define SNAPSHOT_CLIENT_COUNTER_DISCONNECT_PACKETS_RECEIVED             17
#define SNAPSHOT_CLIENT_COUNTER_PACKETS_PROCESSED                       18
#define SNAPSHOT_CLIENT_COUNTER_READ_PACKET_FAILURES                    19
#define SNAPSHOT_CLIENT_COUNTER_PACKETS_RECEIVED                        20
#define SNAPSHOT_CLIENT_COUNTER_PACKETS_RECEIVED_SIMULATOR              21
#define SNAPSHOT_CLIENT_COUNTER_PACKETS_SENT                            22
#define SNAPSHOT_CLIENT_COUNTER_PACKETS_SENT_LOOPBACK                   23
#define SNAPSHOT_CLIENT_COUNTER_PACKETS_SENT_SIMULATOR                  24

#define SNAPSHOT_CLIENT_NUM_COUNTERS                                    25

struct snapshot_client_config_t
{
    void * context;
    void (*state_change_callback)(void*,int,int);
    void (*send_loopback_packet_callback)(void*,const struct snapshot_address_t*,uint8_t*,int);
    void (*process_passthrough_callback)(void*,const uint8_t*,int);
#if SNAPSHOT_DEVELOPMENT
    struct snapshot_network_simulator_t * network_simulator;
#endif // #if SNAPSHOT_DEVELOPMENT
};

void snapshot_default_client_config( struct snapshot_client_config_t * config );

struct snapshot_client_t * snapshot_client_create( const char * bind_address, const struct snapshot_client_config_t * config, double time );

void snapshot_client_destroy( struct snapshot_client_t * client );

void snapshot_client_connect( struct snapshot_client_t * client, uint8_t * connect_token );

void snapshot_client_update( struct snapshot_client_t * client, double time );

void snapshot_client_disconnect( struct snapshot_client_t * client );

int snapshot_client_state( struct snapshot_client_t * client );

int snapshot_client_index( struct snapshot_client_t * client );

int snapshot_client_max_clients( struct snapshot_client_t * client );

void snapshot_client_connect_loopback( struct snapshot_client_t * client, struct snapshot_address_t * server_address, int client_index, int max_clients );

void snapshot_client_disconnect_loopback( struct snapshot_client_t * client );

bool snapshot_client_process_packet( struct snapshot_client_t * client, const struct snapshot_address_t * from, uint8_t * packet_data, int packet_bytes );

int snapshot_client_loopback( struct snapshot_client_t * client );

void snapshot_client_send_passthrough_packet( struct snapshot_client_t * client, const uint8_t * passthrough_data, int passthrough_bytes );

uint16_t snapshot_client_port( struct snapshot_client_t * client );

const struct snapshot_address_t * snapshot_client_server_address( struct snapshot_client_t * client );

const char * snapshot_client_state_name( int client_state );

#if SNAPSHOT_DEVELOPMENT
void snapshot_client_set_development_flags( struct snapshot_client_t * client, uint64_t flags );
#endif // #if SNAPSHOT_DEVELOPMENT

const uint64_t * snapshot_client_counters( struct snapshot_client_t * client );

#endif // #ifndef SNAPSHOT_CLIENT_H
