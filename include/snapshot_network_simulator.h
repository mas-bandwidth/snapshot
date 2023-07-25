/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_NETWORK_SIMULATOR_H
#define SNAPSHOT_NETWORK_SIMULATOR_H

#include "snapshot.h"

#if SNAPSHOT_DEVELOPMENT

struct snapshot_network_simulator_t * snapshot_network_simulator_create( void * context );

void snapshot_network_simulator_set( struct snapshot_network_simulator_t * network_simulator, 
                                     float latency_milliseconds, 
                                     float jitter_milliseconds, 
                                     float packet_loss_percent, 
                                     float duplicate_percent );

void snapshot_network_simulator_reset( struct snapshot_network_simulator_t * network_simulator );

void snapshot_network_simulator_destroy( struct snapshot_network_simulator_t * network_simulator );

void snapshot_network_simulator_send_packet( struct snapshot_network_simulator_t * network_simulator, 
                                             const struct snapshot_address_t * from, 
                                             const struct snapshot_address_t * to, 
                                             uint8_t * packet_data, 
                                             int packet_bytes );

int snapshot_network_simulator_receive_packets( struct snapshot_network_simulator_t * network_simulator, 
                                                const struct snapshot_address_t * to, 
                                                int max_packets, 
                                                uint8_t ** packet_data, 
                                                int * packet_bytes, 
                                                struct snapshot_address_t * from );

void snapshot_network_simulator_update( struct snapshot_network_simulator_t * network_simulator, double time );

#endif // #if SNAPSHOT_DEVELOPMENT

#endif // #ifndef SNAPSHOT_NETWORK_SIMULATOR
