/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_ENDPOINT_H
#define SNAPSHOT_ENDPOINT_H

#include "snapshot_packet_header.h"

#define SNAPSHOT_FRAGMENT_HEADER_BYTES                                      5

#define SNAPSHOT_MAX_FRAGMENTS                                            256

#define SNAPSHOT_ENDPOINT_MAX_WRITE_PACKETS                               256

#define SNAPSHOT_ENDPOINT_NAME_BYTES                                      256

#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_SENT                          0
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED                      1
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_ACKED                         2
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_STALE                         3
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_INVALID                       4
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND             5
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE          6
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT                        7
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED                    8
#define SNAPSHOT_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID                     9
#define SNAPSHOT_ENDPOINT_NUM_COUNTERS                                     10

struct snapshot_endpoint_config_t
{
    void * context;
    char name[SNAPSHOT_ENDPOINT_NAME_BYTES];
    int index;
    int fragment_above;
    int max_fragments;
    int fragment_size;
    int ack_buffer_size;
    int sent_packets_buffer_size;
    int received_packets_buffer_size;
    int fragment_reassembly_buffer_size;
    float rtt_smoothing_factor;
    float packet_loss_smoothing_factor;
    float bandwidth_smoothing_factor;
    int packet_header_size;
};

void snapshot_endpoint_default_config( struct snapshot_endpoint_config_t * config );

struct snapshot_endpoint_t
{
    void * context;
    struct snapshot_endpoint_config_t config;
    double time;
    float rtt;
    float packet_loss;
    float sent_bandwidth_kbps;
    float received_bandwidth_kbps;
    float acked_bandwidth_kbps;
    int num_acks;
    uint16_t * acks;
    uint16_t sequence;
    struct snapshot_sequence_buffer_t * sent_packets;
    struct snapshot_sequence_buffer_t * received_packets;
    struct snapshot_sequence_buffer_t * fragment_reassembly;
    uint64_t counters[SNAPSHOT_ENDPOINT_NUM_COUNTERS];
};

struct snapshot_endpoint_t * snapshot_endpoint_create( struct snapshot_endpoint_config_t * config, double time );

void snapshot_endpoint_destroy( struct snapshot_endpoint_t * endpoint );

uint16_t snapshot_endpoint_sequence( struct snapshot_endpoint_t * endpoint );

void snapshot_endpoint_write_packets( struct snapshot_endpoint_t * endpoint, uint8_t * payload_data, int payload_bytes, int * num_packets, uint8_t ** packet_data, int * packet_bytes );

void snapshot_endpoint_process_packet( struct snapshot_endpoint_t * endpoint, uint8_t * packet_data, int packet_bytes, uint8_t * payload_buffer, uint8_t ** out_payload_data, int * out_payload_bytes, uint16_t * out_packet_sequence, uint16_t * out_packet_ack, uint32_t * out_packet_ack_bits );

void snapshot_endpoint_mark_payload_processed( struct snapshot_endpoint_t * endpoint, uint16_t sequence, uint16_t ack, uint32_t ack_bits, int payload_bytes );

uint16_t * snapshot_endpoint_get_acks( struct snapshot_endpoint_t * endpoint, int * num_acks );

void snapshot_endpoint_clear_acks( struct snapshot_endpoint_t * endpoint );

void snapshot_endpoint_reset( struct snapshot_endpoint_t * endpoint );

void snapshot_endpoint_update( struct snapshot_endpoint_t * endpoint, double time );

float snapshot_endpoint_rtt( struct snapshot_endpoint_t * endpoint );

float snapshot_endpoint_packet_loss( struct snapshot_endpoint_t * endpoint );

void snapshot_endpoint_bandwidth( struct snapshot_endpoint_t * endpoint, float * sent_bandwidth_kbps, float * received_bandwidth_kbps, float * acked_bandwidth_kbps );

const uint64_t * snapshot_endpoint_counters( struct snapshot_endpoint_t * endpoint );

// -------------------------------------------------------------------

#endif // #ifndef SNAPSHOT_ENDPOINT_H
