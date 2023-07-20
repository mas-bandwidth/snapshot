/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_PACKET_HEADER_H
#define SNAPSHOT_PACKET_HEADER_H

#include "snapshot.h"

#define SNAPSHOT_MAX_PACKET_HEADER_BYTES 9

int snapshot_write_packet_header( uint8_t * packet_data, uint16_t sequence, uint16_t ack, uint32_t ack_bits );

int snapshot_read_packet_header( const char * name, const uint8_t * packet_data, int packet_bytes, uint16_t * sequence, uint16_t * ack, uint32_t * ack_bits );

#endif // #ifndef SNAPSHOT_PACKET_HEADER_H