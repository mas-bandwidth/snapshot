/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_ADDRESS_H
#define SNAPSHOT_ADDRESS_H

#include "snapshot.h"

#ifndef SNAPSHOT_ADDRESS_ALREADY_DEFINED
#define SNAPSHOT_ADDRESS_ALREADY_DEFINED
struct snapshot_address_t
{
    union { uint8_t ipv4[4]; uint16_t ipv6[8]; } data;
    uint16_t port;
    uint8_t type;
};
#endif 

int snapshot_address_parse( struct snapshot_address_t * address, const char * address_string );

const char * snapshot_address_to_string( const struct snapshot_address_t * address, char * buffer );

const char * snapshot_address_to_string_without_port( const struct snapshot_address_t * address, char * buffer );

SNAPSHOT_BOOL snapshot_address_equal( const struct snapshot_address_t * a, const struct snapshot_address_t * b );

void snapshot_address_anonymize( struct snapshot_address_t * address );

#endif // #ifndef SNAPSHOT_ADDRESS_H
