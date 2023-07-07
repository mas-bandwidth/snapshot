/*
    Snapshot SDK Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licenses under different terms are available. Email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_PLATFORM_H
#define SNAPSHOT_PLATFORM_H

int snapshot_platform_init();

void snapshot_platform_term();

const char * snapshot_platform_getenv( const char * var );

uint16_t snapshot_platform_ntohs( uint16_t in );

uint16_t snapshot_platform_htons( uint16_t in );

int snapshot_platform_inet_pton4( const char * address_string, uint32_t * address_out );

int snapshot_platform_inet_pton6( const char * address_string, uint16_t * address_out );

int snapshot_platform_inet_ntop6( const uint16_t * address, char * address_string, size_t address_string_size );

#endif // #ifndef SNAPSHOT_PLATFORM_H
