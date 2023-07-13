/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_address.h"
#include "snapshot_platform.h"

#include <stdlib.h>

#define SNAPSHOT_ADDRESS_BUFFER_SAFETY 32

int snapshot_address_parse( snapshot_address_t * address, const char * address_string_in )
{
    snapshot_assert( address );
    snapshot_assert( address_string_in );

    if ( !address )
        return SNAPSHOT_ERROR;

    if ( !address_string_in )
        return SNAPSHOT_ERROR;

    memset( address, 0, sizeof( snapshot_address_t ) );

    // first try to parse the string as an IPv6 address:
    // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
    // 2. otherwise try to parse as an IPv6 address using inet_pton

    char buffer[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH + SNAPSHOT_ADDRESS_BUFFER_SAFETY*2];

    char * address_string = buffer + SNAPSHOT_ADDRESS_BUFFER_SAFETY;
    snapshot_copy_string( address_string, address_string_in, SNAPSHOT_MAX_ADDRESS_STRING_LENGTH );

    int address_string_length = (int) strlen( address_string );

    if ( address_string[0] == '[' )
    {
        const int base_index = address_string_length - 1;

        // note: no need to search past 6 characters as ":65535" is longest possible port value
        for ( int i = 0; i < 6; ++i )
        {
            const int index = base_index - i;
            if ( index < 0 )
            {
                return SNAPSHOT_ERROR;
            }
            if ( address_string[index] == ':' )
            {
                address->port = (uint16_t) ( atoi( &address_string[index + 1] ) );
                address_string[index-1] = '\0';
                break;
            }
            else if ( address_string[index] == ']' )
            {
                // no port number
                address->port = 0;
                address_string[index] = '\0';
                break;
            }
        }
        address_string += 1;
    }

    uint16_t addr6[8];
    if ( snapshot_platform_inet_pton6( address_string, addr6 ) == SNAPSHOT_OK )
    {
        address->type = SNAPSHOT_ADDRESS_IPV6;
        for ( int i = 0; i < 8; ++i )
        {
            address->data.ipv6[i] = snapshot_platform_ntohs( addr6[i] );
        }
        return SNAPSHOT_OK;
    }

    // otherwise it's probably an IPv4 address:
    // 1. look for ":portnum", if found save the portnum and strip it out
    // 2. parse remaining ipv4 address via inet_pton

    address_string_length = (int) strlen( address_string );
    const int base_index = address_string_length - 1;
    for ( int i = 0; i < 6; ++i )
    {
        const int index = base_index - i;
        if ( index < 0 )
            break;
        if ( address_string[index] == ':' )
        {
            address->port = (uint16_t)( atoi( &address_string[index + 1] ) );
            address_string[index] = '\0';
        }
    }

    uint32_t addr4;
    if ( snapshot_platform_inet_pton4( address_string, &addr4 ) == SNAPSHOT_OK )
    {
        address->type = SNAPSHOT_ADDRESS_IPV4;
        address->data.ipv4[3] = (uint8_t) ( ( addr4 & 0xFF000000 ) >> 24 );
        address->data.ipv4[2] = (uint8_t) ( ( addr4 & 0x00FF0000 ) >> 16 );
        address->data.ipv4[1] = (uint8_t) ( ( addr4 & 0x0000FF00 ) >> 8  );
        address->data.ipv4[0] = (uint8_t) ( ( addr4 & 0x000000FF )     );
        return SNAPSHOT_OK;
    }

    return SNAPSHOT_ERROR;
}

const char * snapshot_address_to_string( const snapshot_address_t * address, char * buffer )
{
    snapshot_assert( buffer );

    if ( address->type == SNAPSHOT_ADDRESS_IPV6 )
    {
#if defined(WINVER) && WINVER <= 0x0502
        // ipv6 not supported
        buffer[0] = '\0';
        return buffer;
#else
        uint16_t ipv6_network_order[8];
        for ( int i = 0; i < 8; ++i )
            ipv6_network_order[i] = snapshot_platform_htons( address->data.ipv6[i] );
        char address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
        snapshot_platform_inet_ntop6( ipv6_network_order, address_string, sizeof( address_string ) );
        if ( address->port == 0 )
        {
            snapshot_copy_string( buffer, address_string, SNAPSHOT_MAX_ADDRESS_STRING_LENGTH );
            return buffer;
        }
        else
        {
            if ( snprintf( buffer, SNAPSHOT_MAX_ADDRESS_STRING_LENGTH, "[%s]:%hu", address_string, address->port ) < 0 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "address string truncated: [%s]:%hu", address_string, address->port );
            }
            return buffer;
        }
#endif
    }
    else if ( address->type == SNAPSHOT_ADDRESS_IPV4 )
    {
        if ( address->port != 0 )
        {
            snprintf( buffer,
                      SNAPSHOT_MAX_ADDRESS_STRING_LENGTH,
                      "%d.%d.%d.%d:%d",
                      address->data.ipv4[0],
                      address->data.ipv4[1],
                      address->data.ipv4[2],
                      address->data.ipv4[3],
                      address->port );
        }
        else
        {
            snprintf( buffer,
                      SNAPSHOT_MAX_ADDRESS_STRING_LENGTH,
                      "%d.%d.%d.%d",
                      address->data.ipv4[0],
                      address->data.ipv4[1],
                      address->data.ipv4[2],
                      address->data.ipv4[3] );
        }
        return buffer;
    }
    else
    {
        snprintf( buffer, SNAPSHOT_MAX_ADDRESS_STRING_LENGTH, "%s", "NONE" );
        return buffer;
    }
}

SNAPSHOT_BOOL snapshot_address_equal( const snapshot_address_t * a, const snapshot_address_t * b )
{
    snapshot_assert( a );
    snapshot_assert( b );

    if ( a->type != b->type )
        return SNAPSHOT_FALSE;

    if ( a->type == SNAPSHOT_ADDRESS_IPV4 )
    {
        if ( a->port != b->port )
            return SNAPSHOT_FALSE;

        for ( int i = 0; i < 4; ++i )
        {
            if ( a->data.ipv4[i] != b->data.ipv4[i] )
                return SNAPSHOT_FALSE;
        }
    }
    else if ( a->type == SNAPSHOT_ADDRESS_IPV6 )
    {
        if ( a->port != b->port )
            return SNAPSHOT_FALSE;

        for ( int i = 0; i < 8; ++i )
        {
            if ( a->data.ipv6[i] != b->data.ipv6[i] )
                return SNAPSHOT_FALSE;
        }
    }

    return SNAPSHOT_TRUE;
}

void snapshot_address_anonymize( snapshot_address_t * address )
{
    snapshot_assert( address );
    if ( address->type == SNAPSHOT_ADDRESS_IPV4 )
    {
        address->data.ipv4[3] = 0;
    }
    else
    {
        address->data.ipv6[4] = 0;
        address->data.ipv6[5] = 0;
        address->data.ipv6[6] = 0;
        address->data.ipv6[7] = 0;
    }
    address->port = 0;
}
