/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_connect_token.h"
#include "snapshot_read_write.h"
#include "snapshot_crypto.h"
#include <time.h>

int snapshot_generate_connect_token( int num_server_addresses, 
                                     const char ** server_addresses, 
                                     int expire_seconds, 
                                     int timeout_seconds,
                                     uint64_t client_id, 
                                     uint64_t protocol_id, 
                                     const uint8_t * private_key, 
                                     uint8_t * user_data, 
                                     uint8_t * output_buffer )
{
    snapshot_assert( num_server_addresses > 0 );
    snapshot_assert( num_server_addresses <= SNAPSHOT_MAX_SERVERS_PER_CONNECT );
    snapshot_assert( server_addresses );
    snapshot_assert( private_key );
    snapshot_assert( user_data );
    snapshot_assert( output_buffer );

    // parse server addresses

    struct snapshot_address_t parsed_server_addresses[SNAPSHOT_MAX_SERVERS_PER_CONNECT];
    int i;
    for ( i = 0; i < num_server_addresses; ++i )
    {
        if ( snapshot_address_parse( &parsed_server_addresses[i], server_addresses[i] ) != SNAPSHOT_OK )
        {
            return SNAPSHOT_ERROR;
        }
    }

    // generate a connect token

    uint8_t nonce[SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES];
    snapshot_crypto_random_bytes( nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );

    struct snapshot_connect_token_private_t connect_token_private;
    snapshot_generate_connect_token_private( &connect_token_private, client_id, timeout_seconds, num_server_addresses, parsed_server_addresses, user_data );

    // write it to a buffer

    uint8_t connect_token_data[SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES];
    snapshot_write_connect_token_private( &connect_token_private, connect_token_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

    // encrypt the buffer

    uint64_t create_timestamp = time( NULL );
    uint64_t expire_timestamp = ( expire_seconds >= 0 ) ? ( create_timestamp + expire_seconds ) : 0xFFFFFFFFFFFFFFFFULL;
    if ( snapshot_encrypt_connect_token_private( connect_token_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES, SNAPSHOT_VERSION_INFO, protocol_id, expire_timestamp, nonce, private_key ) != SNAPSHOT_OK )
        return SNAPSHOT_ERROR;

    // wrap a connect token around the private connect token data

    struct snapshot_connect_token_t connect_token;
    memcpy( connect_token.version_info, SNAPSHOT_VERSION_INFO, SNAPSHOT_VERSION_INFO_BYTES );
    connect_token.protocol_id = protocol_id;
    connect_token.create_timestamp = create_timestamp;
    connect_token.expire_timestamp = expire_timestamp;
    memcpy( connect_token.nonce, nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );
    memcpy( connect_token.private_data, connect_token_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );
    connect_token.num_server_addresses = num_server_addresses;
    for ( i = 0; i < num_server_addresses; ++i )
        connect_token.server_addresses[i] = parsed_server_addresses[i];
    memcpy( connect_token.client_to_server_key, connect_token_private.client_to_server_key, SNAPSHOT_KEY_BYTES );
    memcpy( connect_token.server_to_client_key, connect_token_private.server_to_client_key, SNAPSHOT_KEY_BYTES );
    connect_token.timeout_seconds = timeout_seconds;

    // write the connect token to the output buffer

    snapshot_write_connect_token( &connect_token, output_buffer, SNAPSHOT_CONNECT_TOKEN_BYTES );

    return SNAPSHOT_OK;
}

void snapshot_write_connect_token( struct snapshot_connect_token_t * connect_token, uint8_t * buffer, int buffer_length )
{
    snapshot_assert( connect_token );
    snapshot_assert( buffer );
    snapshot_assert( buffer_length >= SNAPSHOT_CONNECT_TOKEN_BYTES );

    uint8_t * start = buffer;

    (void) start;
    (void) buffer_length;

    snapshot_write_bytes( &buffer, connect_token->version_info, SNAPSHOT_VERSION_INFO_BYTES );

    snapshot_write_uint64( &buffer, connect_token->protocol_id );

    snapshot_write_uint64( &buffer, connect_token->create_timestamp );

    snapshot_write_uint64( &buffer, connect_token->expire_timestamp );

    snapshot_write_bytes( &buffer, connect_token->nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );

    snapshot_write_bytes( &buffer, connect_token->private_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

    int i,j;

    snapshot_write_uint32( &buffer, connect_token->timeout_seconds );

    snapshot_write_uint32( &buffer, connect_token->num_server_addresses );

    for ( i = 0; i < connect_token->num_server_addresses; ++i )
    {
        if ( connect_token->server_addresses[i].type == SNAPSHOT_ADDRESS_IPV4 )
        {
            snapshot_write_uint8( &buffer, SNAPSHOT_ADDRESS_IPV4 );
            for ( j = 0; j < 4; ++j )
            {
                snapshot_write_uint8( &buffer, connect_token->server_addresses[i].data.ipv4[j] );
            }
            snapshot_write_uint16( &buffer, connect_token->server_addresses[i].port );
        }
        else if ( connect_token->server_addresses[i].type == SNAPSHOT_ADDRESS_IPV6 )
        {
            snapshot_write_uint8( &buffer, SNAPSHOT_ADDRESS_IPV6 );
            for ( j = 0; j < 8; ++j )
            {
                snapshot_write_uint16( &buffer, connect_token->server_addresses[i].data.ipv6[j] );
            }
            snapshot_write_uint16( &buffer, connect_token->server_addresses[i].port );
        }
        else
        {
            snapshot_assert( 0 );
        }
    }

    snapshot_write_bytes( &buffer, connect_token->client_to_server_key, SNAPSHOT_KEY_BYTES );

    snapshot_write_bytes( &buffer, connect_token->server_to_client_key, SNAPSHOT_KEY_BYTES );

    snapshot_assert( buffer - start <= SNAPSHOT_CONNECT_TOKEN_BYTES );

    memset( buffer, 0, SNAPSHOT_CONNECT_TOKEN_BYTES - ( buffer - start ) );
}

int snapshot_read_connect_token( const uint8_t * buffer, int buffer_length, struct snapshot_connect_token_t * connect_token )
{
    snapshot_assert( buffer );
    snapshot_assert( connect_token );

    if ( buffer_length != SNAPSHOT_CONNECT_TOKEN_BYTES )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "read connect data has bad buffer length (%d)", buffer_length );
        return SNAPSHOT_ERROR;
    }

    snapshot_read_bytes( &buffer, connect_token->version_info, SNAPSHOT_VERSION_INFO_BYTES );
    if ( connect_token->version_info[0] != 'S' || 
         connect_token->version_info[1] != 'N' || 
         connect_token->version_info[2] != 'A' || 
         connect_token->version_info[3] != 'P' || 
         connect_token->version_info[4] != 'S' ||
         connect_token->version_info[5] != 'H' ||
         connect_token->version_info[6] != 'O' ||
         connect_token->version_info[7] != 'T' ||
         connect_token->version_info[8] != '\0' )
    {
        connect_token->version_info[8] = '\0';
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "read connect data has bad version info (got %s, expected %s)", connect_token->version_info, SNAPSHOT_VERSION_INFO );
        return SNAPSHOT_ERROR;
    }

    connect_token->protocol_id = snapshot_read_uint64( &buffer );

    connect_token->create_timestamp = snapshot_read_uint64( &buffer );

    connect_token->expire_timestamp = snapshot_read_uint64( &buffer );

    if ( connect_token->create_timestamp > connect_token->expire_timestamp )
        return SNAPSHOT_ERROR;

    snapshot_read_bytes( &buffer, connect_token->nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );

    snapshot_read_bytes( &buffer, connect_token->private_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

    connect_token->timeout_seconds = (int) snapshot_read_uint32( &buffer );

    connect_token->num_server_addresses = snapshot_read_uint32( &buffer );

    if ( connect_token->num_server_addresses <= 0 || connect_token->num_server_addresses > SNAPSHOT_MAX_SERVERS_PER_CONNECT )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "read connect data has bad number of server addresses (%d)", connect_token->num_server_addresses );
        return SNAPSHOT_ERROR;
    }

    int i,j;

    for ( i = 0; i < connect_token->num_server_addresses; ++i )
    {
        connect_token->server_addresses[i].type = snapshot_read_uint8( &buffer );

        if ( connect_token->server_addresses[i].type == SNAPSHOT_ADDRESS_IPV4 )
        {
            for ( j = 0; j < 4; ++j )
            {
                connect_token->server_addresses[i].data.ipv4[j] = snapshot_read_uint8( &buffer );
            }
            connect_token->server_addresses[i].port = snapshot_read_uint16( &buffer );
        }
        else if ( connect_token->server_addresses[i].type == SNAPSHOT_ADDRESS_IPV6 )
        {
            for ( j = 0; j < 8; ++j )
            {
                connect_token->server_addresses[i].data.ipv6[j] = snapshot_read_uint16( &buffer );
            }
            connect_token->server_addresses[i].port = snapshot_read_uint16( &buffer );
        }
        else
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "read connect data has bad address type (%d)", connect_token->server_addresses[i].type );
            return SNAPSHOT_ERROR;
        }
    }

    snapshot_read_bytes( &buffer, connect_token->client_to_server_key, SNAPSHOT_KEY_BYTES );

    snapshot_read_bytes( &buffer, connect_token->server_to_client_key, SNAPSHOT_KEY_BYTES );
    
    return SNAPSHOT_OK;
}

void snapshot_generate_connect_token_private( struct snapshot_connect_token_private_t * connect_token, 
                                              uint64_t client_id, 
                                              int timeout_seconds,
                                              int num_server_addresses, 
                                              struct snapshot_address_t * server_addresses, 
                                              uint8_t * user_data )
{
    snapshot_assert( connect_token );
    snapshot_assert( num_server_addresses > 0 );
    snapshot_assert( num_server_addresses <= SNAPSHOT_MAX_SERVERS_PER_CONNECT );
    snapshot_assert( server_addresses );
    snapshot_assert( user_data );

    connect_token->client_id = client_id;
    connect_token->timeout_seconds = timeout_seconds;
    connect_token->num_server_addresses = num_server_addresses;
    
    int i;
    for ( i = 0; i < num_server_addresses; ++i )
    {
        memcpy( &connect_token->server_addresses[i], &server_addresses[i], sizeof( struct snapshot_address_t ) );
    }

    snapshot_crypto_random_bytes( connect_token->client_to_server_key, SNAPSHOT_KEY_BYTES );
    snapshot_crypto_random_bytes( connect_token->server_to_client_key, SNAPSHOT_KEY_BYTES );

    if ( user_data != NULL )
    {
        memcpy( connect_token->user_data, user_data, SNAPSHOT_USER_DATA_BYTES );
    }
    else
    {
        memset( connect_token->user_data, 0, SNAPSHOT_USER_DATA_BYTES );
    }
}

void snapshot_write_connect_token_private( struct snapshot_connect_token_private_t * connect_token, uint8_t * buffer, int buffer_length )
{
    (void) buffer_length;

    snapshot_assert( connect_token );
    snapshot_assert( connect_token->num_server_addresses > 0 );
    snapshot_assert( connect_token->num_server_addresses <= SNAPSHOT_MAX_SERVERS_PER_CONNECT );
    snapshot_assert( buffer );
    snapshot_assert( buffer_length >= SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

    uint8_t * start = buffer;

    (void) start;

    snapshot_write_uint64( &buffer, connect_token->client_id );

    snapshot_write_uint32( &buffer, connect_token->timeout_seconds );

    snapshot_write_uint32( &buffer, connect_token->num_server_addresses );

    int i,j;

    for ( i = 0; i < connect_token->num_server_addresses; ++i )
    {
        if ( connect_token->server_addresses[i].type == SNAPSHOT_ADDRESS_IPV4 )
        {
            snapshot_write_uint8( &buffer, SNAPSHOT_ADDRESS_IPV4 );
            for ( j = 0; j < 4; ++j )
            {
                snapshot_write_uint8( &buffer, connect_token->server_addresses[i].data.ipv4[j] );
            }
            snapshot_write_uint16( &buffer, connect_token->server_addresses[i].port );
        }
        else if ( connect_token->server_addresses[i].type == SNAPSHOT_ADDRESS_IPV6 )
        {
            snapshot_write_uint8( &buffer, SNAPSHOT_ADDRESS_IPV6 );
            for ( j = 0; j < 8; ++j )
            {
                snapshot_write_uint16( &buffer, connect_token->server_addresses[i].data.ipv6[j] );
            }
            snapshot_write_uint16( &buffer, connect_token->server_addresses[i].port );
        }
        else
        {
            snapshot_assert( 0 );
        }
    }

    snapshot_write_bytes( &buffer, connect_token->client_to_server_key, SNAPSHOT_KEY_BYTES );

    snapshot_write_bytes( &buffer, connect_token->server_to_client_key, SNAPSHOT_KEY_BYTES );

    snapshot_write_bytes( &buffer, connect_token->user_data, SNAPSHOT_USER_DATA_BYTES );

    snapshot_assert( buffer - start <= SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES - SNAPSHOT_MAC_BYTES );

    memset( buffer, 0, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES - ( buffer - start ) );
}

int snapshot_encrypt_connect_token_private( uint8_t * buffer, 
                                            int buffer_length, 
                                            uint8_t * version_info, 
                                            uint64_t protocol_id, 
                                            uint64_t expire_timestamp, 
                                            const uint8_t * nonce, 
                                            const uint8_t * key )
{
    snapshot_assert( buffer );
    snapshot_assert( buffer_length == SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );
    snapshot_assert( key );

    (void) buffer_length;

    uint8_t additional_data[SNAPSHOT_VERSION_INFO_BYTES+8+8];
    {
        uint8_t * p = additional_data;
        snapshot_write_bytes( &p, version_info, SNAPSHOT_VERSION_INFO_BYTES );
        snapshot_write_uint64( &p, protocol_id );
        snapshot_write_uint64( &p, expire_timestamp );
    }

    return snapshot_crypto_encrypt_aead_bignonce( buffer, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES - SNAPSHOT_MAC_BYTES, additional_data, sizeof( additional_data ), nonce, key );
}

int snapshot_decrypt_connect_token_private( uint8_t * buffer, 
                                            int buffer_length, 
                                            uint8_t * version_info, 
                                            uint64_t protocol_id, 
                                            uint64_t expire_timestamp, 
                                            uint8_t * nonce, 
                                            uint8_t * key )
{
    snapshot_assert( buffer );
    snapshot_assert( buffer_length == SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );
    snapshot_assert( key );

    (void) buffer_length;

    uint8_t additional_data[SNAPSHOT_VERSION_INFO_BYTES+8+8];
    {
        uint8_t * p = additional_data;
        snapshot_write_bytes( &p, version_info, SNAPSHOT_VERSION_INFO_BYTES );
        snapshot_write_uint64( &p, protocol_id );
        snapshot_write_uint64( &p, expire_timestamp );
    }
    return snapshot_crypto_decrypt_aead_bignonce( buffer, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES, additional_data, sizeof( additional_data ), nonce, key );
}

int snapshot_read_connect_token_private( const uint8_t * buffer, int buffer_length, struct snapshot_connect_token_private_t * connect_token )
{
    snapshot_assert( buffer );
    snapshot_assert( connect_token );

    if ( buffer_length < SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES )
        return SNAPSHOT_ERROR;
    
    connect_token->client_id = snapshot_read_uint64( &buffer );

    connect_token->timeout_seconds = (int) snapshot_read_uint32( &buffer );

    connect_token->num_server_addresses = snapshot_read_uint32( &buffer );

    if ( connect_token->num_server_addresses <= 0 )
        return SNAPSHOT_ERROR;

    if ( connect_token->num_server_addresses > SNAPSHOT_MAX_SERVERS_PER_CONNECT )
        return SNAPSHOT_ERROR;

    int i,j;

    for ( i = 0; i < connect_token->num_server_addresses; ++i )
    {
        connect_token->server_addresses[i].type = snapshot_read_uint8( &buffer );

        if ( connect_token->server_addresses[i].type == SNAPSHOT_ADDRESS_IPV4 )
        {
            for ( j = 0; j < 4; ++j )
            {
                connect_token->server_addresses[i].data.ipv4[j] = snapshot_read_uint8( &buffer );
            }
            connect_token->server_addresses[i].port = snapshot_read_uint16( &buffer );
        }
        else if ( connect_token->server_addresses[i].type == SNAPSHOT_ADDRESS_IPV6 )
        {
            for ( j = 0; j < 8; ++j )
            {
                connect_token->server_addresses[i].data.ipv6[j] = snapshot_read_uint16( &buffer );
            }
            connect_token->server_addresses[i].port = snapshot_read_uint16( &buffer );
        }
        else
        {
            return SNAPSHOT_ERROR;
        }
    }

    snapshot_read_bytes( &buffer, connect_token->client_to_server_key, SNAPSHOT_KEY_BYTES );

    snapshot_read_bytes( &buffer, connect_token->server_to_client_key, SNAPSHOT_KEY_BYTES );

    snapshot_read_bytes( &buffer, connect_token->user_data, SNAPSHOT_USER_DATA_BYTES );

    return SNAPSHOT_OK;
}
