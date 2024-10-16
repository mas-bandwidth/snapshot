/*
    Snapshot 

    Copyright © 2024 Más Bandwidth LLC. 

    This source code is licensed under GPL version 3 or any later version.

    Commercial licensing under different terms is available. Email licensing@mas-bandwidth.com for details.
*/

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include "snapshot.h"
#include "snapshot_client.h"
#include "snapshot_platform.h"
#include "snapshot_crypto.h"
#include "snapshot_connect_token.h"

#define TEST_PROTOCOL_ID 0x1122334455667788
#define TEST_CONNECT_TOKEN_EXPIRY 30
#define TEST_CONNECT_TOKEN_TIMEOUT 10

static uint8_t test_private_key[SNAPSHOT_KEY_BYTES] = { 0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea, 
                                                        0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4, 
                                                        0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
                                                        0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 };

static volatile int quit = 0;

void interrupt_handler( int signal )
{
    (void) signal;
    quit = 1;
}

int main( int argc, char ** argv )
{
    if ( snapshot_init() != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to initialize snapshot" );
        return 1;
    }

    double time = 0.0;
    double delta_time = 1.0 / 60.0;

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "[client]" );

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );
    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0", &client_config, time );

    if ( !client )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create client" );
        return 1;
    }

    const char * server_address = ( argc != 2 ) ? "127.0.0.1:40000" : argv[1];        

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );
    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client id is %.16" PRIx64, client_id );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    if ( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_CONNECT_TOKEN_TIMEOUT, client_id, TEST_PROTOCOL_ID, test_private_key, user_data, connect_token ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to generate connect token" );
        return 1;
    }

    snapshot_client_connect( client, connect_token );

    signal( SIGINT, interrupt_handler );

    while ( !quit )
    {
        snapshot_client_update( client, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        snapshot_platform_sleep( delta_time );

        time += delta_time;
    }

    if ( quit )
    {
        printf( "\n" );
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "shutting down" );
    }

    snapshot_client_destroy( client );

    snapshot_term();
    
    return 0;
}
