/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include "snapshot.h"
#include "snapshot_server.h"
#include "snapshot_platform.h"

#define TEST_PROTOCOL_ID 0x1122334455667788

static uint8_t private_key[SNAPSHOT_KEY_BYTES] = { 0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea, 
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
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to initialize shapshot" );
        return 1;
    }

    double time = 0.0;
    double delta_time = 1.0 / 60.0;

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "[server]" );

    const char * server_address = "0.0.0.0:40000"; //"127.0.0.1:40000";
    if ( argc == 2 )
        server_address = argv[1];

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( server_address, &server_config, time );

    if ( !server )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create server" );
        return 1;
    }

    signal( SIGINT, interrupt_handler );

    while ( !quit )
    {
        snapshot_server_update( server, time );

        snapshot_platform_sleep( delta_time );

        time += delta_time;
    }

    if ( quit )
    {
        printf( "\n" );
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "shutting down" );
    }

    snapshot_server_destroy( server );

    fflush( stdout );

    snapshot_term();

    return 0;
}
