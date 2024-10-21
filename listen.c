/*
    Snapshot 

    Copyright © 2024 Más Bandwidth LLC. 

    This source code is licensed under GPL version 3 or any later version.

    Commercial licensing under different terms is available. Email licensing@mas-bandwidth.com for details
*/

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include "snapshot.h"
#include "snapshot_crypto.h"
#include "snapshot_client.h"
#include "snapshot_server.h"
#include "snapshot_address.h"
#include "snapshot_platform.h"

#define TEST_PROTOCOL_ID 0x1122334455667788

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

struct loopback_context_t
{
    struct snapshot_client_t * client;
    struct snapshot_server_t * server;
};

void client_send_loopback_packet_callback( void * context, const struct snapshot_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    struct loopback_context_t * loopback_context = (struct loopback_context_t*) context;
    snapshot_server_process_packet( loopback_context->server, from, packet_data, packet_bytes );
}

void server_send_loopback_packet_callback( void * context, const struct snapshot_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    struct loopback_context_t * loopback_context = (struct loopback_context_t*) context;
    snapshot_client_process_packet( loopback_context->client, from, packet_data, packet_bytes );
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

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "[listen]" );

    // start the listen server

    const char * server_address_string = "0.0.0.0:40000";
    if ( argc == 2 )
        server_address_string = argv[1];

    struct snapshot_address_t server_address;
    if ( snapshot_address_parse( &server_address, server_address_string ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "bad server address: %s", server_address_string );
        return 1;
    }

    struct loopback_context_t loopback_context;

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.context = &loopback_context;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.send_loopback_packet_callback = server_send_loopback_packet_callback;
    memcpy( &server_config.private_key, test_private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( server_address_string, &server_config, time );

    if ( !server )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create server" );
        return 1;
    }

    server_address.port = snapshot_server_port( server );

    // create a local client in slot 0

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );
    client_config.context = &loopback_context;
    client_config.send_loopback_packet_callback = client_send_loopback_packet_callback;

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:0", &client_config, time );

    if ( !client )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create client" );
        return 1;
    }
   
    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );
    snapshot_client_connect_loopback( client, &server_address, 0, SNAPSHOT_MAX_CLIENTS );

    snapshot_server_connect_loopback_client( server, 0, client_id, NULL );

    loopback_context.client = client;

    // main loop

    signal( SIGINT, interrupt_handler );

    while ( !quit )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        snapshot_platform_sleep( delta_time );

        time += delta_time;
    }

    // shut down

    if ( quit )
    {
        printf( "\n" );
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "shutting down" );
    }

    snapshot_client_destroy( client );

    snapshot_server_destroy( server );

    fflush( stdout );

    snapshot_term();

    return 0;
}
