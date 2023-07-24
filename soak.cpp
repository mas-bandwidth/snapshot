/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
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
#include "snapshot_connect_token.h"

#include <map>

// -------------------------------------------------------------------

struct AllocatorEntry
{
    uint64_t bytes;
};

class Allocator
{
    int64_t num_allocations;
    std::map<void*, AllocatorEntry*> entries;

public:

    Allocator()
    {
        num_allocations = 0;
    }

    ~Allocator()
    {
        printf( "checking for memory leaks...\n" );
        if ( num_allocations > 0 )
        {
            printf( "leaked %d allocations\n", (int) num_allocations );
        }
        else
        {
            printf( "no memory leaks found.\n" );
        }
        snapshot_assert( num_allocations == 0 );
        snapshot_assert( entries.size() == 0 );
    }

    void * Alloc( size_t size )
    {
        void * pointer = malloc( size );
        snapshot_assert( pointer );
        snapshot_assert( entries[pointer] == NULL );
        AllocatorEntry * entry = new AllocatorEntry();
        entry->bytes = size;
        entries[pointer] = entry;
        num_allocations++;
        return pointer;
    }

    void Free( void * pointer )
    {
        snapshot_assert( pointer );
        snapshot_assert( num_allocations > 0 );
        std::map<void*, AllocatorEntry*>::iterator itor = entries.find( pointer );
        snapshot_assert( itor != entries.end() );
        // printf( "free %d bytes\n", (int)itor->second->bytes );
        entries.erase( itor );
        num_allocations--;
        free( pointer );
    }
};

void * malloc_function( void * context, size_t bytes )
{
    snapshot_assert( context );
    Allocator * allocator = (Allocator*) context;
    // printf( "allocated %d bytes\n", (int)bytes ); fflush( stdout );
    return allocator->Alloc( bytes );
}

void free_function( void * context, void * p )
{
    snapshot_assert( context );
    Allocator * allocator = (Allocator*) context;
    return allocator->Free( p );
}

// -------------------------------------------------------------------

static void log_function( int level, const char * format, ... )
{
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof( buffer ), format, args );
    if ( level != SNAPSHOT_LOG_LEVEL_NONE )
    {
        const char * level_string = snapshot_log_level_string( level );
        printf( "%.6f: %s: %s\n", snapshot_platform_time(), level_string, buffer );
    }
    else
    {
        printf( "%s\n", buffer );
    }
    va_end( args );
    fflush( stdout );
}

// -------------------------------------------------------------------

#include <assert.h>

static void assert_function( const char * condition, const char * function, const char * file, int line )
{
    snapshot_printf( "assert failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
    fflush( stdout );
    assert( false );
}

// -------------------------------------------------------------------

#define TEST_PROTOCOL_ID 0x1122334455667788
#define CONNECT_TOKEN_EXPIRY 30
#define CONNECT_TOKEN_TIMEOUT 5

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

const int MAX_SERVERS = 16;
const int MAX_CLIENTS = 200;

static snapshot_client_t * client[MAX_CLIENTS];
static snapshot_server_t * server[MAX_SERVERS];

int main( int argc, char ** argv )
{
    (void) argc;
    (void) argv;

    if ( snapshot_init() != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to initialize shapshot" );
        return 1;
    }

    Allocator allocator;

    snapshot_allocator( malloc_function, free_function );

    snapshot_log_function( log_function );

    snapshot_assert_function( assert_function );

    double time = 0.0;
    double delta_time = 1.0 / 60.0;

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "[soak]" );

    signal( SIGINT, interrupt_handler );

    while ( !quit )
    {
        // create servers

        for ( int i = 0; i < MAX_SERVERS; i++ )
        {
            if ( server[i] == NULL && ( rand() % 100 ) == 0 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "creating server %d", i );

                const int max_clients = 1 + rand() % ( SNAPSHOT_MAX_CLIENTS - 1 );

                char server_address[1024];
                snprintf( server_address, sizeof(server_address), "127.0.0.1:%d", 40000 + i );

                struct snapshot_server_config_t server_config;
                snapshot_default_server_config( &server_config );
                server_config.context = &allocator;
                server_config.max_clients = max_clients;
                server_config.protocol_id = TEST_PROTOCOL_ID;
                memcpy( &server_config.private_key, test_private_key, SNAPSHOT_KEY_BYTES );

                server[i] = snapshot_server_create( server_address, &server_config, time );

                if ( !server[i] )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create server :(" );
                    return 1;
                }

                snapshot_server_set_development_flags( server[i], SNAPSHOT_DEVELOPMENT_FLAG_VALIDATE_PAYLOAD );
            }
        }

        // update servers

        for ( int i = 0; i < MAX_SERVERS; i++ )
        {
            if ( server[i] )
            {
                snapshot_server_update( server[i], time );
            }
        }    

        // destroy servers

        for ( int i = 0; i < MAX_SERVERS; i++ )
        {
            if ( server[i] != NULL && ( rand() % 10000 ) == 0 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "destroying server %d", i );
                snapshot_server_destroy( server[i] );
                server[i] = NULL;
            }
        }

        // create clients

        for ( int i = 0; i < MAX_CLIENTS; i++ )
        {
            if ( client[i] == NULL && ( rand() % 100 ) == 0 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "creating client %d", i );

                struct snapshot_client_config_t client_config;
                snapshot_default_client_config( &client_config );
                client_config.context = &allocator;
                client[i] = snapshot_client_create( "0.0.0.0", &client_config, time );

                if ( !client[i] )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create client :(" );
                    return 1;
                }

                snapshot_client_set_development_flags( client[i], SNAPSHOT_DEVELOPMENT_FLAG_VALIDATE_PAYLOAD );
            }
        }

        // update clients

        for ( int i = 0; i < MAX_CLIENTS; i++ )
        {
            if ( client[i] )
            {
                snapshot_client_update( client[i], time );
            }
        }    

        // connect clients

        for ( int i = 0; i < MAX_CLIENTS; i++ )
        {
            if ( client[i] && snapshot_client_state( client[i] ) != SNAPSHOT_CLIENT_STATE_CONNECTED && ( rand() % 100 ) == 0  )
            {
                const int server_index = rand() % MAX_SERVERS;

                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "connecting client %d to server %d", i, server_index );

                char server_address_string[1024];
                snprintf( server_address_string, sizeof(server_address_string), "127.0.0.1:%d", 40000 + server_index );

                const char * server_address = server_address_string;

                uint64_t client_id = 0;
                snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );
                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client id is %.16" PRIx64, client_id );

                uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
                snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

                uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

                if ( snapshot_generate_connect_token( 1, &server_address, CONNECT_TOKEN_EXPIRY, CONNECT_TOKEN_TIMEOUT, client_id, TEST_PROTOCOL_ID, test_private_key, user_data, connect_token ) != SNAPSHOT_OK )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to generate connect token" );
                    return 1;
                }

                snapshot_client_connect( client[i], connect_token );
            }
        }

        // disconnect clients

        for ( int i = 0; i < MAX_CLIENTS; i++ )
        {
            if ( client[i] && snapshot_client_state( client[i] ) == SNAPSHOT_CLIENT_STATE_CONNECTED && ( rand() % 2500 ) == 0  )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "disconnecting client %d", i );
                snapshot_client_disconnect( client[i] );
            }
        }

        // destroy clients

        for ( int i = 0; i < MAX_CLIENTS; i++ )
        {
            if ( client[i] != NULL && ( rand() % 2500 ) == 0 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "destroying client %d", i );
                snapshot_client_destroy( client[i] );
                client[i] = NULL;
            }
        }

        snapshot_platform_sleep( delta_time );

        time += delta_time;
    }

    // shut down

    if ( quit )
    {
        printf( "\n" );
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "shutting down" );
    }

    for ( int i = 0; i < MAX_CLIENTS; i++ )
    {
        if ( client[i] )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "destroying client %d", i );
            snapshot_client_destroy( client[i] );
            client[i] = NULL;
        }
    }

    for ( int i = 0; i < MAX_SERVERS; i++ )
    {
        if ( server[i] )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "destroying server %d", i );
            snapshot_server_destroy( server[i] );
            server[i] = NULL;
        }
    }

    fflush( stdout );

    snapshot_term();

    return 0;
}
