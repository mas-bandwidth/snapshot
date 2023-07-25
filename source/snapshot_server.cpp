/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_server.h"
#include "snapshot_address.h"
#include "snapshot_platform.h"
#include "snapshot_crypto.h"
#include "snapshot_packets.h"
#include "snapshot_connect_token.h"
#include "snapshot_replay_protection.h"
#include "snapshot_encryption_manager.h"
#include "snapshot_network_simulator.h"
#include "snapshot_endpoint.h"

#include <time.h>

#define SNAPSHOT_MAX_CONNECT_TOKEN_ENTRIES            ( SNAPSHOT_MAX_CLIENTS * 4 )
#define SNAPSHOT_SERVER_MAX_SIM_RECEIVE_PACKETS     ( 256 * SNAPSHOT_MAX_CLIENTS )

// ------------------------------------------------------------------------------------------

void snapshot_default_server_config( struct snapshot_server_config_t * config )
{
    snapshot_assert( config );
    config->context = NULL;
    config->max_clients = SNAPSHOT_MAX_CLIENTS;
    config->connect_disconnect_callback = NULL;
    config->send_loopback_packet_callback = NULL;
    config->process_passthrough_callback = NULL;
#if SNAPSHOT_DEVELOPMENT
    config->network_simulator = NULL;
#endif // #if SNAPSHOT_DEVELOPMENT
};

// ------------------------------------------------------------------------------------------

struct snapshot_connect_token_entry_t
{
    double time;
    uint8_t mac[SNAPSHOT_MAC_BYTES];
    struct snapshot_address_t address;
};

void snapshot_connect_token_entries_reset( struct snapshot_connect_token_entry_t * connect_token_entries )
{
    int i;
    for ( i = 0; i < SNAPSHOT_MAX_CONNECT_TOKEN_ENTRIES; ++i )
    {
        connect_token_entries[i].time = -1000.0;
        memset( connect_token_entries[i].mac, 0, SNAPSHOT_MAC_BYTES );
        memset( &connect_token_entries[i].address, 0, sizeof( struct snapshot_address_t ) );
    }
}

int snapshot_connect_token_entries_find_or_add( struct snapshot_connect_token_entry_t * connect_token_entries, 
                                                const struct snapshot_address_t * address, 
                                                uint8_t * mac, 
                                                double time )
{
    snapshot_assert( connect_token_entries );
    snapshot_assert( address );
    snapshot_assert( mac );

    // find the matching entry for the token mac and the oldest token entry. constant time worst case. This is intentional!

    int matching_token_index = -1;
    int oldest_token_index = -1;
    double oldest_token_time = 0.0;

    int i;
    for ( i = 0; i < SNAPSHOT_MAX_CONNECT_TOKEN_ENTRIES; ++i )
    {
        if ( memcmp( mac, connect_token_entries[i].mac, SNAPSHOT_MAC_BYTES ) == 0 )
            matching_token_index = i;
        
        if ( oldest_token_index == -1 || connect_token_entries[i].time < oldest_token_time )
        {
            oldest_token_time = connect_token_entries[i].time;
            oldest_token_index = i;
        }
    }

    // if no entry is found with the mac, this is a new connect token. replace the oldest token entry.

    snapshot_assert( oldest_token_index != -1 );

    if ( matching_token_index == -1 )
    {
        connect_token_entries[oldest_token_index].time = time;
        connect_token_entries[oldest_token_index].address = *address;
        memcpy( connect_token_entries[oldest_token_index].mac, mac, SNAPSHOT_MAC_BYTES );
        return 1;
    }

    // allow connect tokens we have already seen from the same address

    snapshot_assert( matching_token_index >= 0 );
    snapshot_assert( matching_token_index < SNAPSHOT_MAX_CONNECT_TOKEN_ENTRIES );
    if ( snapshot_address_equal( &connect_token_entries[matching_token_index].address, address ) )
        return 1;

    return 0;
}

// ------------------------------------------------------------------------------------------

struct snapshot_server_t
{
    struct snapshot_server_config_t config;
    struct snapshot_platform_socket_t * socket;
    struct snapshot_address_t address;
    uint64_t flags;
    double time;
    int max_clients;
    int num_connected_clients;
    uint64_t global_sequence;
    uint64_t challenge_sequence;
    uint8_t allowed_packets[SNAPSHOT_NUM_PACKETS];
    uint8_t challenge_key[SNAPSHOT_KEY_BYTES];
    int client_connected[SNAPSHOT_MAX_CLIENTS];
    int client_timeout[SNAPSHOT_MAX_CLIENTS];
    int client_loopback[SNAPSHOT_MAX_CLIENTS];
    int client_confirmed[SNAPSHOT_MAX_CLIENTS];
    int client_encryption_index[SNAPSHOT_MAX_CLIENTS];
    uint64_t client_id[SNAPSHOT_MAX_CLIENTS];
    uint64_t client_sequence[SNAPSHOT_MAX_CLIENTS];
    double client_last_internal_packet_send_time[SNAPSHOT_MAX_CLIENTS];
    double client_last_packet_receive_time[SNAPSHOT_MAX_CLIENTS];
    uint8_t client_user_data[SNAPSHOT_MAX_CLIENTS][SNAPSHOT_USER_DATA_BYTES];
    struct snapshot_replay_protection_t client_replay_protection[SNAPSHOT_MAX_CLIENTS];
    struct snapshot_endpoint_t * client_endpoint[SNAPSHOT_MAX_CLIENTS];
    struct snapshot_address_t client_address[SNAPSHOT_MAX_CLIENTS];
    struct snapshot_connect_token_entry_t connect_token_entries[SNAPSHOT_MAX_CONNECT_TOKEN_ENTRIES];
    struct snapshot_encryption_manager_t encryption_manager;
#if SNAPSHOT_DEVELOPMENT
    uint64_t development_flags;
    uint8_t * sim_receive_packet_data[SNAPSHOT_SERVER_MAX_SIM_RECEIVE_PACKETS];
    int sim_receive_packet_bytes[SNAPSHOT_SERVER_MAX_SIM_RECEIVE_PACKETS];
    struct snapshot_address_t sim_receive_from[SNAPSHOT_SERVER_MAX_SIM_RECEIVE_PACKETS];
#endif // #if SNAPSHOT_DEVELOPMENT
    uint64_t counters[SNAPSHOT_SERVER_NUM_COUNTERS];
};

struct snapshot_server_t * snapshot_server_create( const char * server_address_string, const struct snapshot_server_config_t * config, double time )
{  
    snapshot_assert( config );

    struct snapshot_address_t server_address;
    memset( &server_address, 0, sizeof( server_address ) );
    if ( snapshot_address_parse( &server_address, server_address_string ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to parse server public address" );
        return NULL;
    }

    struct snapshot_platform_socket_t * socket = NULL;

    if ( !config->network_simulator )
    {
        snapshot_address_t bind_address;
        memset( &bind_address, 0, sizeof(bind_address) );
        bind_address.type = server_address.type;
        bind_address.port = server_address.port;

        socket = snapshot_platform_socket_create( config->context, &bind_address, SNAPSHOT_PLATFORM_SOCKET_NON_BLOCKING, 0.0f, SNAPSHOT_SERVER_SOCKET_SNDBUF_SIZE, SNAPSHOT_SERVER_SOCKET_RCVBUF_SIZE );

        if ( socket == NULL )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create server socket" );
            return NULL;
        }

        server_address.port = bind_address.port;
    }
    else
    {
        if ( server_address.port == 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "must bind to a specific port when using network simulator" );
            return NULL;
        }
    }

    struct snapshot_server_t * server = (struct snapshot_server_t*) snapshot_malloc( config->context, sizeof( struct snapshot_server_t ) );
    if ( !server )
    {
        if ( socket )
        {
            snapshot_platform_socket_destroy( socket );
        }
        return NULL;
    }

    memset( server, 0, sizeof(snapshot_server_t) );

#if SNAPSHOT_DEVELOPMENT
    if ( config->network_simulator )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server listening on %s with %d client slots (network simulator)", server_address_string, config->max_clients );
    }
    else
#endif // #if SNAPSHOT_DEVELOPMENT
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server listening on %s with %d client slots", server_address_string, config->max_clients );
    }

    server->config = *config;
    server->socket = socket;
    server->address = server_address;
    server->time = time;
    server->global_sequence = 1ULL << 63;

    memset( server->client_connected, 0, sizeof( server->client_connected ) );
    memset( server->client_loopback, 0, sizeof( server->client_loopback ) );
    memset( server->client_confirmed, 0, sizeof( server->client_confirmed ) );
    memset( server->client_id, 0, sizeof( server->client_id ) );
    memset( server->client_sequence, 0, sizeof( server->client_sequence ) );
    memset( server->client_last_internal_packet_send_time, 0, sizeof( server->client_last_internal_packet_send_time ) );
    memset( server->client_last_packet_receive_time, 0, sizeof( server->client_last_packet_receive_time ) );
    memset( server->client_address, 0, sizeof( server->client_address ) );
    memset( server->client_user_data, 0, sizeof( server->client_user_data ) );

    for ( int i = 0; i < SNAPSHOT_MAX_CLIENTS; ++i )
    {
        server->client_encryption_index[i] = -1;
    }

    snapshot_connect_token_entries_reset( server->connect_token_entries );

    snapshot_encryption_manager_reset( &server->encryption_manager );

    for ( int i = 0; i < SNAPSHOT_MAX_CLIENTS; ++i )
    {
        snapshot_replay_protection_reset( &server->client_replay_protection[i] );
    }

    server->allowed_packets[SNAPSHOT_CONNECTION_REQUEST_PACKET] = 1;
    server->allowed_packets[SNAPSHOT_CONNECTION_RESPONSE_PACKET] = 1;
    server->allowed_packets[SNAPSHOT_KEEP_ALIVE_PACKET] = 1;
    server->allowed_packets[SNAPSHOT_PAYLOAD_PACKET] = 1;
    server->allowed_packets[SNAPSHOT_PASSTHROUGH_PACKET] = 1;
    server->allowed_packets[SNAPSHOT_DISCONNECT_PACKET] = 1;

    for ( int i = 0; i < SNAPSHOT_MAX_CLIENTS; i++ )
    {
        snapshot_endpoint_config_t endpoint_config;
        snapshot_endpoint_default_config( &endpoint_config );
        snprintf( endpoint_config.name, sizeof(endpoint_config.name), "server[%d]", i );
        endpoint_config.context = config->context;
        
        server->client_endpoint[i] = snapshot_endpoint_create( &endpoint_config, time );

        if ( !server->client_endpoint[i] )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create client endpoint #%d", i );
            snapshot_server_destroy( server );
            return NULL;
        }
    }

    server->max_clients = config->max_clients;
    server->num_connected_clients = 0;
    server->challenge_sequence = 0;    

    snapshot_crypto_random_bytes( server->challenge_key, SNAPSHOT_KEY_BYTES );

    return server;
}

void snapshot_server_destroy( struct snapshot_server_t * server )
{
    snapshot_assert( server );

    for ( int i = 0; i < SNAPSHOT_MAX_CLIENTS; i++ )
    {
        if ( server->client_endpoint[i] )
        {
            snapshot_endpoint_destroy( server->client_endpoint[i] );
        }
    }

    if ( server->socket )
    {
        snapshot_platform_socket_destroy( server->socket );
    }

    snapshot_free( server->config.context, server );
}

void snapshot_server_send_global_packet( snapshot_server_t * server, void * packet, const struct snapshot_address_t * to, uint8_t * packet_key )
{
    snapshot_assert( server );
    snapshot_assert( packet );
    snapshot_assert( to );
    snapshot_assert( packet_key );

    uint8_t buffer[SNAPSHOT_MAX_PACKET_BYTES];

    int packet_bytes = 0;

    uint8_t * packet_data = snapshot_write_packet( packet, buffer, SNAPSHOT_MAX_PACKET_BYTES, server->global_sequence, packet_key, server->config.protocol_id, &packet_bytes );

    snapshot_assert( packet_bytes <= SNAPSHOT_MAX_PACKET_BYTES );

#if SNAPSHOT_DEVELOPMENT
    if ( server->config.network_simulator )
    {
        snapshot_network_simulator_send_packet( server->config.network_simulator, &server->address, to, packet_data, packet_bytes );
        server->counters[SNAPSHOT_SERVER_COUNTER_PACKETS_SENT_SIMULATOR]++;
    }
    else
#endif // #if SNAPSHOT_DEVELOPMENT
    {
        snapshot_platform_socket_send_packet( server->socket, to, packet_data, packet_bytes );
        server->counters[SNAPSHOT_SERVER_COUNTER_PACKETS_SENT]++;
    }

    server->global_sequence++;
}

void snapshot_server_send_packet_to_client( struct snapshot_server_t * server, int client_index, void * packet )
{
    snapshot_assert( server );
    snapshot_assert( packet );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( server->client_connected[client_index] );

    uint8_t * packet_key = NULL;

    if ( !server->client_loopback[client_index] )
    {
        if ( !snapshot_encryption_manager_touch( &server->encryption_manager, 
                                                 server->client_encryption_index[client_index], 
                                                 &server->client_address[client_index], 
                                                 server->time ) )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "encryption mapping is out of date for client %d", client_index );
            return;
        }

        packet_key = snapshot_encryption_manager_get_send_key( &server->encryption_manager, server->client_encryption_index[client_index] );
    }

    uint8_t buffer[SNAPSHOT_MAX_PACKET_BYTES];

    int packet_bytes = 0;

    uint8_t * packet_data = snapshot_write_packet( packet, buffer, SNAPSHOT_MAX_PACKET_BYTES, server->client_sequence[client_index], packet_key, server->config.protocol_id, &packet_bytes );

    snapshot_assert( packet_bytes <= SNAPSHOT_MAX_PACKET_BYTES );

    if ( !server->client_loopback[client_index] )
    {
#if SNAPSHOT_DEVELOPMENT
        if ( server->config.network_simulator )
        {
            snapshot_network_simulator_send_packet( server->config.network_simulator, &server->address, &server->client_address[client_index], packet_data, packet_bytes );
            server->counters[SNAPSHOT_SERVER_COUNTER_PACKETS_SENT_SIMULATOR]++;
        }
        else
#endif // #if SNAPSHOT_DEVELOPMENT
        {
            snapshot_platform_socket_send_packet( server->socket, &server->client_address[client_index], packet_data, packet_bytes );
            server->counters[SNAPSHOT_SERVER_COUNTER_PACKETS_SENT]++;
        }
    }
    else
    {
        server->config.send_loopback_packet_callback( server->config.context, &server->address, packet_data, packet_bytes );
        server->counters[SNAPSHOT_SERVER_COUNTER_PACKETS_SENT_LOOPBACK]++;
    }

    server->client_sequence[client_index]++;
}

void snapshot_server_disconnect_client_internal( struct snapshot_server_t * server, int client_index, int send_disconnect_packets )
{
    snapshot_assert( server );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( server->client_connected[client_index] );
    snapshot_assert( !server->client_loopback[client_index] );
    snapshot_assert( server->encryption_manager.client_index[server->client_encryption_index[client_index]] == client_index );

    char client_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
    snapshot_address_to_string( &server->client_address[client_index], client_address_string );
    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server disconnected client %s [%.16" PRIx64 "] from slot %d", client_address_string, server->client_id[client_index], client_index );

    if ( server->config.connect_disconnect_callback )
    {
        server->config.connect_disconnect_callback( server->config.context, client_index, 0 );
    }

    if ( send_disconnect_packets )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server sent disconnect packets to client %d", client_index );

        int i;
        for ( i = 0; i < SNAPSHOT_NUM_DISCONNECT_PACKETS; ++i )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server sent disconnect packet %d", i );

            struct snapshot_disconnect_packet_t packet;
            packet.packet_type = SNAPSHOT_DISCONNECT_PACKET;

            snapshot_server_send_packet_to_client( server, client_index, &packet );

            server->counters[SNAPSHOT_SERVER_COUNTER_DISCONNECT_PACKETS_SENT]++;
        }
    }

    snapshot_replay_protection_reset( &server->client_replay_protection[client_index] );

    if ( server->client_endpoint[client_index] )
    {
        snapshot_endpoint_reset( server->client_endpoint[client_index] );
    }

    server->encryption_manager.client_index[server->client_encryption_index[client_index]] = -1;

    snapshot_encryption_manager_remove_encryption_mapping( &server->encryption_manager, &server->client_address[client_index], server->time );

    server->client_connected[client_index] = 0;
    server->client_confirmed[client_index] = 0;
    server->client_id[client_index] = 0;
    server->client_sequence[client_index] = 0;
    server->client_last_internal_packet_send_time[client_index] = 0.0;
    server->client_last_packet_receive_time[client_index] = 0.0;
    memset( &server->client_address[client_index], 0, sizeof( struct snapshot_address_t ) );
    server->client_encryption_index[client_index] = -1;
    memset( server->client_user_data[client_index], 0, SNAPSHOT_USER_DATA_BYTES );

    server->num_connected_clients--;

    snapshot_assert( server->num_connected_clients >= 0 );

    server->counters[SNAPSHOT_SERVER_COUNTER_CLIENT_DISCONNECTS]++;
}

void snapshot_server_disconnect_client( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );

    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( server->client_loopback[client_index] == 0 );

    if ( !server->client_connected[client_index] )
        return;

    if ( server->client_loopback[client_index] )
        return;

    snapshot_server_disconnect_client_internal( server, client_index, 1 );
}

void snapshot_server_disconnect_all_clients( struct snapshot_server_t * server )
{
    snapshot_assert( server );

    int i;
    for ( i = 0; i < server->max_clients; ++i )
    {
        if ( server->client_connected[i] && !server->client_loopback[i] )
        {
            snapshot_server_disconnect_client_internal( server, i, 1 );
        }
    }
}

int snapshot_server_find_client_index_by_id( struct snapshot_server_t * server, uint64_t client_id )
{
    snapshot_assert( server );

    int i;
    for ( i = 0; i < server->max_clients; ++i )
    {   
        if ( server->client_connected[i] && server->client_id[i] == client_id )
            return i;
    }

    return -1;
}

int snapshot_server_find_client_index_by_address( struct snapshot_server_t * server, const struct snapshot_address_t * address )
{
    snapshot_assert( server );
    snapshot_assert( address );

    if ( address->type == 0 )
        return -1;

    int i;
    for ( i = 0; i < server->max_clients; ++i )
    {   
        if ( server->client_connected[i] && snapshot_address_equal( &server->client_address[i], address ) )
            return i;
    }

    return -1;
}

void snapshot_server_process_connection_request_packet( snapshot_server_t * server, 
                                                        const struct snapshot_address_t * from, 
                                                        struct snapshot_connection_request_packet_t * packet )
{
    snapshot_assert( server );

    (void) from;

    struct snapshot_connect_token_private_t connect_token_private;
    if ( snapshot_read_connect_token_private( packet->connect_token_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES, &connect_token_private ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. failed to read connect token" );
        return;
    }

    int found_server_address = 0;
    int i;
    for ( i = 0; i < connect_token_private.num_server_addresses; ++i )
    {
        if ( snapshot_address_equal( &server->address, &connect_token_private.server_addresses[i] ) )
        {
            found_server_address = 1;
        }
    }
    if ( !found_server_address )
    {   
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. server address not in connect token whitelist" );
        return;
    }

    if ( snapshot_server_find_client_index_by_address( server, from ) != -1 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. a client with this address is already connected" );
        return;
    }

    if ( snapshot_server_find_client_index_by_id( server, connect_token_private.client_id ) != -1 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. a client with this id is already connected" );
        return;
    }

    if ( !snapshot_connect_token_entries_find_or_add( server->connect_token_entries, 
                                                      from, 
                                                      packet->connect_token_data + SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES - SNAPSHOT_MAC_BYTES, 
                                                      server->time ) )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. connect token has already been used" );
        return;
    }

    if ( server->num_connected_clients == server->max_clients )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server denied connection request. server is full" );

        struct snapshot_connection_denied_packet_t p;
        p.packet_type = SNAPSHOT_CONNECTION_DENIED_PACKET;
        
        snapshot_server_send_global_packet( server, &p, from, connect_token_private.server_to_client_key );

        server->counters[SNAPSHOT_SERVER_COUNTER_CONNECTION_DENIED_PACKETS_SENT]++;

        return;
    }

    double expire_time = ( connect_token_private.timeout_seconds >= 0 ) ? server->time + connect_token_private.timeout_seconds : -1.0;

    if ( !snapshot_encryption_manager_add_encryption_mapping( &server->encryption_manager, 
                                                              from, 
                                                              connect_token_private.server_to_client_key, 
                                                              connect_token_private.client_to_server_key, 
                                                              server->time, 
                                                              expire_time,
                                                              connect_token_private.timeout_seconds ) )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. failed to add encryption mapping" );
        return;
    }

    struct snapshot_challenge_token_t challenge_token;
    challenge_token.client_id = connect_token_private.client_id;
    memcpy( challenge_token.user_data, connect_token_private.user_data, SNAPSHOT_USER_DATA_BYTES );

    struct snapshot_connection_challenge_packet_t challenge_packet;
    challenge_packet.packet_type = SNAPSHOT_CONNECTION_CHALLENGE_PACKET;
    challenge_packet.challenge_token_sequence = server->challenge_sequence;
    snapshot_write_challenge_token( &challenge_token, challenge_packet.challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES );
    if ( snapshot_encrypt_challenge_token( challenge_packet.challenge_token_data, 
                                           SNAPSHOT_CHALLENGE_TOKEN_BYTES, 
                                           server->challenge_sequence, 
                                           server->challenge_key ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. failed to encrypt challenge token" );
        return;
    }

    server->challenge_sequence++;

    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server sent connection challenge packet" );

    snapshot_server_send_global_packet( server, &challenge_packet, from, connect_token_private.server_to_client_key );

    server->counters[SNAPSHOT_SERVER_COUNTER_CONNECTION_CHALLENGE_PACKETS_SENT]++;
}

int snapshot_server_find_free_client_index( struct snapshot_server_t * server )
{
    snapshot_assert( server );

    int i;
    for ( i = 0; i < server->max_clients; ++i )
    {
        if ( !server->client_connected[i] )
            return i;
    }

    return -1;
}

void snapshot_server_connect_client( struct snapshot_server_t * server, 
                                     int client_index, 
                                     const struct snapshot_address_t * address, 
                                     uint64_t client_id, 
                                     int encryption_index,
                                     int timeout_seconds, 
                                     void * user_data )
{
    snapshot_assert( server );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( address );
    snapshot_assert( encryption_index != -1 );
    snapshot_assert( user_data );
    snapshot_assert( server->encryption_manager.client_index[encryption_index] == -1 );

    server->num_connected_clients++;

    snapshot_assert( server->num_connected_clients <= server->max_clients );

    snapshot_assert( server->client_connected[client_index] == 0 );

    snapshot_encryption_manager_set_expire_time( &server->encryption_manager, encryption_index, -1.0 );
    
    server->encryption_manager.client_index[encryption_index] = client_index;

    server->client_connected[client_index] = 1;
    server->client_timeout[client_index] = timeout_seconds;
    server->client_encryption_index[client_index] = encryption_index;
    server->client_id[client_index] = client_id;
    server->client_sequence[client_index] = 0;
    server->client_address[client_index] = *address;
    server->client_last_internal_packet_send_time[client_index] = server->time;
    server->client_last_packet_receive_time[client_index] = server->time;
    memcpy( server->client_user_data[client_index], user_data, SNAPSHOT_USER_DATA_BYTES );

    char address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server accepted client %s [%.16" PRIx64 "] in slot %d", snapshot_address_to_string( address, address_string ), client_id, client_index );

    struct snapshot_keep_alive_packet_t packet;
    packet.packet_type = SNAPSHOT_KEEP_ALIVE_PACKET;
    packet.client_index = client_index;
    packet.max_clients = server->max_clients;

    snapshot_server_send_packet_to_client( server, client_index, &packet );

    server->counters[SNAPSHOT_SERVER_COUNTER_KEEP_ALIVE_PACKETS_SENT]++;

    server->client_last_internal_packet_send_time[client_index] = server->time;

    if ( server->config.connect_disconnect_callback )
    {
        server->config.connect_disconnect_callback( server->config.context, client_index, 1 );
    }

    server->counters[SNAPSHOT_SERVER_COUNTER_CLIENT_CONNECTS]++;
}

void snapshot_server_process_connection_response_packet( struct snapshot_server_t * server, 
                                                         const struct snapshot_address_t * from, 
                                                         struct snapshot_connection_response_packet_t * packet, 
                                                         int encryption_index )
{
    snapshot_assert( server );

    if ( snapshot_decrypt_challenge_token( packet->challenge_token_data, 
                                           SNAPSHOT_CHALLENGE_TOKEN_BYTES, 
                                           packet->challenge_token_sequence, 
                                           server->challenge_key ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection response. failed to decrypt challenge token" );
        return;
    }

    struct snapshot_challenge_token_t challenge_token;
    if ( snapshot_read_challenge_token( packet->challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES, &challenge_token ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection response. failed to read challenge token" );
        return;
    }

    uint8_t * packet_send_key = snapshot_encryption_manager_get_send_key( &server->encryption_manager, encryption_index );

    if ( !packet_send_key )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection response. no packet send key" );
        return;
    }

    if ( snapshot_server_find_client_index_by_address( server, from ) != -1 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection response. a client with this address is already connected" );
        return;
    }

    if ( snapshot_server_find_client_index_by_id( server, challenge_token.client_id ) != -1 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection response. a client with this id is already connected" );
        return;
    }

    if ( server->num_connected_clients == server->max_clients )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server denied connection response. server is full" );

        struct snapshot_connection_denied_packet_t p;
        p.packet_type = SNAPSHOT_CONNECTION_DENIED_PACKET;

        snapshot_server_send_global_packet( server, &p, from, packet_send_key );

        return;
    }

    int client_index = snapshot_server_find_free_client_index( server );

    snapshot_assert( client_index != -1 );

    int timeout_seconds = snapshot_encryption_manager_get_timeout( &server->encryption_manager, encryption_index );

    snapshot_server_connect_client( server, client_index, from, challenge_token.client_id, encryption_index, timeout_seconds, challenge_token.user_data );
}

int snapshot_server_process_payload( struct snapshot_server_t * server, int client_index, uint8_t * payload_data, int payload_bytes )
{
    snapshot_assert( server );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( payload_data );
    snapshot_assert( payload_bytes > 0 );
    snapshot_assert( payload_bytes <= SNAPSHOT_MAX_PAYLOAD_BYTES );
    snapshot_assert( server->client_connected[client_index] );

    if ( !server->client_connected[client_index] )
        return SNAPSHOT_ERROR;

#if SNAPSHOT_DEVELOPMENT

    if ( server->development_flags & SNAPSHOT_DEVELOPMENT_FLAG_VALIDATE_PAYLOAD )
    {    
        snapshot_verify_packet_data( payload_data, payload_bytes );

        server->counters[SNAPSHOT_SERVER_COUNTER_PAYLOADS_RECEIVED]++;

        return SNAPSHOT_OK;
    }

#endif // #if SNAPSHOT_DEVELOPMENT

    // todo: process the real payload

    (void) server;
    (void) client_index;
    
    return SNAPSHOT_OK;
}

void snapshot_server_process_passthrough( struct snapshot_server_t * server, const snapshot_address_t * client_address, int client_index, uint8_t * passthrough_data, int passthrough_bytes )
{
    snapshot_assert( server );
    snapshot_assert( client_address );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( passthrough_data );
    snapshot_assert( passthrough_bytes > 0 );
    snapshot_assert( passthrough_bytes <= SNAPSHOT_MAX_PASSTHROUGH_BYTES );

    if ( server->config.process_passthrough_callback != NULL )
    {
        server->config.process_passthrough_callback( server->config.context, client_address, client_index, passthrough_data, passthrough_bytes );
    }
}

bool snapshot_server_process_packet( struct snapshot_server_t * server, const struct snapshot_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    snapshot_assert( server );
    snapshot_assert( from );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes > 0 );
    snapshot_assert( packet_bytes <= SNAPSHOT_MAX_PACKET_BYTES );

    if ( packet_bytes < 1 )
        return false;

    server->counters[SNAPSHOT_SERVER_COUNTER_PACKETS_PROCESSED]++;

    uint64_t sequence;

    int encryption_index = -1;
    int client_index = snapshot_server_find_client_index_by_address( server, from );
    if ( client_index != -1 )
    {
        snapshot_assert( client_index >= 0 );
        snapshot_assert( client_index < server->max_clients );
        encryption_index = server->client_encryption_index[client_index];
    }
    else
    {
        encryption_index = snapshot_encryption_manager_find_encryption_mapping( &server->encryption_manager, from, server->time );
    }
    
    uint8_t * read_packet_key = snapshot_encryption_manager_get_receive_key( &server->encryption_manager, encryption_index );

    if ( !read_packet_key && packet_data[0] != 0 )
    {
        char address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server could not process packet because no encryption mapping exists for %s", snapshot_address_to_string( from, address_string ) );
        return false;
    }

    uint8_t out_packet_data[2048];

    uint64_t current_timestamp = time( NULL );

    void * packet = snapshot_read_packet( packet_data, 
                                          packet_bytes, 
                                          &sequence, 
                                          read_packet_key, 
                                          server->config.protocol_id, 
                                          current_timestamp, 
                                          server->config.private_key, 
                                          server->allowed_packets,
                                          out_packet_data,
                                          ( client_index != -1 ) ? &server->client_replay_protection[client_index] : NULL );

    if ( !packet )
    {
        server->counters[SNAPSHOT_SERVER_COUNTER_READ_PACKET_FAILURES]++;
        return false;
    }

    uint8_t packet_type = ( (uint8_t*) packet ) [0];

    switch ( packet_type )
    {
        case SNAPSHOT_CONNECTION_REQUEST_PACKET:
        {    
            server->counters[SNAPSHOT_SERVER_COUNTER_CONNECTION_REQUEST_PACKETS_RECEIVED]++;

            if ( ( server->flags & SNAPSHOT_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS ) == 0 )
            {
                char from_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server received connection request from %s", snapshot_address_to_string( from, from_address_string ) );
                snapshot_server_process_connection_request_packet( server, from, (struct snapshot_connection_request_packet_t*) packet );
                return true;
            }
        }
        break;

        case SNAPSHOT_CONNECTION_RESPONSE_PACKET:
        {    
            server->counters[SNAPSHOT_SERVER_COUNTER_CONNECTION_RESPONSE_PACKETS_RECEIVED]++;

            if ( ( server->flags & SNAPSHOT_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS ) == 0 )
            {
                char from_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server received connection response from %s", snapshot_address_to_string( from, from_address_string ) );
                snapshot_server_process_connection_response_packet( server, from, (struct snapshot_connection_response_packet_t*) packet, encryption_index );
                return true;
            }
        }
        break;

        case SNAPSHOT_KEEP_ALIVE_PACKET:
        {
            server->counters[SNAPSHOT_SERVER_COUNTER_KEEP_ALIVE_PACKETS_RECEIVED]++;

            if ( client_index != -1 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server received keep alive packet from client %d", client_index );
                server->client_last_packet_receive_time[client_index] = server->time;
                if ( !server->client_confirmed[client_index] )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server confirmed connection with client %d", client_index );
                    server->client_confirmed[client_index] = 1;
                }
                return true;
            }
        }
        break;

        case SNAPSHOT_PAYLOAD_PACKET:
        {
            server->counters[SNAPSHOT_SERVER_COUNTER_PAYLOAD_PACKETS_RECEIVED]++;

            if ( client_index != -1 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server received payload packet from client %d", client_index );
                server->client_last_packet_receive_time[client_index] = server->time;
                if ( !server->client_confirmed[client_index] )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server confirmed connection with client %d", client_index );
                    server->client_confirmed[client_index] = 1;
                }
                struct snapshot_payload_packet_t * payload_packet = (snapshot_payload_packet_t*) packet;
                uint8_t * payload_packet_data = payload_packet->payload_data;
                int payload_packet_bytes = payload_packet->payload_bytes;
                uint8_t buffer[SNAPSHOT_PACKET_PREFIX_BYTES + SNAPSHOT_MAX_PACKET_BYTES + SNAPSHOT_PACKET_POSTFIX_BYTES];
                uint8_t * payload_data = NULL;
                int payload_bytes = 0;
                uint16_t payload_sequence = 0;
                uint16_t payload_ack = 0;
                uint32_t payload_ack_bits = 0;
                snapshot_endpoint_process_packet( server->client_endpoint[client_index], payload_packet_data, payload_packet_bytes, buffer, &payload_data, &payload_bytes, &payload_sequence, &payload_ack, &payload_ack_bits );
                if ( payload_data )
                {
                    if ( snapshot_server_process_payload( server, client_index, payload_data, payload_bytes ) == SNAPSHOT_OK )
                    {
                        snapshot_endpoint_mark_payload_processed( server->client_endpoint[client_index], payload_sequence, payload_ack, payload_ack_bits, payload_packet_bytes );
                    }
                }
                return true;
            }
        }
        break;

        case SNAPSHOT_PASSTHROUGH_PACKET:
        {
            server->counters[SNAPSHOT_SERVER_COUNTER_PASSTHROUGH_PACKETS_RECEIVED]++;

            if ( client_index != -1 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server received passthrough packet from client %d", client_index );
                server->client_last_packet_receive_time[client_index] = server->time;
                if ( !server->client_confirmed[client_index] )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server confirmed connection with client %d", client_index );
                    server->client_confirmed[client_index] = 1;
                }
                struct snapshot_passthrough_packet_t * passthrough_packet = (snapshot_passthrough_packet_t*) packet;
                snapshot_server_process_passthrough( server, &server->client_address[client_index], client_index, passthrough_packet->passthrough_data, passthrough_packet->passthrough_bytes );
                return true;
            }
        }
        break;

        case SNAPSHOT_DISCONNECT_PACKET:
        {
            server->counters[SNAPSHOT_SERVER_COUNTER_DISCONNECT_PACKETS_RECEIVED]++;

            if ( client_index != -1 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server received disconnect packet from client %d", client_index );
                snapshot_server_disconnect_client_internal( server, client_index, 0 );
                return true;
           }
        }
        break;

        default:
            break;
    }

    return false;
}

void snapshot_server_receive_packets( struct snapshot_server_t * server )
{
    snapshot_assert( server );

#if SNAPSHOT_DEVELOPMENT
    if ( server->config.network_simulator )
    {
        // process packets received from network simulator

        int num_packets_received = snapshot_network_simulator_receive_packets( server->config.network_simulator, 
                                                                               &server->address, 
                                                                               SNAPSHOT_SERVER_MAX_SIM_RECEIVE_PACKETS, 
                                                                               server->sim_receive_packet_data, 
                                                                               server->sim_receive_packet_bytes, 
                                                                               server->sim_receive_from );

        int i;
        for ( i = 0; i < num_packets_received; ++i )
        {
            server->counters[SNAPSHOT_SERVER_COUNTER_PACKETS_RECEIVED_SIMULATOR]++;
            snapshot_server_process_packet( server, &server->sim_receive_from[i], server->sim_receive_packet_data[i], server->sim_receive_packet_bytes[i] );
            snapshot_destroy_packet( server->config.context, server->sim_receive_packet_data[i] );
        }
    }
    else
#endif // #if SNAPSHOT_DEVELOPMENT
    {
        // process packets received from socket

        while ( 1 )
        {
            struct snapshot_address_t from;
            
            uint8_t buffer[SNAPSHOT_PACKET_PREFIX_BYTES + SNAPSHOT_MAX_PACKET_BYTES + SNAPSHOT_PACKET_POSTFIX_BYTES];
            uint8_t* packet_data = buffer + SNAPSHOT_PACKET_PREFIX_BYTES;

            int packet_bytes = 0;
            
            if ( server->socket != NULL )
            {
                packet_bytes = snapshot_platform_socket_receive_packet( server->socket, &from, packet_data + SNAPSHOT_PACKET_PREFIX_BYTES, SNAPSHOT_MAX_PACKET_BYTES );
            }

            if ( packet_bytes == 0 )
                break;

            server->counters[SNAPSHOT_SERVER_COUNTER_PACKETS_RECEIVED]++;

            snapshot_server_process_packet( server, &from, packet_data + SNAPSHOT_PACKET_PREFIX_BYTES, packet_bytes );
        }
    }
}

void snapshot_server_send_packets( struct snapshot_server_t * server )
{
    snapshot_assert( server );

    int i;
    for ( i = 0; i < server->max_clients; ++i )
    {
        if ( server->client_connected[i] && !server->client_loopback[i] &&
             ( server->client_last_internal_packet_send_time[i] + 0.1 <= server->time ) )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server sent keep alive packet to client %d", i );
            struct snapshot_keep_alive_packet_t packet;
            packet.packet_type = SNAPSHOT_KEEP_ALIVE_PACKET;
            packet.client_index = i;
            packet.max_clients = server->max_clients;
            snapshot_server_send_packet_to_client( server, i, &packet );
            server->counters[SNAPSHOT_SERVER_COUNTER_KEEP_ALIVE_PACKETS_SENT]++;
            server->client_last_internal_packet_send_time[i] = server->time;
        }
    }
}

void snapshot_server_check_for_timeouts( struct snapshot_server_t * server )
{
    snapshot_assert( server );

    int i;
    for ( i = 0; i < server->max_clients; ++i )
    {
        if ( server->client_connected[i] && server->client_timeout[i] > 0 && !server->client_loopback[i] &&
             ( server->client_last_packet_receive_time[i] + server->client_timeout[i] <= server->time ) )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server timed out client %d", i );
            snapshot_server_disconnect_client_internal( server, i, 0 );
        }
    }
}

int snapshot_server_client_connected( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );

    if ( client_index < 0 || client_index >= server->max_clients )
        return 0;

    return server->client_connected[client_index];
}

uint64_t snapshot_server_client_id( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );

    if ( client_index < 0 || client_index >= server->max_clients )
        return 0;

    return server->client_id[client_index];
}

struct snapshot_address_t * snapshot_server_client_address( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );

    if (client_index < 0 || client_index >= server->max_clients)
        return NULL;

    return &server->client_address[client_index];
}

int snapshot_server_num_connected_clients( struct snapshot_server_t * server )
{
    snapshot_assert( server );
    return server->num_connected_clients;
}

void * snapshot_server_client_user_data( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    return server->client_user_data[client_index];
}

int snapshot_server_connected_clients( struct snapshot_server_t * server )
{
    return server->num_connected_clients;
}

int snapshot_server_max_clients( struct snapshot_server_t * server )
{
    return server->max_clients;
}

void snapshot_server_send_payload_to_client( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );

    if ( !server->client_connected[client_index] )
        return;

#if SNAPSHOT_DEVELOPMENT

    // test payload for validation

    if ( server->development_flags & SNAPSHOT_DEVELOPMENT_FLAG_VALIDATE_PAYLOAD )
    {
        uint8_t * payload_data = snapshot_create_packet( server->config.context, SNAPSHOT_MAX_PAYLOAD_BYTES );

        int payload_bytes = 0;

        snapshot_generate_packet_data( payload_data, payload_bytes, SNAPSHOT_MAX_PAYLOAD_BYTES );

        int num_packets = 0;
        uint8_t * packet_data[SNAPSHOT_ENDPOINT_MAX_WRITE_PACKETS];
        int packet_bytes[SNAPSHOT_ENDPOINT_MAX_WRITE_PACKETS];

        snapshot_endpoint_write_packets( server->client_endpoint[client_index], payload_data, payload_bytes, &num_packets, &packet_data[0], &packet_bytes[0] );

        if ( num_packets == 1 )
        {
            // send whole packet

            snapshot_payload_packet_t * packet = snapshot_wrap_payload_packet( packet_data[0], packet_bytes[0] );

            snapshot_server_send_packet_to_client( server, client_index, packet );

            server->counters[SNAPSHOT_SERVER_COUNTER_PAYLOAD_PACKETS_SENT]++;
        }
        else
        {
            // send fragments

            for ( int i = 0; i < num_packets; i++ )
            {
                snapshot_payload_packet_t * packet = snapshot_wrap_payload_packet( packet_data[i], packet_bytes[i] );

                snapshot_server_send_packet_to_client( server, client_index, packet );

                server->counters[SNAPSHOT_SERVER_COUNTER_PAYLOAD_PACKETS_SENT]++;

                snapshot_destroy_packet( server->config.context, packet_data[i] );
            }
        }

        snapshot_destroy_packet( server->config.context, payload_data );

        server->counters[SNAPSHOT_SERVER_COUNTER_PAYLOADS_SENT]++;

        return;
    }
#endif // #if SNAPSHOT_DEVELOPMENT

    // todo: generate real payload
}

void snapshot_server_send_payloads( struct snapshot_server_t * server )
{
    snapshot_assert( server );
    for ( int i = 0; i < server->max_clients; i++ )
    {
        snapshot_server_send_payload_to_client( server, i );
    }
}

void snapshot_server_update( struct snapshot_server_t * server, double time )
{
    snapshot_assert( server );
    server->time = time;
    snapshot_server_receive_packets( server );
    snapshot_server_send_payloads( server );
    snapshot_server_send_packets( server );
    snapshot_server_check_for_timeouts( server );
}

void snapshot_server_connect_loopback_client( struct snapshot_server_t * server, int client_index, uint64_t client_id, const uint8_t * user_data )
{
    snapshot_assert( server );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( !server->client_connected[client_index] );

    server->num_connected_clients++;

    snapshot_assert( server->num_connected_clients <= server->max_clients );

    server->client_connected[client_index] = 1;
    server->client_loopback[client_index] = 1;
    server->client_confirmed[client_index] = 1;
    server->client_encryption_index[client_index] = -1;
    server->client_id[client_index] = client_id;
    server->client_sequence[client_index] = 0;
    memset( &server->client_address[client_index], 0, sizeof( struct snapshot_address_t ) );
    server->client_last_internal_packet_send_time[client_index] = server->time - 1.0;
    server->client_last_packet_receive_time[client_index] = server->time - 1.0;

    if ( user_data )
    {
        memcpy( server->client_user_data[client_index], user_data, SNAPSHOT_USER_DATA_BYTES );
    }
    else
    {
        memset( server->client_user_data[client_index], 0, SNAPSHOT_USER_DATA_BYTES );
    }

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server connected loopback client [%.16" PRIx64 "] in slot %d", client_id, client_index );

    if ( server->config.connect_disconnect_callback )
    {
        server->config.connect_disconnect_callback( server->config.context, client_index, 1 );
    }

    server->counters[SNAPSHOT_SERVER_COUNTER_CLIENT_LOOPBACK_CONNECTS]++;
}

void snapshot_server_disconnect_loopback_client( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( server->client_connected[client_index] );
    snapshot_assert( server->client_loopback[client_index] );

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server disconnected loopback client %d", client_index );

    if ( server->config.connect_disconnect_callback )
    {
        server->config.connect_disconnect_callback( server->config.context, client_index, 0 );
    }

    server->client_connected[client_index] = 0;
    server->client_loopback[client_index] = 0;
    server->client_confirmed[client_index] = 0;
    server->client_id[client_index] = 0;
    server->client_sequence[client_index] = 0;
    server->client_last_internal_packet_send_time[client_index] = 0.0;
    server->client_last_packet_receive_time[client_index] = 0.0;
    memset( &server->client_address[client_index], 0, sizeof( struct snapshot_address_t ) );
    server->client_encryption_index[client_index] = -1;
    memset( server->client_user_data[client_index], 0, SNAPSHOT_USER_DATA_BYTES );

    server->num_connected_clients--;

    snapshot_assert( server->num_connected_clients >= 0 );

    server->counters[SNAPSHOT_SERVER_COUNTER_CLIENT_LOOPBACK_DISCONNECTS]++;
}

void snapshot_server_send_passthrough_packet( struct snapshot_server_t * server, int client_index, const uint8_t * passthrough_data, int passthrough_bytes )
{
    snapshot_assert( server );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( passthrough_data );
    snapshot_assert( passthrough_bytes > 0 );

    uint8_t buffer[SNAPSHOT_PACKET_PREFIX_BYTES + sizeof(snapshot_passthrough_packet_t) + SNAPSHOT_MAX_PASSTHROUGH_BYTES + SNAPSHOT_PACKET_POSTFIX_BYTES];

    struct snapshot_passthrough_packet_t * packet = (snapshot_passthrough_packet_t*) ( buffer + SNAPSHOT_PACKET_PREFIX_BYTES );

    packet->packet_type = SNAPSHOT_PASSTHROUGH_PACKET;
    packet->passthrough_bytes = passthrough_bytes;
    memcpy( packet->passthrough_data, passthrough_data, passthrough_bytes );

    snapshot_server_send_packet_to_client( server, client_index, packet );

    server->counters[SNAPSHOT_SERVER_COUNTER_PASSTHROUGH_PACKETS_SENT]++;
}

int snapshot_server_client_loopback( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    return server->client_loopback[client_index];
}

uint16_t snapshot_server_port( struct snapshot_server_t * server )
{
    snapshot_assert( server );
    return server->address.port;
}

void snapshot_server_set_flags( struct snapshot_server_t * server, uint64_t flags )
{
    snapshot_assert( server );
    server->flags = flags;
}

#if SNAPSHOT_DEVELOPMENT

void snapshot_server_set_development_flags( struct snapshot_server_t * server, uint64_t flags )
{
    snapshot_assert( server );
    server->development_flags = flags;
}

#endif // #if SNAPSHOT_DEVELOPMENT

const uint64_t * snapshot_server_counters( struct snapshot_server_t * server )
{
    snapshot_assert( server );
    return server->counters;
}
