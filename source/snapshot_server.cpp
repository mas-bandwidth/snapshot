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

#define SNAPSHOT_NUM_DISCONNECT_PACKETS                                         10
#define SNAPSHOT_MAX_CONNECT_TOKEN_ENTRIES            ( SNAPSHOT_MAX_CLIENTS * 4 )
#define SNAPSHOT_SERVER_MAX_SIM_RECEIVE_PACKETS     ( 256 * SNAPSHOT_MAX_CLIENTS )

struct snapshot_server_t
{
    struct snapshot_server_config_t config;
    struct snapshot_platform_socket_t socket;
    struct snapshot_address_t address;
    uint64_t flags;
    double time;
    int running;
    int max_clients;
    int num_connected_clients;
    uint64_t global_sequence;
    uint64_t challenge_sequence;
    uint8_t challenge_key[SNAPSHOT_KEY_BYTES];
    int client_connected[SNAPSHOT_MAX_CLIENTS];
    int client_timeout[SNAPSHOT_MAX_CLIENTS];
    int client_loopback[SNAPSHOT_MAX_CLIENTS];
    int client_confirmed[SNAPSHOT_MAX_CLIENTS];
    int client_encryption_index[SNAPSHOT_MAX_CLIENTS];
    uint64_t client_id[SNAPSHOT_MAX_CLIENTS];
    uint64_t client_sequence[SNAPSHOT_MAX_CLIENTS];
    double client_last_packet_send_time[SNAPSHOT_MAX_CLIENTS];
    double client_last_packet_receive_time[SNAPSHOT_MAX_CLIENTS];
    uint8_t client_user_data[SNAPSHOT_MAX_CLIENTS][SNAPSHOT_USER_DATA_BYTES];
    struct snapshot_replay_protection_t client_replay_protection[SNAPSHOT_MAX_CLIENTS];
    struct snapshot_address_t client_address[SNAPSHOT_MAX_CLIENTS];
    // todo: connect token entries (pending connects)
    // struct snapshot_connect_token_entry_t connect_token_entries[SNAPSHOT_MAX_CONNECT_TOKEN_ENTRIES];
    struct snapshot_encryption_manager_t encryption_manager;
    uint8_t * sim_receive_packet_data[SNAPSHOT_SERVER_MAX_SIM_RECEIVE_PACKETS];
    int sim_receive_packet_bytes[SNAPSHOT_SERVER_MAX_SIM_RECEIVE_PACKETS];
    struct snapshot_address_t sim_receive_from[SNAPSHOT_SERVER_MAX_SIM_RECEIVE_PACKETS];
};

// todo: naff function
/*
int snapshot_server_socket_create( struct snapshot_platform_socket_t * socket,
                                   struct snapshot_address_t * address,
                                   int send_buffer_size,
                                   int receive_buffer_size,
                                   const struct snapshot_server_config_t * config )
{
    snapshot_assert( socket );
    snapshot_assert( address );
    snapshot_assert( config );

    if ( !config->network_simulator )
    {
        if ( snapshot_platform_socket_create( socket, address, SNAPSHOT_PLATFORM_SOCKET_NON_BLOCKING, send_buffer_size, receive_buffer_size ) != SNAPSHOT_OK )
        {
            return 0;
        }
    }

    return 1;
}
*/

struct snapshot_server_t * snapshot_server_create( const char * server_address_string, const struct snapshot_server_config_t * config, double time )
{  
    // todo
    (void) server_address_string;
    (void) config;
    (void) time;

    /*
    snapshot_assert( config );
    snapshot_assert( snapshot.initialized );

    struct snapshot_address_t server_address1;
    struct snapshot_address_t server_address2;

    memset( &server_address1, 0, sizeof( server_address1 ) );
    memset( &server_address2, 0, sizeof( server_address2 ) );

    if ( snapshot_parse_address( server_address1_string, &server_address1 ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "error: failed to parse server public address\n" );
        return NULL;
    }

    if ( server_address2_string != NULL && snapshot_parse_address( server_address2_string, &server_address2 ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "error: failed to parse server public address2\n" );
        return NULL;
    }

    struct snapshot_address_t bind_address_ipv4;
    struct snapshot_address_t bind_address_ipv6;

    memset( &bind_address_ipv4, 0, sizeof( bind_address_ipv4 ) );
    memset( &bind_address_ipv6, 0, sizeof( bind_address_ipv6 ) );

    struct snapshot_platform_socket_t socket;

    memset( &socket_ipv4, 0, sizeof( socket ) );

    // todo: blargh

    if ( server_address1.type == SNAPSHOT_ADDRESS_IPV4 || server_address2.type == SNAPSHOT_ADDRESS_IPV4 )
    {
        bind_address_ipv4.type = SNAPSHOT_ADDRESS_IPV4;
        bind_address_ipv4.port = server_address1.type == SNAPSHOT_ADDRESS_IPV4 ? server_address1.port : server_address2.port;

        if ( !snapshot_server_socket_create( &socket_ipv4, &bind_address_ipv4, SNAPSHOT_SERVER_SOCKET_SNDBUF_SIZE, SNAPSHOT_SERVER_SOCKET_RCVBUF_SIZE, config ) )
        {
            return NULL;
        }
    }

    if ( server_address1.type == SNAPSHOT_ADDRESS_IPV6 || server_address2.type == SNAPSHOT_ADDRESS_IPV6 )
    {
        bind_address_ipv6.type = SNAPSHOT_ADDRESS_IPV6;
        bind_address_ipv6.port = server_address1.type == SNAPSHOT_ADDRESS_IPV6 ? server_address1.port : server_address2.port;

        if ( !snapshot_server_socket_create( &socket_ipv6, &bind_address_ipv6, SNAPSHOT_SERVER_SOCKET_SNDBUF_SIZE, SNAPSHOT_SERVER_SOCKET_RCVBUF_SIZE, config ) )
        {
            return NULL;
        }
    }

    struct snapshot_server_t * server = (struct snapshot_server_t*) config->allocate_function( config->allocator_context, sizeof( struct snapshot_server_t ) );
    if ( !server )
    {
        snapshot_socket_destroy( &socket_ipv4 );
        snapshot_socket_destroy( &socket_ipv6 );
        return NULL;
    }

    if ( !config->network_simulator )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server listening on %s\n", server_address1_string );
    }
    else
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server listening on %s (network simulator)\n", server_address1_string );
    }

    server->config = *config;
    server->socket_holder.ipv4 = socket_ipv4;
    server->socket_holder.ipv6 = socket_ipv6;
    server->address = server_address1;
    server->flags = 0;
    server->time = time;
    server->running = 0;
    server->max_clients = 0;
    server->num_connected_clients = 0;
    server->global_sequence = 1ULL << 63;

    memset( server->client_connected, 0, sizeof( server->client_connected ) );
    memset( server->client_loopback, 0, sizeof( server->client_loopback ) );
    memset( server->client_confirmed, 0, sizeof( server->client_confirmed ) );
    memset( server->client_id, 0, sizeof( server->client_id ) );
    memset( server->client_sequence, 0, sizeof( server->client_sequence ) );
    memset( server->client_last_packet_send_time, 0, sizeof( server->client_last_packet_send_time ) );
    memset( server->client_last_packet_receive_time, 0, sizeof( server->client_last_packet_receive_time ) );
    memset( server->client_address, 0, sizeof( server->client_address ) );
    memset( server->client_user_data, 0, sizeof( server->client_user_data ) );

    int i;
    for ( i = 0; i < SNAPSHOT_MAX_CLIENTS; ++i )
        server->client_encryption_index[i] = -1;

    snapshot_connect_token_entries_reset( server->connect_token_entries );

    snapshot_encryption_manager_reset( &server->encryption_manager );

    for ( i = 0; i < SNAPSHOT_MAX_CLIENTS; ++i )
        snapshot_replay_protection_reset( &server->client_replay_protection[i] );

    memset( &server->client_packet_queue, 0, sizeof( server->client_packet_queue ) );

    return server;
    */

    return NULL;
}

void snapshot_server_stop( struct snapshot_server_t * server );

void snapshot_server_destroy( struct snapshot_server_t * server )
{
    snapshot_assert( server );

    snapshot_server_stop( server );

    snapshot_platform_socket_destroy( &server->socket );

    snapshot_free( server->config.context, server );
}

void snapshot_server_start( struct snapshot_server_t * server, int max_clients )
{
    snapshot_assert( server );
    snapshot_assert( max_clients > 0 );
    snapshot_assert( max_clients <= SNAPSHOT_MAX_CLIENTS );

    if ( server->running )
        snapshot_server_stop( server );

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server started with %d client slots\n", max_clients );

    server->running = 1;
    server->max_clients = max_clients;
    server->num_connected_clients = 0;
    server->challenge_sequence = 0;    
    snapshot_crypto_random_bytes( server->challenge_key, SNAPSHOT_KEY_BYTES );
}

void snapshot_server_send_global_packet( snapshot_server_t * server, void * packet, struct snapshot_address_t * to, uint8_t * packet_key )
{
    snapshot_assert( server );
    snapshot_assert( packet );
    snapshot_assert( to );
    snapshot_assert( packet_key );

    uint8_t packet_data[SNAPSHOT_MAX_PACKET_BYTES];

    // todo
    (void) packet_data;
    /*
    int packet_bytes = snapshot_write_packet( packet, packet_data, SNAPSHOT_MAX_PACKET_BYTES, server->global_sequence, packet_key, server->config.protocol_id );

    snapshot_assert( packet_bytes <= SNAPSHOT_MAX_PACKET_BYTES );

    if ( server->config.network_simulator )
    {
        snapshot_network_simulator_send_packet( server->config.network_simulator, &server->address, to, packet_data, packet_bytes );
    }
    else
    {
        if ( server->config.override_send_and_receive )
        {
            server->config.send_packet_override( server->config.callback_context, to, packet_data, packet_bytes );
        }
        else if ( to->type == SNAPSHOT_ADDRESS_IPV4 )
        {
            snapshot_socket_send_packet( &server->socket_holder.ipv4, to, packet_data, packet_bytes );
        }
        else if ( to->type == SNAPSHOT_ADDRESS_IPV6 )
        {
            snapshot_socket_send_packet( &server->socket_holder.ipv6, to, packet_data, packet_bytes );
        }
    }
    */

    server->global_sequence++;
}

void snapshot_server_send_client_packet( struct snapshot_server_t * server, void * packet, int client_index )
{
    snapshot_assert( server );
    snapshot_assert( packet );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( server->client_connected[client_index] );
    snapshot_assert( !server->client_loopback[client_index] );

    uint8_t packet_data[SNAPSHOT_MAX_PACKET_BYTES];

    if ( !snapshot_encryption_manager_touch( &server->encryption_manager, 
                                             server->client_encryption_index[client_index], 
                                             &server->client_address[client_index], 
                                             server->time ) )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "error: encryption mapping is out of date for client %d\n", client_index );
        return;
    }

    uint8_t * packet_key = snapshot_encryption_manager_get_send_key( &server->encryption_manager, server->client_encryption_index[client_index] );

    // todo
    (void) packet_key;
    (void) packet_data;

    /*
    int packet_bytes = snapshot_write_packet( packet, packet_data, SNAPSHOT_MAX_PACKET_BYTES, server->client_sequence[client_index], packet_key, server->config.protocol_id );

    snapshot_assert( packet_bytes <= SNAPSHOT_MAX_PACKET_BYTES );

    if ( server->config.network_simulator )
    {
        snapshot_network_simulator_send_packet( server->config.network_simulator, &server->address, &server->client_address[client_index], packet_data, packet_bytes );
    }
    else
    {
        if ( server->config.override_send_and_receive )
        {
            server->config.send_packet_override( server->config.callback_context, &server->client_address[client_index], packet_data, packet_bytes );
        }
        else
        {
            if ( server->client_address[client_index].type == SNAPSHOT_ADDRESS_IPV4 )
            {
                snapshot_socket_send_packet( &server->socket_holder.ipv4, &server->client_address[client_index], packet_data, packet_bytes );
            }
            else if ( server->client_address[client_index].type == SNAPSHOT_ADDRESS_IPV6 )
            {
                snapshot_socket_send_packet( &server->socket_holder.ipv6, &server->client_address[client_index], packet_data, packet_bytes );
            }
        }
    }
    */

    server->client_sequence[client_index]++;

    server->client_last_packet_send_time[client_index] = server->time;
}

void snapshot_server_disconnect_client_internal( struct snapshot_server_t * server, int client_index, int send_disconnect_packets )
{
    snapshot_assert( server );
    snapshot_assert( server->running );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( server->client_connected[client_index] );
    snapshot_assert( !server->client_loopback[client_index] );
    snapshot_assert( server->encryption_manager.client_index[server->client_encryption_index[client_index]] == client_index );

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server disconnected client %d\n", client_index );

    if ( server->config.connect_disconnect_callback )
    {
        server->config.connect_disconnect_callback( server->config.context, client_index, 0 );
    }

    if ( send_disconnect_packets )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server sent disconnect packets to client %d\n", client_index );

        int i;
        for ( i = 0; i < SNAPSHOT_NUM_DISCONNECT_PACKETS; ++i )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server sent disconnect packet %d\n", i );

            struct snapshot_connection_disconnect_packet_t packet;
            packet.packet_type = SNAPSHOT_CONNECTION_DISCONNECT_PACKET;

            snapshot_server_send_client_packet( server, &packet, client_index );
        }
    }

    // todo: don't want to use queues, if possible
    /*
    while ( 1 )
    {
        void * packet = snapshot_packet_queue_pop( &server->client_packet_queue[client_index], NULL );
        if ( !packet )
            break;
        server->config.free_function( server->config.allocator_context, packet );
    }

    snapshot_packet_queue_clear( &server->client_packet_queue[client_index] );
    */

    snapshot_replay_protection_reset( &server->client_replay_protection[client_index] );

    server->encryption_manager.client_index[server->client_encryption_index[client_index]] = -1;

    snapshot_encryption_manager_remove_encryption_mapping( &server->encryption_manager, &server->client_address[client_index], server->time );

    server->client_connected[client_index] = 0;
    server->client_confirmed[client_index] = 0;
    server->client_id[client_index] = 0;
    server->client_sequence[client_index] = 0;
    server->client_last_packet_send_time[client_index] = 0.0;
    server->client_last_packet_receive_time[client_index] = 0.0;
    memset( &server->client_address[client_index], 0, sizeof( struct snapshot_address_t ) );
    server->client_encryption_index[client_index] = -1;
    memset( server->client_user_data[client_index], 0, SNAPSHOT_USER_DATA_BYTES );

    server->num_connected_clients--;

    snapshot_assert( server->num_connected_clients >= 0 );
}

void snapshot_server_disconnect_client( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );

    if ( !server->running )
        return;

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

    if ( !server->running )
        return;

    int i;
    for ( i = 0; i < server->max_clients; ++i )
    {
        if ( server->client_connected[i] && !server->client_loopback[i] )
        {
            snapshot_server_disconnect_client_internal( server, i, 1 );
        }
    }
}

void snapshot_server_stop( struct snapshot_server_t * server )
{
    snapshot_assert( server );

    if ( !server->running )
        return;

    snapshot_server_disconnect_all_clients( server );

    server->running = 0;
    server->max_clients = 0;
    server->num_connected_clients = 0;

    server->global_sequence = 0;
    server->challenge_sequence = 0;
    memset( server->challenge_key, 0, SNAPSHOT_KEY_BYTES );

    // todo: connect token entries
//    snapshot_connect_token_entries_reset( server->connect_token_entries );

    snapshot_encryption_manager_reset( &server->encryption_manager );

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server stopped\n" );
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

int snapshot_server_find_client_index_by_address( struct snapshot_server_t * server, struct snapshot_address_t * address )
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
                                                        struct snapshot_address_t * from, 
                                                        struct snapshot_connection_request_packet_t * packet )
{
    snapshot_assert( server );

    (void) from;

    struct snapshot_connect_token_private_t connect_token_private;
    if ( snapshot_read_connect_token_private( packet->connect_token_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES, &connect_token_private ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. failed to read connect token\n" );
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
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. server address not in connect token whitelist\n" );
        return;
    }

    if ( snapshot_server_find_client_index_by_address( server, from ) != -1 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. a client with this address is already connected\n" );
        return;
    }

    if ( snapshot_server_find_client_index_by_id( server, connect_token_private.client_id ) != -1 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. a client with this id is already connected\n" );
        return;
    }

    // todo
    /*
    if ( !snapshot_connect_token_entries_find_or_add( server->connect_token_entries, 
                                                     from, 
                                                     packet->connect_token_data + SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES - SNAPSHOT_MAC_BYTES, 
                                                     server->time ) )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. connect token has already been used\n" );
        return;
    }
    */

    if ( server->num_connected_clients == server->max_clients )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server denied connection request. server is full\n" );

        struct snapshot_connection_denied_packet_t p;
        p.packet_type = SNAPSHOT_CONNECTION_DENIED_PACKET;
        
        snapshot_server_send_global_packet( server, &p, from, connect_token_private.server_to_client_key );

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
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. failed to add encryption mapping\n" );
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
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection request. failed to encrypt challenge token\n" );
        return;
    }

    server->challenge_sequence++;

    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server sent connection challenge packet\n" );

    snapshot_server_send_global_packet( server, &challenge_packet, from, connect_token_private.server_to_client_key );
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
                                     struct snapshot_address_t * address, 
                                     uint64_t client_id, 
                                     int encryption_index,
                                     int timeout_seconds, 
                                     void * user_data )
{
    snapshot_assert( server );
    snapshot_assert( server->running );
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
    server->client_last_packet_send_time[client_index] = server->time;
    server->client_last_packet_receive_time[client_index] = server->time;
    memcpy( server->client_user_data[client_index], user_data, SNAPSHOT_USER_DATA_BYTES );

    char address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server accepted client %s %.16" PRIx64 " in slot %d\n", snapshot_address_to_string( address, address_string ), client_id, client_index );

    struct snapshot_connection_keep_alive_packet_t packet;
    packet.packet_type = SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET;
    packet.client_index = client_index;
    packet.max_clients = server->max_clients;

    snapshot_server_send_client_packet( server, &packet, client_index );

    if ( server->config.connect_disconnect_callback )
    {
        server->config.connect_disconnect_callback( server->config.context, client_index, 1 );
    }
}

void snapshot_server_process_connection_response_packet( struct snapshot_server_t * server, 
                                                         struct snapshot_address_t * from, 
                                                         struct snapshot_connection_response_packet_t * packet, 
                                                         int encryption_index )
{
    snapshot_assert( server );

    if ( snapshot_decrypt_challenge_token( packet->challenge_token_data, 
                                           SNAPSHOT_CHALLENGE_TOKEN_BYTES, 
                                           packet->challenge_token_sequence, 
                                           server->challenge_key ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection response. failed to decrypt challenge token\n" );
        return;
    }

    struct snapshot_challenge_token_t challenge_token;
    if ( snapshot_read_challenge_token( packet->challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES, &challenge_token ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection response. failed to read challenge token\n" );
        return;
    }

    uint8_t * packet_send_key = snapshot_encryption_manager_get_send_key( &server->encryption_manager, encryption_index );

    if ( !packet_send_key )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection response. no packet send key\n" );
        return;
    }

    if ( snapshot_server_find_client_index_by_address( server, from ) != -1 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection response. a client with this address is already connected\n" );
        return;
    }

    if ( snapshot_server_find_client_index_by_id( server, challenge_token.client_id ) != -1 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server ignored connection response. a client with this id is already connected\n" );
        return;
    }

    if ( server->num_connected_clients == server->max_clients )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server denied connection response. server is full\n" );

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

void snapshot_server_process_packet( struct snapshot_server_t * server, 
                                     struct snapshot_address_t * from, 
                                     void * packet, 
                                     uint64_t sequence, 
                                     int encryption_index, 
                                     int client_index )
{
    snapshot_assert( server );
    snapshot_assert( packet );

    (void) from;
    (void) sequence;

    uint8_t packet_type = ( (uint8_t*) packet ) [0];

    switch ( packet_type )
    {
        case SNAPSHOT_CONNECTION_REQUEST_PACKET:
        {    
            if ( ( server->flags & SNAPSHOT_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS ) == 0 )
            {
                char from_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server received connection request from %s\n", snapshot_address_to_string( from, from_address_string ) );
                snapshot_server_process_connection_request_packet( server, from, (struct snapshot_connection_request_packet_t*) packet );
            }
        }
        break;

        case SNAPSHOT_CONNECTION_RESPONSE_PACKET:
        {    
            if ( ( server->flags & SNAPSHOT_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS ) == 0 )
            {
                char from_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server received connection response from %s\n", snapshot_address_to_string( from, from_address_string ) );
                snapshot_server_process_connection_response_packet( server, from, (struct snapshot_connection_response_packet_t*) packet, encryption_index );
            }
        }
        break;

        case SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET:
        {
            if ( client_index != -1 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server received connection keep alive packet from client %d\n", client_index );
                server->client_last_packet_receive_time[client_index] = server->time;
                if ( !server->client_confirmed[client_index] )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server confirmed connection with client %d\n", client_index );
                    server->client_confirmed[client_index] = 1;
                }
            }
        }
        break;

        case SNAPSHOT_CONNECTION_PAYLOAD_PACKET:
        {
            if ( client_index != -1 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server received connection payload packet from client %d\n", client_index );
                server->client_last_packet_receive_time[client_index] = server->time;
                if ( !server->client_confirmed[client_index] )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server confirmed connection with client %d\n", client_index );
                    server->client_confirmed[client_index] = 1;
                }
                // todo: process payload packet in-place
                return;
            }
        }
        break;

        case SNAPSHOT_CONNECTION_DISCONNECT_PACKET:
        {
            if ( client_index != -1 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server received disconnect packet from client %d\n", client_index );
                snapshot_server_disconnect_client_internal( server, client_index, 0 );
           }
        }
        break;

        default:
            break;
    }

    // todo: dont' want to free here. process in-place
    // server->config.free_function( server->config.allocator_context, packet );
}

// todo: this is the inject packet function for loopback
/*
void snapshot_server_process_packet( struct snapshot_server_t * server, struct snapshot_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    uint8_t allowed_packets[SNAPSHOT_CONNECTION_NUM_PACKETS];
    memset( allowed_packets, 0, sizeof( allowed_packets ) );
    allowed_packets[SNAPSHOT_CONNECTION_REQUEST_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_RESPONSE_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_PAYLOAD_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_DISCONNECT_PACKET] = 1;

    uint64_t current_timestamp = (uint64_t) time( NULL );

    uint64_t sequence;

    int encryption_index = -1;
    int client_index = snasphot_server_find_client_index_by_address( server, from );
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
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server could not process packet because no encryption mapping exists for %s\n", snapshot_address_to_string( from, address_string ) );
        return;
    }

    void * packet = snapshot_read_packet( packet_data, 
                                          packet_bytes, 
                                          &sequence, 
                                          read_packet_key, 
                                          server->config.protocol_id, 
                                          current_timestamp, 
                                          server->config.private_key, 
                                          allowed_packets, 
                                          ( client_index != -1 ) ? &server->client_replay_protection[client_index] : NULL, 
                                          server->config.allocator_context, 
                                          server->config.allocate_function );

    if ( !packet )
        return;

    snapshot_server_process_packet_internal( server, from, packet, sequence, encryption_index, client_index );
}
*/

void snapshot_server_read_and_process_packet( struct snapshot_server_t * server, 
                                              struct snapshot_address_t * from, 
                                              uint8_t * packet_data, 
                                              int packet_bytes, 
                                              uint64_t current_timestamp, 
                                              uint8_t * allowed_packets )
{
    if ( !server->running )
        return;

    if ( packet_bytes <= 1 )
        return;

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
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server could not process packet because no encryption mapping exists for %s\n", snapshot_address_to_string( from, address_string ) );
        return;
    }

    // todo
    (void) sequence;
    (void) current_timestamp;
    (void) allowed_packets;

    /*
    void * packet = snapshot_read_packet( packet_data, 
                                          packet_bytes, 
                                          &sequence, 
                                          read_packet_key, 
                                          server->config.protocol_id, 
                                          current_timestamp, 
                                          server->config.private_key, 
                                          allowed_packets, 
                                          ( client_index != -1 ) ? &server->client_replay_protection[client_index] : NULL );

    if ( !packet )
        return;

    snapshot_server_process_packet( server, from, packet, sequence, encryption_index, client_index );
                                        */
}

void snapshot_server_receive_packets( struct snapshot_server_t * server )
{
    snapshot_assert( server );

    uint8_t allowed_packets[SNAPSHOT_CONNECTION_NUM_PACKETS];
    memset( allowed_packets, 0, sizeof( allowed_packets ) );
    allowed_packets[SNAPSHOT_CONNECTION_REQUEST_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_RESPONSE_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_PAYLOAD_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_DISCONNECT_PACKET] = 1;

    uint64_t current_timestamp = (uint64_t) time( NULL );

    if ( !server->config.network_simulator )
    {
        // process packets received from socket

        while ( 1 )
        {
            struct snapshot_address_t from;
            
            uint8_t packet_data[SNAPSHOT_MAX_PACKET_BYTES];
            
            int packet_bytes = 0;
            
            if ( server->socket.handle != 0 )
            {
                packet_bytes = snapshot_platform_socket_receive_packet( &server->socket, &from, packet_data, SNAPSHOT_MAX_PACKET_BYTES );
            }

            if ( packet_bytes == 0 )
                break;

            snapshot_server_read_and_process_packet( server, &from, packet_data, packet_bytes, current_timestamp, allowed_packets );
        }
    }
    else
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
            snapshot_server_read_and_process_packet( server, 
                                                     &server->sim_receive_from[i], 
                                                     server->sim_receive_packet_data[i], 
                                                     server->sim_receive_packet_bytes[i], 
                                                     current_timestamp, 
                                                     allowed_packets );

            snapshot_free( server->config.context, server->sim_receive_packet_data[i] );
        }
    }
}

void snapshot_server_send_packets( struct snapshot_server_t * server )
{
    snapshot_assert( server );

    if ( !server->running )
        return;

    int i;
    for ( i = 0; i < server->max_clients; ++i )
    {
        if ( server->client_connected[i] && !server->client_loopback[i] &&
             ( server->client_last_packet_send_time[i] + 0.1 <= server->time ) )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server sent connection keep alive packet to client %d\n", i );
            struct snapshot_connection_keep_alive_packet_t packet;
            packet.packet_type = SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET;
            packet.client_index = i;
            packet.max_clients = server->max_clients;
            snapshot_server_send_client_packet( server, &packet, i );
        }
    }
}

void snapshot_server_check_for_timeouts( struct snapshot_server_t * server )
{
    snapshot_assert( server );

    if ( !server->running )
        return;

    int i;
    for ( i = 0; i < server->max_clients; ++i )
    {
        if ( server->client_connected[i] && server->client_timeout[i] > 0 && !server->client_loopback[i] &&
             ( server->client_last_packet_receive_time[i] + server->client_timeout[i] <= server->time ) )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server timed out client %d\n", i );
            snapshot_server_disconnect_client_internal( server, i, 0 );
        }
    }
}

int snapshot_server_client_connected( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );

    if ( !server->running )
        return 0;

    if ( client_index < 0 || client_index >= server->max_clients )
        return 0;

    return server->client_connected[client_index];
}

uint64_t snapshot_server_client_id( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );

    if ( !server->running )
        return 0;

    if ( client_index < 0 || client_index >= server->max_clients )
        return 0;

    return server->client_id[client_index];
}

struct snapshot_address_t * snapshot_server_client_address( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );

    if (!server->running)
        return NULL;

    if (client_index < 0 || client_index >= server->max_clients)
        return NULL;

    return &server->client_address[client_index];
}

uint64_t snapshot_server_next_packet_sequence( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    if ( !server->client_connected[client_index] )
        return 0;
    return server->client_sequence[client_index];    
}

void snapshot_server_send_packet( struct snapshot_server_t * server, int client_index, const uint8_t * packet_data, int packet_bytes )
{
    snapshot_assert( server );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes >= 0 );
    snapshot_assert( packet_bytes <= SNAPSHOT_MAX_PACKET_BYTES );

    if ( !server->running )
        return;

    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    if ( !server->client_connected[client_index] )
        return;

    if ( !server->client_loopback[client_index] )
    {
        uint8_t buffer[SNAPSHOT_MAX_PAYLOAD_BYTES*2];

        struct snapshot_connection_payload_packet_t * packet = (struct snapshot_connection_payload_packet_t*) buffer;

        packet->packet_type = SNAPSHOT_CONNECTION_PAYLOAD_PACKET;
        packet->payload_bytes = packet_bytes;
        memcpy( packet->payload_data, packet_data, packet_bytes );

        if ( !server->client_confirmed[client_index] )
        {
            struct snapshot_connection_keep_alive_packet_t keep_alive_packet;
            keep_alive_packet.packet_type = SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET;
            keep_alive_packet.client_index = client_index;
            keep_alive_packet.max_clients = server->max_clients;
            snapshot_server_send_client_packet( server, &keep_alive_packet, client_index );
        }

        snapshot_server_send_client_packet( server, packet, client_index );
    }
    else
    {
        snapshot_assert( server->config.send_loopback_packet_callback );

        server->config.send_loopback_packet_callback( server->config.context,
                                                      client_index, 
                                                      packet_data, 
                                                      packet_bytes, 
                                                      server->client_sequence[client_index]++ );

        server->client_last_packet_send_time[client_index] = server->time;
    }
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

int snapshot_server_running( struct snapshot_server_t * server )
{
    snapshot_assert( server );
    return server->running;
}

int snapshot_server_max_clients( struct snapshot_server_t * server )
{
    return server->max_clients;
}

void snapshot_server_update( struct snapshot_server_t * server, double time )
{
    snapshot_assert( server );
    server->time = time;
    snapshot_server_receive_packets( server );
    snapshot_server_send_packets( server );
    snapshot_server_check_for_timeouts( server );
}

void snapshot_server_connect_loopback_client( struct snapshot_server_t * server, int client_index, uint64_t client_id, const uint8_t * user_data )
{
    snapshot_assert( server );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( server->running );
    snapshot_assert( !server->client_connected[client_index] );

    server->num_connected_clients++;

    snapshot_assert( server->num_connected_clients <= server->max_clients );

    server->client_loopback[client_index] = 1;
    server->client_connected[client_index] = 1;
    server->client_confirmed[client_index] = 1;
    server->client_encryption_index[client_index] = -1;
    server->client_id[client_index] = client_id;
    server->client_sequence[client_index] = 0;
    memset( &server->client_address[client_index], 0, sizeof( struct snapshot_address_t ) );
    server->client_last_packet_send_time[client_index] = server->time;
    server->client_last_packet_receive_time[client_index] = server->time;

    if ( user_data )
    {
        memcpy( server->client_user_data[client_index], user_data, SNAPSHOT_USER_DATA_BYTES );
    }
    else
    {
        memset( server->client_user_data[client_index], 0, SNAPSHOT_USER_DATA_BYTES );
    }

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server connected loopback client %.16" PRIx64 " in slot %d\n", client_id, client_index );

    if ( server->config.connect_disconnect_callback )
    {
        server->config.connect_disconnect_callback( server->config.context, client_index, 1 );
    }
}

void snapshot_server_disconnect_loopback_client( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( server->running );
    snapshot_assert( server->client_connected[client_index] );
    snapshot_assert( server->client_loopback[client_index] );

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "server disconnected loopback client %d\n", client_index );

    if ( server->config.connect_disconnect_callback )
    {
        server->config.connect_disconnect_callback( server->config.context, client_index, 0 );
    }

    server->client_connected[client_index] = 0;
    server->client_loopback[client_index] = 0;
    server->client_confirmed[client_index] = 0;
    server->client_id[client_index] = 0;
    server->client_sequence[client_index] = 0;
    server->client_last_packet_send_time[client_index] = 0.0;
    server->client_last_packet_receive_time[client_index] = 0.0;
    memset( &server->client_address[client_index], 0, sizeof( struct snapshot_address_t ) );
    server->client_encryption_index[client_index] = -1;
    memset( server->client_user_data[client_index], 0, SNAPSHOT_USER_DATA_BYTES );

    server->num_connected_clients--;

    snapshot_assert( server->num_connected_clients >= 0 );
}

int snapshot_server_client_loopback( struct snapshot_server_t * server, int client_index )
{
    snapshot_assert( server );
    snapshot_assert( server->running );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    return server->client_loopback[client_index];
}

void snapshot_server_process_loopback_packet( struct snapshot_server_t * server, int client_index, const uint8_t * packet_data, int packet_bytes, uint64_t packet_sequence )
{
    snapshot_assert( server );
    snapshot_assert( client_index >= 0 );
    snapshot_assert( client_index < server->max_clients );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes >= 0 );
    snapshot_assert( packet_bytes <= SNAPSHOT_MAX_PACKET_BYTES );
    snapshot_assert( server->client_connected[client_index] );
    snapshot_assert( server->client_loopback[client_index] );
    snapshot_assert( server->running );

    // todo: zero copy update
    (void) packet_sequence;
    /*
    struct snapshot_connection_payload_packet_t * packet = snapshot_create_payload_packet( packet_bytes, server->config.context, server->config.allocate_function );
    if ( !packet )
        return;

    memcpy( packet->payload_data, packet_data, packet_bytes );

    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "server processing loopback packet from client %d\n", client_index );

    server->client_last_packet_receive_time[client_index] = server->time;

    snapshot_packet_queue_push( &server->client_packet_queue[client_index], packet, packet_sequence );
    */
}

uint16_t snapshot_server_get_port( struct snapshot_server_t * server )
{
    snapshot_assert( server );
    return server->address.port;
}
