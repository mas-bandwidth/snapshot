/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_client.h"
#include "snapshot_address.h"
#include "snapshot_platform.h"
#include "snapshot_connect_token.h"
#include "snapshot_challenge_token.h"
#include "snapshot_replay_protection.h"

const char * snapshot_client_state_name( int client_state )
{
    switch ( client_state )
    {
        case SNAPSHOT_CLIENT_STATE_CONNECT_TOKEN_EXPIRED:                return "connect token expired";
        case SNAPSHOT_CLIENT_STATE_INVALID_CONNECT_TOKEN:                return "invalid connect token";
        case SNAPSHOT_CLIENT_STATE_CONNECTION_TIMED_OUT:                 return "connection timed out";
        case SNAPSHOT_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT:         return "connection request timed out";
        case SNAPSHOT_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT:        return "connection response timed out";
        case SNAPSHOT_CLIENT_STATE_CONNECTION_DENIED:                    return "connection denied";
        case SNAPSHOT_CLIENT_STATE_DISCONNECTED:                         return "disconnected";
        case SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST:           return "sending connection request";
        case SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:          return "sending connection response";
        case SNAPSHOT_CLIENT_STATE_CONNECTED:                            return "connected";
        default:
            snapshot_assert( 0 );
            return "???";
    }
}

void snapshot_default_client_config( struct snapshot_client_config_t * config )
{
    snapshot_assert( config );
    config->context = NULL;
    config->network_simulator = NULL;
    config->state_change_callback = NULL;
    config->send_loopback_packet_callback = NULL;
};

struct snapshot_client_t
{
    struct snapshot_client_config_t config;
    int state;
    double time;
    double connect_start_time;
    double last_packet_send_time;
    double last_packet_receive_time;
    int should_disconnect;
    int should_disconnect_state;
    uint64_t sequence;
    int client_index;
    int max_clients;
    int server_address_index;
    struct snapshot_address_t address;
    struct snapshot_address_t server_address;
    struct snapshot_connect_token_t connect_token;
    struct snapshot_platform_socket_t socket;
    struct snapshot_replay_protection_t replay_protection;
    uint64_t challenge_token_sequence;
    uint8_t challenge_token_data[SNAPSHOT_CHALLENGE_TOKEN_BYTES];
    int loopback;
};

struct snapshot_client_t * snapshot_client_create( const char * address_string,
                                                   const struct snapshot_client_config_t * config,
                                                   double time )
{
    snapshot_assert( config );

    struct snapshot_address_t address;

    memset( &address, 0, sizeof( address ) );

    if ( snapshot_address_parse( &address, address_string ) != SNAPSHOT_OK )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "error: failed to parse client address\n" );
        return NULL;
    }

    struct snapshot_platform_socket_t socket;

    memset( &socket, 0, sizeof( socket ) );

    if ( !config->network_simulator )
    {
        if ( snapshot_platform_socket_create( &socket, &address, 0.0f, SNAPSHOT_PLATFORM_SOCKET_NON_BLOCKING, SNAPSHOT_CLIENT_SOCKET_SNDBUF_SIZE, SNAPSHOT_CLIENT_SOCKET_RCVBUF_SIZE ) != SNAPSHOT_OK )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "error: failed to create client socket\n" );
            return NULL;
        }
    }
    else
    {
        if ( address.port == 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "error: must bind to a specific port when using network simulator\n" );
            return NULL;
        }
    }

    struct snapshot_client_t * client = (struct snapshot_client_t*) snapshot_malloc( config->context, sizeof( struct snapshot_client_t ) );

    if ( !client )
    {
        snapshot_platform_socket_destroy( &socket );
        return NULL;
    }

    if ( !config->network_simulator )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client started on port %d\n", address.port );
    }
    else
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client started on port %d (network simulator)\n", address.port );
    }

    client->config = *config;
    client->socket = socket;
    client->address = address;
    client->state = SNAPSHOT_CLIENT_STATE_DISCONNECTED;
    client->time = time;
    client->connect_start_time = 0.0;
    client->last_packet_send_time = -1000.0;
    client->last_packet_receive_time = -1000.0;
    client->should_disconnect = 0;
    client->should_disconnect_state = SNAPSHOT_CLIENT_STATE_DISCONNECTED;
    client->sequence = 0;
    client->client_index = 0;
    client->max_clients = 0;
    client->server_address_index = 0;
    client->challenge_token_sequence = 0;
    client->loopback = 0;
    memset( &client->server_address, 0, sizeof( struct snapshot_address_t ) );
    memset( &client->connect_token, 0, sizeof( struct snapshot_connect_token_t ) );
    memset( client->challenge_token_data, 0, SNAPSHOT_CHALLENGE_TOKEN_BYTES );

    snapshot_replay_protection_reset( &client->replay_protection );

    return client;
}

#if 0 // todo

void snapshot_client_destroy( struct snapshot_client_t * client )
{
    snapshot_assert( client );
    if ( !client->loopback )
        snapshot_client_disconnect( client );
    else
        snapshot_client_disconnect_loopback( client );
    snapshot_socket_destroy( &client->socket_holder.ipv4 );
    snapshot_socket_destroy( &client->socket_holder.ipv6 );
    snapshot_packet_queue_clear( &client->packet_receive_queue );
    client->config.free_function( client->config.allocator_context, client );
}

void snapshot_client_set_state( struct snapshot_client_t * client, int client_state )
{
    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client changed state from '%s' to '%s'\n", snapshot_client_state_name( client->state ), snapshot_client_state_name( client_state ) );

    if ( client->config.state_change_callback )
    {
        client->config.state_change_callback( client->config.callback_context, client->state, client_state );
    }

    client->state = client_state;
}

void snapshot_client_reset_before_next_connect( struct snapshot_client_t * client )
{
    client->connect_start_time = client->time;
    client->last_packet_send_time = client->time - 1.0f;
    client->last_packet_receive_time = client->time;
    client->should_disconnect = 0;
    client->should_disconnect_state = SNAPSHOT_CLIENT_STATE_DISCONNECTED;
    client->challenge_token_sequence = 0;

    memset( client->challenge_token_data, 0, SNAPSHOT_CHALLENGE_TOKEN_BYTES );

    snapshot_replay_protection_reset( &client->replay_protection );
}

void snapshot_client_reset_connection_data( struct snapshot_client_t * client, int client_state )
{
    snapshot_assert( client );

    client->sequence = 0;
    client->loopback = 0;
    client->client_index = 0;
    client->max_clients = 0;
    client->connect_start_time = 0.0;
    client->server_address_index = 0;
    memset( &client->server_address, 0, sizeof( struct snapshot_address_t ) );
    memset( &client->connect_token, 0, sizeof( struct snapshot_connect_token_t ) );
    memset( &client->context, 0, sizeof( struct snapshot_context_t ) );

    snapshot_client_set_state( client, client_state );

    snapshot_client_reset_before_next_connect( client );

    // todo: i want to process packets in-place, instead of putting them on a queue
    /*
    while ( 1 )
    {
        void * packet = snapshot_packet_queue_pop( &client->packet_receive_queue, NULL );
        if ( !packet )
            break;
        client->config.free_function( client->config.allocator_context, packet );
    }
    snapshot_packet_queue_clear( &client->packet_receive_queue );
    */
}

void snapshot_client_disconnect_internal( struct snapshot_client_t * client, int destination_state, int send_disconnect_packets );

void snapshot_client_connect( struct snapshot_client_t * client, uint8_t * connect_token )
{
    snapshot_assert( client );
    snapshot_assert( connect_token );

    snapshot_client_disconnect( client );

    if ( snapshot_read_connect_token( connect_token, SNAPSHOT_CONNECT_TOKEN_BYTES, &client->connect_token ) != SNAPSHOT_OK )
    {
        snapshot_client_set_state( client, SNAPSHOT_CLIENT_STATE_INVALID_CONNECT_TOKEN );
        return;
    }

    client->server_address_index = 0;
    client->server_address = client->connect_token.server_addresses[0];

    char server_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connecting to server %s [%d/%d]\n", snapshot_address_to_string( &client->server_address, server_address_string ), client->server_address_index + 1, client->connect_token.num_server_addresses );

    memcpy( client->context.read_packet_key, client->connect_token.server_to_client_key, SNAPSHOT_KEY_BYTES );
    memcpy( client->context.write_packet_key, client->connect_token.client_to_server_key, SNAPSHOT_KEY_BYTES );

    snapshot_client_reset_before_next_connect( client );

    snapshot_client_set_state( client, SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST );
}

void snapshot_client_process_packet_internal( struct snapshot_client_t * client, struct snapshot_address_t * from, uint8_t * packet, uint64_t sequence )
{
    snapshot_assert( client );
    snapshot_assert( packet );

    uint8_t packet_type = ( (uint8_t*) packet ) [0];

    switch ( packet_type )
    {
        case SNAPSHOT_CONNECTION_DENIED_PACKET:
        {
            if ( ( client->state == SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST || 
                   client->state == SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_RESPONSE ) 
                                                && 
                      snapshot_address_equal( from, &client->server_address ) )
            {
                client->should_disconnect = 1;
                client->should_disconnect_state = SNAPSHOT_CLIENT_STATE_CONNECTION_DENIED;
                client->last_packet_receive_time = client->time;
            }
        }
        break;

        case SNAPSHOT_CONNECTION_CHALLENGE_PACKET:
        {
            if ( client->state == SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST && snapshot_address_equal( from, &client->server_address ) )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client received connection challenge packet from server\n" );

                struct snapshot_connection_challenge_packet_t * p = (struct snapshot_connection_challenge_packet_t*) packet;
                client->challenge_token_sequence = p->challenge_token_sequence;
                memcpy( client->challenge_token_data, p->challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES );
                client->last_packet_receive_time = client->time;

                snapshot_client_set_state( client, SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_RESPONSE );
            }
        }
        break;

        case SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET:
        {
            if ( snapshot_address_equal( from, &client->server_address ) )
            {
                struct snapshot_connection_keep_alive_packet_t * p = (struct snapshot_connection_keep_alive_packet_t*) packet;

                if ( client->state == SNAPSHOT_CLIENT_STATE_CONNECTED )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client received connection keep alive packet from server\n" );

                    client->last_packet_receive_time = client->time;
                }
                else if ( client->state == SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_RESPONSE )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client received connection keep alive packet from server\n" );

                    client->last_packet_receive_time = client->time;
                    client->client_index = p->client_index;
                    client->max_clients = p->max_clients;

                    snapshot_client_set_state( client, SNAPSHOT_CLIENT_STATE_CONNECTED );

                    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connected to server\n" );
                }
            }
        }
        break;

        case SNAPSHOT_CONNECTION_PAYLOAD_PACKET:
        {
            if ( client->state == SNAPSHOT_CLIENT_STATE_CONNECTED && snapshot_address_equal( from, &client->server_address ) )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client received connection payload packet from server\n" );

                snapshot_packet_queue_push( &client->packet_receive_queue, packet, sequence );

                client->last_packet_receive_time = client->time;

                return;
            }
        }
        break;

        case SNAPSHOT_CONNECTION_DISCONNECT_PACKET:
        {
            if ( client->state == SNAPSHOT_CLIENT_STATE_CONNECTED && snapshot_address_equal( from, &client->server_address ) )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client received disconnect packet from server\n" );

                client->should_disconnect = 1;
                client->should_disconnect_state = SNAPSHOT_CLIENT_STATE_DISCONNECTED;
                client->last_packet_receive_time = client->time;
            }
        }
        break;

        default:
            break;
    }

    client->config.free_function( client->config.allocator_context, packet );    
}

void snapshot_client_process_packet( struct snapshot_client_t * client, struct snapshot_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    (void) client;
    (void) from;
    (void) packet_data;
    (void) packet_bytes;

    uint8_t allowed_packets[SNAPSHOT_CONNECTION_NUM_PACKETS];
    memset( allowed_packets, 0, sizeof( allowed_packets ) );
    allowed_packets[SNAPSHOT_CONNECTION_DENIED_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_CHALLENGE_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_PAYLOAD_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_DISCONNECT_PACKET] = 1;

    uint64_t current_timestamp = (uint64_t) time( NULL );

    uint64_t sequence;

    void * packet = snapshot_read_packet( packet_data, 
                                          packet_bytes, 
                                          &sequence, 
                                          client->context.read_packet_key, 
                                          client->connect_token.protocol_id, 
                                          current_timestamp, 
                                          NULL, 
                                          allowed_packets, 
                                          &client->replay_protection, 
                                          client->config.allocator_context, 
                                          client->config.allocate_function );

    if ( !packet )
        return;
    
    snapshot_client_process_packet_internal( client, from, (uint8_t*)packet, sequence );
}

void snapshot_client_receive_packets( struct snapshot_client_t * client )
{
    snapshot_assert( client );
    snapshot_assert( !client->loopback );

    uint8_t allowed_packets[SNAPSHOT_CONNECTION_NUM_PACKETS];
    memset( allowed_packets, 0, sizeof( allowed_packets ) );
    allowed_packets[SNAPSHOT_CONNECTION_DENIED_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_CHALLENGE_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_PAYLOAD_PACKET] = 1;
    allowed_packets[SNAPSHOT_CONNECTION_DISCONNECT_PACKET] = 1;

    uint64_t current_timestamp = (uint64_t) time( NULL );

    if ( !client->config.network_simulator )
    {
        // process packets received from socket

        while ( 1 )
        {
            struct snapshot_address_t from;
            uint8_t packet_data[SNAPSHOT_MAX_PACKET_BYTES];
            int packet_bytes = 0;

            if ( client->config.override_send_and_receive )
            {
                packet_bytes = client->config.receive_packet_override( client->config.callback_context, &from, packet_data, SNAPSHOT_MAX_PACKET_BYTES );
            }
            else if ( client->server_address.type == SNAPSHOT_ADDRESS_IPV4 )
            {
                packet_bytes = snapshot_socket_receive_packet( &client->socket_holder.ipv4, &from, packet_data, SNAPSHOT_MAX_PACKET_BYTES );
            }
            else if ( client->server_address.type == SNAPSHOT_ADDRESS_IPV6 )
            {
                packet_bytes = snapshot_socket_receive_packet( &client->socket_holder.ipv6, &from, packet_data, SNAPSHOT_MAX_PACKET_BYTES );
            }

            if ( packet_bytes == 0 )
                break;

            uint64_t sequence;
            void * packet = snapshot_read_packet( packet_data, 
                                                  packet_bytes, 
                                                  &sequence, 
                                                  client->context.read_packet_key, 
                                                  client->connect_token.protocol_id, 
                                                  current_timestamp, 
                                                  NULL, 
                                                  allowed_packets, 
                                                  &client->replay_protection, 
                                                  client->config.allocator_context, 
                                                  client->config.allocate_function );

            if ( !packet )
                continue;

            snapshot_client_process_packet_internal( client, &from, (uint8_t*)packet, sequence );
        }
    }
    else
    {
        // process packets received from network simulator

        int num_packets_received = snapshot_network_simulator_receive_packets( client->config.network_simulator, 
                                                                               &client->address, 
                                                                               SNAPSHOT_CLIENT_MAX_RECEIVE_PACKETS, 
                                                                               client->receive_packet_data, 
                                                                               client->receive_packet_bytes, 
                                                                               client->receive_from );

        int i;
        for ( i = 0; i < num_packets_received; ++i )
        {
            uint64_t sequence;

            void * packet = snapshot_read_packet( client->receive_packet_data[i], 
                                                  client->receive_packet_bytes[i], 
                                                  &sequence, 
                                                  client->context.read_packet_key, 
                                                  client->connect_token.protocol_id, 
                                                  current_timestamp, 
                                                  NULL, 
                                                  allowed_packets, 
                                                  &client->replay_protection, 
                                                  client->config.allocator_context, 
                                                  client->config.allocate_function );

            client->config.free_function( client->config.allocator_context, client->receive_packet_data[i] );

            if ( !packet )
                continue;

            snapshot_client_process_packet_internal( client, &client->receive_from[i], (uint8_t*)packet, sequence );
        }
    }
}

void snapshot_client_send_packet_to_server_internal( struct snapshot_client_t * client, void * packet )
{
    snapshot_assert( client );
    snapshot_assert( !client->loopback );
    
    uint8_t packet_data[SNAPSHOT_MAX_PACKET_BYTES];

    int packet_bytes = snapshot_write_packet( packet, 
                                              packet_data, 
                                              SNAPSHOT_MAX_PACKET_BYTES, 
                                              client->sequence++, 
                                              client->context.write_packet_key, 
                                              client->connect_token.protocol_id );

    snapshot_assert( packet_bytes <= SNAPSHOT_MAX_PACKET_BYTES );

    if ( client->config.network_simulator )
    {
        snapshot_network_simulator_send_packet( client->config.network_simulator, &client->address, &client->server_address, packet_data, packet_bytes );
    }
    else
    {
        if ( client->config.override_send_and_receive )
        {
            client->config.send_packet_override( client->config.callback_context, &client->server_address, packet_data, packet_bytes );
        }
        else if ( client->server_address.type == SNAPSHOT_ADDRESS_IPV4 )
        {
            snapshot_socket_send_packet( &client->socket_holder.ipv4, &client->server_address, packet_data, packet_bytes );
        }
        else if ( client->server_address.type == SNAPSHOT_ADDRESS_IPV6 )
        {
            snapshot_socket_send_packet( &client->socket_holder.ipv6, &client->server_address, packet_data, packet_bytes );
        }
    }

    client->last_packet_send_time = client->time;
}

void snapshot_client_send_packets( struct snapshot_client_t * client )
{
    snapshot_assert( client );
    snapshot_assert( !client->loopback );

    switch ( client->state )
    {
        case SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST:
        {
            if ( client->last_packet_send_time + ( 1.0 / SNAPSHOT_PACKET_SEND_RATE ) >= client->time )
                return;

            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client sent connection request packet to server\n" );

            struct snapshot_connection_request_packet_t packet;
            packet.packet_type = SNAPSHOT_CONNECTION_REQUEST_PACKET;
            memcpy( packet.version_info, SNAPSHOT_VERSION_INFO, SNAPSHOT_VERSION_INFO_BYTES );
            packet.protocol_id = client->connect_token.protocol_id;
            packet.connect_token_expire_timestamp = client->connect_token.expire_timestamp;
            memcpy( packet.connect_token_nonce, client->connect_token.nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );
            memcpy( packet.connect_token_data, client->connect_token.private_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

            snapshot_client_send_packet_to_server_internal( client, &packet );
        }
        break;

        case SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:
        {
            if ( client->last_packet_send_time + ( 1.0 / SNAPSHOT_PACKET_SEND_RATE ) >= client->time )
                return;

            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client sent connection response packet to server\n" );

            struct snapshot_connection_response_packet_t packet;
            packet.packet_type = SNAPSHOT_CONNECTION_RESPONSE_PACKET;
            packet.challenge_token_sequence = client->challenge_token_sequence;
            memcpy( packet.challenge_token_data, client->challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES );

            snapshot_client_send_packet_to_server_internal( client, &packet );
        }
        break;

        case SNAPSHOT_CLIENT_STATE_CONNECTED:
        {
            if ( client->last_packet_send_time + ( 1.0 / SNAPSHOT_PACKET_SEND_RATE ) >= client->time )
                return;

            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client sent connection keep-alive packet to server\n" );

            struct snapshot_connection_keep_alive_packet_t packet;
            packet.packet_type = SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET;
            packet.client_index = 0;
            packet.max_clients = 0;

            snapshot_client_send_packet_to_server_internal( client, &packet );
        }
        break;
        
        default:
            break;
    }
}

int snapshot_client_connect_to_next_server( struct snapshot_client_t * client )
{
    snapshot_assert( client );

    if ( client->server_address_index + 1 >= client->connect_token.num_server_addresses )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client has no more servers to connect to\n" );
        return 0;
    }

    client->server_address_index++;
    client->server_address = client->connect_token.server_addresses[client->server_address_index];

    snapshot_client_reset_before_next_connect( client );

    char server_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connecting to next server %s [%d/%d]\n", 
        snapshot_address_to_string( &client->server_address, server_address_string ), 
        client->server_address_index + 1, 
        client->connect_token.num_server_addresses );

    snapshot_client_set_state( client, SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST );

    return 1;
}

void snapshot_client_update( struct snapshot_client_t * client, double time )
{
    snapshot_assert( client );

    client->time = time;

    if ( client->loopback )
        return;

    snapshot_client_receive_packets( client );

    snapshot_client_send_packets( client );

    if ( client->state > SNAPSHOT_CLIENT_STATE_DISCONNECTED && client->state < SNAPSHOT_CLIENT_STATE_CONNECTED )
    {
        uint64_t connect_token_expire_seconds = ( client->connect_token.expire_timestamp - client->connect_token.create_timestamp );            
        if ( client->time - client->connect_start_time >= connect_token_expire_seconds )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connect failed. connect token expired\n" );
            snapshot_client_disconnect_internal( client, SNAPSHOT_CLIENT_STATE_CONNECT_TOKEN_EXPIRED, 0 );
            return;
        }
    }

    if ( client->should_disconnect )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client should disconnect -> %s\n", snapshot_client_state_name( client->should_disconnect_state ) );
        if ( snapshot_client_connect_to_next_server( client ) )
            return;
        snapshot_client_disconnect_internal( client, client->should_disconnect_state, 0 );
        return;
    }

    switch ( client->state )
    {
        case SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST:
        {
            if ( client->connect_token.timeout_seconds > 0 && client->last_packet_receive_time + client->connect_token.timeout_seconds < time )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connect failed. connection request timed out\n" );
                if ( snapshot_client_connect_to_next_server( client ) )
                    return;
                snapshot_client_disconnect_internal( client, SNAPSHOT_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT, 0 );
                return;
            }
        }
        break;

        case SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:
        {
            if ( client->connect_token.timeout_seconds > 0 && client->last_packet_receive_time + client->connect_token.timeout_seconds < time )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connect failed. connection response timed out\n" );
                if ( snapshot_client_connect_to_next_server( client ) )
                    return;
                snapshot_client_disconnect_internal( client, SNAPSHOT_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT, 0 );
                return;
            }
        }
        break;

        case SNAPSHOT_CLIENT_STATE_CONNECTED:
        {
            if ( client->connect_token.timeout_seconds > 0 && client->last_packet_receive_time + client->connect_token.timeout_seconds < time )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connection timed out\n" );
                snapshot_client_disconnect_internal( client, SNAPSHOT_CLIENT_STATE_CONNECTION_TIMED_OUT, 0 );
                return;
            }
        }
        break;

        default:
            break;
    }
}

#endif // todo
