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
#include "snapshot_packets.h"
#include "snapshot_network_simulator.h"
#include "snapshot_endpoint.h"
#include <time.h>

#define SNAPSHOT_CLIENT_MAX_SIM_RECEIVE_PACKETS 256

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
    config->state_change_callback = NULL;
    config->send_loopback_packet_callback = NULL;
    config->process_passthrough_callback = NULL;
#if SNAPSHOT_DEVELOPMENT
    config->network_simulator = NULL;
#endif // #if SNAPSHOT_DEVELOPMENT
};

struct snapshot_client_t
{
    struct snapshot_client_config_t config;
    int state;
    double time;
    double connect_start_time;
    double last_internal_packet_send_time;
    double last_packet_receive_time;
    int should_disconnect;
    int should_disconnect_state;
    uint64_t sequence;
    int client_index;
    int max_clients;
    int connect_server_index;
    struct snapshot_address_t bind_address;
    struct snapshot_address_t server_address;
    struct snapshot_connect_token_t connect_token;
    struct snapshot_platform_socket_t * socket;
    struct snapshot_endpoint_t * endpoint;
    struct snapshot_replay_protection_t replay_protection;
    uint64_t challenge_token_sequence;
    uint8_t challenge_token_data[SNAPSHOT_CHALLENGE_TOKEN_BYTES];
    uint8_t read_packet_key[SNAPSHOT_KEY_BYTES];
    uint8_t write_packet_key[SNAPSHOT_KEY_BYTES];
    uint8_t allowed_packets[SNAPSHOT_NUM_PACKETS];
    int loopback;
#if SNAPSHOT_DEVELOPMENT
    uint64_t development_flags;
    uint8_t * sim_receive_packet_data[SNAPSHOT_CLIENT_MAX_SIM_RECEIVE_PACKETS];
    int sim_receive_packet_bytes[SNAPSHOT_CLIENT_MAX_SIM_RECEIVE_PACKETS];
    struct snapshot_address_t sim_receive_from[SNAPSHOT_CLIENT_MAX_SIM_RECEIVE_PACKETS];
#endif // #if SNAPSHOT_DEVELOPMENT
    uint64_t counters[SNAPSHOT_CLIENT_NUM_COUNTERS];
};

struct snapshot_client_t * snapshot_client_create( const char * bind_address_string,
                                                   const struct snapshot_client_config_t * config,
                                                   double time )
{
    snapshot_assert( config );

    struct snapshot_address_t bind_address;
    memset( &bind_address, 0, sizeof( bind_address ) );
    if ( snapshot_address_parse( &bind_address, bind_address_string ) != SNAPSHOT_OK || bind_address.type == SNAPSHOT_ADDRESS_NONE )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to parse client bind address: '%s'", bind_address_string );
        return NULL;
    }

    struct snapshot_platform_socket_t * socket = NULL;

#if SNAPSHOT_DEVELOPMENT
    if ( config->network_simulator )
    {
        if ( bind_address.port == 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "must bind to a specific port when using network simulator" );
            return NULL;
        }
    }
    else
#endif // #if SNAPSHOT_DEVELOPMENT
    {
        socket = snapshot_platform_socket_create( config->context, &bind_address, SNAPSHOT_PLATFORM_SOCKET_NON_BLOCKING, 0.0f, SNAPSHOT_CLIENT_SOCKET_SNDBUF_SIZE, SNAPSHOT_CLIENT_SOCKET_RCVBUF_SIZE );

        if ( socket == NULL )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create client socket" );
            return NULL;
        }
    }

    struct snapshot_client_t * client = (struct snapshot_client_t*) snapshot_malloc( config->context, sizeof( struct snapshot_client_t ) );

    memset( client, 0, sizeof(snapshot_client_t) );

    if ( !client )
    {
        if ( socket )
        {
            snapshot_platform_socket_destroy( socket );
        }
        return NULL;
    }

#if SNAPSHOT_DEVELOPMENT
    if ( config->network_simulator )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client started on port %d (network simulator)", bind_address.port );
    }
    else
#endif // #if SNAPSHOT_DEVELOPMENT
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client started on port %d", bind_address.port );
    }

    client->config = *config;
    client->socket = socket;
    client->bind_address = bind_address;
    client->state = SNAPSHOT_CLIENT_STATE_DISCONNECTED;
    client->time = time;
    client->connect_start_time = 0.0;
    client->last_internal_packet_send_time = -1000.0;
    client->last_packet_receive_time = -1000.0;
    client->should_disconnect = 0;
    client->should_disconnect_state = SNAPSHOT_CLIENT_STATE_DISCONNECTED;
    client->sequence = 0;
    client->client_index = 0;
    client->max_clients = 0;
    client->connect_server_index = 0;
    client->challenge_token_sequence = 0;
    client->loopback = 0;
    memset( &client->server_address, 0, sizeof( struct snapshot_address_t ) );
    memset( &client->connect_token, 0, sizeof( struct snapshot_connect_token_t ) );
    memset( client->challenge_token_data, 0, SNAPSHOT_CHALLENGE_TOKEN_BYTES );

    snapshot_replay_protection_reset( &client->replay_protection );

    client->allowed_packets[SNAPSHOT_CONNECTION_DENIED_PACKET] = 1;
    client->allowed_packets[SNAPSHOT_CONNECTION_CHALLENGE_PACKET] = 1;
    client->allowed_packets[SNAPSHOT_KEEP_ALIVE_PACKET] = 1;
    client->allowed_packets[SNAPSHOT_PAYLOAD_PACKET] = 1;
    client->allowed_packets[SNAPSHOT_PASSTHROUGH_PACKET] = 1;
    client->allowed_packets[SNAPSHOT_DISCONNECT_PACKET] = 1;

    snapshot_endpoint_config_t endpoint_config;
    snapshot_endpoint_default_config( &endpoint_config );
    snapshot_copy_string( endpoint_config.name, "client", sizeof(endpoint_config.name) );
    endpoint_config.context = config->context;
    
    client->endpoint = snapshot_endpoint_create( &endpoint_config, time );

    if ( !client->endpoint )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create client endpoint" );
        snapshot_client_destroy( client );
        return NULL;
    }

    return client;
}

void snapshot_client_destroy( struct snapshot_client_t * client )
{
    snapshot_assert( client );

    if ( !client->loopback )
    {
        snapshot_client_disconnect( client );
    }
    else
    {
        snapshot_client_disconnect_loopback( client );
    }
    
    if ( client->endpoint )
    {
        snapshot_endpoint_destroy( client->endpoint );
    }
    
    if ( client->socket )
    {
        snapshot_platform_socket_destroy( client->socket );
    }

    snapshot_free( client->config.context, client );
}

void snapshot_client_set_state( struct snapshot_client_t * client, int client_state )
{
    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client changed state from '%s' to '%s'", snapshot_client_state_name( client->state ), snapshot_client_state_name( client_state ) );

    if ( client->config.state_change_callback )
    {
        client->config.state_change_callback( client->config.context, client->state, client_state );
    }

    client->state = client_state;
}

void snapshot_client_reset_before_next_connect( struct snapshot_client_t * client )
{
    client->connect_start_time = client->time;
    client->last_internal_packet_send_time = client->time - 1.0f;
    client->last_packet_receive_time = client->time;
    client->should_disconnect = 0;
    client->should_disconnect_state = SNAPSHOT_CLIENT_STATE_DISCONNECTED;
    client->challenge_token_sequence = 0;

    memset( client->challenge_token_data, 0, SNAPSHOT_CHALLENGE_TOKEN_BYTES );

    snapshot_replay_protection_reset( &client->replay_protection );

    snapshot_endpoint_reset( client->endpoint );
}

void snapshot_client_reset_connection_data( struct snapshot_client_t * client, int client_state )
{
    snapshot_assert( client );

    client->sequence = 0;
    client->loopback = 0;
    client->client_index = 0;
    client->max_clients = 0;
    client->connect_start_time = 0.0;
    client->connect_server_index = 0;
    memset( &client->server_address, 0, sizeof( struct snapshot_address_t ) );
    memset( &client->connect_token, 0, sizeof( struct snapshot_connect_token_t ) );

    snapshot_client_set_state( client, client_state );

    snapshot_client_reset_before_next_connect( client );
}

void snapshot_client_disconnect_internal( struct snapshot_client_t * client, int destination_state, int send_disconnect_packets );

void snapshot_client_connect( struct snapshot_client_t * client, uint8_t * connect_token )
{
    snapshot_assert( client );
    snapshot_assert( connect_token );

    snapshot_client_disconnect( client );

    client->counters[SNAPSHOT_CLIENT_COUNTER_CONNECT_CALLS]++;

    if ( snapshot_read_connect_token( connect_token, SNAPSHOT_CONNECT_TOKEN_BYTES, &client->connect_token ) != SNAPSHOT_OK )
    {
        snapshot_client_set_state( client, SNAPSHOT_CLIENT_STATE_INVALID_CONNECT_TOKEN );
        return;
    }

    client->connect_server_index = 0;
    client->server_address = client->connect_token.server_addresses[0];

    char server_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];

    if ( client->connect_token.num_server_addresses > 1 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connecting to server %s [%d/%d]", snapshot_address_to_string( &client->server_address, server_address_string ), client->connect_server_index + 1, client->connect_token.num_server_addresses );
    }
    else
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connecting to server %s", snapshot_address_to_string( &client->server_address, server_address_string ) );
    }

    memcpy( client->read_packet_key, client->connect_token.server_to_client_key, SNAPSHOT_KEY_BYTES );
    memcpy( client->write_packet_key, client->connect_token.client_to_server_key, SNAPSHOT_KEY_BYTES );

    snapshot_client_reset_before_next_connect( client );

    snapshot_client_set_state( client, SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST );
}

int snapshot_client_process_payload( struct snapshot_client_t * client, uint8_t * payload_data, int payload_bytes )
{
    snapshot_assert( client );
    snapshot_assert( payload_data );
    snapshot_assert( payload_bytes > 0 );
    snapshot_assert( payload_bytes <= SNAPSHOT_MAX_PAYLOAD_BYTES );

#if SNAPSHOT_DEVELOPMENT

    if ( client->development_flags & SNAPSHOT_DEVELOPMENT_FLAG_VALIDATE_PAYLOAD )
    {    
        snapshot_verify_packet_data( payload_data, payload_bytes );

        client->counters[SNAPSHOT_CLIENT_COUNTER_PAYLOADS_RECEIVED]++;

        return SNAPSHOT_OK;
    }

#endif // #if SNAPSHOT_DEVELOPME SNAPSHOT_OKNT

    (void) client;

    // todo: process real payload

    return SNAPSHOT_OK;
}

void snapshot_client_process_passthrough( struct snapshot_client_t * client, uint8_t * data, int bytes )
{
    snapshot_assert( client );
    snapshot_assert( data );
    snapshot_assert( bytes > 0 );
    snapshot_assert( bytes <= SNAPSHOT_MAX_PASSTHROUGH_BYTES );

    if ( client->config.process_passthrough_callback != NULL )
    {
        client->config.process_passthrough_callback( client->config.context, data, bytes );
    }
}

bool snapshot_client_process_packet( struct snapshot_client_t * client, const struct snapshot_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    snapshot_assert( client );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes > 0 );

    client->counters[SNAPSHOT_CLIENT_COUNTER_PACKETS_PROCESSED]++;

    uint64_t current_timestamp = (uint64_t) time( NULL );

    uint8_t out_packet_buffer[1024];

    uint64_t sequence;

    void * packet = snapshot_read_packet( packet_data, 
                                          packet_bytes, 
                                          &sequence, 
                                          client->read_packet_key, 
                                          client->connect_token.protocol_id, 
                                          current_timestamp, 
                                          NULL, 
                                          client->allowed_packets, 
                                          out_packet_buffer,
                                          &client->replay_protection );

    if ( !packet )
    {
        client->counters[SNAPSHOT_CLIENT_COUNTER_READ_PACKET_FAILURES]++;
        return false;
    }

    uint8_t packet_type = ( (uint8_t*) packet ) [0];

    switch ( packet_type )
    {
        case SNAPSHOT_CONNECTION_DENIED_PACKET:
        {
            client->counters[SNAPSHOT_CLIENT_COUNTER_CONNECTION_DENIED_PACKETS_RECEIVED]++;

            if ( ( client->state == SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST || 
                   client->state == SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_RESPONSE ) 
                                                && 
                      snapshot_address_equal( from, &client->server_address ) )
            {
                client->should_disconnect = 1;
                client->should_disconnect_state = SNAPSHOT_CLIENT_STATE_CONNECTION_DENIED;
                client->last_packet_receive_time = client->time;
                return true;
            }
        }
        break;

        case SNAPSHOT_CONNECTION_CHALLENGE_PACKET:
        {
            client->counters[SNAPSHOT_CLIENT_COUNTER_CONNECTION_CHALLENGE_PACKETS_RECEIVED]++;

            if ( client->state == SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST && snapshot_address_equal( from, &client->server_address ) )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client received connection challenge packet from server" );

                struct snapshot_connection_challenge_packet_t * p = (struct snapshot_connection_challenge_packet_t*) packet;
                client->challenge_token_sequence = p->challenge_token_sequence;
                memcpy( client->challenge_token_data, p->challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES );
                client->last_packet_receive_time = client->time;

                snapshot_client_set_state( client, SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_RESPONSE );

                return true;
            }
        }
        break;

        case SNAPSHOT_KEEP_ALIVE_PACKET:
        {
            client->counters[SNAPSHOT_CLIENT_COUNTER_KEEP_ALIVE_PACKETS_RECEIVED]++;

            if ( snapshot_address_equal( from, &client->server_address ) )
            {
                struct snapshot_keep_alive_packet_t * p = (struct snapshot_keep_alive_packet_t*) packet;

                if ( client->state == SNAPSHOT_CLIENT_STATE_CONNECTED )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client received keep alive packet from server" );

                    client->last_packet_receive_time = client->time;

                    return true;
                }
                else if ( client->state == SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_RESPONSE )
                {
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client received keep alive packet from server" );

                    client->last_packet_receive_time = client->time;
                    client->client_index = p->client_index;
                    client->max_clients = p->max_clients;

                    snapshot_client_set_state( client, SNAPSHOT_CLIENT_STATE_CONNECTED );

                    char server_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
                    snapshot_address_to_string( &client->server_address, server_address_string );
                    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connected to server %s slot %d", server_address_string, p->client_index );
    
                    return true;
                }
            }
        }
        break;

        case SNAPSHOT_PAYLOAD_PACKET:
        {
            client->counters[SNAPSHOT_CLIENT_COUNTER_PAYLOAD_PACKETS_RECEIVED]++;

            if ( client->state == SNAPSHOT_CLIENT_STATE_CONNECTED && snapshot_address_equal( from, &client->server_address ) )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client received payload packet from server" );

                struct snapshot_payload_packet_t * payload_packet = (snapshot_payload_packet_t*) packet;

                uint8_t * payload_packet_data = payload_packet->payload_data;
                int payload_packet_bytes = payload_packet->payload_bytes;

                uint8_t buffer[SNAPSHOT_PACKET_PREFIX_BYTES + SNAPSHOT_MAX_PACKET_BYTES + SNAPSHOT_PACKET_POSTFIX_BYTES];

                uint8_t * payload_data = NULL;
                int payload_bytes = 0;

                uint16_t payload_sequence = 0;
                uint16_t payload_ack = 0;
                uint32_t payload_ack_bits = 0;

                snapshot_endpoint_process_packet( client->endpoint, payload_packet_data, payload_packet_bytes, buffer, &payload_data, &payload_bytes, &payload_sequence, &payload_ack, &payload_ack_bits );

                if ( payload_data )
                {
                    if ( snapshot_client_process_payload( client, payload_data, payload_bytes ) == SNAPSHOT_OK )
                    {
                        snapshot_endpoint_mark_payload_processed( client->endpoint, payload_sequence, payload_ack, payload_ack_bits, payload_bytes );
                    }
                }

                client->last_packet_receive_time = client->time;

                return true;
            }
        }
        break;

        case SNAPSHOT_PASSTHROUGH_PACKET:
        {
            client->counters[SNAPSHOT_CLIENT_COUNTER_PASSTHROUGH_PACKETS_RECEIVED]++;

            if ( client->state == SNAPSHOT_CLIENT_STATE_CONNECTED && snapshot_address_equal( from, &client->server_address ) )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client received passthrough packet from server" );

                struct snapshot_passthrough_packet_t * p = (struct snapshot_passthrough_packet_t*) packet;

                snapshot_client_process_passthrough( client, p->passthrough_data, p->passthrough_bytes );

                client->last_packet_receive_time = client->time;

                return true;
            }
        }
        break;

        case SNAPSHOT_DISCONNECT_PACKET:
        {
            client->counters[SNAPSHOT_CLIENT_COUNTER_DISCONNECT_PACKETS_RECEIVED]++;

            if ( client->state == SNAPSHOT_CLIENT_STATE_CONNECTED && snapshot_address_equal( from, &client->server_address ) )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client received disconnect packet from server" );

                client->should_disconnect = 1;
                client->should_disconnect_state = SNAPSHOT_CLIENT_STATE_DISCONNECTED;
                client->last_packet_receive_time = client->time;

                return true;
            }
        }
        break;

        default:
            break;
    }

    return false;
}

void snapshot_client_receive_packets( struct snapshot_client_t * client )
{
    snapshot_assert( client );

    if ( client->loopback )
        return;

    snapshot_assert( !client->loopback );

#if SNAPSHOT_DEVELOPMENT
    if ( client->config.network_simulator )
    {
        // process packets received from network simulator

        int num_packets_received = snapshot_network_simulator_receive_packets( client->config.network_simulator, 
                                                                               &client->bind_address, 
                                                                               SNAPSHOT_CLIENT_MAX_SIM_RECEIVE_PACKETS, 
                                                                               client->sim_receive_packet_data, 
                                                                               client->sim_receive_packet_bytes, 
                                                                               client->sim_receive_from );

        for ( int i = 0; i < num_packets_received; ++i )
        {
            snapshot_client_process_packet( client, &client->sim_receive_from[i], client->sim_receive_packet_data[i], client->sim_receive_packet_bytes[i] );
            snapshot_destroy_packet( client->config.context, client->sim_receive_packet_data[i] );
            client->sim_receive_packet_data[i] = NULL;
            client->counters[SNAPSHOT_CLIENT_COUNTER_PACKETS_RECEIVED_SIMULATOR]++;
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
            uint8_t * packet_data = buffer + SNAPSHOT_PACKET_PREFIX_BYTES;
            int packet_bytes = snapshot_platform_socket_receive_packet( client->socket, &from, packet_data, SNAPSHOT_MAX_PACKET_BYTES );
            if ( packet_bytes == 0 )
                break;

            client->counters[SNAPSHOT_CLIENT_COUNTER_PACKETS_RECEIVED]++;

            snapshot_client_process_packet( client, &from, packet_data, packet_bytes );
        }
    }
}

void snapshot_client_send_packet_to_server( struct snapshot_client_t * client, void * packet )
{
    snapshot_assert( client );

    uint8_t buffer[SNAPSHOT_MAX_PACKET_BYTES];

    int packet_bytes = 0;

    uint8_t * packet_data = snapshot_write_packet( packet, 
                                                   buffer, 
                                                   SNAPSHOT_MAX_PACKET_BYTES, 
                                                   client->sequence++, 
                                                   !client->loopback ? client->write_packet_key : NULL,
                                                   client->connect_token.protocol_id,
                                                   &packet_bytes );

    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes <= SNAPSHOT_MAX_PACKET_BYTES );

    if ( !client->loopback )
    {
#if SNAPSHOT_DEVELOPMENT
        if ( client->config.network_simulator )
        {
            snapshot_network_simulator_send_packet( client->config.network_simulator, &client->bind_address, &client->server_address, packet_data, packet_bytes );
            client->counters[SNAPSHOT_CLIENT_COUNTER_PACKETS_SENT_SIMULATOR]++;
        }
        else
#endif // #if SNAPSHOT_DEVELOPMENT
        {
            snapshot_platform_socket_send_packet( client->socket, &client->server_address, packet_data, packet_bytes );
            client->counters[SNAPSHOT_CLIENT_COUNTER_PACKETS_SENT]++;
        }
    }
    else
    {
        client->config.send_loopback_packet_callback( client->config.context, &client->bind_address, packet_data, packet_bytes );
        client->counters[SNAPSHOT_CLIENT_COUNTER_PACKETS_SENT_LOOPBACK]++;
    }
}

void snapshot_client_send_internal_packets( struct snapshot_client_t * client )
{
    snapshot_assert( client );

    if ( client->loopback )
        return;

    snapshot_assert( !client->loopback );

    switch ( client->state )
    {
        case SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST:
        {
            if ( client->last_internal_packet_send_time + 0.1 >= client->time )
                return;

            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client sent connection request packet to server" );

            struct snapshot_connection_request_packet_t packet;
            packet.packet_type = SNAPSHOT_CONNECTION_REQUEST_PACKET;
            memcpy( packet.version_info, SNAPSHOT_VERSION_INFO, SNAPSHOT_VERSION_INFO_BYTES );
            packet.protocol_id = client->connect_token.protocol_id;
            packet.connect_token_expire_timestamp = client->connect_token.expire_timestamp;
            memcpy( packet.connect_token_nonce, client->connect_token.nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );
            memcpy( packet.connect_token_data, client->connect_token.private_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

            snapshot_client_send_packet_to_server( client, &packet );

            client->counters[SNAPSHOT_CLIENT_COUNTER_CONNECTION_REQUEST_PACKETS_SENT]++;

            client->last_internal_packet_send_time = client->time;
        }
        break;

        case SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:
        {
            if ( client->last_internal_packet_send_time + 0.1 >= client->time )
                return;

            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client sent connection response packet to server" );

            struct snapshot_connection_response_packet_t packet;
            packet.packet_type = SNAPSHOT_CONNECTION_RESPONSE_PACKET;
            packet.challenge_token_sequence = client->challenge_token_sequence;
            memcpy( packet.challenge_token_data, client->challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES );

            snapshot_client_send_packet_to_server( client, &packet );

            client->counters[SNAPSHOT_CLIENT_COUNTER_CONNECTION_RESPONSE_PACKETS_SENT]++;

            client->last_internal_packet_send_time = client->time;
        }
        break;

        case SNAPSHOT_CLIENT_STATE_CONNECTED:
        {
            if ( client->last_internal_packet_send_time + 0.1 >= client->time )
                return;

            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client sent connection keep-alive packet to server" );

            struct snapshot_keep_alive_packet_t packet;
            packet.packet_type = SNAPSHOT_KEEP_ALIVE_PACKET;
            packet.client_index = 0;
            packet.max_clients = 0;

            snapshot_client_send_packet_to_server( client, &packet );

            client->counters[SNAPSHOT_CLIENT_COUNTER_KEEP_ALIVE_PACKETS_SENT]++;

            client->last_internal_packet_send_time = client->time;
        }
        break;
        
        default:
            break;
    }
}

int snapshot_client_connect_to_next_server( struct snapshot_client_t * client )
{
    snapshot_assert( client );

    if ( client->connect_server_index + 1 >= client->connect_token.num_server_addresses )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client has no more servers to connect to" );
        return 0;
    }

    client->connect_server_index++;
    client->server_address = client->connect_token.server_addresses[client->connect_server_index];

    snapshot_client_reset_before_next_connect( client );

    char server_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];

    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connecting to next server %s [%d/%d]", 
        snapshot_address_to_string( &client->server_address, server_address_string ), 
        client->connect_server_index + 1, 
        client->connect_token.num_server_addresses );

    snapshot_client_set_state( client, SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST );

    return 1;
}

void snapshot_client_update_state_machine( struct snapshot_client_t * client )
{
    if ( client->loopback )
        return;

    if ( client->state > SNAPSHOT_CLIENT_STATE_DISCONNECTED && client->state < SNAPSHOT_CLIENT_STATE_CONNECTED )
    {
        uint64_t connect_token_expire_seconds = ( client->connect_token.expire_timestamp - client->connect_token.create_timestamp );            
        if ( client->time - client->connect_start_time >= connect_token_expire_seconds )
        {
            char server_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
            snapshot_address_to_string( &client->server_address, server_address_string );
            snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connect to %s failed. connect token expired", server_address_string );
            snapshot_client_disconnect_internal( client, SNAPSHOT_CLIENT_STATE_CONNECT_TOKEN_EXPIRED, 0 );
            return;
        }
    }

    if ( client->should_disconnect )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client should disconnect -> %s", snapshot_client_state_name( client->should_disconnect_state ) );
        if ( snapshot_client_connect_to_next_server( client ) )
            return;
        snapshot_client_disconnect_internal( client, client->should_disconnect_state, 0 );
        return;
    }

    switch ( client->state )
    {
        case SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_REQUEST:
        {
            if ( client->connect_token.timeout_seconds > 0 && client->last_packet_receive_time + client->connect_token.timeout_seconds < client->time )
            {
                char server_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
                snapshot_address_to_string( &client->server_address, server_address_string );
                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connect to %s failed. connection request timed out", server_address_string );
                if ( snapshot_client_connect_to_next_server( client ) )
                    return;
                snapshot_client_disconnect_internal( client, SNAPSHOT_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT, 0 );
                return;
            }
        }
        break;

        case SNAPSHOT_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:
        {
            if ( client->connect_token.timeout_seconds > 0 && client->last_packet_receive_time + client->connect_token.timeout_seconds < client->time )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connect failed. connection response timed out" );
                if ( snapshot_client_connect_to_next_server( client ) )
                    return;
                snapshot_client_disconnect_internal( client, SNAPSHOT_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT, 0 );
                return;
            }
        }
        break;

        case SNAPSHOT_CLIENT_STATE_CONNECTED:
        {
            if ( client->connect_token.timeout_seconds > 0 && client->last_packet_receive_time + client->connect_token.timeout_seconds < client->time )
            {
                char server_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
                snapshot_address_to_string( &client->server_address, server_address_string );
                snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connection to %s timed out", server_address_string );
                snapshot_client_disconnect_internal( client, SNAPSHOT_CLIENT_STATE_CONNECTION_TIMED_OUT, 0 );
                return;
            }
        }
        break;

        default:
            break;
    }
}

void snapshot_client_send_payload( struct snapshot_client_t * client )
{
    snapshot_assert( client );

    if ( client->state != SNAPSHOT_CLIENT_STATE_CONNECTED )
        return;

#if SNAPSHOT_DEVELOPMENT

    // test payload for validation

    if ( client->development_flags & SNAPSHOT_DEVELOPMENT_FLAG_VALIDATE_PAYLOAD )
    {
        uint8_t * payload_data = snapshot_create_packet( client->config.context, SNAPSHOT_MAX_PAYLOAD_BYTES );

        int payload_bytes = 0;

        snapshot_generate_packet_data( payload_data, payload_bytes, SNAPSHOT_MAX_PAYLOAD_BYTES );

        int num_packets = 0;
        uint8_t * packet_data[SNAPSHOT_ENDPOINT_MAX_WRITE_PACKETS];
        int packet_bytes[SNAPSHOT_ENDPOINT_MAX_WRITE_PACKETS];

        snapshot_endpoint_write_packets( client->endpoint, payload_data, payload_bytes, &num_packets, &packet_data[0], &packet_bytes[0] );

        if ( num_packets == 1 )
        {
            // send whole packet

            snapshot_payload_packet_t * packet = snapshot_wrap_payload_packet( packet_data[0], packet_bytes[0] );

            snapshot_client_send_packet_to_server( client, packet );

            client->counters[SNAPSHOT_CLIENT_COUNTER_PAYLOAD_PACKETS_SENT]++;
        }
        else
        {
            // send fragments

            for ( int i = 0; i < num_packets; i++ )
            {
                snapshot_payload_packet_t * packet = snapshot_wrap_payload_packet( packet_data[i], packet_bytes[i] );

                snapshot_client_send_packet_to_server( client, packet );

                client->counters[SNAPSHOT_CLIENT_COUNTER_PAYLOAD_PACKETS_SENT]++;

                snapshot_destroy_packet( client->config.context, packet_data[i] );
            }
        }

        snapshot_destroy_packet( client->config.context, payload_data );

        client->counters[SNAPSHOT_CLIENT_COUNTER_PAYLOADS_SENT]++;

        return;
    }
#endif // #if SNAPSHOT_DEVELOPMENT

    // todo: generate real payload
}

void snapshot_client_update( struct snapshot_client_t * client, double time )
{
    snapshot_assert( client );

    client->time = time;

    snapshot_client_receive_packets( client );

    snapshot_client_send_payload( client );

    snapshot_client_send_internal_packets( client );

    snapshot_client_update_state_machine( client );
}

void snapshot_client_disconnect( struct snapshot_client_t * client )
{
    snapshot_assert( client );
    snapshot_assert( !client->loopback );
    snapshot_client_disconnect_internal( client, SNAPSHOT_CLIENT_STATE_DISCONNECTED, 1 );
    client->counters[SNAPSHOT_CLIENT_COUNTER_DISCONNECT_CALLS]++;
}

void snapshot_client_disconnect_internal( struct snapshot_client_t * client, int destination_state, int send_disconnect_packets )
{
    snapshot_assert( !client->loopback );
    snapshot_assert( destination_state <= SNAPSHOT_CLIENT_STATE_DISCONNECTED );

    if ( client->state <= SNAPSHOT_CLIENT_STATE_DISCONNECTED || client->state == destination_state )
        return;

    if ( client->state == SNAPSHOT_CLIENT_STATE_CONNECTED )
    {
        char server_address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
        snapshot_address_to_string( &client->server_address, server_address_string );
        snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client disconnected from server %s slot %d", server_address_string, client->client_index );
    }

    if ( !client->loopback && send_disconnect_packets && client->state > SNAPSHOT_CLIENT_STATE_DISCONNECTED )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client sent disconnect packets to server" );

        int i;
        for ( i = 0; i < SNAPSHOT_NUM_DISCONNECT_PACKETS; ++i )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "client sent disconnect packet %d", i );

            struct snapshot_disconnect_packet_t packet;
            packet.packet_type = SNAPSHOT_DISCONNECT_PACKET;

            snapshot_client_send_packet_to_server( client, &packet );

            client->counters[SNAPSHOT_CLIENT_COUNTER_DISCONNECT_PACKETS_SENT]++;

            client->last_internal_packet_send_time = client->time;
        }
    }

    snapshot_client_reset_connection_data( client, destination_state );
}

int snapshot_client_state( struct snapshot_client_t * client )
{
    snapshot_assert( client );
    return client->state;
}

int snapshot_client_index( struct snapshot_client_t * client )
{
    snapshot_assert( client );
    return client->client_index;
}

int snapshot_client_max_clients( struct snapshot_client_t * client )
{   
    snapshot_assert( client );
    return client->max_clients;
}

uint16_t snapshot_client_port( struct snapshot_client_t * client )
{
    return client->bind_address.port;
}

void snapshot_client_connect_loopback( struct snapshot_client_t * client, snapshot_address_t * server_address, int client_index, int max_clients )
{
    snapshot_assert( client );
    snapshot_assert( server_address );
    snapshot_assert( client->state <= SNAPSHOT_CLIENT_STATE_DISCONNECTED );
    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client connected to server via loopback in slot %d", client_index );
    client->state = SNAPSHOT_CLIENT_STATE_CONNECTED;
    client->server_address = *server_address;
    client->client_index = client_index;
    client->max_clients = max_clients;
    client->loopback = 1;
    client->counters[SNAPSHOT_CLIENT_COUNTER_CONNECT_LOOPBACK_CALLS]++;
}

void snapshot_client_disconnect_loopback( struct snapshot_client_t * client )
{
    snapshot_assert( client );
    snapshot_assert( client->loopback );
    snapshot_printf( SNAPSHOT_LOG_LEVEL_INFO, "client disconnected from server loopback in slot %d", client->client_index );
    snapshot_client_reset_connection_data( client, SNAPSHOT_CLIENT_STATE_DISCONNECTED );
    client->counters[SNAPSHOT_CLIENT_COUNTER_DISCONNECT_LOOPBACK_CALLS]++;
}

int snapshot_client_loopback( struct snapshot_client_t * client )
{
    snapshot_assert( client );
    return client->loopback;
}

void snapshot_client_send_passthrough_packet( struct snapshot_client_t * client, const uint8_t * passthrough_data, int passthrough_bytes )
{
    snapshot_assert( client );
    snapshot_assert( passthrough_data );
    snapshot_assert( passthrough_bytes > 0 );
    snapshot_assert( client->state == SNAPSHOT_CLIENT_STATE_CONNECTED );

    if ( client->state != SNAPSHOT_CLIENT_STATE_CONNECTED )
        return;

    uint8_t buffer[SNAPSHOT_PACKET_PREFIX_BYTES + sizeof(snapshot_passthrough_packet_t) + SNAPSHOT_MAX_PASSTHROUGH_BYTES + SNAPSHOT_PACKET_POSTFIX_BYTES];

    struct snapshot_passthrough_packet_t * packet = (snapshot_passthrough_packet_t*) ( buffer + SNAPSHOT_PACKET_PREFIX_BYTES );

    packet->packet_type = SNAPSHOT_PASSTHROUGH_PACKET;
    packet->passthrough_bytes = passthrough_bytes;
    memcpy( packet->passthrough_data, passthrough_data, passthrough_bytes );

    client->counters[SNAPSHOT_CLIENT_COUNTER_PASSTHROUGH_PACKETS_SENT]++;

    snapshot_client_send_packet_to_server( client, packet );
}

const struct snapshot_address_t * snapshot_client_server_address( struct snapshot_client_t * client )
{
    snapshot_assert( client );
    return &client->server_address;
}

#if SNAPSHOT_DEVELOPMENT

void snapshot_client_set_development_flags( struct snapshot_client_t * client, uint64_t flags )
{
    snapshot_assert( client );
    client->development_flags = flags;
}

#endif // #if SNAPSHOT_DEVELOPMENT

const uint64_t * snapshot_client_counters( struct snapshot_client_t * client )
{
    snapshot_assert( client );
    return client->counters;
}
