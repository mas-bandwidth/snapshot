/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_platform_ios.h"

#if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_IOS

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreFoundation/CoreFoundation.h>

// ---------------------------------------------------

static mach_timebase_info_data_t timebase_info;

int snapshot_platform_init()
{
    mach_timebase_info( &timebase_info );

    return SNAPSHOT_OK;
}

void snapshot_platform_term()
{
    // ...
}

const char * snapshot_platform_getenv( const char * var )
{
    return getenv( var );
}

// ---------------------------------------------------

uint16_t snapshot_platform_ntohs( uint16_t in )
{
    return (uint16_t)( ( ( in << 8 ) & 0xFF00 ) | ( ( in >> 8 ) & 0x00FF ) );
}

uint16_t snapshot_platform_htons( uint16_t in )
{
    return (uint16_t)( ( ( in << 8 ) & 0xFF00 ) | ( ( in >> 8 ) & 0x00FF ) );
}

int snapshot_platform_inet_pton4( const char * address_string, uint32_t * address_out )
{
    sockaddr_in sockaddr4;
    bool success = inet_pton( AF_INET, address_string, &sockaddr4.sin_addr ) == 1;
    *address_out = sockaddr4.sin_addr.s_addr;
    return success ? SNAPSHOT_OK : SNAPSHOT_ERROR;
}

int snapshot_platform_inet_pton6( const char * address_string, uint16_t * address_out )
{
    return inet_pton( AF_INET6, address_string, address_out ) == 1 ? SNAPSHOT_OK : SNAPSHOT_ERROR;
}

int snapshot_platform_inet_ntop6( const uint16_t * address, char * address_string, size_t address_string_size )
{
    return inet_ntop( AF_INET6, (void*)address, address_string, socklen_t( address_string_size ) ) == NULL ? SNAPSHOT_ERROR : SNAPSHOT_OK;
}

int snapshot_platform_hostname_resolve( const char * hostname, const char * port, snapshot_address_t * address )
{
    addrinfo hints;
    memset( &hints, 0, sizeof(hints) );
    addrinfo * result;
    if ( getaddrinfo( hostname, port, &hints, &result ) == 0 )
    {
        if ( result )
        {
            if ( result->ai_addr->sa_family == AF_INET6 )
            {
                sockaddr_in6 * addr_ipv6 = (sockaddr_in6 *)( result->ai_addr );
                address->type = SNAPSHOT_ADDRESS_IPV6;
                for ( int i = 0; i < 8; ++i )
                {
                    address->data.ipv6[i] = snapshot_platform_ntohs( ( (uint16_t*) &addr_ipv6->sin6_addr ) [i] );
                }
                address->port = snapshot_platform_ntohs( addr_ipv6->sin6_port );
                freeaddrinfo( result );
                return SNAPSHOT_OK;
            }
            else if ( result->ai_addr->sa_family == AF_INET )
            {
                sockaddr_in * addr_ipv4 = (sockaddr_in *)( result->ai_addr );
                address->type = SNAPSHOT_ADDRESS_IPV4;
                address->data.ipv4[0] = (uint8_t) ( ( addr_ipv4->sin_addr.s_addr & 0x000000FF ) );
                address->data.ipv4[1] = (uint8_t) ( ( addr_ipv4->sin_addr.s_addr & 0x0000FF00 ) >> 8 );
                address->data.ipv4[2] = (uint8_t) ( ( addr_ipv4->sin_addr.s_addr & 0x00FF0000 ) >> 16 );
                address->data.ipv4[3] = (uint8_t) ( ( addr_ipv4->sin_addr.s_addr & 0xFF000000 ) >> 24 );
                address->port = snapshot_platform_ntohs( addr_ipv4->sin_port );
                freeaddrinfo( result );
                return SNAPSHOT_OK;
            }
            else
            {
                snapshot_assert( 0 );
                freeaddrinfo( result );
                return SNAPSHOT_ERROR;
            }
        }
    }

    return SNAPSHOT_ERROR;
}

int snapshot_platform_id()
{
    return SNAPSHOT_PLATFORM_IOS;
}

// ---------------------------------------------------

static uint64_t time_start = 0;

double snapshot_platform_time()
{
    uint64_t current = mach_absolute_time();
    return ( (double) ( current - time_start ) ) * ( (double) timebase_info.numer ) / ( (double) timebase_info.denom ) / 1000000000.0;
}

void snapshot_platform_sleep( double time )
{
    usleep( (int) ( time * 1000000 ) );
}

// ---------------------------------------------------

void snapshot_platform_socket_destroy( snapshot_platform_socket_t * socket );

snapshot_platform_socket_t * snapshot_platform_socket_create( void * context, snapshot_address_t * address, int socket_type, float timeout_seconds, int send_buffer_size, int receive_buffer_size )
{
    snapshot_assert( address );
    snapshot_assert( address->type != SNAPSHOT_ADDRESS_NONE );

    snapshot_platform_socket_t * socket = (snapshot_platform_socket_t*) snapshot_malloc( context, sizeof( snapshot_platform_socket_t ) );

    snapshot_assert( socket );

    socket->context = context;

    // create socket

    socket->handle = ::socket( ( address->type == SNAPSHOT_ADDRESS_IPV6 ) ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP );

    if ( socket->handle < 0 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create socket" );
        snapshot_platform_socket_destroy( socket );
        return NULL;
    }

    // force IPv6 only if necessary

    if ( address->type == SNAPSHOT_ADDRESS_IPV6 )
    {
        int yes = 1;
        if ( setsockopt( socket->handle, IPPROTO_IPV6, IPV6_V6ONLY, (char*)( &yes ), sizeof( yes ) ) != 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to set socket ipv6 only" );
            snapshot_platform_socket_destroy( socket );
            return NULL;
        }
    }

    // increase socket send and receive buffer sizes

    if ( setsockopt( socket->handle, SOL_SOCKET, SO_SNDBUF, (char*)( &send_buffer_size ), sizeof( int ) ) != 0 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to set socket send buffer size" );
        return NULL;
    }

    if ( setsockopt( socket->handle, SOL_SOCKET, SO_RCVBUF, (char*)( &receive_buffer_size ), sizeof( int ) ) != 0 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to set socket receive buffer size" );
        snapshot_platform_socket_destroy( socket );
        return NULL;
    }

    // bind to port

    if ( address->type == SNAPSHOT_ADDRESS_IPV6 )
    {
        sockaddr_in6 socket_address;
        memset( &socket_address, 0, sizeof( sockaddr_in6 ) );
        socket_address.sin6_family = AF_INET6;
        for ( int i = 0; i < 8; ++i )
        {
            ( (uint16_t*) &socket_address.sin6_addr ) [i] = snapshot_platform_htons( address->data.ipv6[i] );
        }
        socket_address.sin6_port = snapshot_platform_htons( address->port );

        if ( bind( socket->handle, (sockaddr*) &socket_address, sizeof( socket_address ) ) < 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to bind socket (ipv6)" );
            snapshot_platform_socket_destroy( socket );
            return NULL;
        }
    }
    else
    {
        sockaddr_in socket_address;
        memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr.s_addr = ( ( (uint32_t) address->data.ipv4[0] ) )      | 
                                         ( ( (uint32_t) address->data.ipv4[1] ) << 8 )  | 
                                         ( ( (uint32_t) address->data.ipv4[2] ) << 16 ) | 
                                         ( ( (uint32_t) address->data.ipv4[3] ) << 24 );
        socket_address.sin_port = snapshot_platform_htons( address->port );

        if ( bind( socket->handle, (sockaddr*) &socket_address, sizeof( socket_address ) ) < 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to bind socket (ipv4)" );
            snapshot_platform_socket_destroy( socket );
            return NULL;
        }
    }

    // if bound to port 0 find the actual port we got

    if ( address->port == 0 )
    {
        if ( address->type == SNAPSHOT_ADDRESS_IPV6 )
        {
            sockaddr_in6 sin;
            socklen_t len = sizeof( sin );
            if ( getsockname( socket->handle, (sockaddr*)( &sin ), &len ) == -1 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to get socket port (ipv6)" );
                snapshot_platform_socket_destroy( socket );
                return NULL;
            }
            address->port = snapshot_platform_ntohs( sin.sin6_port );
        }
        else
        {
            sockaddr_in sin;
            socklen_t len = sizeof( sin );
            if ( getsockname( socket->handle, (sockaddr*)( &sin ), &len ) == -1 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to get socket port (ipv4)" );
                snapshot_platform_socket_destroy( socket );
                return NULL;
            }
            address->port = snapshot_platform_ntohs( sin.sin_port );
        }
    }

    // set non-blocking io and receive timeout

    if ( socket_type == SNAPSHOT_PLATFORM_SOCKET_NON_BLOCKING )
    {
        if ( fcntl( socket->handle, F_SETFL, O_NONBLOCK, 1 ) == -1 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to set socket to non-blocking" );
            snapshot_platform_socket_destroy( socket );
            return NULL;
        }
    }
    else if ( timeout_seconds > 0.0f )
    {
        // set receive timeout
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = (int) ( timeout_seconds * 1000000.0 );
        if ( setsockopt( socket->handle, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof( tv ) ) < 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to set socket receive timeout" );
            snapshot_platform_socket_destroy( socket );
            return NULL;
        }
    }
    else
    {
        // socket is blocking with no timeout
    }

#if SNAPSHOT_PACKET_TAGGING

    // tag packet as low latency

    if ( enable_packet_tagging )
    {
        if ( address->type == SNAPSHOT_ADDRESS_IPV6 )
        {
            #if defined(IPV6_TCLASS)
            int tos = 0xA0;
            if ( setsockopt( socket->handle, IPPROTO_IPV6, IPV6_TCLASS, (const char *)&tos, sizeof(tos) ) != 0 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "failed to set socket tos (ipv6)" );
            }
            #endif
        }
        else
        {
            #if defined(IP_TOS)
            int tos = 0xA0;
            if ( setsockopt( socket->handle, IPPROTO_IP, IP_TOS, (const char *)&tos, sizeof(tos) ) != 0 )
            {
                snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "failed to set socket tos (ipv4)" );
            }
            #endif
        }
    }

#else // #if SNAPSHOT_PACKET_TAGGING

    (void) enable_packet_tagging;

#endif // #if SNAPSHOT_PACKET_TAGGING

    return socket;
}

void snapshot_platform_socket_destroy( snapshot_platform_socket_t * socket )
{
    snapshot_assert( socket );

    if ( socket->handle > 0 )
    {
        close( socket->handle );
    }
    
    snapshot_free( socket->context, socket );
}

void snapshot_platform_socket_send_packet( snapshot_platform_socket_t * socket, const snapshot_address_t * to, const void * packet_data, int packet_bytes )
{
    snapshot_assert( socket );
    snapshot_assert( to );
    snapshot_assert( to->type == SNAPSHOT_ADDRESS_IPV6 || to->type == SNAPSHOT_ADDRESS_IPV4 );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes > 0 );

    if ( to->type == SNAPSHOT_ADDRESS_IPV6 )
    {
        sockaddr_in6 socket_address;
        memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin6_family = AF_INET6;
        for ( int i = 0; i < 8; ++i )
        {
            ( (uint16_t*) &socket_address.sin6_addr ) [i] = snapshot_platform_htons( to->data.ipv6[i] );
        }
        socket_address.sin6_port = snapshot_platform_htons( to->port );
        int result = int( sendto( socket->handle, (char*)( packet_data ), packet_bytes, 0, (sockaddr*)( &socket_address ), sizeof(sockaddr_in6) ) );
        if ( result < 0 )
        {
            char address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
            snapshot_address_to_string( to, address_string );
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "sendto (%s) failed: %s", address_string, strerror( errno ) );
        }
    }
    else if ( to->type == SNAPSHOT_ADDRESS_IPV4 )
    {
        sockaddr_in socket_address;
        memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr.s_addr = ( ( (uint32_t) to->data.ipv4[0] ) )        | 
                                         ( ( (uint32_t) to->data.ipv4[1] ) << 8 )   | 
                                         ( ( (uint32_t) to->data.ipv4[2] ) << 16 )  | 
                                         ( ( (uint32_t) to->data.ipv4[3] ) << 24 );
        socket_address.sin_port = snapshot_platform_htons( to->port );
        int result = int( sendto( socket->handle, (const char*)( packet_data ), packet_bytes, 0, (sockaddr*)( &socket_address ), sizeof(sockaddr_in) ) );
        if ( result < 0 )
        {
            char address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
            snapshot_address_to_string( to, address_string );
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "sendto (%s) failed: %s", address_string, strerror( errno ) );
        }
    }
    else
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "invalid address type. could not send packet" );
    }
}

int snapshot_platform_socket_receive_packet( snapshot_platform_socket_t * socket, snapshot_address_t * from, void * packet_data, int max_packet_size )
{
    snapshot_assert( socket );
    snapshot_assert( from );
    snapshot_assert( packet_data );
    snapshot_assert( max_packet_size > 0 );

    sockaddr_storage sockaddr_from;
    socklen_t from_length = sizeof( sockaddr_from );

    int result = int( recvfrom( socket->handle, (char*) packet_data, max_packet_size, 0, (sockaddr*) &sockaddr_from, &from_length ) );

    if ( result <= 0 )
    {
        if ( errno == EAGAIN || errno == EINTR )
        {
            return 0;
        }

        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "recvfrom failed with error %d", errno );
        
        return 0;
    }

    if ( sockaddr_from.ss_family == AF_INET6 )
    {
        sockaddr_in6 * addr_ipv6 = (sockaddr_in6*) &sockaddr_from;
        from->type = SNAPSHOT_ADDRESS_IPV6;
        for ( int i = 0; i < 8; ++i )
        {
            from->data.ipv6[i] = snapshot_platform_ntohs( ( (uint16_t*) &addr_ipv6->sin6_addr ) [i] );
        }
        from->port = snapshot_platform_ntohs( addr_ipv6->sin6_port );
    }
    else if ( sockaddr_from.ss_family == AF_INET )
    {
        sockaddr_in * addr_ipv4 = (sockaddr_in*) &sockaddr_from;
        from->type = SNAPSHOT_ADDRESS_IPV4;
        from->data.ipv4[0] = (uint8_t) ( ( addr_ipv4->sin_addr.s_addr & 0x000000FF ) );
        from->data.ipv4[1] = (uint8_t) ( ( addr_ipv4->sin_addr.s_addr & 0x0000FF00 ) >> 8 );
        from->data.ipv4[2] = (uint8_t) ( ( addr_ipv4->sin_addr.s_addr & 0x00FF0000 ) >> 16 );
        from->data.ipv4[3] = (uint8_t) ( ( addr_ipv4->sin_addr.s_addr & 0xFF000000 ) >> 24 );
        from->port = snapshot_platform_ntohs( addr_ipv4->sin_port );
    }
    else
    {
        snapshot_assert( 0 );
        return 0;
    }
  
    snapshot_assert( result >= 0 );

    return result;
}

// ---------------------------------------------------

snapshot_platform_thread_t * snapshot_platform_thread_create( void * context, snapshot_platform_thread_func_t thread_function, void * arg )
{
    snapshot_platform_thread_t * thread = (snapshot_platform_thread_t*) snapshot_malloc( context, sizeof( snapshot_platform_thread_t) );

    snapshot_assert( thread );

    thread->context = context;
    
    if ( pthread_create( &thread->handle, NULL, thread_function, arg ) != 0 )
    {
        snapshot_free( context, thread );
        return NULL;
    }

    return thread;
}

void snapshot_platform_thread_join( snapshot_platform_thread_t * thread )
{
    snapshot_assert( thread );
    pthread_join( thread->handle, NULL );
}

void snapshot_platform_thread_destroy( snapshot_platform_thread_t * thread )
{
    snapshot_assert( thread );
    snapshot_free( thread->context, thread );
}

bool snapshot_platform_thread_high_priority( snapshot_platform_thread_t * thread )
{
    // todo
    (void)thread;
    return false;
}

// ---------------------------------------------------

int snapshot_platform_mutex_create( snapshot_platform_mutex_t * mutex )
{
    snapshot_assert( mutex );

    memset( mutex, 0, sizeof(snapshot_platform_mutex_t) );

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype( &attr, 0 );
    int result = pthread_mutex_init( &mutex->handle, &attr );
    pthread_mutexattr_destroy( &attr );

    if ( result != 0 )
    {
        return SNAPSHOT_ERROR;
    }

    mutex->ok = true;

    return SNAPSHOT_OK;
}

void snapshot_platform_mutex_acquire( snaphot_platform_mutex_t * mutex )
{
    snapshot_assert( mutex );
    snapshot_assert( mutex->ok );
    pthread_mutex_lock( &mutex->handle );
}

void snapshot_platform_mutex_release( snapshot_platform_mutex_t * mutex )
{
    snapshot_assert( mutex );
    snapshot_assert( mutex->ok );
    pthread_mutex_unlock( &mutex->handle );
}

void snapshot_platform_mutex_destroy( snapshot_platform_mutex_t * mutex )
{
    snapshot_assert( mutex );
    if ( mutex->ok )
    {
        pthread_mutex_destroy( &mutex->handle );
        memset( mutex, 0, sizeof(snapshot_platform_mutex_t) );
    }
}

// ---------------------------------------------------

#else // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_IOS

int snapshot_ios_dummy_symbol = 0;

#endif // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_IOS