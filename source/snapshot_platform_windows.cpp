/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_platform_windows.h"

#if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_WINDOWS

#include "snapshot_platform.h"
#include "snapshot_address.h"

#if SNAPSHOT_UNREAL_ENGINE
#include "Windows/AllowWindowsPlatformTypes.h"
#include "Windows/PreWindowsApi.h"
#endif // #if SNAPSHOT_UNREAL_ENGINE

#define NOMINMAX
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#ifndef SNAPSHOT_UNREAL_ENGINE
#include <windows.h>
#else // #ifndef SNAPSHOT_UNREAL_ENGINE
#include "Windows/MinWindows.h"
#endif // #ifndef SNAPSHOT_UNREAL_ENGINE
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <malloc.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <qos2.h>

#pragma comment( lib, "WS2_32.lib" )
#pragma comment( lib, "IPHLPAPI.lib" )

#ifdef SetPort
#undef SetPort
#endif // #ifdef SetPort

extern void * snapshot_malloc( void * context, size_t bytes );

extern void snapshot_free( void * context, void * p );

static int timer_initialized = 0;
static LARGE_INTEGER timer_frequency;
static LARGE_INTEGER timer_start;

// init

int snapshot_platform_init()
{
    QueryPerformanceFrequency( &timer_frequency );
    QueryPerformanceCounter( &timer_start );

    WSADATA WsaData;
    if ( WSAStartup( MAKEWORD(2,2), &WsaData ) != NO_ERROR )
    {
        return SNAPSHOT_ERROR;
    }

    return SNAPSHOT_OK;
}

void snapshot_platform_term()
{
    WSACleanup();
}

const char * snapshot_platform_getenv( const char * var )
{
    return getenv( var );
}

// threads

struct thread_shim_data_t
{
    void * context;
    void * real_thread_data;
    snapshot_platform_thread_func_t real_thread_function;
};

static DWORD WINAPI thread_function_shim( void * data )
{
    snapshot_assert( data );
    thread_shim_data_t * shim_data = (thread_shim_data_t*) data;
    void * context = shim_data->context;
    void * real_thread_data = shim_data->real_thread_data;
    snapshot_platform_thread_func_t real_thread_function = shim_data->real_thread_function;
    snapshot_free( context, data );
    real_thread_function( real_thread_data );
    return 0;
}

snapshot_platform_thread_t * snapshot_platform_thread_create( void * context, snapshot_platform_thread_func_t thread_function, void * arg )
{
    snapshot_platform_thread_t * thread = (snapshot_platform_thread_t*) snapshot_malloc( context, sizeof( snapshot_platform_thread_t ) );

    snapshot_assert( thread );

    thread->context = context;

    thread_shim_data_t * shim_data = (thread_shim_data_t*) snapshot_malloc( context, sizeof(thread_shim_data_t) );
    snapshot_assert( shim_data );
    if ( !shim_data )
    {
        snapshot_free( context, thread );
        return NULL;
    }
    shim_data->context = context;
    shim_data->real_thread_function = thread_function;
    shim_data->real_thread_data = arg;

    thread->handle = CreateThread(NULL, 0, thread_function_shim, shim_data, 0, NULL);

    if ( thread->handle == NULL )
    {
        snapshot_free( context, thread );
        snapshot_free( context, shim_data );
        return NULL;
    }

    return thread;
}

void snapshot_platform_thread_join( snapshot_platform_thread_t * thread )
{
    snapshot_assert( thread );
    WaitForSingleObject( thread->handle, INFINITE );
}

void snapshot_platform_thread_destroy( snapshot_platform_thread_t * thread )
{
    snapshot_assert( thread );
    snapshot_free( thread->context, thread );
}

bool snapshot_platform_thread_high_priority( snapshot_platform_thread_t * thread )
{
    snapshot_assert( thread );
    return SetThreadPriority( thread->handle, THREAD_PRIORITY_TIME_CRITICAL );
}

int snapshot_platform_mutex_create( snapshot_platform_mutex_t * mutex )
{
    snapshot_assert( mutex );

    memset( mutex, 0, sizeof(snapshot_platform_mutex_t) );

    if ( !InitializeCriticalSectionAndSpinCount( (LPCRITICAL_SECTION)&mutex->handle, 0xFF ) )
    {
        return SNAPSHOT_ERROR;
    }

    mutex->ok = true;

    return SNAPSHOT_OK;
}

void snapshot_platform_mutex_acquire( snapshot_platform_mutex_t * mutex )
{
    snapshot_assert( mutex );
    snapshot_assert( mutex->ok );
    EnterCriticalSection( (LPCRITICAL_SECTION)&mutex->handle );
}

void snapshot_platform_mutex_release( snapshot_platform_mutex_t * mutex )
{
    snapshot_assert( mutex );
    snapshot_assert( mutex->ok );
    LeaveCriticalSection( (LPCRITICAL_SECTION)&mutex->handle );
}

void snapshot_platform_mutex_destroy( snapshot_platform_mutex_t * mutex )
{
    snapshot_assert( mutex );
    if ( mutex->ok )
    {
        DeleteCriticalSection( (LPCRITICAL_SECTION)&mutex->handle );
        memset(mutex, 0, sizeof(snapshot_platform_mutex_t));
    }
}

// time

void snapshot_platform_sleep( double time )
{
    const int milliseconds = (int) ( time * 1000 );
    Sleep( milliseconds );
}

double snapshot_platform_time()
{
    LARGE_INTEGER now;
    QueryPerformanceCounter( &now );
    return ( (double) ( now.QuadPart - timer_start.QuadPart ) ) / ( (double) ( timer_frequency.QuadPart ) );
}

// sockets

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
    return inet_ntop( AF_INET6, (void*)address, address_string, address_string_size ) == NULL ? SNAPSHOT_ERROR : SNAPSHOT_OK;
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
    return SNAPSHOT_PLATFORM_WINDOWS;
}

void snapshot_platform_socket_destroy( snapshot_platform_socket_t * );

snapshot_platform_socket_t * snapshot_platform_socket_create( void * context, snapshot_address_t * address, int socket_type, float timeout_seconds, int send_buffer_size, int receive_buffer_size )
{
    snapshot_platform_socket_t * s = (snapshot_platform_socket_t *) snapshot_malloc( context, sizeof( snapshot_platform_socket_t ) );

    snapshot_assert( s );

    s->context = context;

    snapshot_assert( address );
    snapshot_assert( address->type != SNAPSHOT_ADDRESS_NONE );

    // create socket

    s->handle = socket( ( address->type == SNAPSHOT_ADDRESS_IPV6 ) ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP );

    if ( s->handle == INVALID_SOCKET )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create socket" );
        snapshot_free( context, s );
        return NULL;
    }

    // force IPv6 only if necessary

    if ( address->type == SNAPSHOT_ADDRESS_IPV6 )
    {
        int yes = 1;
        if ( setsockopt( s->handle, IPPROTO_IPV6, IPV6_V6ONLY, (char*)( &yes ), sizeof( yes ) ) != 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to set socket ipv6 only" );
            snapshot_platform_socket_destroy( s );
            return NULL;
        }
    }

    // increase socket send and receive buffer sizes

    if ( setsockopt( s->handle, SOL_SOCKET, SO_SNDBUF, (char*)( &send_buffer_size ), sizeof( int ) ) != 0 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to set socket send buffer size" );
        snapshot_platform_socket_destroy( s );
        return NULL;
    }

    if ( setsockopt( s->handle, SOL_SOCKET, SO_RCVBUF, (char*)( &receive_buffer_size ), sizeof( int ) ) != 0 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to set socket receive buffer size" );
        snapshot_platform_socket_destroy( s );
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

        if ( bind( s->handle, (sockaddr*) &socket_address, sizeof( socket_address ) ) < 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to bind socket (ipv6)" );
            snapshot_platform_socket_destroy( s );
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

        if ( bind( s->handle, (sockaddr*) &socket_address, sizeof( socket_address ) ) < 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to bind socket (ipv4)" );
            snapshot_platform_socket_destroy( s );
            return NULL;
        }
    }

    // if bound to port 0 find the actual port we got

    sockaddr_in sin4;
    sockaddr_in6 sin6;
    sockaddr * addr = NULL;

    if ( address->type == SNAPSHOT_ADDRESS_IPV6 )
    {
        addr = (sockaddr*) &sin6;
        socklen_t len = sizeof( sin6 );
        if ( getsockname( s->handle, addr, &len ) == -1 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to get socket address (ipv6)" );
            snapshot_platform_socket_destroy( s );
            return NULL;
        }
        address->port = snapshot_platform_ntohs( sin6.sin6_port );
    }
    else
    {
        addr = (sockaddr*) &sin4;
        socklen_t len = sizeof( sin4 );
        if ( getsockname( s->handle, addr, &len ) == -1 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to get socket address (ipv4)" );
            snapshot_platform_socket_destroy( s );
            return NULL;
        }
        address->port = snapshot_platform_ntohs( sin4.sin_port );
    }

    // set non-blocking io

    if ( socket_type == SNAPSHOT_PLATFORM_SOCKET_NON_BLOCKING )
    {
        DWORD nonBlocking = 1;
        if ( ioctlsocket( s->handle, FIONBIO, &nonBlocking ) != 0 )
        {
            snapshot_platform_socket_destroy( s );
            return NULL;
        }
    }
    else if ( timeout_seconds > 0.0f )
    {
        // set receive timeout
        DWORD tv = DWORD( timeout_seconds * 1000.0f );
        if ( setsockopt( s->handle, SOL_SOCKET, SO_RCVTIMEO, (const char *)( &tv ), sizeof( tv ) ) < 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to set socket receive timeout" );
            snapshot_platform_socket_destroy( s );
            return NULL;
        }
    }
    else
    {
        // timeout < 0, socket is blocking with no timeout
    }

    return s;
}

void snapshot_platform_socket_destroy( snapshot_platform_socket_t * socket )
{
    snapshot_assert( socket );

    if ( socket->handle != 0 )
    {
        closesocket( socket->handle );
        socket->handle = 0;
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
        int result = sendto( socket->handle, (char*)( packet_data ), packet_bytes, 0, (sockaddr*)( &socket_address ), sizeof( sockaddr_in6 ) );
        if ( result < 0 )
        {
            char address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
            snapshot_address_to_string( to, address_string );
            char error_string[256] = {0};
            strerror_s( error_string, sizeof( error_string ), errno );
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "sendto (%s) failed: %s", address_string, error_string );
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
        int result = sendto( socket->handle, (const char*)( packet_data ), packet_bytes, 0, (sockaddr*)( &socket_address ), sizeof( sockaddr_in ) );
        if ( result < 0 )
        {
            char address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
            snapshot_address_to_string( to, address_string );
            char error_string[256] = {0};
            strerror_s( error_string, sizeof( error_string ), errno );
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "sendto (%s) failed: %s", address_string, error_string );
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

    typedef int socklen_t;
    
    sockaddr_storage sockaddr_from;
    socklen_t from_length = sizeof( sockaddr_from );

    int result = recvfrom( socket->handle, (char*) packet_data, max_packet_size, 0, (sockaddr*) &sockaddr_from, &from_length );

    if ( result == SOCKET_ERROR )
    {
        int error = WSAGetLastError();

        if ( error == WSAEWOULDBLOCK || error == WSAETIMEDOUT || error == WSAECONNRESET )
            return 0;

        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "recvfrom failed with error %d", error );

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

#if SNAPSHOT_UNREAL_ENGINE
#include "Windows/PostWindowsApi.h"
#include "Windows/HideWindowsPlatformTypes.h"
#endif // #if SNAPSHOT_UNREAL_ENGINE

#else // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_WINDOWS

int snapshot_windows_dummy_symbol = 0;

#endif // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_WINDOWS
