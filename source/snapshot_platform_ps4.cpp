/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_platform_ps4.h"

#if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_PS4

#include "snapshot_platform.h"
#include "snapshot_address.h"

#include <kernel.h>
#include <net.h>
#include <libnetctl.h>
#include <libsecure.h>
#include <string.h>
#include "sodium.h"

#define HEAP_SIZE_NET (16 * 1024)

static int handle_net;

static const char * snapshot_randombytes_implementation_name()
{
    return "ps4";
}

static void snapshot_randombytes_stir()
{
}

static void snapshot_randombytes_buf( void * const buf, const size_t size )
{
    SceLibSecureBlock mem_block = { buf, size };
    SceLibSecureErrorType error = sceLibSecureRandom( &mem_block );
    (void)error;
    snapshot_assert( error == SCE_LIBSECURE_OK );
}

static uint32_t snapshot_randombytes_random()
{
    uint32_t random;
    snapshot_randombytes_buf( &random, sizeof( random ) );
    return random;
}

static uint32_t snapshot_randombytes_uniform( const uint32_t upper_bound )
{
    uint32_t mask = upper_bound - 1;

    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8; // mask is smallest ((power of 2) - 1) > upper_bound

    uint32_t result;
    do
    {
        result = mask & snapshot_randombytes_random();  // 16-bit random number
    } while ( result >= upper_bound );
    return result;
}

static int snapshot_randombytes_close()
{
    return 0;
}

static randombytes_implementation snapshot_random_implementation =
{
    &snapshot_randombytes_implementation_name,
    &snapshot_randombytes_random,
    &snapshot_randombytes_stir,
    &snapshot_randombytes_uniform,
    &snapshot_randombytes_buf,
    &snapshot_randombytes_close,
};

int snapshot_platform_init()
{
    if ( randombytes_set_implementation( &snapshot_random_implementation ) != 0 )
        return SNAPSHOT_ERROR;

    if ( ( handle_net = sceNetPoolCreate("net", HEAP_SIZE_NET, 0 ) ) < 0 )
        return SNAPSHOT_ERROR;

    return SNAPSHOT_OK;
}

void snapshot_platform_term()
{
    sceNetPoolDestroy( handle_net );
}

const char * snapshot_platform_getenv( const char * )
{
    return NULL; // not supported
}

// threads

struct thread_shim_data_t
{
    void * context;
    void * real_thread_data;
    snapshot_platform_thread_func_t real_thread_function;
};

static void* thread_function_shim( void * data )
{
    snapshot_assert( data );
    thread_shim_data_t * shim_data = (thread_shim_data_t*) data;
    void * context = shim_data->context;
    void * real_thread_data = shim_data->real_thread_data;
    snapshot_platform_thread_func_t real_thread_function = shim_data->real_thread_function;
    snapshot_free( context, data );
    real_thread_function( real_thread_data );
    return NULL;
}

snapshot_platform_thread_t * snapshot_platform_thread_create( void * context, snapshot_platform_thread_func_t thread_function, void * arg )
{
    snapshot_platform_thread_t * thread = (snapshot_platform_thread_t *) snapshot_malloc( context, sizeof( snapshot_platform_thread_t ) );
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

    if ( scePthreadCreate( &thread->handle, NULL, thread_function_shim, shim_data, "snapshot" ) != 0 )
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
    scePthreadJoin( thread->handle, NULL );
}

void snapshot_platform_thread_destroy( snapshot_platform_thread_t * thread )
{
    snapshot_assert( thread );
    snapshot_free( thread->context, thread );
}

bool snapshot_platform_thread_high_priority( snapshot_platform_thread_t * thread )
{
    scePthreadSetprio( thread->handle, SCE_KERNEL_PRIO_FIFO_HIGHEST );
    return true;
}

int snapshot_platform_mutex_create( snapshot_platform_mutex_t * mutex )
{
    snapshot_assert( mutex );

    memset( mutex, 0, sizeof( snapshot_platform_mutex_t) );

    ScePthreadMutexattr attr;
    scePthreadMutexattrInit(&attr);
    scePthreadMutexattrSettype( &attr, SCE_PTHREAD_MUTEX_RECURSIVE );
    bool success = scePthreadMutexInit( &mutex->handle, &attr, "snapshot" ) == SCE_OK;
    scePthreadMutexattrDestroy( &attr );
    
    if ( !success )
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
    scePthreadMutexLock( &mutex->handle );
}

void snapshot_platform_mutex_release( snapshot_platform_mutex_t * mutex )
{
    snapshot_assert( mutex );
    snapshot_assert( mutex->ok );
    scePthreadMutexUnlock( &mutex->handle );
}

void snapshot_platform_mutex_destroy( snapshot_platform_mutex_t * mutex )
{
    snapshot_assert( mutex );
    if ( mutex->ok )
    {
        scePthreadMutexDestroy( &mutex->handle );
        memset( mutex, 0, sizeof(snapshot_platform_mutex_t) );
    }
}

// time

void snapshot_platform_sleep( double time )
{
    sceKernelUsleep( time * 1000000.0 );
}

double snapshot_platform_time()
{
    return double( sceKernelGetProcessTime() ) / 1000000.0;
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

int snapshot_platform_hostname_resolve( const char * hostname, const char * port, snapshot_address_t * address )
{
    SceNetId resolver = sceNetResolverCreate( "resolver", handle_net, 0 );
    if ( resolver < 0 )
        return SNAPSHOT_ERROR;

    SceNetSockaddrIn addr;
    memset( &addr, 0, sizeof(addr) );
    addr.sin_len = sizeof(addr);
    addr.sin_family = SCE_NET_AF_INET;
    int result = sceNetResolverStartNtoa( resolver, hostname, &addr.sin_addr, 0, 0, 0 );
    sceNetResolverDestroy( resolver );

    if ( result < 0 )
        return SNAPSHOT_ERROR;

    if ( addr.sin_family != SCE_NET_AF_INET )
        return SNAPSHOT_ERROR;

    address->type = SNAPSHOT_ADDRESS_IPV4;
    address->data.ipv4[0] = (uint8_t)((addr.sin_addr.s_addr & 0x000000FF));
    address->data.ipv4[1] = (uint8_t)((addr.sin_addr.s_addr & 0x0000FF00) >> 8);
    address->data.ipv4[2] = (uint8_t)((addr.sin_addr.s_addr & 0x00FF0000) >> 16);
    address->data.ipv4[3] = (uint8_t)((addr.sin_addr.s_addr & 0xFF000000) >> 24);
    address->port = uint16_t( atoi( port ) );
    return SNAPSHOT_OK;
}

int snapshot_platform_inet_pton4( const char * address_string, uint32_t * address_out )
{
    SceNetInAddr sockaddr4;
    bool success = sceNetInetPton( SCE_NET_AF_INET, address_string, &sockaddr4.s_addr ) == 1;
    *address_out = sockaddr4.s_addr;
    return success ? SNAPSHOT_OK : SNAPSHOT_ERROR;
}

int snapshot_platform_inet_pton6( const char * address_string, uint16_t * address_out )
{
    return SNAPSHOT_ERROR;
}

int snapshot_platform_inet_ntop6( const uint16_t * address, char * address_string, size_t address_string_size )
{
    return SNAPSHOT_ERROR;
}

void snapshot_platform_socket_destroy( snapshot_platform_socket_t * socket );

snapshot_platform_socket_t * snapshot_platform_socket_create( void * context, snapshot_address_t * address, int socket_type, float timeout_seconds, int send_buffer_size, int receive_buffer_size )
{
    snapshot_platform_socket_t * s = (snapshot_platform_socket_t *) snapshot_malloc( context, sizeof( snapshot_platform_socket_t ) );
    snapshot_assert( s );
    s->context = context;

    snapshot_assert( address );
    snapshot_assert( address->type == SNAPSHOT_ADDRESS_IPV4 );

    // create socket

    s->handle = sceNetSocket( "snapshot", SCE_NET_AF_INET, SCE_NET_SOCK_DGRAM, SCE_NET_IPPROTO_UDP );

    if ( s->handle < 0 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to create socket" );
        snapshot_platform_socket_destroy( s );
        return NULL;
    }

    // increase socket send and receive buffer sizes

    if ( sceNetSetsockopt( s->handle, SCE_NET_SOL_SOCKET, SCE_NET_SO_SNDBUF, (char*)( &send_buffer_size ), sizeof( int ) ) != 0 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to set socket send buffer size" );
        snapshot_platform_socket_destroy( s );
        return NULL;
    }

    if ( sceNetSetsockopt( s->handle, SCE_NET_SOL_SOCKET, SCE_NET_SO_RCVBUF, (char*)( &receive_buffer_size ), sizeof( int ) ) != 0 )
    {
        snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to set socket receive buffer size" );
        snapshot_platform_socket_destroy( s );
        return NULL;
    }

    // bind to port

    {
        SceNetSockaddrIn socket_address;
        memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = SCE_NET_AF_INET;
        socket_address.sin_addr.s_addr = ( ( (uint32_t) address->data.ipv4[0] ) )      | 
                                         ( ( (uint32_t) address->data.ipv4[1] ) << 8 )  | 
                                         ( ( (uint32_t) address->data.ipv4[2] ) << 16 ) | 
                                         ( ( (uint32_t) address->data.ipv4[3] ) << 24 );
        socket_address.sin_port = snapshot_platform_htons( address->port );

        if ( sceNetBind( s->handle, (SceNetSockaddr*) &socket_address, sizeof( socket_address ) ) < 0 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to bind socket (ipv4)" );
            snapshot_platform_socket_destroy( s );
            return NULL;
        }
    }

    // if bound to port 0 find the actual port we got

    if ( address->port == 0 )
    {
        SceNetSockaddrIn sin;
        SceNetSocklen_t len = sizeof( sin );
        if ( sceNetGetsockname( s->handle, (SceNetSockaddr*)( &sin ), &len ) == -1 )
        {
            snapshot_printf( SNAPSHOT_LOG_LEVEL_ERROR, "failed to get socket port (ipv4)" );
            snapshot_platform_socket_destroy( s );
            return NULL;
        }
        address->port = snapshot_platform_ntohs( sin.sin_port );
    }

    // set non-blocking io

    s->type = socket_type;
    s->timeout_seconds = timeout_seconds;
    if ( socket_type == SNAPSHOT_PLATFORM_SOCKET_NON_BLOCKING )
    {
        int value = SCE_KERNEL_O_NONBLOCK;
        if ( sceNetSetsockopt( s->handle, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, &value, sizeof( value ) ) < 0 )
        {
            snapshot_platform_socket_destroy( s );
            return NULL;
        }
    }
    else if ( timeout_seconds > 0.0f )
    {
        s->timeout_seconds = timeout_seconds;
        // set receive timeout
        int tv = int( timeout_seconds * 1000000.0f );
        if ( sceNetSetsockopt( s->handle, SCE_NET_SOL_SOCKET, SCE_NET_SO_RCVTIMEO, &tv, sizeof( tv ) ) < 0 )
        {
            snapshot_platform_socket_destroy( s );
            return NULL;
        }
    }
    else
    {
        // timeout <= 0, socket is blocking with no timeout
    }

    return s;
}

void snapshot_platform_socket_destroy( snapshot_platform_socket_t * socket )
{
    snapshot_assert( socket );

    if ( socket->handle != 0 )
    {
        sceNetSocketClose( socket->handle );
        socket->handle = 0;
    }

    snapshot_free( socket->context, socket );
}

void snapshot_platform_socket_send_packet( snapshot_platform_socket_t * socket, const snapshot_address_t * to, const void * packet_data, int packet_bytes )
{
    snapshot_assert( socket );
    snapshot_assert( to );
    snapshot_assert( to->type == SNAPSHOT_ADDRESS_IPV4 );
    snapshot_assert( packet_data );
    snapshot_assert( packet_bytes > 0 );

    if ( to->type == SNAPSHOT_ADDRESS_IPV4 )
    {
        SceNetSockaddrIn socket_address;
        memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = SCE_NET_AF_INET;
        socket_address.sin_addr.s_addr = ( ( (uint32_t) to->data.ipv4[0] ) )        | 
                                         ( ( (uint32_t) to->data.ipv4[1] ) << 8 )   | 
                                         ( ( (uint32_t) to->data.ipv4[2] ) << 16 )  | 
                                         ( ( (uint32_t) to->data.ipv4[3] ) << 24 );
        socket_address.sin_port = snapshot_platform_htons( to->port );
        int result = sceNetSendto( socket->handle, (const char*)( packet_data ), packet_bytes, 0, (SceNetSockaddr*)( &socket_address ), sizeof( SceNetSockaddrIn ) );
        if ( result < 0 )
        {
            char address_string[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
            snapshot_address_to_string( to, address_string );
            snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "sendto (%s) failed: %s", address_string, strerror( sce_net_errno ) );
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

    SceNetSockaddrIn sockaddr_from;
    SceNetSocklen_t from_length = sizeof( sockaddr_from );

    int result = sceNetRecvfrom( socket->handle, (char*) packet_data, max_packet_size, socket->timeout_seconds == 0.0f && socket->type == SNAPSHOT_PLATFORM_SOCKET_NON_BLOCKING ? SCE_NET_MSG_DONTWAIT : 0, (SceNetSockaddr*) &sockaddr_from, &from_length );

    if ( result <= 0 )
    {
        if ( sce_net_errno == SCE_NET_EAGAIN || sce_net_errno == SCE_NET_EINTR )
        {
            return 0;
        }

        snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "recvfrom failed with error %d", sce_net_errno );
        
        return 0;
    }

    if ( sockaddr_from.sin_family == SCE_NET_AF_INET )
    {
        from->type = SNAPSHOT_ADDRESS_IPV4;
        from->data.ipv4[0] = (uint8_t) ( ( sockaddr_from.sin_addr.s_addr & 0x000000FF ) );
        from->data.ipv4[1] = (uint8_t) ( ( sockaddr_from.sin_addr.s_addr & 0x0000FF00 ) >> 8 );
        from->data.ipv4[2] = (uint8_t) ( ( sockaddr_from.sin_addr.s_addr & 0x00FF0000 ) >> 16 );
        from->data.ipv4[3] = (uint8_t) ( ( sockaddr_from.sin_addr.s_addr & 0xFF000000 ) >> 24 );
        from->port = snapshot_platform_ntohs( sockaddr_from.sin_port );
    }
    else
    {
        snapshot_assert( 0 );
        return 0;
    }
  
    snapshot_assert( result >= 0 );

    return result;

}

int snapshot_platform_id()
{
    return SNAPSHOT_PLATFORM_PS4;
}

#else // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_PS4

int snapshot_ps4_dummy_symbol = 0;

#endif // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_PS4
