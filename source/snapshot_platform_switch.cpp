/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_platform_switch.h"

#if 0 // todo

#if NEXT_PLATFORM == NEXT_PLATFORM_SWITCH

#include <nn/socket.h>
#include <nn/crypto.h>
#include <nn/nifm.h>
#include <random>
#include <sodium.h>

extern void * next_malloc( void * context, size_t bytes );

extern void next_free( void * context, void * p );

// threads

next_platform_thread_t * next_platform_thread_create( void * context, next_platform_thread_func_t fn, void * arg )
{
    const size_t STACK_SIZE = nn::os::ThreadStackAlignment * 512;
    next_platform_thread_t * thread = (next_platform_thread_t *) next_malloc( context, sizeof( next_platform_thread_t ) );
    next_assert( thread );
    thread->context = context;
#if _WIN32
    thread->stack = (char *)( _aligned_malloc( STACK_SIZE, nn::os::ThreadStackAlignment ) );
#else
    thread->stack = (char *)( aligned_alloc( nn::os::ThreadStackAlignment, STACK_SIZE ) );
#endif
    if ( nn::os::CreateThread( &thread->handle, fn, arg, thread->stack, STACK_SIZE, nn::os::DefaultThreadPriority ).IsFailure() )
    {
#if _WIN32
        _aligned_free( thread->stack );
#else
        delete thread->stack;
#endif
        next_free( context, thread );
        return NULL;
    }

    nn::os::StartThread( &thread->handle );

    return thread;
}

void next_platform_thread_join( next_platform_thread_t * thread )
{
    next_assert( thread );

    nn::os::WaitThread( &thread->handle );
}

void next_platform_thread_destroy( next_platform_thread_t * thread )
{
    next_assert( thread );

    nn::os::DestroyThread( &thread->handle );
#if _WIN32
    _aligned_free( thread->stack );
#else
    delete thread->stack;
#endif
    next_free( thread->context, thread );
}

bool next_platform_thread_high_priority( next_platform_thread_t * thread )
{
    // todo
    (void)thread;
    return false;
}

int next_platform_mutex_create( next_platform_mutex_t * mutex )
{
    next_assert( mutex );
    nn::os::InitializeMutex( &mutex->handle, true, 0 );
    return NEXT_OK;
}

void next_platform_mutex_acquire( next_platform_mutex_t * mutex )
{
    next_assert( mutex );
    nn::os::LockMutex( &mutex->handle );
}

void next_platform_mutex_release( next_platform_mutex_t * mutex )
{
    next_assert( mutex );
    nn::os::UnlockMutex( &mutex->handle );
}

void next_platform_mutex_destroy( next_platform_mutex_t * mutex )
{
    next_assert( mutex );
    nn::os::FinalizeMutex( &mutex->handle );
    memset( mutex, 0, sizeof(next_platform_mutex_t) );
}

// time

void next_platform_sleep( double time )
{
    nn::TimeSpan timespan = nn::TimeSpan::FromNanoSeconds( int64_t( time * 1000.0 * 1000.0 * 1000.0 ) );
    nn::os::SleepThread( timespan );
}

static nn::os::Tick time_start;

static const char * next_randombytes_implementation_name()
{
    return "switch";
}

static void next_randombytes_stir()
{
}

static uint32_t next_randombytes_random()
{
    uint32_t random;
    nn::crypto::GenerateCryptographicallyRandomBytes( &random, sizeof( random ) );
    return random;
}

static uint32_t next_randombytes_uniform( const uint32_t upper_bound )
{
    uint32_t mask = upper_bound - 1;

    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8; // mask is smallest ((power of 2) - 1) > upper_bound

    uint32_t result;
    do
    {
        result = mask & next_randombytes_random();  // 16-bit random number
    } while ( result >= upper_bound );
    return result;
}

static void next_randombytes_buf( void * const buf, const size_t size )
{
    nn::crypto::GenerateCryptographicallyRandomBytes( buf, size );
}

static int next_randombytes_close()
{
    return 0;
}

static randombytes_implementation next_random_implementation =
{
    &next_randombytes_implementation_name,
    &next_randombytes_random,
    &next_randombytes_stir,
    &next_randombytes_uniform,
    &next_randombytes_buf,
    &next_randombytes_close,
};

int next_platform_init()
{
    if ( randombytes_set_implementation( &next_random_implementation ) != 0 )
        return NEXT_ERROR;

    time_start = nn::os::GetSystemTick();

    nn::Result result = nn::nifm::Initialize(); // it's valid to call this multiple times
    if ( result.IsFailure() )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "failed to initialize nintendo network connection manager" );
        return NEXT_ERROR;
    }

    return NEXT_OK;
}

double next_platform_time()
{
    return ( nn::os::GetSystemTick() - time_start ).ToTimeSpan().GetNanoSeconds() / ( 1000.0 * 1000.0 * 1000.0 );
}

void next_platform_term()
{
}

const char * next_platform_getenv( const char * var )
{
    return getenv( var );
}

// sockets

uint16_t next_platform_ntohs( uint16_t in )
{
    return nn::socket::InetNtohs( in );
}

uint16_t next_platform_htons( uint16_t in )
{
    return nn::socket::InetHtons( in );
}

int next_platform_hostname_resolve( const char * hostname, const char * port, next_address_t * address )
{
    nn::socket::AddrInfo hints;
    memset( &hints, 0, sizeof(hints) );
    nn::socket::AddrInfo * result;
    if ( nn::socket::GetAddrInfo( hostname, port, &hints, &result ) == nn::socket::AiErrno::EAi_Success )
    {
        if ( result )
        {
            if ( result->ai_addr->sa_family == nn::socket::Family::Af_Inet )
            {
                nn::socket::SockAddrIn * addr_ipv4 = (nn::socket::SockAddrIn *)( result->ai_addr );
                address->type = NEXT_ADDRESS_IPV4;
                address->data.ipv4[0] = (uint8_t) ( ( addr_ipv4->sin_addr.S_addr & 0x000000FF ) );
                address->data.ipv4[1] = (uint8_t) ( ( addr_ipv4->sin_addr.S_addr & 0x0000FF00 ) >> 8 );
                address->data.ipv4[2] = (uint8_t) ( ( addr_ipv4->sin_addr.S_addr & 0x00FF0000 ) >> 16 );
                address->data.ipv4[3] = (uint8_t) ( ( addr_ipv4->sin_addr.S_addr & 0xFF000000 ) >> 24 );
                address->port = next_platform_ntohs( addr_ipv4->sin_port );
                nn::socket::FreeAddrInfo( result );
                return NEXT_OK;
            }
            else
            {
                next_assert( 0 );
                nn::socket::FreeAddrInfo( result );
                return NEXT_ERROR;
            }
        }
    }

    return NEXT_ERROR;
}

int next_platform_inet_pton4( const char * address_string, uint32_t * address_out )
{
    return nn::socket::InetPton( nn::socket::Family::Af_Inet, address_string, address_out ) == 1 ? NEXT_OK : NEXT_ERROR;
}

int next_platform_inet_pton6( const char * address_string, uint16_t * address_out )
{
    return NEXT_ERROR;
}

int next_platform_inet_ntop6( const uint16_t * address, char * address_string, size_t address_string_size )
{
    return NEXT_ERROR;
}

void next_platform_socket_destroy( next_platform_socket_t * socket );

int next_platform_socket_init( next_platform_socket_t * s, next_address_t * address, int socket_type, float timeout_seconds, int send_buffer_size, int receive_buffer_size, bool enable_packet_tagging )
{
    // create socket
    
    s->handle = nn::socket::Socket( nn::socket::Family::Af_Inet, nn::socket::Type::Sock_Dgram, nn::socket::Protocol::IpProto_Udp );

    s->address = *address;
    s->type = socket_type;
    s->timeout_seconds = timeout_seconds;
    s->send_buffer_size = send_buffer_size;
    s->receive_buffer_size = receive_buffer_size;
    s->enable_packet_tagging = enable_packet_tagging;

    if ( s->handle == nn::socket::InvalidSocket )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "failed to create socket" );
        return NEXT_ERROR;
    }

    // increase socket send and receive buffer sizes

    if ( nn::socket::SetSockOpt( s->handle, nn::socket::Level::Sol_Socket, nn::socket::Option::So_SndBuf, (void*)( &send_buffer_size ), nn::socket::SockLenT( sizeof( int ) ) ) != 0 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "failed to set socket send buffer size" );
        return NEXT_ERROR;
    }

    if ( nn::socket::SetSockOpt( s->handle, nn::socket::Level::Sol_Socket, nn::socket::Option::So_RcvBuf, (void*)( &receive_buffer_size ), nn::socket::SockLenT( sizeof( int ) ) ) != 0 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "failed to set socket receive buffer size" );
        return NEXT_ERROR;
    }

    // bind to port

    if ( address->type == NEXT_ADDRESS_IPV6 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "switch doesn't support ipv6!" );
        return NEXT_ERROR;
    }
    else
    {
        nn::socket::SockAddrIn socket_address = { 0 };
        socket_address.sin_family = nn::socket::Family::Af_Inet;
        socket_address.sin_addr.S_addr = ( ( (uint32_t) address->data.ipv4[0] ) )        | 
                                         ( ( (uint32_t) address->data.ipv4[1] ) << 8 )   | 
                                         ( ( (uint32_t) address->data.ipv4[2] ) << 16 )  | 
                                         ( ( (uint32_t) address->data.ipv4[3] ) << 24 );
        socket_address.sin_port = next_platform_htons( address->port );
        socket_address.sin_len = sizeof( socket_address );
        if ( nn::socket::Bind( s->handle, (nn::socket::SockAddr*)( &socket_address ), nn::socket::SockLenT( sizeof( socket_address ) ) ) < 0 )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "failed to bind socket (ipv4): %d", int( nn::socket::GetLastError() ) );
            return NEXT_ERROR;
        }
    }

    // if bound to port 0 find the actual port we got

    if ( address->port == 0 )
    {
        nn::socket::SockAddrIn addr;
        nn::socket::SockLenT len = sizeof( addr );
        if ( nn::socket::GetSockName( s->handle, (nn::socket::SockAddr*)( &addr ), &len ) == -1 )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "failed to get socket port (ipv4)" );
            return NEXT_ERROR;
        }
        address->port = next_platform_ntohs( addr.sin_port );
        s->address.port = address->port;
    }

    // set non-blocking io

    if ( socket_type == NEXT_PLATFORM_SOCKET_NON_BLOCKING )
    {
        if ( nn::socket::Fcntl( s->handle, nn::socket::FcntlCommand::F_SetFl, nn::socket::FcntlFlag::O_NonBlock, 1 ) == -1 )
        {
            return NEXT_ERROR;
        }
    }
    else if ( timeout_seconds > 0.0f )
    {
        // set receive timeout
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = long( timeout_seconds * 1000000.0f );
        if ( nn::socket::SetSockOpt( s->handle, nn::socket::Level::Sol_Socket, nn::socket::Option::So_RcvTimeo, &tv, sizeof( tv ) ) < 0 )
        {
            return NEXT_ERROR;
        }
    }
    else
    {
        // timeout < 0, socket is blocking with no timeout
    }

#if NEXT_PACKET_TAGGING

    // tag as latency sensitive

    if ( enable_packet_tagging )
    {
        next_assert( address->type == NEXT_ADDRESS_IPV4 );
        int tos = 0xA0;
        if ( nn::socket::SetSockOpt( s->handle, IPPROTO_IP, IP_TOS, (const char*) &tos, sizeof(tos) ) != 0)
        {
            next_printf(NEXT_LOG_LEVEL_DEBUG, "failed to set socket tos (ipv4)");
        }
    }

#else // If NEXT_PACKET_TAGGING

    (void) enable_packet_tagging;

#endif // #if NEXT_PACKET_TAGGING
    
    return NEXT_OK;
}

next_platform_socket_t * next_platform_socket_create( void * context, next_address_t * address, int socket_type, float timeout_seconds, int send_buffer_size, int receive_buffer_size, bool enable_packet_tagging )
{
    next_assert( address );

    next_assert( address->type == NEXT_ADDRESS_IPV4 );

    next_platform_socket_t * socket = (next_platform_socket_t *) next_malloc( context, sizeof( next_platform_socket_t ) );

    if ( !socket ) 
        return NULL;

    socket->context = context;

    if ( next_platform_socket_init( socket, address, socket_type, timeout_seconds, send_buffer_size, receive_buffer_size, enable_packet_tagging ) != NEXT_OK )
    {
        next_platform_socket_destroy( socket );
        return NULL;
    }

    return socket;
}

void next_platform_socket_cleanup( next_platform_socket_t * socket )
{
    if ( socket->handle != nn::socket::InvalidSocket )
    {
        nn::socket::Close( socket->handle );
        socket->handle = nn::socket::InvalidSocket;
    }
}

void next_platform_socket_destroy( next_platform_socket_t * socket )
{
    next_assert( socket );

    next_platform_socket_cleanup( socket );

    next_free( socket->context, socket );
}

void next_platform_socket_send_packet( next_platform_socket_t * socket, const next_address_t * to, const void * packet_data, int packet_bytes )
{
    next_assert( socket );
    next_assert( to );
    next_assert( to->type == NEXT_ADDRESS_IPV4 );
    next_assert( packet_data );
    next_assert( packet_bytes > 0 );

    if ( socket->handle == nn::socket::InvalidSocket )
    {
        return;
    }

    if ( to->type == NEXT_ADDRESS_IPV6 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "switch doesn't support ipv6" );
    }
    else if ( to->type == NEXT_ADDRESS_IPV4 )
    {
        nn::socket::SockAddrIn socket_address;
        memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = nn::socket::Family::Af_Inet;
        socket_address.sin_addr.S_addr = ( ( (uint32_t) to->data.ipv4[0] ) )        | 
                                         ( ( (uint32_t) to->data.ipv4[1] ) << 8 )   | 
                                         ( ( (uint32_t) to->data.ipv4[2] ) << 16 )  | 
                                         ( ( (uint32_t) to->data.ipv4[3] ) << 24 );
        socket_address.sin_port = next_platform_htons( to->port );
        int result = int( nn::socket::SendTo( socket->handle, (const void*)( packet_data ), packet_bytes, nn::socket::MsgFlag::Msg_None, (nn::socket::SockAddr*)( &socket_address ), nn::socket::SockLenT( sizeof( socket_address ) ) ) );
        if ( result < 0 )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "sendto failed: %d", int( nn::socket::GetLastError() ) );
        }
    }
    else
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "invalid address type. could not send packet" );
    }
}

int next_platform_socket_receive_packet( next_platform_socket_t * socket, next_address_t * from, void * packet_data, int max_packet_size )
{
    next_assert( socket );
    next_assert( from );
    next_assert( packet_data );
    next_assert( max_packet_size > 0 );

    if ( socket->handle == nn::socket::InvalidSocket )
    {
        next_address_t address = socket->address;
        int type = socket->type;
        float timeout_seconds = socket->timeout_seconds;
        int send_buffer_size = socket->send_buffer_size;
        int receive_buffer_size = socket->receive_buffer_size;
        bool enable_packet_tagging = socket->enable_packet_tagging;

        if ( next_platform_socket_init( socket, &address, type, timeout_seconds, send_buffer_size, receive_buffer_size, enable_packet_tagging ) == NEXT_ERROR )
        {
            next_platform_socket_cleanup( socket );
            return 0;
        }
    }

    nn::socket::SockAddrStorage sockaddr_from;
    nn::socket::SockLenT from_length = sizeof( sockaddr_from );

    int result = int( nn::socket::RecvFrom( socket->handle, (void*)( packet_data ), max_packet_size, nn::socket::MsgFlag::Msg_None, (nn::socket::SockAddr*)(  &sockaddr_from ), &from_length ) );

    if ( result <= 0 )
    {
        nn::socket::Errno err = nn::socket::GetLastError();
        if ( err == nn::socket::Errno::EAgain || err == nn::socket::Errno::EIntr )
        {
            return 0;
        }

        if ( err == nn::socket::Errno::ENetDown || err == nn::socket::Errno::EBadf)
        {
            next_platform_socket_cleanup( socket );
        }

        next_printf( NEXT_LOG_LEVEL_DEBUG, "recvfrom failed with error %d", int( err ) );
        
        return 0;
    }

    nn::socket::SockAddrIn * addr_ipv4 = (nn::socket::SockAddrIn*) &sockaddr_from;
    from->type = NEXT_ADDRESS_IPV4;
    from->data.ipv4[0] = (uint8_t) ( ( addr_ipv4->sin_addr.S_addr & 0x000000FF ) );
    from->data.ipv4[1] = (uint8_t) ( ( addr_ipv4->sin_addr.S_addr & 0x0000FF00 ) >> 8 );
    from->data.ipv4[2] = (uint8_t) ( ( addr_ipv4->sin_addr.S_addr & 0x00FF0000 ) >> 16 );
    from->data.ipv4[3] = (uint8_t) ( ( addr_ipv4->sin_addr.S_addr & 0xFF000000 ) >> 24 );
    from->port = next_platform_ntohs( addr_ipv4->sin_port );

    next_assert( result >= 0 );

    return result;
}

int next_platform_connection_type()
{
    return NEXT_CONNECTION_TYPE_WIFI; // switch is always on wifi
}

int next_platform_id()
{
    return NEXT_PLATFORM_SWITCH;
}

#else // #if NEXT_PLATFORM == NEXT_PLATFORM_SWITCH

int next_switch_dummy_symbol = 0;

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_SWITCH

#endif // todo