/*
    Network Next SDK. Copyright © 2017 - 2023 Network Next, Inc.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following
    conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
       and the following disclaimer in the documentation and/or other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
       products derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
    IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
    OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "next.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <float.h>
#include <string.h>
#include <inttypes.h>
#if defined( _MSC_VER )
#include <malloc.h>
#endif // #if defined( _MSC_VER )
#include <time.h>

#if defined( _MSC_VER )
#pragma warning(push)
#pragma warning(disable:4996)
#pragma warning(disable:4127)
#pragma warning(disable:4244)
#pragma warning(disable:4668)
#endif

#if !NEXT_DEVELOPMENT
#define NEXT_SERVER_BACKEND_HOSTNAME                "prod5.spacecats.net"
#else // #if !NEXT_DEVELOPMENT
#define NEXT_SERVER_BACKEND_HOSTNAME                 "dev5.spacecats.net"
#endif // #if !NEXT_DEVELOPMENT
#define NEXT_SERVER_BACKEND_PORT                                  "45000"

#define NEXT_SERVER_INIT_TIMEOUT                                     10.0
#define NEXT_SERVER_AUTODETECT_TIMEOUT                                9.0
#define NEXT_SERVER_RESOLVE_HOSTNAME_TIMEOUT                         10.0
#define NEXT_ADDRESS_BYTES                                             19
#define NEXT_ADDRESS_BUFFER_SAFETY                                     32
#define NEXT_DEFAULT_SOCKET_SEND_BUFFER_SIZE                      1000000
#define NEXT_DEFAULT_SOCKET_RECEIVE_BUFFER_SIZE                   1000000
#define NEXT_REPLAY_PROTECTION_BUFFER_SIZE                           1024
#define NEXT_PING_HISTORY_ENTRY_COUNT                                1024
#define NEXT_CLIENT_STATS_WINDOW                                     10.0
#define NEXT_PING_SAFETY                                              1.0
#define NEXT_UPGRADE_TIMEOUT                                          5.0
#define NEXT_CLIENT_SESSION_TIMEOUT                                   5.0
#define NEXT_CLIENT_ROUTE_TIMEOUT                                    16.5
#define NEXT_SERVER_PING_TIMEOUT                                      5.0
#define NEXT_SERVER_SESSION_TIMEOUT                                  60.0
#define NEXT_SERVER_INIT_TIMEOUT                                     10.0
#define NEXT_INITIAL_PENDING_SESSION_SIZE                              64
#define NEXT_INITIAL_SESSION_SIZE                                      64
#define NEXT_PINGS_PER_SECOND                                          10
#define NEXT_DIRECT_PINGS_PER_SECOND                                   10
#define NEXT_COMMAND_QUEUE_LENGTH                                    1024
#define NEXT_NOTIFY_QUEUE_LENGTH                                     1024
#define NEXT_CLIENT_STATS_UPDATES_PER_SECOND                           10
#define NEXT_SECONDS_BETWEEN_SERVER_UPDATES                          10.0
#define NEXT_SECONDS_BETWEEN_SESSION_UPDATES                         10.0
#define NEXT_UPGRADE_TOKEN_BYTES                                      128
#define NEXT_MAX_NEAR_RELAYS                                           32
#define NEXT_ROUTE_TOKEN_BYTES                                         76
#define NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES                              116
#define NEXT_CONTINUE_TOKEN_BYTES                                      17
#define NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES                            57
#define NEXT_PING_TOKEN_BYTES                                          46
#define NEXT_ENCRYPTED_PING_TOKEN_BYTES                                86
#define NEXT_UPDATE_TYPE_DIRECT                                         0
#define NEXT_UPDATE_TYPE_ROUTE                                          1
#define NEXT_UPDATE_TYPE_CONTINUE                                       2
#define NEXT_MAX_TOKENS                                                 7
#define NEXT_UPDATE_SEND_TIME                                        0.25
#define NEXT_ROUTE_REQUEST_SEND_TIME                                 0.25
#define NEXT_CONTINUE_REQUEST_SEND_TIME                              0.25
#define NEXT_SLICE_SECONDS                                           10.0
#define NEXT_ROUTE_REQUEST_TIMEOUT                                      5
#define NEXT_CONTINUE_REQUEST_TIMEOUT                                   5
#define NEXT_SESSION_UPDATE_RESEND_TIME                               1.0
#define NEXT_SESSION_UPDATE_TIMEOUT                                     5
#define NEXT_BANDWIDTH_LIMITER_INTERVAL                               1.0
#define NEXT_MATCH_DATA_RESEND_TIME                                  10.0
#define NEXT_MATCH_DATA_FLUSH_RESEND_TIME                             1.0
#define NEXT_SERVER_FLUSH_TIMEOUT                                    30.0

#define NEXT_CLIENT_COUNTER_OPEN_SESSION                                0
#define NEXT_CLIENT_COUNTER_CLOSE_SESSION                               1
#define NEXT_CLIENT_COUNTER_UPGRADE_SESSION                             2
#define NEXT_CLIENT_COUNTER_FALLBACK_TO_DIRECT                          3
#define NEXT_CLIENT_COUNTER_PACKET_SENT_PASSTHROUGH                     4
#define NEXT_CLIENT_COUNTER_PACKET_RECEIVED_PASSTHROUGH                 5
#define NEXT_CLIENT_COUNTER_PACKET_SENT_DIRECT                          6
#define NEXT_CLIENT_COUNTER_PACKET_RECEIVED_DIRECT                      7
#define NEXT_CLIENT_COUNTER_PACKET_SENT_NEXT                            8
#define NEXT_CLIENT_COUNTER_PACKET_RECEIVED_NEXT                        9
#define NEXT_CLIENT_COUNTER_MULTIPATH                                  10
#define NEXT_CLIENT_COUNTER_PACKETS_LOST_CLIENT_TO_SERVER              11
#define NEXT_CLIENT_COUNTER_PACKETS_LOST_SERVER_TO_CLIENT              12
#define NEXT_CLIENT_COUNTER_PACKETS_OUT_OF_ORDER_CLIENT_TO_SERVER      13
#define NEXT_CLIENT_COUNTER_PACKETS_OUT_OF_ORDER_SERVER_TO_CLIENT      14

#define NEXT_CLIENT_COUNTER_MAX                                        64

#define NEXT_PACKET_LOSS_TRACKER_HISTORY                             1024
#define NEXT_PACKET_LOSS_TRACKER_SAFETY                                30
#define NEXT_SECONDS_BETWEEN_PACKET_LOSS_UPDATES                      0.1

#define NEXT_SERVER_INIT_RESPONSE_OK                                    0
#define NEXT_SERVER_INIT_RESPONSE_UNKNOWN_CUSTOMER                      1
#define NEXT_SERVER_INIT_RESPONSE_UNKNOWN_DATACENTER                    2
#define NEXT_SERVER_INIT_RESPONSE_SDK_VERSION_TOO_OLD                   3
#define NEXT_SERVER_INIT_RESPONSE_SIGNATURE_CHECK_FAILED                4
#define NEXT_SERVER_INIT_RESPONSE_CUSTOMER_NOT_ACTIVE                   5
#define NEXT_SERVER_INIT_RESPONSE_DATACENTER_NOT_ENABLED                6

#define NEXT_FLAGS_BAD_ROUTE_TOKEN                                 (1<<0)
#define NEXT_FLAGS_NO_ROUTE_TO_CONTINUE                            (1<<1)
#define NEXT_FLAGS_PREVIOUS_UPDATE_STILL_PENDING                   (1<<2)
#define NEXT_FLAGS_BAD_CONTINUE_TOKEN                              (1<<3)
#define NEXT_FLAGS_ROUTE_EXPIRED                                   (1<<4)
#define NEXT_FLAGS_ROUTE_REQUEST_TIMED_OUT                         (1<<5)
#define NEXT_FLAGS_CONTINUE_REQUEST_TIMED_OUT                      (1<<6)
#define NEXT_FLAGS_ROUTE_TIMED_OUT                                 (1<<7)
#define NEXT_FLAGS_UPGRADE_RESPONSE_TIMED_OUT                      (1<<8)
#define NEXT_FLAGS_ROUTE_UPDATE_TIMED_OUT                          (1<<9)
#define NEXT_FLAGS_DIRECT_PONG_TIMED_OUT                          (1<<10)
#define NEXT_FLAGS_NEXT_PONG_TIMED_OUT                            (1<<11)
#define NEXT_FLAGS_COUNT                                               12

#define NEXT_MAX_DATACENTER_NAME_LENGTH                               256

#define NEXT_MAX_SESSION_DATA_BYTES                                  1024

#define NEXT_MAX_SESSION_UPDATE_RETRIES                                10

#define NEXT_PASSTHROUGH_PACKET                                         0
#define NEXT_DIRECT_PACKET                                              1
#define NEXT_DIRECT_PING_PACKET                                         2
#define NEXT_DIRECT_PONG_PACKET                                         3
#define NEXT_UPGRADE_REQUEST_PACKET                                     4
#define NEXT_UPGRADE_RESPONSE_PACKET                                    5
#define NEXT_UPGRADE_CONFIRM_PACKET                                     6
#define NEXT_OLD_RELAY_PING_PACKET                                      7
#define NEXT_OLD_RELAY_PONG_PACKET                                      8
#define NEXT_ROUTE_REQUEST_PACKET                                       9
#define NEXT_ROUTE_RESPONSE_PACKET                                     10
#define NEXT_CLIENT_TO_SERVER_PACKET                                   11
#define NEXT_SERVER_TO_CLIENT_PACKET                                   12
#define NEXT_PING_PACKET                                               13
#define NEXT_PONG_PACKET                                               14
#define NEXT_CONTINUE_REQUEST_PACKET                                   15
#define NEXT_CONTINUE_RESPONSE_PACKET                                  16
#define NEXT_CLIENT_STATS_PACKET                                       17
#define NEXT_ROUTE_UPDATE_PACKET                                       18
#define NEXT_ROUTE_UPDATE_ACK_PACKET                                   19
#define NEXT_RELAY_PING_PACKET                                         20
#define NEXT_RELAY_PONG_PACKET                                         21

#define NEXT_BACKEND_SERVER_INIT_REQUEST_PACKET                        50
#define NEXT_BACKEND_SERVER_INIT_RESPONSE_PACKET                       51
#define NEXT_BACKEND_SERVER_UPDATE_REQUEST_PACKET                      52
#define NEXT_BACKEND_SERVER_UPDATE_RESPONSE_PACKET                     53
#define NEXT_BACKEND_SESSION_UPDATE_REQUEST_PACKET                     54
#define NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET                    55
#define NEXT_BACKEND_MATCH_DATA_REQUEST_PACKET                         56
#define NEXT_BACKEND_MATCH_DATA_RESPONSE_PACKET                        57

#define NEXT_CLIENT_ROUTE_UPDATE_TIMEOUT                               15

#define NEXT_MAX_SESSION_DEBUG                                       1024

#define NEXT_PING_RATE                                                 10

#define NEXT_ETHERNET_HEADER_BYTES                                     18
#define NEXT_IPV4_HEADER_BYTES                                         20
#define NEXT_UDP_HEADER_BYTES                                           8
#define NEXT_HEADER_BYTES                                              33

// todo: this must be replaced with a new keypair in production
static uint8_t next_server_backend_public_key[] =
{
     76,  97, 202, 140,  71, 135,  62, 212,
    160, 181, 151, 195, 202, 224, 207, 113,
      8,  45,  37,  60, 145,  14, 212, 111,
     25,  34, 175, 186,  37, 150, 163,  64
};

// todo: this must be replaced with a new keypair in production
static uint8_t next_router_public_key[] =
{
    0x49, 0x2e, 0x79, 0x74, 0x49, 0x7d, 0x9d, 0x34,
    0xa7, 0x55, 0x50, 0xeb, 0xab, 0x03, 0xde, 0xa9,
    0x1b, 0xff, 0x61, 0xc6, 0x0e, 0x65, 0x92, 0xd7,
    0x09, 0x64, 0xe9, 0x34, 0x12, 0x32, 0x5f, 0x46
};

#if !defined (NEXT_LITTLE_ENDIAN ) && !defined( NEXT_BIG_ENDIAN )

  #ifdef __BYTE_ORDER__
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
      #define NEXT_LITTLE_ENDIAN 1
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
      #define NEXT_BIG_ENDIAN 1
    #else
      #error Unknown machine endianess detected. Please define NEXT_LITTLE_ENDIAN or NEXT_BIG_ENDIAN.
    #endif // __BYTE_ORDER__

  // Detect with GLIBC's endian.h
  #elif defined(__GLIBC__)
    #include <endian.h>
    #if (__BYTE_ORDER == __LITTLE_ENDIAN)
      #define NEXT_LITTLE_ENDIAN 1
    #elif (__BYTE_ORDER == __BIG_ENDIAN)
      #define NEXT_BIG_ENDIAN 1
    #else
      #error Unknown machine endianess detected. Please define NEXT_LITTLE_ENDIAN or NEXT_BIG_ENDIAN.
    #endif // __BYTE_ORDER

  // Detect with _LITTLE_ENDIAN and _BIG_ENDIAN macro
  #elif defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
    #define NEXT_LITTLE_ENDIAN 1
  #elif defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN)
    #define NEXT_BIG_ENDIAN 1

  // Detect with architecture macros
  #elif    defined(__sparc)     || defined(__sparc__)                           \
        || defined(_POWER)      || defined(__powerpc__)                         \
        || defined(__ppc__)     || defined(__hpux)      || defined(__hppa)      \
        || defined(_MIPSEB)     || defined(_POWER)      || defined(__s390__)
    #define NEXT_BIG_ENDIAN 1
  #elif    defined(__i386__)    || defined(__alpha__)   || defined(__ia64)      \
        || defined(__ia64__)    || defined(_M_IX86)     || defined(_M_IA64)     \
        || defined(_M_ALPHA)    || defined(__amd64)     || defined(__amd64__)   \
        || defined(_M_AMD64)    || defined(__x86_64)    || defined(__x86_64__)  \
        || defined(_M_X64)      || defined(__bfin__)
    #define NEXT_LITTLE_ENDIAN 1
  #elif defined(_MSC_VER) && defined(_M_ARM)
    #define NEXT_LITTLE_ENDIAN 1
  #else
    #error Unknown machine endianess detected. Please define NEXT_LITTLE_ENDIAN or NEXT_BIG_ENDIAN.
  #endif

#endif

#if defined( _MSC_VER ) && _MSC_VER < 1700
typedef __int32 int32_t;
typedef __int64 int64_t;
#define PRId64 "I64d"
#define SCNd64 "I64d"
#define PRIx64 "I64x"
#define SCNx64 "I64x"
#else
#include <inttypes.h>
#endif

void next_printf( const char * format, ... );

static void default_assert_function( const char * condition, const char * function, const char * file, int line )
{
    next_printf( "assert failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
    fflush( stdout );
    #if defined(_MSC_VER)
        __debugbreak();
    #elif defined(__ORBIS__)
        __builtin_trap();
    #elif defined(__PROSPERO__)
        __builtin_trap();
    #elif defined(__clang__)
        __builtin_debugtrap();
    #elif defined(__GNUC__)
        __builtin_trap();
    #elif defined(linux) || defined(__linux) || defined(__linux__) || defined(__APPLE__)
        raise(SIGTRAP);
    #else
        #error "asserts not supported on this platform!"
    #endif
}

#if defined( _MSC_VER ) && _MSC_VER < 1900

#define snprintf c99_snprintf
#define vsnprintf c99_vsnprintf

__inline int c99_vsnprintf(char *outBuf, size_t size, const char *format, va_list ap)
{
    int count = -1;

    if (size != 0)
        count = _vsnprintf_s(outBuf, size, _TRUNCATE, format, ap);
    if (count == -1)
        count = _vscprintf(format, ap);

    return count;
}

__inline int c99_snprintf(char *outBuf, size_t size, const char *format, ...)
{
    int count;
    va_list ap;

    va_start(ap, format);
    count = c99_vsnprintf(outBuf, size, format, ap);
    va_end(ap);

    return count;
}

#endif

uint16_t next_ntohs( uint16_t in )
{
    return (uint16_t)( ( ( in << 8 ) & 0xFF00 ) | ( ( in >> 8 ) & 0x00FF ) );
}

uint16_t next_htons( uint16_t in )
{
    return (uint16_t)( ( ( in << 8 ) & 0xFF00 ) | ( ( in >> 8 ) & 0x00FF ) );
}

#if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS
#include "next_windows.h"
#elif NEXT_PLATFORM == NEXT_PLATFORM_MAC
#include "next_mac.h"
#elif NEXT_PLATFORM == NEXT_PLATFORM_LINUX
#include "next_linux.h"
#elif NEXT_PLATFORM == NEXT_PLATFORM_SWITCH
#include "next_switch.h"
#elif NEXT_PLATFORM == NEXT_PLATFORM_PS4
#include "next_ps4.h"
#elif NEXT_PLATFORM == NEXT_PLATFORM_PS5
#include "next_ps5.h"
#elif NEXT_PLATFORM == NEXT_PLATFORM_IOS
#include "next_ios.h"
#elif NEXT_PLATFORM == NEXT_PLATFORM_XBOX_ONE
#include "next_xboxone.h"
#endif

#ifdef _GAMING_XBOX
#include "next_gdk.h"
#endif // #ifdef _GAMING_XBOX

extern int next_platform_init();

extern void next_platform_term();

extern const char * next_platform_getenv( const char * );

extern double next_platform_time();

extern void next_platform_sleep( double seconds );

extern int next_platform_inet_pton4( const char * address_string, uint32_t * address_out );

extern int next_platform_inet_pton6( const char * address_string, uint16_t * address_out );

extern int next_platform_inet_ntop6( const uint16_t * address, char * address_string, size_t address_string_size );

extern next_platform_socket_t * next_platform_socket_create( void * context, next_address_t * address, int socket_type, float timeout_seconds, int send_buffer_size, int receive_buffer_size, bool enable_packet_tagging );

extern void next_platform_socket_destroy( next_platform_socket_t * socket );

extern void next_platform_socket_send_packet( next_platform_socket_t * socket, const next_address_t * to, const void * packet_data, int packet_bytes );

extern int next_platform_socket_receive_packet( next_platform_socket_t * socket, next_address_t * from, void * packet_data, int max_packet_size );

extern int next_platform_id();

extern int next_platform_connection_type();

extern int next_platform_hostname_resolve( const char * hostname, const char * port, next_address_t * address );

extern next_platform_thread_t * next_platform_thread_create( void * context, next_platform_thread_func_t func, void * arg );

extern void next_platform_thread_join( next_platform_thread_t * thread );

extern void next_platform_thread_destroy( next_platform_thread_t * thread );

extern bool next_platform_thread_high_priority( next_platform_thread_t * thread );

extern int next_platform_mutex_create( next_platform_mutex_t * mutex );

extern void next_platform_mutex_acquire( next_platform_mutex_t * mutex );

extern void next_platform_mutex_release( next_platform_mutex_t * mutex );

extern void next_platform_mutex_destroy( next_platform_mutex_t * mutex );

struct next_platform_mutex_helper_t
{
    next_platform_mutex_t * mutex;
    next_platform_mutex_helper_t( next_platform_mutex_t * mutex );
    ~next_platform_mutex_helper_t();
};

#define next_platform_mutex_guard( _mutex ) next_platform_mutex_helper_t __mutex_helper( _mutex )

next_platform_mutex_helper_t::next_platform_mutex_helper_t( next_platform_mutex_t * mutex ) : mutex( mutex )
{
    next_assert( mutex );
    next_platform_mutex_acquire( mutex );
}

next_platform_mutex_helper_t::~next_platform_mutex_helper_t()
{
    next_assert( mutex );
    next_platform_mutex_release( mutex );
    mutex = NULL;
}

// -------------------------------------------------------------

// #define NEXT_ENABLE_MEMORY_CHECKS 1

#if NEXT_ENABLE_MEMORY_CHECKS

    #define NEXT_DECLARE_SENTINEL(n) uint32_t next_sentinel_##n[64];

    #define NEXT_INITIALIZE_SENTINEL(pointer,n) for ( int i = 0; i < 64; ++i ) { pointer->next_sentinel_##n[i] = 0xBAADF00D; }

    #define NEXT_VERIFY_SENTINEL(pointer,n) for ( int i = 0; i < 64; ++i ) { next_assert( pointer->next_sentinel_##n[i] == 0xBAADF00D ); }

#else // #if NEXT_ENABLE_MEMORY_CHECKS

    #define NEXT_DECLARE_SENTINEL(n)

    #define NEXT_INITIALIZE_SENTINEL(pointer,n)

    #define NEXT_VERIFY_SENTINEL(pointer,n)

#endif // #if NEXT_ENABLE_MEMORY_CHECKS

// -------------------------------------------------------------

bool next_platform_getenv_bool(const char *name)
{
    const char *v = next_platform_getenv(name);
    if (v != NULL && v[0]) {
        return v[0] == '1' || v[0] == 't' || v[0] == 'T';
    }
    return false;
}

double next_time()
{
#if NEXT_DEVELOPMENT
    return next_platform_time() + 100000.0;
#else // #if NEXT_DEVELOPMENT
    return next_platform_time();
#endif // #if NEXT_DEVELOPMENT
}

void next_sleep( double time_seconds )
{
    next_platform_sleep( time_seconds );
}

static int log_quiet = 0;

void next_quiet( NEXT_BOOL flag )
{
    log_quiet = flag;
}

static int log_level = NEXT_LOG_LEVEL_INFO;

void next_log_level( int level )
{
    log_level = level;
}

void (*next_assert_function_pointer)( const char * condition, const char * function, const char * file, int line ) = default_assert_function;

void next_assert_function( void (*function)( const char * condition, const char * function, const char * file, int line ) )
{
    next_assert_function_pointer = function;
}

const char * next_log_level_string( int level )
{
    if ( level == NEXT_LOG_LEVEL_SPAM )
        return "spam";
    else if ( level == NEXT_LOG_LEVEL_DEBUG )
        return "debug";
    else if ( level == NEXT_LOG_LEVEL_INFO )
        return "info";
    else if ( level == NEXT_LOG_LEVEL_ERROR )
        return "error";
    else if ( level == NEXT_LOG_LEVEL_WARN )
        return "warning";
    else
        return "???";
}

static void default_log_function( int level, const char * format, ... )
{
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof( buffer ), format, args );
    if ( level != NEXT_LOG_LEVEL_NONE )
    {
        if ( !log_quiet )
        {
            const char * level_string = next_log_level_string( level );
            printf( "%.6f: %s: %s\n", next_time(), level_string, buffer );
        }
    }
    else
    {
        printf( "%s\n", buffer );
    }
    va_end( args );
    fflush( stdout );
}

static void (*log_function)( int level, const char * format, ... ) = default_log_function;

void next_log_function( void (*function)( int level, const char * format, ... ) )
{
    log_function = function;
}

static void * next_default_malloc_function( void * context, size_t bytes )
{
    (void) context;
    return malloc( bytes );
}

static void next_default_free_function( void * context, void * p )
{
    (void) context;
    free( p );
}

static void * (*next_malloc_function)( void * context, size_t bytes ) = next_default_malloc_function;
static void (*next_free_function)( void * context, void * p ) = next_default_free_function;

void next_allocator( void * (*malloc_function)( void * context, size_t bytes ), void (*free_function)( void * context, void * p ) )
{
    next_assert( malloc_function );
    next_assert( free_function );
    next_malloc_function = malloc_function;
    next_free_function = free_function;
}

void * next_malloc( void * context, size_t bytes )
{
    next_assert( next_malloc_function );
    return next_malloc_function( context, bytes );
}

void next_free( void * context, void * p )
{
    next_assert( next_free_function );
    return next_free_function( context, p );
}

__inline void clear_and_free( void * context, void * p, size_t p_size )
{
    memset( p, 0, p_size );
    next_free( context, p );
}

void next_printf( const char * format, ... )
{
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof(buffer), format, args );
    log_function( NEXT_LOG_LEVEL_NONE, "%s", buffer );
    va_end( args );
}

void next_printf( int level, const char * format, ... )
{
    if ( level > log_level )
        return;
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof( buffer ), format, args );
    log_function( level, "%s", buffer );
    va_end( args );
}

const char * next_user_id_string( uint64_t user_id, char * buffer, size_t buffer_size )
{
    snprintf( buffer, buffer_size, "%" PRIx64, user_id );
    return buffer;
}

// -------------------------------------------------------------

void next_write_uint8( uint8_t ** p, uint8_t value )
{
    **p = value;
    ++(*p);
}

void next_write_uint16( uint8_t ** p, uint16_t value )
{
    (*p)[0] = value & 0xFF;
    (*p)[1] = value >> 8;
    *p += 2;
}

void next_write_uint32( uint8_t ** p, uint32_t value )
{
    (*p)[0] = value & 0xFF;
    (*p)[1] = ( value >> 8  ) & 0xFF;
    (*p)[2] = ( value >> 16 ) & 0xFF;
    (*p)[3] = value >> 24;
    *p += 4;
}

void next_write_uint64( uint8_t ** p, uint64_t value )
{
    (*p)[0] = value & 0xFF;
    (*p)[1] = ( value >> 8  ) & 0xFF;
    (*p)[2] = ( value >> 16 ) & 0xFF;
    (*p)[3] = ( value >> 24 ) & 0xFF;
    (*p)[4] = ( value >> 32 ) & 0xFF;
    (*p)[5] = ( value >> 40 ) & 0xFF;
    (*p)[6] = ( value >> 48 ) & 0xFF;
    (*p)[7] = value >> 56;
    *p += 8;
}

void next_write_float32( uint8_t ** p, float value )
{
    uint32_t value_int = 0;
    char * p_value = (char*)(&value);
    char * p_value_int = (char*)(&value_int);
    memcpy(p_value_int, p_value, sizeof(uint32_t));
    next_write_uint32( p, value_int);
}

void next_write_float64( uint8_t ** p, double value )
{
    uint64_t value_int = 0;
    char * p_value = (char *)(&value);
    char * p_value_int = (char *)(&value_int);
    memcpy(p_value_int, p_value, sizeof(uint64_t));
    next_write_uint64( p, value_int);
}

void next_write_bytes( uint8_t ** p, const uint8_t * byte_array, int num_bytes )
{
    for ( int i = 0; i < num_bytes; ++i )
    {
        next_write_uint8( p, byte_array[i] );
    }
}

uint8_t next_read_uint8( const uint8_t ** p )
{
    uint8_t value = **p;
    ++(*p);
    return value;
}

uint16_t next_read_uint16( const uint8_t ** p )
{
    uint16_t value;
    value = (*p)[0];
    value |= ( ( (uint16_t)( (*p)[1] ) ) << 8 );
    *p += 2;
    return value;
}

uint32_t next_read_uint32( const uint8_t ** p )
{
    uint32_t value;
    value  = (*p)[0];
    value |= ( ( (uint32_t)( (*p)[1] ) ) << 8 );
    value |= ( ( (uint32_t)( (*p)[2] ) ) << 16 );
    value |= ( ( (uint32_t)( (*p)[3] ) ) << 24 );
    *p += 4;
    return value;
}

uint64_t next_read_uint64( const uint8_t ** p )
{
    uint64_t value;
    value  = (*p)[0];
    value |= ( ( (uint64_t)( (*p)[1] ) ) << 8  );
    value |= ( ( (uint64_t)( (*p)[2] ) ) << 16 );
    value |= ( ( (uint64_t)( (*p)[3] ) ) << 24 );
    value |= ( ( (uint64_t)( (*p)[4] ) ) << 32 );
    value |= ( ( (uint64_t)( (*p)[5] ) ) << 40 );
    value |= ( ( (uint64_t)( (*p)[6] ) ) << 48 );
    value |= ( ( (uint64_t)( (*p)[7] ) ) << 56 );
    *p += 8;
    return value;
}

float next_read_float32( const uint8_t ** p )
{
    uint32_t value_int = next_read_uint32( p );
    float value_float = 0.0f;
    uint8_t * pointer_int = (uint8_t *)( &value_int );
    uint8_t * pointer_float = (uint8_t *)( &value_float );
    memcpy( pointer_float, pointer_int, sizeof( value_int ) );
    return value_float;
}

double next_read_float64( const uint8_t ** p )
{
    uint64_t value_int = next_read_uint64( p );
    double value_float = 0.0;
    uint8_t * pointer_int = (uint8_t *)( &value_int );
    uint8_t * pointer_float = (uint8_t *)( &value_float );
    memcpy( pointer_float, pointer_int, sizeof( value_int ) );
    return value_float;
}

void next_read_bytes( const uint8_t ** p, uint8_t * byte_array, int num_bytes )
{
    for ( int i = 0; i < num_bytes; ++i )
    {
        byte_array[i] = next_read_uint8( p );
    }
}

// ------------------------------------------------------------

void next_write_address( uint8_t ** buffer, const next_address_t * address )
{
    next_assert( buffer );
    next_assert( *buffer );
    next_assert( address );

    uint8_t * start = *buffer;

    (void) buffer;

    if ( address->type == NEXT_ADDRESS_IPV4 )
    {
        next_write_uint8( buffer, NEXT_ADDRESS_IPV4 );
        for ( int i = 0; i < 4; ++i )
        {
            next_write_uint8( buffer, address->data.ipv4[i] );
        }
        next_write_uint16( buffer, address->port );
        for ( int i = 0; i < 12; ++i )
        {
            next_write_uint8( buffer, 0 );
        }
    }
    else if ( address->type == NEXT_ADDRESS_IPV6 )
    {
        next_write_uint8( buffer, NEXT_ADDRESS_IPV6 );
        for ( int i = 0; i < 8; ++i )
        {
            next_write_uint16( buffer, address->data.ipv6[i] );
        }
        next_write_uint16( buffer, address->port );
    }
    else
    {
        for ( int i = 0; i < NEXT_ADDRESS_BYTES; ++i )
        {
            next_write_uint8( buffer, 0 );
        }
    }

    (void) start;

    next_assert( *buffer - start == NEXT_ADDRESS_BYTES );
}

void next_read_address( const uint8_t ** buffer, next_address_t * address )
{
    const uint8_t * start = *buffer;

    memset( address, 0, sizeof(next_address_t) );

    address->type = next_read_uint8( buffer );

    if ( address->type == NEXT_ADDRESS_IPV4 )
    {
        for ( int j = 0; j < 4; ++j )
        {
            address->data.ipv4[j] = next_read_uint8( buffer );
        }
        address->port = next_read_uint16( buffer );
        for ( int i = 0; i < 12; ++i )
        {
            uint8_t dummy = next_read_uint8( buffer ); (void) dummy;
        }
    }
    else if ( address->type == NEXT_ADDRESS_IPV6 )
    {
        for ( int j = 0; j < 8; ++j )
        {
            address->data.ipv6[j] = next_read_uint16( buffer );
        }
        address->port = next_read_uint16( buffer );
    }
    else
    {
        for ( int i = 0; i < NEXT_ADDRESS_BYTES - 1; ++i )
        {
            uint8_t dummy = next_read_uint8( buffer ); (void) dummy;
        }
    }

    (void) start;

    next_assert( *buffer - start == NEXT_ADDRESS_BYTES );
}

void next_read_address_variable( const uint8_t ** buffer, next_address_t * address )
{
    const uint8_t * start = *buffer;

    memset( address, 0, sizeof(next_address_t) );

    address->type = next_read_uint8( buffer );

    if ( address->type == NEXT_ADDRESS_IPV4 )
    {
        for ( int j = 0; j < 4; ++j )
        {
            address->data.ipv4[j] = next_read_uint8( buffer );
        }
        address->port = next_read_uint16( buffer );
    }
    else if ( address->type == NEXT_ADDRESS_IPV6 )
    {
        for ( int j = 0; j < 8; ++j )
        {
            address->data.ipv6[j] = next_read_uint16( buffer );
        }
        address->port = next_read_uint16( buffer );
    }

    (void) start;
}

// -------------------------------------------------------------

static const unsigned char base64_table_encode[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int next_base64_encode_data( const uint8_t * input, size_t input_length, char * output, size_t output_size )
{
    next_assert( input );
    next_assert( output );
    next_assert( output_size > 0 );

    char * pos;
    const uint8_t * end;
    const uint8_t * in;

    size_t output_length = 4 * ( ( input_length + 2 ) / 3 ); // 3-byte blocks to 4-byte

    if ( output_length < input_length )
    {
        return -1; // integer overflow
    }

    if ( output_length >= output_size )
    {
        return -1; // not enough room in output buffer
    }

    end = input + input_length;
    in = input;
    pos = output;
    while ( end - in >= 3 )
    {
        *pos++ = base64_table_encode[in[0] >> 2];
        *pos++ = base64_table_encode[( ( in[0] & 0x03 ) << 4 ) | ( in[1] >> 4 )];
        *pos++ = base64_table_encode[( ( in[1] & 0x0f ) << 2 ) | ( in[2] >> 6 )];
        *pos++ = base64_table_encode[in[2] & 0x3f];
        in += 3;
    }

    if ( end - in )
    {
        *pos++ = base64_table_encode[in[0] >> 2];
        if (end - in == 1)
        {
            *pos++ = base64_table_encode[(in[0] & 0x03) << 4];
            *pos++ = '=';
        }
        else
        {
            *pos++ = base64_table_encode[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = base64_table_encode[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
    }

    output[output_length] = '\0';

    return int( output_length );
}

static const int base64_table_decode[256] =
{
    0,  0,  0,  0,  0,  0,   0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,   0,  0,  0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
    56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
    7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
    0,  0,  0,  63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
};

int next_base64_decode_data( const char * input, uint8_t * output, size_t output_size )
{
    next_assert( input );
    next_assert( output );
    next_assert( output_size > 0 );

    size_t input_length = strlen( input );
    int pad = input_length > 0 && ( input_length % 4 || input[input_length - 1] == '=' );
    size_t L = ( ( input_length + 3 ) / 4 - pad ) * 4;
    size_t output_length = L / 4 * 3 + pad;

    if ( output_length > output_size )
    {
        return 0;
    }

    for ( size_t i = 0, j = 0; i < L; i += 4 )
    {
        int n = base64_table_decode[int( input[i] )] << 18 | base64_table_decode[int( input[i + 1] )] << 12 | base64_table_decode[int( input[i + 2] )] << 6 | base64_table_decode[int( input[i + 3] )];
        output[j++] = uint8_t( n >> 16 );
        output[j++] = uint8_t( n >> 8 & 0xFF );
        output[j++] = uint8_t( n & 0xFF );
    }

    if ( pad )
    {
        int n = base64_table_decode[int( input[L] )] << 18 | base64_table_decode[int( input[L + 1] )] << 12;
        output[output_length - 1] = uint8_t( n >> 16 );

        if (input_length > L + 2 && input[L + 2] != '=')
        {
            n |= base64_table_decode[int( input[L + 2] )] << 6;
            output_length += 1;
            if ( output_length > output_size )
            {
                return 0;
            }
            output[output_length - 1] = uint8_t( n >> 8 & 0xFF );
        }
    }

    return int( output_length );
}

int next_base64_encode_string( const char * input, char * output, size_t output_size )
{
    next_assert( input );
    next_assert( output );
    next_assert( output_size > 0 );

    return next_base64_encode_data( (const uint8_t *)( input ), strlen( input ), output, output_size );
}

int next_base64_decode_string( const char * input, char * output, size_t output_size )
{
    next_assert( input );
    next_assert( output );
    next_assert( output_size > 0 );

    int output_length = next_base64_decode_data( input, (uint8_t *)( output ), output_size - 1 );
    if ( output_length < 0 )
    {
        return 0;
    }

    output[output_length] = '\0';

    return output_length;
}

// -------------------------------------------------------------

typedef uint64_t next_fnv_t;

void next_fnv_init( next_fnv_t * fnv )
{
    *fnv = 0xCBF29CE484222325;
}

void next_fnv_write( next_fnv_t * fnv, const uint8_t * data, size_t size )
{
    for ( size_t i = 0; i < size; i++ )
    {
        (*fnv) ^= data[i];
        (*fnv) *= 0x00000100000001B3;
    }
}

uint64_t next_fnv_finalize( next_fnv_t * fnv )
{
    return *fnv;
}

uint64_t next_hash_string( const char * string )
{
    next_fnv_t fnv;
    next_fnv_init( &fnv );
    next_fnv_write( &fnv, (uint8_t *)( string ), strlen( string ) );
    return next_fnv_finalize( &fnv );
}

uint64_t next_tag_id( const char * name )
{
    if ( name == NULL || name[0] == '\0' || strcmp( name, "default" ) == 0 || strcmp( name, "none" ) == 0 )
        return 0;
    else
        return next_hash_string( name );
}

uint64_t next_relay_id( const char * name )
{
    return next_hash_string( name );
}

uint64_t next_datacenter_id( const char * name )
{
    return next_hash_string( name );
}

uint64_t next_protocol_version()
{
#if !NEXT_DEVELOPMENT
    #define VERSION_STRING(major,minor) #major #minor
    return next_hash_string( VERSION_STRING(NEXT_VERSION_MAJOR_INT, NEXT_VERSION_MINOR_INT) );
#else // #if !NEXT_DEVELOPMENT
    return 0;
#endif // #if !NEXT_DEVELOPMENT
}

// -------------------------------------------------------------

namespace next
{
    /**
        Calculates the population count of an unsigned 32 bit integer at compile time.
        See "Hacker's Delight" and http://www.hackersdelight.org/hdcodetxt/popArrayHS.c.txt
     */

    template <uint32_t x> struct PopCount
    {
        enum {   a = x - ( ( x >> 1 )       & 0x55555555 ),
                 b =   ( ( ( a >> 2 )       & 0x33333333 ) + ( a & 0x33333333 ) ),
                 c =   ( ( ( b >> 4 ) + b ) & 0x0f0f0f0f ),
                 d =   c + ( c >> 8 ),
                 e =   d + ( d >> 16 ),

            result = e & 0x0000003f
        };
    };

    /**
        Calculates the log 2 of an unsigned 32 bit integer at compile time.
     */

    template <uint32_t x> struct Log2
    {
        enum {   a = x | ( x >> 1 ),
                 b = a | ( a >> 2 ),
                 c = b | ( b >> 4 ),
                 d = c | ( c >> 8 ),
                 e = d | ( d >> 16 ),
                 f = e >> 1,

            result = PopCount<f>::result
        };
    };

    /**
        Calculates the number of bits required to serialize an integer value in [min,max] at compile time.
     */

    template <int64_t min, int64_t max> struct BitsRequired
    {
        static const uint32_t result = ( min == max ) ? 0 : ( Log2<uint32_t(max-min)>::result + 1 );
    };

    /**
        Calculates the population count of an unsigned 32 bit integer.
        The population count is the number of bits in the integer set to 1.
        @param x The input integer value.
        @returns The number of bits set to 1 in the input value.
     */

    inline uint32_t popcount( uint32_t x )
    {
    #ifdef __GNUC__
        return __builtin_popcount( x );
    #else // #ifdef __GNUC__
        const uint32_t a = x - ( ( x >> 1 )       & 0x55555555 );
        const uint32_t b =   ( ( ( a >> 2 )       & 0x33333333 ) + ( a & 0x33333333 ) );
        const uint32_t c =   ( ( ( b >> 4 ) + b ) & 0x0f0f0f0f );
        const uint32_t d =   c + ( c >> 8 );
        const uint32_t e =   d + ( d >> 16 );
        const uint32_t result = e & 0x0000003f;
        return result;
    #endif // #ifdef __GNUC__
    }

    /**
        Calculates the log base 2 of an unsigned 32 bit integer.
        @param x The input integer value.
        @returns The log base 2 of the input.
     */

    inline uint32_t log2( uint32_t x )
    {
        const uint32_t a = x | ( x >> 1 );
        const uint32_t b = a | ( a >> 2 );
        const uint32_t c = b | ( b >> 4 );
        const uint32_t d = c | ( c >> 8 );
        const uint32_t e = d | ( d >> 16 );
        const uint32_t f = e >> 1;
        return popcount( f );
    }

    /**
        Calculates the number of bits required to serialize an integer in range [min,max].
        @param min The minimum value.
        @param max The maximum value.
        @returns The number of bits required to serialize the integer.
     */

    inline int bits_required( uint32_t min, uint32_t max )
    {
    #ifdef __GNUC__
        return ( min == max ) ? 0 : 32 - __builtin_clz( max - min );
    #else // #ifdef __GNUC__
        return ( min == max ) ? 0 : log2( max - min ) + 1;
    #endif // #ifdef __GNUC__
    }

    /**
        Reverse the order of bytes in a 64 bit integer.
        @param value The input value.
        @returns The input value with the byte order reversed.
     */

    inline uint64_t bswap( uint64_t value )
    {
    #ifdef __GNUC__
        return __builtin_bswap64( value );
    #else // #ifdef __GNUC__
        value = ( value & 0x00000000FFFFFFFF ) << 32 | ( value & 0xFFFFFFFF00000000 ) >> 32;
        value = ( value & 0x0000FFFF0000FFFF ) << 16 | ( value & 0xFFFF0000FFFF0000 ) >> 16;
        value = ( value & 0x00FF00FF00FF00FF ) << 8  | ( value & 0xFF00FF00FF00FF00 ) >> 8;
        return value;
    #endif // #ifdef __GNUC__
    }

    /**
        Reverse the order of bytes in a 32 bit integer.
        @param value The input value.
        @returns The input value with the byte order reversed.
     */

    inline uint32_t bswap( uint32_t value )
    {
    #ifdef __GNUC__
        return __builtin_bswap32( value );
    #else // #ifdef __GNUC__
        return ( value & 0x000000ff ) << 24 | ( value & 0x0000ff00 ) << 8 | ( value & 0x00ff0000 ) >> 8 | ( value & 0xff000000 ) >> 24;
    #endif // #ifdef __GNUC__
    }

    /**
        Reverse the order of bytes in a 16 bit integer.
        @param value The input value.
        @returns The input value with the byte order reversed.
     */

    inline uint16_t bswap( uint16_t value )
    {
        return ( value & 0x00ff ) << 8 | ( value & 0xff00 ) >> 8;
    }

    /**
        Template to convert an integer value from local byte order to network byte order.
        IMPORTANT: Because most machines running next are little endian, next defines network byte order to be little endian.
        @param value The input value in local byte order. Supported integer types: uint64_t, uint32_t, uint16_t.
        @returns The input value converted to network byte order. If this processor is little endian the output is the same as the input. If the processor is big endian, the output is the input byte swapped.
     */

    template <typename T> T host_to_network( T value )
    {
    #if NEXT_BIG_ENDIAN
        return bswap( value );
    #else // #if NEXT_BIG_ENDIAN
        return value;
    #endif // #if NEXT_BIG_ENDIAN
    }

    /**
        Template to convert an integer value from network byte order to local byte order.
        IMPORTANT: Because most machines running next are little endian, next defines network byte order to be little endian.
        @param value The input value in network byte order. Supported integer types: uint64_t, uint32_t, uint16_t.
        @returns The input value converted to local byte order. If this processor is little endian the output is the same as the input. If the processor is big endian, the output is the input byte swapped.
     */

    template <typename T> T network_to_host( T value )
    {
    #if NEXT_BIG_ENDIAN
        return bswap( value );
    #else // #if NEXT_BIG_ENDIAN
        return value;
    #endif // #if NEXT_BIG_ENDIAN
    }

    /**
        Compares two 16 bit sequence numbers and returns true if the first one is greater than the second (considering wrapping).
        IMPORTANT: This is not the same as s1 > s2!
        Greater than is defined specially to handle wrapping sequence numbers.
        If the two sequence numbers are close together, it is as normal, but they are far apart, it is assumed that they have wrapped around.
        Thus, sequence_greater_than( 1, 0 ) returns true, and so does sequence_greater_than( 0, 65535 )!
        @param s1 The first sequence number.
        @param s2 The second sequence number.
        @returns True if the s1 is greater than s2, with sequence number wrapping considered.
     */

    inline bool sequence_greater_than( uint16_t s1, uint16_t s2 )
    {
        return ( ( s1 > s2 ) && ( s1 - s2 <= 32768 ) ) ||
               ( ( s1 < s2 ) && ( s2 - s1  > 32768 ) );
    }

    /**
        Compares two 16 bit sequence numbers and returns true if the first one is less than the second (considering wrapping).
        IMPORTANT: This is not the same as s1 < s2!
        Greater than is defined specially to handle wrapping sequence numbers.
        If the two sequence numbers are close together, it is as normal, but they are far apart, it is assumed that they have wrapped around.
        Thus, sequence_less_than( 0, 1 ) returns true, and so does sequence_greater_than( 65535, 0 )!
        @param s1 The first sequence number.
        @param s2 The second sequence number.
        @returns True if the s1 is less than s2, with sequence number wrapping considered.
     */

    inline bool sequence_less_than( uint16_t s1, uint16_t s2 )
    {
        return sequence_greater_than( s2, s1 );
    }

    /**
        Bitpacks unsigned integer values to a buffer.
        Integer bit values are written to a 64 bit scratch value from right to left.
        Once the low 32 bits of the scratch is filled with bits it is flushed to memory as a dword and the scratch value is shifted right by 32.
        The bit stream is written to memory in little endian order, which is considered network byte order for this library.
     */

    class BitWriter
    {
    public:

        /**
            Bit writer constructor.
            Creates a bit writer object to write to the specified buffer.
            @param data The pointer to the buffer to fill with bitpacked data.
            @param bytes The size of the buffer in bytes. Must be a multiple of 4, because the bitpacker reads and writes memory as dwords, not bytes.
         */

        BitWriter( void * data, int bytes ) : m_data( (uint32_t*) data ), m_numWords( bytes / 4 )
        {
            next_assert( data );
            next_assert( ( bytes % 4 ) == 0 );                // IMPORTANT: buffer length should be a multiple of 4 bytes
            m_numBits = m_numWords * 32;
            m_bitsWritten = 0;
            m_wordIndex = 0;
            m_scratch = 0;
            m_scratchBits = 0;
        }

        /**
            Write bits to the buffer.
            Bits are written to the buffer as-is, without padding to nearest byte. Will assert if you try to write past the end of the buffer.
            A boolean value writes just 1 bit to the buffer, a value in range [0,31] can be written with just 5 bits and so on.
            IMPORTANT: When you have finished writing to your buffer, take care to call BitWrite::FlushBits, otherwise the last dword of data will not get flushed to memory!
            @param value The integer value to write to the buffer. Must be in [0,(1<<bits)-1].
            @param bits The number of bits to encode in [1,32].
         */

        void WriteBits( uint32_t value, int bits )
        {
            next_assert( bits > 0 );
            next_assert( bits <= 32 );
            next_assert( m_bitsWritten + bits <= m_numBits );
            next_assert( uint64_t( value ) <= ( ( 1ULL << bits ) - 1 ) );

            m_scratch |= uint64_t( value ) << m_scratchBits;

            m_scratchBits += bits;

            if ( m_scratchBits >= 32 )
            {
                next_assert( m_wordIndex < m_numWords );
                m_data[m_wordIndex] = host_to_network( uint32_t( m_scratch & 0xFFFFFFFF ) );
                m_scratch >>= 32;
                m_scratchBits -= 32;
                m_wordIndex++;
            }

            m_bitsWritten += bits;
        }

        /**
            Write an alignment to the bit stream, padding zeros so the bit index becomes is a multiple of 8.
            This is useful if you want to write some data to a packet that should be byte aligned. For example, an array of bytes, or a string.
            IMPORTANT: If the current bit index is already a multiple of 8, nothing is written.
         */

        void WriteAlign()
        {
            const int remainderBits = m_bitsWritten % 8;

            if ( remainderBits != 0 )
            {
                uint32_t zero = 0;
                WriteBits( zero, 8 - remainderBits );
                next_assert( ( m_bitsWritten % 8 ) == 0 );
            }
        }

        /**
            Write an array of bytes to the bit stream.
            Use this when you have to copy a large block of data into your bitstream.
            Faster than just writing each byte to the bit stream via BitWriter::WriteBits( value, 8 ), because it aligns to byte index and copies into the buffer without bitpacking.
            @param data The byte array data to write to the bit stream.
            @param bytes The number of bytes to write.
         */

        void WriteBytes( const uint8_t * data, int bytes )
        {
            next_assert( GetAlignBits() == 0 );
            next_assert( m_bitsWritten + bytes * 8 <= m_numBits );
            next_assert( ( m_bitsWritten % 32 ) == 0 || ( m_bitsWritten % 32 ) == 8 || ( m_bitsWritten % 32 ) == 16 || ( m_bitsWritten % 32 ) == 24 );

            int headBytes = ( 4 - ( m_bitsWritten % 32 ) / 8 ) % 4;
            if ( headBytes > bytes )
                headBytes = bytes;
            for ( int i = 0; i < headBytes; ++i )
                WriteBits( data[i], 8 );
            if ( headBytes == bytes )
                return;

            FlushBits();

            next_assert( GetAlignBits() == 0 );

            int numWords = ( bytes - headBytes ) / 4;
            if ( numWords > 0 )
            {
                next_assert( ( m_bitsWritten % 32 ) == 0 );
                memcpy( &m_data[m_wordIndex], data + headBytes, size_t(numWords) * 4 );
                m_bitsWritten += numWords * 32;
                m_wordIndex += numWords;
                m_scratch = 0;
            }

            next_assert( GetAlignBits() == 0 );

            int tailStart = headBytes + numWords * 4;
            int tailBytes = bytes - tailStart;
            next_assert( tailBytes >= 0 && tailBytes < 4 );
            for ( int i = 0; i < tailBytes; ++i )
                WriteBits( data[tailStart+i], 8 );

            next_assert( GetAlignBits() == 0 );

            next_assert( headBytes + numWords * 4 + tailBytes == bytes );
        }

        /**
            Flush any remaining bits to memory.
            Call this once after you've finished writing bits to flush the last dword of scratch to memory!
         */

        void FlushBits()
        {
            if ( m_scratchBits != 0 )
            {
                next_assert( m_scratchBits <= 32 );
                next_assert( m_wordIndex < m_numWords );
                m_data[m_wordIndex] = host_to_network( uint32_t( m_scratch & 0xFFFFFFFF ) );
                m_scratch >>= 32;
                m_scratchBits = 0;
                m_wordIndex++;
            }
        }

        /**
            How many align bits would be written, if we were to write an align right now?
            @returns Result in [0,7], where 0 is zero bits required to align (already aligned) and 7 is worst case.
         */

        int GetAlignBits() const
        {
            return ( 8 - ( m_bitsWritten % 8 ) ) % 8;
        }

        /**
            How many bits have we written so far?
            @returns The number of bits written to the bit buffer.
         */

        int GetBitsWritten() const
        {
            return m_bitsWritten;
        }

        /**
            How many bits are still available to write?
            For example, if the buffer size is 4, we have 32 bits available to write, if we have already written 10 bytes then 22 are still available to write.
            @returns The number of bits available to write.
         */

        int GetBitsAvailable() const
        {
            return m_numBits - m_bitsWritten;
        }

        /**
            Get a pointer to the data written by the bit writer.
            Corresponds to the data block passed in to the constructor.
            @returns Pointer to the data written by the bit writer.
         */

        const uint8_t * GetData() const
        {
            return (uint8_t*) m_data;
        }

        /**
            The number of bytes flushed to memory.
            This is effectively the size of the packet that you should send after you have finished bitpacking values with this class.
            The returned value is not always a multiple of 4, even though we flush dwords to memory. You won't miss any data in this case because the order of bits written is designed to work with the little endian memory layout.
            IMPORTANT: Make sure you call BitWriter::FlushBits before calling this method, otherwise you risk missing the last dword of data.
         */

        int GetBytesWritten() const
        {
            return ( m_bitsWritten + 7 ) / 8;
        }

    private:

        uint32_t * m_data;              ///< The buffer we are writing to, as a uint32_t * because we're writing dwords at a time.
        uint64_t m_scratch;             ///< The scratch value where we write bits to (right to left). 64 bit for overflow. Once # of bits in scratch is >= 32, the low 32 bits are flushed to memory.
        int m_numBits;                  ///< The number of bits in the buffer. This is equivalent to the size of the buffer in bytes multiplied by 8. Note that the buffer size must always be a multiple of 4.
        int m_numWords;                 ///< The number of words in the buffer. This is equivalent to the size of the buffer in bytes divided by 4. Note that the buffer size must always be a multiple of 4.
        int m_bitsWritten;              ///< The number of bits written so far.
        int m_wordIndex;                ///< The current word index. The next word flushed to memory will be at this index in m_data.
        int m_scratchBits;              ///< The number of bits in scratch. When this is >= 32, the low 32 bits of scratch is flushed to memory as a dword and scratch is shifted right by 32.
    };

    /**
        Reads bit packed integer values from a buffer.
        Relies on the user reconstructing the exact same set of bit reads as bit writes when the buffer was written. This is an unattributed bitpacked binary stream!
        Implementation: 32 bit dwords are read in from memory to the high bits of a scratch value as required. The user reads off bit values from the scratch value from the right, after which the scratch value is shifted by the same number of bits.
     */

    class BitReader
    {
    public:

        /**
            Bit reader constructor.
            Non-multiples of four buffer sizes are supported, as this naturally tends to occur when packets are read from the network.
            However, actual buffer allocated for the packet data must round up at least to the next 4 bytes in memory, because the bit reader reads dwords from memory not bytes.
            @param data Pointer to the bitpacked data to read.
            @param bytes The number of bytes of bitpacked data to read.
         */

    #if NEXT_ASSERTS
        BitReader( const void * data, int bytes ) : m_data( (const uint32_t*) data ), m_numBytes( bytes ), m_numWords( ( bytes + 3 ) / 4)
    #else // #if NEXT_ASSERTS
        BitReader( const void * data, int bytes ) : m_data( (const uint32_t*) data ), m_numBytes( bytes )
    #endif // #if NEXT_ASSERTS
        {
            next_assert( data );
            m_numBits = m_numBytes * 8;
            m_bitsRead = 0;
            m_scratch = 0;
            m_scratchBits = 0;
            m_wordIndex = 0;
        }

        /**
            Would the bit reader would read past the end of the buffer if it read this many bits?
            @param bits The number of bits that would be read.
            @returns True if reading the number of bits would read past the end of the buffer.
         */

        bool WouldReadPastEnd( int bits ) const
        {
            return m_bitsRead + bits > m_numBits;
        }

        /**
            Read bits from the bit buffer.
            This function will assert in debug builds if this read would read past the end of the buffer.
            In production situations, the higher level ReadStream takes care of checking all packet data and never calling this function if it would read past the end of the buffer.
            @param bits The number of bits to read in [1,32].
            @returns The integer value read in range [0,(1<<bits)-1].
         */

        uint32_t ReadBits( int bits )
        {
            next_assert( bits > 0 );
            next_assert( bits <= 32 );
            next_assert( m_bitsRead + bits <= m_numBits );

            m_bitsRead += bits;

            next_assert( m_scratchBits >= 0 && m_scratchBits <= 64 );

            if ( m_scratchBits < bits )
            {
                next_assert( m_wordIndex < m_numWords );
                m_scratch |= uint64_t( network_to_host( m_data[m_wordIndex] ) ) << m_scratchBits;
                m_scratchBits += 32;
                m_wordIndex++;
            }

            next_assert( m_scratchBits >= bits );

            const uint32_t output = m_scratch & ( (uint64_t(1)<<bits) - 1 );

            m_scratch >>= bits;
            m_scratchBits -= bits;

            return output;
        }

        /**
            Read an align.
            Call this on read to correspond to a WriteAlign call when the bitpacked buffer was written.
            This makes sure we skip ahead to the next aligned byte index. As a safety check, we verify that the padding to next byte is zero bits and return false if that's not the case.
            This will typically abort packet read. Just another safety measure...
            @returns True if we successfully read an align and skipped ahead past zero pad, false otherwise (probably means, no align was written to the stream).
         */

        bool ReadAlign()
        {
            const int remainderBits = m_bitsRead % 8;
            if ( remainderBits != 0 )
            {
                uint32_t value = ReadBits( 8 - remainderBits );
                next_assert( m_bitsRead % 8 == 0 );
                if ( value != 0 )
                    return false;
            }
            return true;
        }

        /**
            Read bytes from the bitpacked data.
         */

        void ReadBytes( uint8_t * data, int bytes )
        {
            next_assert( GetAlignBits() == 0 );
            next_assert( m_bitsRead + bytes * 8 <= m_numBits );
            next_assert( ( m_bitsRead % 32 ) == 0 || ( m_bitsRead % 32 ) == 8 || ( m_bitsRead % 32 ) == 16 || ( m_bitsRead % 32 ) == 24 );

            int headBytes = ( 4 - ( m_bitsRead % 32 ) / 8 ) % 4;
            if ( headBytes > bytes )
                headBytes = bytes;
            for ( int i = 0; i < headBytes; ++i )
                data[i] = (uint8_t) ReadBits( 8 );
            if ( headBytes == bytes )
                return;

            next_assert( GetAlignBits() == 0 );

            int numWords = ( bytes - headBytes ) / 4;
            if ( numWords > 0 )
            {
                next_assert( ( m_bitsRead % 32 ) == 0 );
                memcpy( data + headBytes, &m_data[m_wordIndex], size_t(numWords) * 4 );
                m_bitsRead += numWords * 32;
                m_wordIndex += numWords;
                m_scratchBits = 0;
            }

            next_assert( GetAlignBits() == 0 );

            int tailStart = headBytes + numWords * 4;
            int tailBytes = bytes - tailStart;
            next_assert( tailBytes >= 0 && tailBytes < 4 );
            for ( int i = 0; i < tailBytes; ++i )
                data[tailStart+i] = (uint8_t) ReadBits( 8 );

            next_assert( GetAlignBits() == 0 );

            next_assert( headBytes + numWords * 4 + tailBytes == bytes );
        }

        /**
            How many align bits would be read, if we were to read an align right now?
            @returns Result in [0,7], where 0 is zero bits required to align (already aligned) and 7 is worst case.
         */

        int GetAlignBits() const
        {
            return ( 8 - m_bitsRead % 8 ) % 8;
        }

        /**
            How many bits have we read so far?
            @returns The number of bits read from the bit buffer so far.
         */

        int GetBitsRead() const
        {
            return m_bitsRead;
        }

        /**
            How many bits are still available to read?
            For example, if the buffer size is 4, we have 32 bits available to read, if we have already written 10 bytes then 22 are still available.
            @returns The number of bits available to read.
         */

        int GetBitsRemaining() const
        {
            return m_numBits - m_bitsRead;
        }

    private:

        const uint32_t * m_data;            ///< The bitpacked data we're reading as a dword array.
        uint64_t m_scratch;                 ///< The scratch value. New data is read in 32 bits at a top to the left of this buffer, and data is read off to the right.
        int m_numBits;                      ///< Number of bits to read in the buffer. Of course, we can't *really* know this so it's actually m_numBytes * 8.
        int m_numBytes;                     ///< Number of bytes to read in the buffer. We know this, and this is the non-rounded up version.
    #if NEXT_ASSERTS
        int m_numWords;                     ///< Number of words to read in the buffer. This is rounded up to the next word if necessary.
    #endif // #if NEXT_ASSERTS
        int m_bitsRead;                     ///< Number of bits read from the buffer so far.
        int m_scratchBits;                  ///< Number of bits currently in the scratch value. If the user wants to read more bits than this, we have to go fetch another dword from memory.
        int m_wordIndex;                    ///< Index of the next word to read from memory.
    };

    /**
        Functionality common to all stream classes.
     */

    class BaseStream
    {
    public:

        /**
            Base stream constructor.
         */

        explicit BaseStream() : m_context( NULL ) {}

        /**
            Set a context on the stream.
         */

        void SetContext( void * context )
        {
            m_context = context;
        }

        /**
            Get the context pointer set on the stream.
            @returns The context pointer. May be NULL.
         */

        void * GetContext() const
        {
            return m_context;
        }

    private:

        void * m_context;                           ///< The context pointer set on the stream. May be NULL.
    };

    /**
        Stream class for writing bitpacked data.
        This class is a wrapper around the bit writer class. Its purpose is to provide unified interface for reading and writing.
        You can determine if you are writing to a stream by calling Stream::IsWriting inside your templated serialize method.
        This is evaluated at compile time, letting the compiler generate optimized serialize functions without the hassle of maintaining separate read and write functions.
        IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* macros instead. See test/shared.h for some examples.
     */

    class WriteStream : public BaseStream
    {
    public:

        enum { IsWriting = 1 };
        enum { IsReading = 0 };

        /**
            Write stream constructor.
            @param buffer The buffer to write to.
            @param bytes The number of bytes in the buffer. Must be a multiple of four.
            @param allocator The allocator to use for stream allocations. This lets you dynamically allocate memory as you read and write packets.
         */

        WriteStream( uint8_t * buffer, int bytes ) : m_writer( buffer, bytes ) {}

        /**
            Serialize an integer (write).
            @param value The integer value in [min,max].
            @param min The minimum value.
            @param max The maximum value.
            @returns Always returns true. All checking is performed by debug asserts only on write.
         */

        bool SerializeInteger( int32_t value, int32_t min, int32_t max )
        {
            next_assert( min < max );
            next_assert( value >= min );
            next_assert( value <= max );
            const int bits = bits_required( min, max );
            uint32_t unsigned_value = value - min;
            m_writer.WriteBits( unsigned_value, bits );
            return true;
        }

        /**
            Serialize a number of bits (write).
            @param value The unsigned integer value to serialize. Must be in range [0,(1<<bits)-1].
            @param bits The number of bits to write in [1,32].
            @returns Always returns true. All checking is performed by debug asserts on write.
         */

        bool SerializeBits( uint32_t value, int bits )
        {
            next_assert( bits > 0 );
            next_assert( bits <= 32 );
            m_writer.WriteBits( value, bits );
            return true;
        }

        /**
            Serialize an array of bytes (write).
            @param data Array of bytes to be written.
            @param bytes The number of bytes to write.
            @returns Always returns true. All checking is performed by debug asserts on write.
         */

        bool SerializeBytes( const uint8_t * data, int bytes )
        {
            next_assert( data );
            next_assert( bytes >= 0 );
            SerializeAlign();
            m_writer.WriteBytes( data, bytes );
            return true;
        }

        /**
            Serialize an align (write).
            @returns Always returns true. All checking is performed by debug asserts on write.
         */

        bool SerializeAlign()
        {
            m_writer.WriteAlign();
            return true;
        }

        /**
            If we were to write an align right now, how many bits would be required?
            @returns The number of zero pad bits required to achieve byte alignment in [0,7].
         */

        int GetAlignBits() const
        {
            return m_writer.GetAlignBits();
        }

        /**
            Flush the stream to memory after you finish writing.
            Always call this after you finish writing and before you call WriteStream::GetData, or you'll potentially truncate the last dword of data you wrote.
         */

        void Flush()
        {
            m_writer.FlushBits();
        }

        /**
            Get a pointer to the data written by the stream.
            IMPORTANT: Call WriteStream::Flush before you call this function!
            @returns A pointer to the data written by the stream
         */

        const uint8_t * GetData() const
        {
            return m_writer.GetData();
        }

        /**
            How many bytes have been written so far?
            @returns Number of bytes written. This is effectively the packet size.
         */

        int GetBytesProcessed() const
        {
            return m_writer.GetBytesWritten();
        }

        /**
            Get number of bits written so far.
            @returns Number of bits written.
         */

        int GetBitsProcessed() const
        {
            return m_writer.GetBitsWritten();
        }

    private:

        BitWriter m_writer;                 ///< The bit writer used for all bitpacked write operations.
    };

    /**
        Stream class for reading bitpacked data.
        This class is a wrapper around the bit reader class. Its purpose is to provide unified interface for reading and writing.
        You can determine if you are reading from a stream by calling Stream::IsReading inside your templated serialize method.
        This is evaluated at compile time, letting the compiler generate optimized serialize functions without the hassle of maintaining separate read and write functions.
        IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* macros instead. See test/shared.h for some examples.
     */

    class ReadStream : public BaseStream
    {
    public:

        enum { IsWriting = 0 };
        enum { IsReading = 1 };

        /**
            Read stream constructor.
            @param buffer The buffer to read from.
            @param bytes The number of bytes in the buffer. May be a non-multiple of four, however if it is, the underlying buffer allocated should be large enough to read the any remainder bytes as a dword.
            @param allocator The allocator to use for stream allocations. This lets you dynamically allocate memory as you read and write packets.
         */

        ReadStream( const uint8_t * buffer, int bytes ) : BaseStream(), m_reader( buffer, bytes ) {}

        /**
            Serialize an integer (read).
            @param value The integer value read is stored here. It is guaranteed to be in [min,max] if this function succeeds.
            @param min The minimum allowed value.
            @param max The maximum allowed value.
            @returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
         */

        bool SerializeInteger( int32_t & value, int32_t min, int32_t max )
        {
            next_assert( min < max );
            const int bits = bits_required( min, max );
            if ( m_reader.WouldReadPastEnd( bits ) )
                return false;
            uint32_t unsigned_value = m_reader.ReadBits( bits );
            value = (int32_t) unsigned_value + min;
            return true;
        }

        /**
            Serialize a number of bits (read).
            @param value The integer value read is stored here. Will be in range [0,(1<<bits)-1].
            @param bits The number of bits to read in [1,32].
            @returns Returns true if the serialize read succeeded, false otherwise.
         */

        bool SerializeBits( uint32_t & value, int bits )
        {
            next_assert( bits > 0 );
            next_assert( bits <= 32 );
            if ( m_reader.WouldReadPastEnd( bits ) )
                return false;
            uint32_t read_value = m_reader.ReadBits( bits );
            value = read_value;
            return true;
        }

        /**
            Serialize an array of bytes (read).
            @param data Array of bytes to read.
            @param bytes The number of bytes to read.
            @returns Returns true if the serialize read succeeded. False otherwise.
         */

        bool SerializeBytes( uint8_t * data, int bytes )
        {
            if ( !SerializeAlign() )
                return false;
            if ( m_reader.WouldReadPastEnd( bytes * 8 ) )
                return false;
            m_reader.ReadBytes( data, bytes );
            return true;
        }

        /**
            Serialize an align (read).
            @returns Returns true if the serialize read succeeded. False otherwise.
         */

        bool SerializeAlign()
        {
            const int alignBits = m_reader.GetAlignBits();
            if ( m_reader.WouldReadPastEnd( alignBits ) )
                return false;
            if ( !m_reader.ReadAlign() )
                return false;
            return true;
        }

        /**
            If we were to read an align right now, how many bits would we need to read?
            @returns The number of zero pad bits required to achieve byte alignment in [0,7].
         */

        int GetAlignBits() const
        {
            return m_reader.GetAlignBits();
        }

        /**
            Get number of bits read so far.
            @returns Number of bits read.
         */

        int GetBitsProcessed() const
        {
            return m_reader.GetBitsRead();
        }

        /**
            How many bytes have been read so far?
            @returns Number of bytes read. Effectively this is the number of bits read, rounded up to the next byte where necessary.
         */

        int GetBytesProcessed() const
        {
            return ( m_reader.GetBitsRead() + 7 ) / 8;
        }

    private:

        BitReader m_reader;             ///< The bit reader used for all bitpacked read operations.
    };

    /**
        Serialize integer value (read/write).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param value The integer value to serialize in [min,max].
        @param min The minimum value.
        @param max The maximum value.
     */

    #define serialize_int( stream, value, min, max )                    \
        do                                                              \
        {                                                               \
            next_assert( min < max );                                   \
            int32_t int32_value = 0;                                    \
            if ( Stream::IsWriting )                                    \
            {                                                           \
                next_assert( int64_t(value) >= int64_t(min) );          \
                next_assert( int64_t(value) <= int64_t(max) );          \
                int32_value = (int32_t) value;                          \
            }                                                           \
            if ( !stream.SerializeInteger( int32_value, min, max ) )    \
            {                                                           \
                return false;                                           \
            }                                                           \
            if ( Stream::IsReading )                                    \
            {                                                           \
                value = int32_value;                                    \
                if ( int64_t(value) < int64_t(min) ||                   \
                     int64_t(value) > int64_t(max) )                    \
                {                                                       \
                    return false;                                       \
                }                                                       \
            }                                                           \
        } while (0)

    /**
        Serialize bits to the stream (read/write).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param value The unsigned integer value to serialize.
        @param bits The number of bits to serialize in [1,32].
     */

    #define serialize_bits( stream, value, bits )                       \
        do                                                              \
        {                                                               \
            next_assert( bits > 0 );                                    \
            next_assert( bits <= 32 );                                  \
            uint32_t uint32_value = 0;                                  \
            if ( Stream::IsWriting )                                    \
            {                                                           \
                uint32_value = (uint32_t) value;                        \
            }                                                           \
            if ( !stream.SerializeBits( uint32_value, bits ) )          \
            {                                                           \
                return false;                                           \
            }                                                           \
            if ( Stream::IsReading )                                    \
            {                                                           \
                value = uint32_value;                                   \
            }                                                           \
        } while (0)

    /**
        Serialize a boolean value to the stream (read/write).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param value The boolean value to serialize.
     */

    #define serialize_bool( stream, value )                             \
        do                                                              \
        {                                                               \
            uint32_t uint32_bool_value = 0;                             \
            if ( Stream::IsWriting )                                    \
            {                                                           \
                uint32_bool_value = value ? 1 : 0;                      \
            }                                                           \
            serialize_bits( stream, uint32_bool_value, 1 );             \
            if ( Stream::IsReading )                                    \
            {                                                           \
                value = uint32_bool_value ? true : false;               \
            }                                                           \
        } while (0)

    template <typename Stream> bool serialize_float_internal( Stream & stream, float & value )
    {
        uint32_t int_value;
        if ( Stream::IsWriting )
        {
            memcpy( &int_value, &value, 4 );
        }
        bool result = stream.SerializeBits( int_value, 32 );
        if ( Stream::IsReading && result )
        {
            memcpy( &value, &int_value, 4 );
        }
        return result;
    }

    /**
        Serialize floating point value (read/write).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param value The float value to serialize.
     */

    #define serialize_float( stream, value )                                        \
        do                                                                          \
        {                                                                           \
            if ( !next::serialize_float_internal( stream, value ) )                 \
            {                                                                       \
                return false;                                                       \
            }                                                                       \
        } while (0)

    /**
        Serialize a 32 bit unsigned integer to the stream (read/write).
        This is a helper macro to make unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param value The unsigned 32 bit integer value to serialize.
     */

    #define serialize_uint32( stream, value ) serialize_bits( stream, value, 32 );

    template <typename Stream> bool serialize_uint64_internal( Stream & stream, uint64_t & value )
    {
        uint32_t hi = 0, lo = 0;
        if ( Stream::IsWriting )
        {
            lo = value & 0xFFFFFFFF;
            hi = value >> 32;
        }
        serialize_bits( stream, lo, 32 );
        serialize_bits( stream, hi, 32 );
        if ( Stream::IsReading )
        {
            value = ( uint64_t(hi) << 32 ) | lo;
        }
        return true;
    }

    /**
        Serialize a 64 bit unsigned integer to the stream (read/write).
        This is a helper macro to make unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param value The unsigned 64 bit integer value to serialize.
     */

    #define serialize_uint64( stream, value )                                       \
        do                                                                          \
        {                                                                           \
            if ( !next::serialize_uint64_internal( stream, value ) )                \
                return false;                                                       \
        } while (0)

    template <typename Stream> bool serialize_double_internal( Stream & stream, double & value )
    {
        union DoubleInt
        {
            double double_value;
            uint64_t int_value;
        };
        DoubleInt tmp = { 0 };
        if ( Stream::IsWriting )
        {
            tmp.double_value = value;
        }
        serialize_uint64( stream, tmp.int_value );
        if ( Stream::IsReading )
        {
            value = tmp.double_value;
        }
        return true;
    }

    /**
        Serialize double precision floating point value to the stream (read/write).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param value The double precision floating point value to serialize.
     */

    #define serialize_double( stream, value )                                       \
        do                                                                          \
        {                                                                           \
            if ( !next::serialize_double_internal( stream, value ) )                \
            {                                                                       \
                return false;                                                       \
            }                                                                       \
        } while (0)

    template <typename Stream> bool serialize_bytes_internal( Stream & stream, uint8_t * data, int bytes )
    {
        return stream.SerializeBytes( data, bytes );
    }

    /**
        Serialize an array of bytes to the stream (read/write).
        This is a helper macro to make unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param data Pointer to the data to be serialized.
        @param bytes The number of bytes to serialize.
     */

    #define serialize_bytes( stream, data, bytes )                                  \
        do                                                                          \
        {                                                                           \
            if ( !next::serialize_bytes_internal( stream, data, bytes ) )           \
            {                                                                       \
                return false;                                                       \
            }                                                                       \
        } while (0)

    template <typename Stream> bool serialize_string_internal( Stream & stream, char * string, int buffer_size )
    {
        int length = 0;
        if ( Stream::IsWriting )
        {
            length = (int) strlen( string );
            next_assert( length < buffer_size );
        }
        serialize_int( stream, length, 0, uint64_t(buffer_size) - 1 );
        serialize_bytes( stream, (uint8_t*)string, length );
        if ( Stream::IsReading )
        {
            string[length] = '\0';
        }
        return true;
    }

    /**
        Serialize a string to the stream (read/write).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param string The string to serialize write. Pointer to buffer to be filled on read.
        @param buffer_size The size of the string buffer. String with terminating null character must fit into this buffer.
     */

    #define serialize_string( stream, string, buffer_size )                                 \
        do                                                                                  \
        {                                                                                   \
            if ( !next::serialize_string_internal( stream, string, buffer_size ) )          \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
        } while (0)

    /**
        Serialize an alignment to the stream (read/write).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
     */

    #define serialize_align( stream )                                                       \
        do                                                                                  \
        {                                                                                   \
            if ( !stream.SerializeAlign() )                                                 \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
        } while (0)

    /**
        Serialize an object to the stream (read/write).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param object The object to serialize. Must have a serialize method on it.
     */

    #define serialize_object( stream, object )                                              \
        do                                                                                  \
        {                                                                                   \
            if ( !object.Serialize( stream ) )                                              \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
        }                                                                                   \
        while(0)

    template <typename Stream, typename T> bool serialize_int_relative_internal( Stream & stream, T previous, T & current )
    {
        uint32_t difference = 0;
        if ( Stream::IsWriting )
        {
            next_assert( previous < current );
            difference = current - previous;
        }

        bool oneBit = false;
        if ( Stream::IsWriting )
        {
            oneBit = difference == 1;
        }
        serialize_bool( stream, oneBit );
        if ( oneBit )
        {
            if ( Stream::IsReading )
            {
                current = previous + 1;
            }
            return true;
        }

        bool twoBits = false;
        if ( Stream::IsWriting )
        {
            twoBits = difference <= 6;
        }
        serialize_bool( stream, twoBits );
        if ( twoBits )
        {
            serialize_int( stream, difference, 2, 6 );
            if ( Stream::IsReading )
            {
                current = previous + difference;
            }
            return true;
        }

        bool fourBits = false;
        if ( Stream::IsWriting )
        {
            fourBits = difference <= 23;
        }
        serialize_bool( stream, fourBits );
        if ( fourBits )
        {
            serialize_int( stream, difference, 7, 23 );
            if ( Stream::IsReading )
            {
                current = previous + difference;
            }
            return true;
        }

        bool eightBits = false;
        if ( Stream::IsWriting )
        {
            eightBits = difference <= 280;
        }
        serialize_bool( stream, eightBits );
        if ( eightBits )
        {
            serialize_int( stream, difference, 24, 280 );
            if ( Stream::IsReading )
            {
                current = previous + difference;
            }
            return true;
        }

        bool twelveBits = false;
        if ( Stream::IsWriting )
        {
            twelveBits = difference <= 4377;
        }
        serialize_bool( stream, twelveBits );
        if ( twelveBits )
        {
            serialize_int( stream, difference, 281, 4377 );
            if ( Stream::IsReading )
            {
                current = previous + difference;
            }
            return true;
        }

        bool sixteenBits = false;
        if ( Stream::IsWriting )
        {
            sixteenBits = difference <= 69914;
        }
        serialize_bool( stream, sixteenBits );
        if ( sixteenBits )
        {
            serialize_int( stream, difference, 4378, 69914 );
            if ( Stream::IsReading )
            {
                current = previous + difference;
            }
            return true;
        }

        uint32_t value = current;
        serialize_uint32( stream, value );
        if ( Stream::IsReading )
        {
            current = value;
        }

        return true;
    }

    /**
        Serialize an integer value relative to another (read/write).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param previous The previous integer value.
        @param current The current integer value.
     */

    #define serialize_int_relative( stream, previous, current )                             \
        do                                                                                  \
        {                                                                                   \
            if ( !next::serialize_int_relative_internal( stream, previous, current ) )      \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
        } while (0)

    template <typename Stream> bool serialize_ack_relative_internal( Stream & stream, uint16_t sequence, uint16_t & ack )
    {
        int ack_delta = 0;
        bool ack_in_range = false;
        if ( Stream::IsWriting )
        {
            if ( ack < sequence )
            {
                ack_delta = sequence - ack;
            }
            else
            {
                ack_delta = (int)sequence + 65536 - ack;
            }
            next_assert( ack_delta > 0 );
            next_assert( uint16_t( sequence - ack_delta ) == ack );
            ack_in_range = ack_delta <= 64;
        }
        serialize_bool( stream, ack_in_range );
        if ( ack_in_range )
        {
            serialize_int( stream, ack_delta, 1, 64 );
            if ( Stream::IsReading )
            {
                ack = sequence - ack_delta;
            }
        }
        else
        {
            serialize_bits( stream, ack, 16 );
        }
        return true;
    }

    /**
        Serialize an ack relative to the current sequence number (read/write).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param sequence The current sequence number.
        @param ack The ack sequence number, which is typically near the current sequence number.
     */

    #define serialize_ack_relative( stream, sequence, ack  )                                        \
        do                                                                                          \
        {                                                                                           \
            if ( !next::serialize_ack_relative_internal( stream, sequence, ack ) )                  \
            {                                                                                       \
                return false;                                                                       \
            }                                                                                       \
        } while (0)

    template <typename Stream> bool serialize_sequence_relative_internal( Stream & stream, uint16_t sequence1, uint16_t & sequence2 )
    {
        if ( Stream::IsWriting )
        {
            uint32_t a = sequence1;
            uint32_t b = sequence2 + ( ( sequence1 > sequence2 ) ? 65536 : 0 );
            serialize_int_relative( stream, a, b );
        }
        else
        {
            uint32_t a = sequence1;
            uint32_t b = 0;
            serialize_int_relative( stream, a, b );
            if ( b >= 65536 )
            {
                b -= 65536;
            }
            sequence2 = uint16_t( b );
        }

        return true;
    }

    /**
        Serialize a sequence number relative to another (read/write).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read or write stream.
        @param sequence1 The first sequence number to serialize relative to.
        @param sequence2 The second sequence number to be encoded relative to the first.
     */

    #define serialize_sequence_relative( stream, sequence1, sequence2 )                             \
        do                                                                                          \
        {                                                                                           \
            if ( !next::serialize_sequence_relative_internal( stream, sequence1, sequence2 ) )      \
            {                                                                                       \
                return false;                                                                       \
            }                                                                                       \
        } while (0)

    template <typename Stream> bool serialize_address_internal( Stream & stream, next_address_t & address )
    {
        serialize_bits( stream, address.type, 2 );
        if ( address.type == NEXT_ADDRESS_IPV4 )
        {
            serialize_bytes( stream, address.data.ipv4, 4 );
            serialize_bits( stream, address.port, 16 );
        }
        else if ( address.type == NEXT_ADDRESS_IPV6 )
        {
            for ( int i = 0; i < 8; ++i )
            {
                serialize_bits( stream, address.data.ipv6[i], 16 );
            }
            serialize_bits( stream, address.port, 16 );
        }
        else
        {
            if ( Stream::IsReading )
            {
                memset( &address, 0, sizeof(next_address_t) );
            }
        }
        return true;
    }

    #define serialize_address( stream, address )                                                    \
        do                                                                                          \
        {                                                                                           \
            if ( !next::serialize_address_internal( stream, address ) )                             \
            {                                                                                       \
                return false;                                                                       \
            }                                                                                       \
        } while (0)
}

// -------------------------------------------------------------

#include "next_crypto.h"

void next_random_bytes( uint8_t * buffer, int bytes )
{
    next_randombytes_buf( buffer, bytes );
}

float next_random_float()
{
    uint32_t uint32_value;
    next_random_bytes( (uint8_t*)&uint32_value, sizeof(uint32_value) );
    uint64_t uint64_value = uint64_t(uint32_value);
    double double_value = double(uint64_value) / 0xFFFFFFFF;
    return float(double_value);
}

uint64_t next_random_uint64()
{
    uint64_t value;
    next_random_bytes( (uint8_t*)&value, sizeof(value) );
    return value;
}

// -------------------------------------------------------------

struct NextUpgradeToken
{
    uint64_t session_id;
    uint64_t expire_timestamp;
    next_address_t client_address;
    next_address_t server_address;

    NextUpgradeToken()
    {
        session_id = 0;
        expire_timestamp = 0;
        memset( &client_address, 0, sizeof(next_address_t) );
        memset( &server_address, 0, sizeof(next_address_t) );
    }

    int Write( uint8_t * buffer, const uint8_t * private_key )
    {
        next_assert( buffer );
        next_assert( private_key );

        memset( buffer, 0, NEXT_UPGRADE_TOKEN_BYTES );

        uint8_t * nonce = buffer;
        next_random_bytes( nonce, NEXT_CRYPTO_SECRETBOX_NONCEBYTES );
        buffer += NEXT_CRYPTO_SECRETBOX_NONCEBYTES;

        uint8_t * p = buffer;

        next_write_uint64( &p, session_id );
        next_write_uint64( &p, expire_timestamp );
        next_write_address( &p, &client_address );
        next_write_address( &p, &server_address );

        int bytes_written = p - buffer;

        next_crypto_secretbox_easy( buffer, buffer, NEXT_UPGRADE_TOKEN_BYTES - NEXT_CRYPTO_SECRETBOX_NONCEBYTES - NEXT_CRYPTO_SECRETBOX_MACBYTES, nonce, private_key );

        next_assert( NEXT_CRYPTO_SECRETBOX_NONCEBYTES + bytes_written + NEXT_CRYPTO_SECRETBOX_MACBYTES <= NEXT_UPGRADE_TOKEN_BYTES );

        return NEXT_CRYPTO_SECRETBOX_NONCEBYTES + bytes_written + NEXT_CRYPTO_SECRETBOX_MACBYTES;
    }

    bool Read( const uint8_t * buffer, const uint8_t * private_key )
    {
        next_assert( buffer );
        next_assert( private_key );

        const uint8_t * nonce = buffer;

        uint8_t decrypted[NEXT_UPGRADE_TOKEN_BYTES];
        memcpy( decrypted, buffer + NEXT_CRYPTO_SECRETBOX_NONCEBYTES, NEXT_UPGRADE_TOKEN_BYTES - NEXT_CRYPTO_SECRETBOX_NONCEBYTES );

        if ( next_crypto_secretbox_open_easy( decrypted, decrypted, NEXT_UPGRADE_TOKEN_BYTES - NEXT_CRYPTO_SECRETBOX_NONCEBYTES, nonce, private_key ) != 0 )
            return false;

        const uint8_t * p = decrypted;

        session_id = next_read_uint64( &p );
        expire_timestamp = next_read_uint64( &p );
        next_read_address( &p, &client_address );
        next_read_address( &p, &server_address );

        return true;
    }
};

// ---------------------------------------------------------------

struct next_replay_protection_t
{
    NEXT_DECLARE_SENTINEL(0)

    uint64_t most_recent_sequence;
    uint64_t received_packet[NEXT_REPLAY_PROTECTION_BUFFER_SIZE];

    NEXT_DECLARE_SENTINEL(1)
};

void next_replay_protection_initialize_sentinels( next_replay_protection_t * replay_protection )
{
    (void) replay_protection;
    next_assert( replay_protection );
    NEXT_INITIALIZE_SENTINEL( replay_protection, 0 )
    NEXT_INITIALIZE_SENTINEL( replay_protection, 1 )
}

void next_replay_protection_verify_sentinels( next_replay_protection_t * replay_protection )
{
    (void) replay_protection;
    next_assert( replay_protection );
    NEXT_VERIFY_SENTINEL( replay_protection, 0 )
    NEXT_VERIFY_SENTINEL( replay_protection, 1 )
}

void next_replay_protection_reset( next_replay_protection_t * replay_protection )
{
    next_replay_protection_initialize_sentinels( replay_protection );

    replay_protection->most_recent_sequence = 0;

    memset( replay_protection->received_packet, 0xFF, sizeof( replay_protection->received_packet ) );

    next_replay_protection_verify_sentinels( replay_protection );
}

int next_replay_protection_already_received( next_replay_protection_t * replay_protection, uint64_t sequence )
{
    next_replay_protection_verify_sentinels( replay_protection );

    if ( sequence + NEXT_REPLAY_PROTECTION_BUFFER_SIZE <= replay_protection->most_recent_sequence )
        return 1;

    int index = (int) ( sequence % NEXT_REPLAY_PROTECTION_BUFFER_SIZE );

    if ( replay_protection->received_packet[index] == 0xFFFFFFFFFFFFFFFFLL )
        return 0;

    if ( replay_protection->received_packet[index] >= sequence )
        return 1;

    return 0;
}

void next_replay_protection_advance_sequence( next_replay_protection_t * replay_protection, uint64_t sequence )
{
    next_replay_protection_verify_sentinels( replay_protection );

    if ( sequence > replay_protection->most_recent_sequence )
    {
        replay_protection->most_recent_sequence = sequence;
    }

    int index = (int) ( sequence % NEXT_REPLAY_PROTECTION_BUFFER_SIZE );

    replay_protection->received_packet[index] = sequence;
}

// -------------------------------------------------------------

int next_wire_packet_bits( int payload_bytes )
{
    return ( NEXT_ETHERNET_HEADER_BYTES + NEXT_IPV4_HEADER_BYTES + NEXT_UDP_HEADER_BYTES + 1 + 15 + NEXT_HEADER_BYTES + payload_bytes + 2 ) * 8;
}

struct next_bandwidth_limiter_t
{
    uint64_t bits_sent;
    double last_check_time;
    double average_kbps;
};

void next_bandwidth_limiter_reset( next_bandwidth_limiter_t * bandwidth_limiter )
{
    next_assert( bandwidth_limiter );
    bandwidth_limiter->last_check_time = -100.0;
    bandwidth_limiter->bits_sent = 0;
    bandwidth_limiter->average_kbps = 0.0;
}

bool next_bandwidth_limiter_add_packet( next_bandwidth_limiter_t * bandwidth_limiter, double current_time, uint32_t kbps_allowed, uint32_t packet_bits )
{
    next_assert( bandwidth_limiter );
    const bool invalid = bandwidth_limiter->last_check_time < 0.0;
    if ( invalid || current_time - bandwidth_limiter->last_check_time >= NEXT_BANDWIDTH_LIMITER_INTERVAL - 0.001f )
    {
        bandwidth_limiter->bits_sent = 0;
        bandwidth_limiter->last_check_time = current_time;
    }
    bandwidth_limiter->bits_sent += packet_bits;
    return bandwidth_limiter->bits_sent > uint64_t(kbps_allowed) * 1000 * NEXT_BANDWIDTH_LIMITER_INTERVAL;
}

void next_bandwidth_limiter_add_sample( next_bandwidth_limiter_t * bandwidth_limiter, double kbps )
{
    if ( bandwidth_limiter->average_kbps == 0.0 && kbps != 0.0 )
    {
        bandwidth_limiter->average_kbps = kbps;
        return;
    }

    if ( bandwidth_limiter->average_kbps != 0.0 && kbps == 0.0 )
    {
        bandwidth_limiter->average_kbps = 0.0;
        return;
    }

    const double delta = kbps - bandwidth_limiter->average_kbps;

    if ( delta < 0.000001f )
    {
        bandwidth_limiter->average_kbps = kbps;
        return;
    }

    bandwidth_limiter->average_kbps += delta * 0.1f;
}

double next_bandwidth_limiter_usage_kbps( next_bandwidth_limiter_t * bandwidth_limiter, double current_time )
{
    next_assert( bandwidth_limiter );
    const bool invalid = bandwidth_limiter->last_check_time < 0.0;
    if ( !invalid )
    {
        const double delta_time = current_time - bandwidth_limiter->last_check_time;
        if ( delta_time > 0.1f )
        {
            const double kbps = bandwidth_limiter->bits_sent / delta_time / 1000.0;
            next_bandwidth_limiter_add_sample( bandwidth_limiter, kbps );
        }
    }
    return bandwidth_limiter->average_kbps;
}

// -------------------------------------------------------------

struct next_packet_loss_tracker_t
{
    NEXT_DECLARE_SENTINEL(0)

    uint64_t last_packet_processed;
    uint64_t most_recent_packet_received;

    NEXT_DECLARE_SENTINEL(1)

    uint64_t received_packets[NEXT_PACKET_LOSS_TRACKER_HISTORY];

    NEXT_DECLARE_SENTINEL(2)
};

void next_packet_loss_tracker_initialize_sentinels( next_packet_loss_tracker_t * tracker )
{
    (void) tracker;
    next_assert( tracker );
    NEXT_INITIALIZE_SENTINEL( tracker, 0 )
    NEXT_INITIALIZE_SENTINEL( tracker, 1 )
    NEXT_INITIALIZE_SENTINEL( tracker, 2 )
}

void next_packet_loss_tracker_verify_sentinels( next_packet_loss_tracker_t * tracker )
{
    (void) tracker;
    next_assert( tracker );
    NEXT_VERIFY_SENTINEL( tracker, 0 )
    NEXT_VERIFY_SENTINEL( tracker, 1 )
    NEXT_VERIFY_SENTINEL( tracker, 2 )
}

void next_packet_loss_tracker_reset( next_packet_loss_tracker_t * tracker )
{
    next_assert( tracker );

    next_packet_loss_tracker_initialize_sentinels( tracker );

    tracker->last_packet_processed = 0;
    tracker->most_recent_packet_received = 0;

    for ( int i = 0; i < NEXT_PACKET_LOSS_TRACKER_HISTORY; ++i )
    {
        tracker->received_packets[i] = 0xFFFFFFFFFFFFFFFFUL;
    }

    next_packet_loss_tracker_verify_sentinels( tracker );
}

void next_packet_loss_tracker_packet_received( next_packet_loss_tracker_t * tracker, uint64_t sequence )
{
    next_packet_loss_tracker_verify_sentinels( tracker );

    sequence++;

    const int index = int( sequence % NEXT_PACKET_LOSS_TRACKER_HISTORY );

    tracker->received_packets[index] = sequence;
    tracker->most_recent_packet_received = sequence;
}

int next_packet_loss_tracker_update( next_packet_loss_tracker_t * tracker )
{
    next_packet_loss_tracker_verify_sentinels( tracker );

    int lost_packets = 0;

    uint64_t start = tracker->last_packet_processed + 1;
    uint64_t finish = ( tracker->most_recent_packet_received > NEXT_PACKET_LOSS_TRACKER_SAFETY ) ? ( tracker->most_recent_packet_received - NEXT_PACKET_LOSS_TRACKER_SAFETY ) : 0;

    if ( finish > start && finish - start > NEXT_PACKET_LOSS_TRACKER_HISTORY )
    {
        tracker->last_packet_processed = tracker->most_recent_packet_received;
        return 0;
    }

    for ( uint64_t sequence = start; sequence <= finish; ++sequence )
    {
        const int index = int( sequence % NEXT_PACKET_LOSS_TRACKER_HISTORY );
        if ( tracker->received_packets[index] != sequence )
        {
            lost_packets++;
        }
    }

    tracker->last_packet_processed = finish;

    return lost_packets;
}

// -------------------------------------------------------------

struct next_out_of_order_tracker_t
{
    NEXT_DECLARE_SENTINEL(0)

    uint64_t last_packet_processed;
    uint64_t num_out_of_order_packets;

    NEXT_DECLARE_SENTINEL(1)
};

void next_out_of_order_tracker_initialize_sentinels( next_out_of_order_tracker_t * tracker )
{
    (void) tracker;
    next_assert( tracker );
    NEXT_INITIALIZE_SENTINEL( tracker, 0 )
    NEXT_INITIALIZE_SENTINEL( tracker, 1 )
}

void next_out_of_order_tracker_verify_sentinels( next_out_of_order_tracker_t * tracker )
{
    (void) tracker;
    next_assert( tracker );
    NEXT_VERIFY_SENTINEL( tracker, 0 )
    NEXT_VERIFY_SENTINEL( tracker, 1 )
}

void next_out_of_order_tracker_reset( next_out_of_order_tracker_t * tracker )
{
    next_assert( tracker );

    next_out_of_order_tracker_initialize_sentinels( tracker );

    tracker->last_packet_processed = 0;
    tracker->num_out_of_order_packets = 0;

    next_out_of_order_tracker_verify_sentinels( tracker );
}

void next_out_of_order_tracker_packet_received( next_out_of_order_tracker_t * tracker, uint64_t sequence )
{
    next_out_of_order_tracker_verify_sentinels( tracker );

    if ( sequence < tracker->last_packet_processed )
    {
        tracker->num_out_of_order_packets++;
        return;
    }

    tracker->last_packet_processed = sequence;
}

// -------------------------------------------------------------

struct next_jitter_tracker_t
{
    NEXT_DECLARE_SENTINEL(0)

    uint64_t last_packet_processed;
    double last_packet_time;
    double last_packet_delta;
    double jitter;

    NEXT_DECLARE_SENTINEL(1)
};

void next_jitter_tracker_initialize_sentinels( next_jitter_tracker_t * tracker )
{
    (void) tracker;
    next_assert( tracker );
    NEXT_INITIALIZE_SENTINEL( tracker, 0 )
    NEXT_INITIALIZE_SENTINEL( tracker, 1 )
}

void next_jitter_tracker_verify_sentinels( next_jitter_tracker_t * tracker )
{
    (void) tracker;
    next_assert( tracker );
    NEXT_VERIFY_SENTINEL( tracker, 0 )
    NEXT_VERIFY_SENTINEL( tracker, 1 )
}

void next_jitter_tracker_reset( next_jitter_tracker_t * tracker )
{
    next_assert( tracker );

    next_jitter_tracker_initialize_sentinels( tracker );

    tracker->last_packet_processed = 0;
    tracker->last_packet_time = 0.0;
    tracker->last_packet_delta = 0.0;
    tracker->jitter = 0.0;

    next_jitter_tracker_verify_sentinels( tracker );
}

void next_jitter_tracker_packet_received( next_jitter_tracker_t * tracker, uint64_t sequence, double time )
{
    next_jitter_tracker_verify_sentinels( tracker );

    if ( sequence == tracker->last_packet_processed + 1 && tracker->last_packet_time > 0.0 )
    {
        const double delta = time - tracker->last_packet_time;
        const double jitter = fabs( delta - tracker->last_packet_delta );
        tracker->last_packet_delta = delta;

        if ( fabs( jitter - tracker->jitter ) > 0.00001 )
        {
            tracker->jitter += ( jitter - tracker->jitter ) * 0.01;
        }
        else
        {
            tracker->jitter = jitter;
        }
    }

    tracker->last_packet_processed = sequence;
    tracker->last_packet_time = time;
}

// -------------------------------------------------------------

struct NextUpgradeRequestPacket
{
    uint64_t protocol_version;
    uint64_t session_id;
    next_address_t client_address;
    next_address_t server_address;
    uint8_t server_kx_public_key[NEXT_CRYPTO_KX_PUBLICKEYBYTES];
    uint8_t upgrade_token[NEXT_UPGRADE_TOKEN_BYTES];
    uint8_t upcoming_magic[8];
    uint8_t current_magic[8];
    uint8_t previous_magic[8];

    NextUpgradeRequestPacket()
    {
        memset( this, 0, sizeof(NextUpgradeRequestPacket) );
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_uint64( stream, protocol_version );
        serialize_uint64( stream, session_id );
        serialize_address( stream, client_address );
        serialize_address( stream, server_address );
        serialize_bytes( stream, server_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES );
        serialize_bytes( stream, upgrade_token, NEXT_UPGRADE_TOKEN_BYTES );
        serialize_bytes( stream, upcoming_magic, 8 );
        serialize_bytes( stream, current_magic, 8 );
        serialize_bytes( stream, previous_magic, 8 );
        return true;
    }
};

struct NextUpgradeResponsePacket
{
    uint8_t client_open_session_sequence;
    uint8_t client_kx_public_key[NEXT_CRYPTO_KX_PUBLICKEYBYTES];
    uint8_t client_route_public_key[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    uint8_t upgrade_token[NEXT_UPGRADE_TOKEN_BYTES];
    int platform_id;
    int connection_type;

    NextUpgradeResponsePacket()
    {
        memset( this, 0, sizeof(NextUpgradeResponsePacket) );
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_bits( stream, client_open_session_sequence, 8 );
        serialize_bytes( stream, client_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES );
        serialize_bytes( stream, client_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES );
        serialize_bytes( stream, upgrade_token, NEXT_UPGRADE_TOKEN_BYTES );
        serialize_int( stream, platform_id, NEXT_PLATFORM_UNKNOWN, NEXT_PLATFORM_MAX );
        serialize_int( stream, connection_type, NEXT_CONNECTION_TYPE_UNKNOWN, NEXT_CONNECTION_TYPE_MAX );
        return true;
    }
};

struct NextUpgradeConfirmPacket
{
    uint64_t upgrade_sequence;
    uint64_t session_id;
    next_address_t server_address;
    uint8_t client_kx_public_key[NEXT_CRYPTO_KX_PUBLICKEYBYTES];
    uint8_t server_kx_public_key[NEXT_CRYPTO_KX_PUBLICKEYBYTES];

    NextUpgradeConfirmPacket()
    {
        memset( this, 0, sizeof(NextUpgradeConfirmPacket) );
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_uint64( stream, upgrade_sequence );
        serialize_uint64( stream, session_id );
        serialize_address( stream, server_address );
        serialize_bytes( stream, client_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES );
        serialize_bytes( stream, server_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES );
        return true;
    }
};

struct NextDirectPingPacket
{
    uint64_t ping_sequence;

    NextDirectPingPacket()
    {
        ping_sequence = 0;
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_uint64( stream, ping_sequence );
        return true;
    }
};

struct NextDirectPongPacket
{
    uint64_t ping_sequence;

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_uint64( stream, ping_sequence );
        return true;
    }
};

struct NextClientStatsPacket
{
    bool fallback_to_direct;
    bool next;
    bool multipath;
    bool reported;
    bool next_bandwidth_over_limit;
    int platform_id;
    int connection_type;
    float direct_kbps_up;
    float direct_kbps_down;
    float next_kbps_up;
    float next_kbps_down;
    float direct_rtt;
    float direct_jitter;
    float direct_packet_loss;
    float direct_max_packet_loss_seen;
    float next_rtt;
    float next_jitter;
    float next_packet_loss;
    float max_jitter_seen;
    int num_near_relays;
    uint64_t near_relay_ids[NEXT_MAX_NEAR_RELAYS];
    uint8_t near_relay_rtt[NEXT_MAX_NEAR_RELAYS];
    uint8_t near_relay_jitter[NEXT_MAX_NEAR_RELAYS];
    float near_relay_packet_loss[NEXT_MAX_NEAR_RELAYS];
    uint64_t packets_sent_client_to_server;
    uint64_t packets_lost_server_to_client;
    uint64_t packets_out_of_order_server_to_client;
    float jitter_server_to_client;

    NextClientStatsPacket()
    {
        memset( this, 0, sizeof(NextClientStatsPacket) );
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_bool( stream, fallback_to_direct );
        serialize_bool( stream, next );
        serialize_bool( stream, multipath );
        serialize_bool( stream, reported );
        serialize_bool( stream, next_bandwidth_over_limit );
        serialize_int( stream, platform_id, NEXT_PLATFORM_UNKNOWN, NEXT_PLATFORM_MAX );
        serialize_int( stream, connection_type, NEXT_CONNECTION_TYPE_UNKNOWN, NEXT_CONNECTION_TYPE_MAX );
        serialize_float( stream, direct_kbps_up );
        serialize_float( stream, direct_kbps_down );
        serialize_float( stream, next_kbps_up );
        serialize_float( stream, next_kbps_down );
        serialize_float( stream, direct_rtt );
        serialize_float( stream, direct_jitter );
        serialize_float( stream, direct_packet_loss );
        serialize_float( stream, direct_max_packet_loss_seen );
        if ( next )
        {
            serialize_float( stream, next_rtt );
            serialize_float( stream, next_jitter );
            serialize_float( stream, next_packet_loss );
        }
        serialize_int( stream, num_near_relays, 0, NEXT_MAX_NEAR_RELAYS );
        bool has_near_relay_pings = false;
        if ( Stream::IsWriting )
        {
            has_near_relay_pings = num_near_relays > 0;
        }
        serialize_bool( stream, has_near_relay_pings );
        if ( has_near_relay_pings )
        {
            for ( int i = 0; i < num_near_relays; ++i )
            {
                serialize_uint64( stream, near_relay_ids[i] );
                serialize_int( stream, near_relay_rtt[i], 0, 255 );
                serialize_int( stream, near_relay_jitter[i], 0, 255 );
                serialize_float( stream, near_relay_packet_loss[i] );
            }
        }
        serialize_uint64( stream, packets_sent_client_to_server );
        serialize_uint64( stream, packets_lost_server_to_client );
        serialize_uint64( stream, packets_out_of_order_server_to_client );
        serialize_float( stream, jitter_server_to_client );
        return true;
    }
};

struct NextRouteUpdatePacket
{
    uint64_t sequence;
    bool multipath;
    bool has_near_relays;
    int num_near_relays;
    uint64_t near_relay_ids[NEXT_MAX_NEAR_RELAYS];
    next_address_t near_relay_addresses[NEXT_MAX_NEAR_RELAYS];
    uint8_t update_type;
    int num_tokens;
    uint8_t tokens[NEXT_MAX_TOKENS*NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES];
    uint64_t packets_sent_server_to_client;
    uint64_t packets_lost_client_to_server;
    uint64_t packets_out_of_order_client_to_server;
    float jitter_client_to_server;
    bool has_debug;
    char debug[NEXT_MAX_SESSION_DEBUG];
    uint8_t upcoming_magic[8];
    uint8_t current_magic[8];
    uint8_t previous_magic[8];

    NextRouteUpdatePacket()
    {
        memset( this, 0, sizeof(NextRouteUpdatePacket ) );
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_uint64( stream, sequence );

        serialize_bool( stream, has_near_relays );
        if ( has_near_relays )
        {
            serialize_int( stream, num_near_relays, 0, NEXT_MAX_NEAR_RELAYS );
            for ( int i = 0; i < num_near_relays; ++i )
            {
                serialize_uint64( stream, near_relay_ids[i] );
                serialize_address( stream, near_relay_addresses[i] );
            }
        }

        serialize_int( stream, update_type, 0, NEXT_UPDATE_TYPE_CONTINUE );

        if ( update_type != NEXT_UPDATE_TYPE_DIRECT )
        {
            serialize_int( stream, num_tokens, 0, NEXT_MAX_TOKENS );
            serialize_bool( stream, multipath );
        }
        if ( update_type == NEXT_UPDATE_TYPE_ROUTE )
        {
            serialize_bytes( stream, tokens, num_tokens * NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES );
        }
        else if ( update_type == NEXT_UPDATE_TYPE_CONTINUE )
        {
            serialize_bytes( stream, tokens, num_tokens * NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES );
        }

        serialize_uint64( stream, packets_sent_server_to_client );
        serialize_uint64( stream, packets_lost_client_to_server );

        serialize_uint64( stream, packets_out_of_order_client_to_server );

        serialize_float( stream, jitter_client_to_server );

        serialize_bool( stream, has_debug );
        if ( has_debug )
        {
            serialize_string( stream, debug, NEXT_MAX_SESSION_DEBUG );
        }

        serialize_bytes( stream, upcoming_magic, 8 );
        serialize_bytes( stream, current_magic, 8 );
        serialize_bytes( stream, previous_magic, 8 );

        return true;
    }
};

struct NextRouteUpdateAckPacket
{
    uint64_t sequence;

    NextRouteUpdateAckPacket()
    {
        sequence = 0;
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_uint64( stream, sequence );
        return true;
    }
};

static void next_generate_pittle( uint8_t * output, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port, int packet_length )
{
    next_assert( output );
    next_assert( from_address );
    next_assert( from_address_bytes > 0 );
    next_assert( to_address );
    next_assert( to_address_bytes >= 0 );
    next_assert( packet_length > 0 );
#if NEXT_BIG_ENDIAN
    next_bswap( from_port );
    next_bswap( to_port );
    next_bswap( packet_length );
#endif // #if NEXT_BIG_ENDIAN
    uint16_t sum = 0;
    for ( int i = 0; i < from_address_bytes; ++i ) { sum += uint8_t(from_address[i]); }
    const char * from_port_data = (const char*) &from_port;
    sum += uint8_t(from_port_data[0]);
    sum += uint8_t(from_port_data[1]);
    for ( int i = 0; i < to_address_bytes; ++i ) { sum += uint8_t(to_address[i]); }
    const char * to_port_data = (const char*) &to_port;
    sum += uint8_t(to_port_data[0]);
    sum += uint8_t(to_port_data[1]);
    const char * packet_length_data = (const char*) &packet_length;
    sum += uint8_t(packet_length_data[0]);
    sum += uint8_t(packet_length_data[1]);
    sum += uint8_t(packet_length_data[2]);
    sum += uint8_t(packet_length_data[3]);
#if NEXT_BIG_ENDIAN
    next_bswap( sum );
#endif // #if NEXT_BIG_ENDIAN
    const char * sum_data = (const char*) &sum;
    output[0] = 1 | ( uint8_t(sum_data[0]) ^ uint8_t(sum_data[1]) ^ 193 );
    output[1] = 1 | ( ( 255 - output[0] ) ^ 113 );
}

static void next_generate_chonkle( uint8_t * output, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port, int packet_length )
{
    next_assert( output );
    next_assert( magic );
    next_assert( from_address );
    next_assert( from_address_bytes >= 0 );
    next_assert( to_address );
    next_assert( to_address_bytes >= 0 );
    next_assert( packet_length > 0 );
#if NEXT_BIG_ENDIAN
    next_bswap( from_port );
    next_bswap( to_port );
    next_bswap( packet_length );
#endif // #if NEXT_BIG_ENDIAN
    next_fnv_t fnv;
    next_fnv_init( &fnv );
    next_fnv_write( &fnv, magic, 8 );
    next_fnv_write( &fnv, from_address, from_address_bytes );
    next_fnv_write( &fnv, (const uint8_t*) &from_port, 2 );
    next_fnv_write( &fnv, to_address, to_address_bytes );
    next_fnv_write( &fnv, (const uint8_t*) &to_port, 2 );
    next_fnv_write( &fnv, (const uint8_t*) &packet_length, 4 );
    uint64_t hash = next_fnv_finalize( &fnv );
#if NEXT_BIG_ENDIAN
    next_bswap( hash );
#endif // #if NEXT_BIG_ENDIAN
    const char * data = (const char*) &hash;
    output[0] = ( ( data[6] & 0xC0 ) >> 6 ) + 42;
    output[1] = ( data[3] & 0x1F ) + 200;
    output[2] = ( ( data[2] & 0xFC ) >> 2 ) + 5;
    output[3] = data[0];
    output[4] = ( data[2] & 0x03 ) + 78;
    output[5] = ( data[4] & 0x7F ) + 96;
    output[6] = ( ( data[1] & 0xFC ) >> 2 ) + 100;
    if ( ( data[7] & 1 ) == 0 ) { output[7] = 79; } else { output[7] = 7; }
    if ( ( data[4] & 0x80 ) == 0 ) { output[8] = 37; } else { output[8] = 83; }
    output[9] = ( data[5] & 0x07 ) + 124;
    output[10] = ( ( data[1] & 0xE0 ) >> 5 ) + 175;
    output[11] = ( data[6] & 0x3F ) + 33;
    const int value = ( data[1] & 0x03 );
    if ( value == 0 ) { output[12] = 97; } else if ( value == 1 ) { output[12] = 5; } else if ( value == 2 ) { output[12] = 43; } else { output[12] = 13; }
    output[13] = ( ( data[5] & 0xF8 ) >> 3 ) + 210;
    output[14] = ( ( data[7] & 0xFE ) >> 1 ) + 17;
}

bool next_basic_packet_filter( const uint8_t * data, int packet_length )
{
    if ( packet_length == 0 )
        return false;

    if ( data[0] == 0 )
        return true;

    if ( packet_length < 18 )
        return false;

    if ( data[0] < 0x01 || data[0] > 0x63 )
        return false;

    if ( data[1] < 0x2A || data[1] > 0x2D )
        return false;

    if ( data[2] < 0xC8 || data[2] > 0xE7 )
        return false;

    if ( data[3] < 0x05 || data[3] > 0x44 )
        return false;

    if ( data[5] < 0x4E || data[5] > 0x51 )
        return false;

    if ( data[6] < 0x60 || data[6] > 0xDF )
        return false;

    if ( data[7] < 0x64 || data[7] > 0xE3 )
        return false;

    if ( data[8] != 0x07 && data[8] != 0x4F )
        return false;

    if ( data[9] != 0x25 && data[9] != 0x53 )
        return false;

    if ( data[10] < 0x7C || data[10] > 0x83 )
        return false;

    if ( data[11] < 0xAF || data[11] > 0xB6 )
        return false;

    if ( data[12] < 0x21 || data[12] > 0x60 )
        return false;

    if ( data[13] != 0x61 && data[13] != 0x05 && data[13] != 0x2B && data[13] != 0x0D )
        return false;

    if ( data[14] < 0xD2 || data[14] > 0xF1 )
        return false;

    if ( data[15] < 0x11 || data[15] > 0x90 )
        return false;

    return true;
}

void next_address_data( const next_address_t * address, uint8_t * address_data, int * address_bytes, uint16_t * address_port )
{
    next_assert( address );
    if ( address->type == NEXT_ADDRESS_IPV4 )
    {
        address_data[0] = address->data.ipv4[0];
        address_data[1] = address->data.ipv4[1];
        address_data[2] = address->data.ipv4[2];
        address_data[3] = address->data.ipv4[3];
        *address_bytes = 4;
    }
    else if ( address->type == NEXT_ADDRESS_IPV6 )
    {
        for ( int i = 0; i < 8; ++i )
        {
            address_data[i*2]   = address->data.ipv6[i] >> 8;
            address_data[i*2+1] = address->data.ipv6[i] & 0xFF;
        }
        *address_bytes = 16;
    }
    else
    {
        *address_bytes = 0;
    }
    *address_port = address->port;
}

bool next_advanced_packet_filter( const uint8_t * data, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port, int packet_length )
{
    if ( data[0] == 0 )
        return true;

    if ( packet_length < 18 )
        return false;
    
    uint8_t a[15];
    uint8_t b[2];

    next_generate_chonkle( a, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( b, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    if ( memcmp( a, data + 1, 15 ) != 0 )
        return false;
    if ( memcmp( b, data + packet_length - 2, 2 ) != 0 )
        return false;
    return true;
}

// --------------------------------------------------

int next_write_direct_packet( uint8_t * packet_data, uint8_t open_session_sequence, uint64_t send_sequence, const uint8_t * game_packet_data, int game_packet_bytes, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    next_assert( packet_data );
    next_assert( game_packet_data );
    next_assert( game_packet_bytes >= 0 );
    next_assert( game_packet_bytes <= NEXT_MTU );
    uint8_t * p = packet_data;
    next_write_uint8( &p, NEXT_DIRECT_PACKET );
    uint8_t * a = p; p += 15;
    next_write_uint8( &p, open_session_sequence );
    next_write_uint64( &p, send_sequence );
    next_write_bytes( &p, game_packet_data, game_packet_bytes );
    uint8_t * b = p; p += 2;
    int packet_length = p - packet_data;
    next_generate_chonkle( a, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( b, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    return packet_length;
}

int next_write_route_request_packet( uint8_t * packet_data, const uint8_t * token_data, int token_bytes, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    uint8_t * p = packet_data;
    next_write_uint8( &p, NEXT_ROUTE_REQUEST_PACKET );
    uint8_t * a = p; p += 15;
    next_write_bytes( &p, token_data, token_bytes );
    uint8_t * b = p; p += 2;
    int packet_length = p - packet_data;
    next_generate_chonkle( a, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( b, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    return packet_length;
}

int next_write_continue_request_packet( uint8_t * packet_data, const uint8_t * token_data, int token_bytes, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    uint8_t * p = packet_data;
    next_write_uint8( &p, NEXT_CONTINUE_REQUEST_PACKET );
    uint8_t * a = p; p += 15;
    next_write_bytes( &p, token_data, token_bytes );
    uint8_t * b = p; p += 2;
    int packet_length = p - packet_data;
    next_generate_chonkle( a, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( b, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    return packet_length;
}

#define NEXT_DIRECTION_CLIENT_TO_SERVER             0
#define NEXT_DIRECTION_SERVER_TO_CLIENT             1

int next_write_header( int direction, uint8_t type, uint64_t sequence, uint64_t session_id, uint8_t session_version, const uint8_t * private_key, uint8_t * buffer )
{
    next_assert( private_key );
    next_assert( buffer );

    uint8_t * start = buffer;

    (void) start;

    if ( direction == NEXT_DIRECTION_SERVER_TO_CLIENT )
    {
        // high bit must be set
        next_assert( sequence & ( 1ULL << 63 ) );
    }
    else
    {
        // high bit must be clear
        next_assert( ( sequence & ( 1ULL << 63 ) ) == 0 );
    }

    if ( type == NEXT_PING_PACKET || type == NEXT_PONG_PACKET || type == NEXT_ROUTE_RESPONSE_PACKET || type == NEXT_CONTINUE_RESPONSE_PACKET )
    {
        // second highest bit must be set
        next_assert( sequence & ( 1ULL << 62 ) );
    }
    else
    {
        // second highest bit must be clear
        next_assert( ( sequence & ( 1ULL << 62 ) ) == 0 );
    }

    next_write_uint64( &buffer, sequence );

    uint8_t * additional = buffer;
    const int additional_length = 8 + 1;

    next_write_uint64( &buffer, session_id );
    next_write_uint8( &buffer, session_version );

    uint8_t nonce[12];
    {
        uint8_t * p = nonce;
        next_write_uint32( &p, type );
        next_write_uint64( &p, sequence );
    }

    unsigned long long encrypted_length = 0;

    int result = next_crypto_aead_chacha20poly1305_ietf_encrypt( buffer, &encrypted_length,
                                                                 buffer, 0,
                                                                 additional, (unsigned long long) additional_length,
                                                                 NULL, nonce, private_key );

    if ( result != 0 )
        return NEXT_ERROR;

    buffer += encrypted_length;

    next_assert( int( buffer - start ) == NEXT_HEADER_BYTES );

    return NEXT_OK;
}

int next_write_route_response_packet( uint8_t * packet_data, uint64_t send_sequence, uint64_t session_id, uint8_t session_version, const uint8_t * private_key, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    uint8_t * p = packet_data;
    next_write_uint8( &p, NEXT_ROUTE_RESPONSE_PACKET );
    uint8_t * a = p; p += 15;
    uint8_t * b = p; p += NEXT_HEADER_BYTES;
    send_sequence |= uint64_t(1) << 63;
    send_sequence |= uint64_t(1) << 62;
    if ( next_write_header( NEXT_DIRECTION_SERVER_TO_CLIENT, NEXT_ROUTE_RESPONSE_PACKET, send_sequence, session_id, session_version, private_key, b ) != NEXT_OK )
        return 0;
    uint8_t * c = p; p += 2;
    int packet_length = p - packet_data;
    next_generate_chonkle( a, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( c, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    return packet_length;
}

int next_write_client_to_server_packet( uint8_t * packet_data, uint64_t send_sequence, uint64_t session_id, uint8_t session_version, const uint8_t * private_key, const uint8_t * game_packet_data, int game_packet_bytes, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    next_assert( packet_data );
    next_assert( private_key );
    next_assert( game_packet_data );
    next_assert( game_packet_bytes >= 0 );
    next_assert( game_packet_bytes <= NEXT_MTU );
    uint8_t * p = packet_data;
    next_write_uint8( &p, NEXT_CLIENT_TO_SERVER_PACKET );
    uint8_t * a = p; p += 15;
    uint8_t * b = p; p += NEXT_HEADER_BYTES;
    if ( next_write_header( NEXT_DIRECTION_CLIENT_TO_SERVER, NEXT_CLIENT_TO_SERVER_PACKET, send_sequence, session_id, session_version, private_key, b ) != NEXT_OK )
        return 0;
    next_write_bytes( &p, game_packet_data, game_packet_bytes );
    uint8_t * c = p; p += 2;
    int packet_length = p - packet_data;
    next_generate_chonkle( a, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( c, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    return packet_length;
}

int next_write_server_to_client_packet( uint8_t * packet_data, uint64_t send_sequence, uint64_t session_id, uint8_t session_version, const uint8_t * private_key, const uint8_t * game_packet_data, int game_packet_bytes, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    next_assert( packet_data );
    next_assert( private_key );
    next_assert( game_packet_data );
    next_assert( game_packet_bytes >= 0 );
    next_assert( game_packet_bytes <= NEXT_MTU );
    uint8_t * p = packet_data;
    next_write_uint8( &p, NEXT_SERVER_TO_CLIENT_PACKET );
    uint8_t * a = p; p += 15;
    uint8_t * b = p; p += NEXT_HEADER_BYTES;
    send_sequence |= uint64_t(1) << 63;
    if ( next_write_header( NEXT_DIRECTION_SERVER_TO_CLIENT, NEXT_SERVER_TO_CLIENT_PACKET, send_sequence, session_id, session_version, private_key, b ) != NEXT_OK )
        return 0;
    next_write_bytes( &p, game_packet_data, game_packet_bytes );
    uint8_t * c = p; p += 2;
    int packet_length = p - packet_data;
    next_generate_chonkle( a, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( c, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    return packet_length;
}

int next_write_ping_packet( uint8_t * packet_data, uint64_t send_sequence, uint64_t session_id, uint8_t session_version, const uint8_t * private_key, uint64_t ping_sequence, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    next_assert( packet_data );
    next_assert( private_key );
    uint8_t * p = packet_data;
    next_write_uint8( &p, NEXT_PING_PACKET );
    uint8_t * a = p; p += 15;
    uint8_t * b = p; p += NEXT_HEADER_BYTES;
    send_sequence |= uint64_t(1) << 62;
    if ( next_write_header( NEXT_DIRECTION_CLIENT_TO_SERVER, NEXT_PING_PACKET, send_sequence, session_id, session_version, private_key, b ) != NEXT_OK )
        return 0;
    next_write_uint64( &p, ping_sequence );
    uint8_t * c = p; p += 2;
    int packet_length = p - packet_data;
    next_generate_chonkle( a, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( c, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    return packet_length;
}

int next_write_pong_packet( uint8_t * packet_data, uint64_t send_sequence, uint64_t session_id, uint8_t session_version, const uint8_t * private_key, uint64_t ping_sequence, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    next_assert( packet_data );
    next_assert( private_key );
    uint8_t * p = packet_data;
    next_write_uint8( &p, NEXT_PONG_PACKET );
    uint8_t * a = p; p += 15;
    uint8_t * b = p; p += NEXT_HEADER_BYTES;
    send_sequence |= uint64_t(1) << 63;
    send_sequence |= uint64_t(1) << 62;
    if ( next_write_header( NEXT_DIRECTION_SERVER_TO_CLIENT, NEXT_PONG_PACKET, send_sequence, session_id, session_version, private_key, b ) != NEXT_OK )
        return 0;
    next_write_uint64( &p, ping_sequence );
    uint8_t * c = p; p += 2;
    int packet_length = p - packet_data;
    next_generate_chonkle( a, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( c, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    return packet_length;
}

int next_write_continue_response_packet( uint8_t * packet_data, uint64_t send_sequence, uint64_t session_id, uint8_t session_version, const uint8_t * private_key, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    uint8_t * p = packet_data;
    next_write_uint8( &p, NEXT_CONTINUE_RESPONSE_PACKET );
    uint8_t * a = p; p += 15;
    uint8_t * b = p; p += NEXT_HEADER_BYTES;
    send_sequence |= uint64_t(1) << 63;
    send_sequence |= uint64_t(1) << 62;
    if ( next_write_header( NEXT_DIRECTION_SERVER_TO_CLIENT, NEXT_CONTINUE_RESPONSE_PACKET, send_sequence, session_id, session_version, private_key, b ) != NEXT_OK )
        return 0;
    uint8_t * c = p; p += 2;
    int packet_length = p - packet_data;
    next_generate_chonkle( a, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( c, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    return packet_length;
}

int next_write_relay_ping_packet( uint8_t * packet_data, const uint8_t * ping_token, uint64_t ping_sequence, uint64_t session_id, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    uint8_t * p = packet_data;
    next_write_uint8( &p, NEXT_RELAY_PING_PACKET );
    uint8_t * a = p; p += 15;
    next_write_uint64( &p, ping_sequence );
    next_write_uint64( &p, session_id );
    next_write_bytes( &p, ping_token, NEXT_ENCRYPTED_PING_TOKEN_BYTES );
    uint8_t * b = p; p += 2;
    int packet_length = p - packet_data;
    next_generate_chonkle( a, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( b, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    return packet_length;
}

int next_write_relay_pong_packet( uint8_t * packet_data, uint64_t ping_sequence, uint64_t session_id, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    uint8_t * p = packet_data;
    next_write_uint8( &p, NEXT_RELAY_PONG_PACKET );
    uint8_t * a = p; p += 15;
    next_write_uint64( &p, ping_sequence );
    next_write_uint64( &p, session_id );
    uint8_t * b = p; p += 2;
    int packet_length = p - packet_data;
    next_generate_chonkle( a, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( b, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    return packet_length;
}

int next_write_packet( uint8_t packet_id, void * packet_object, uint8_t * packet_data, int * packet_bytes, const int * signed_packet, const int * encrypted_packet, uint64_t * sequence, const uint8_t * sign_private_key, const uint8_t * encrypt_private_key, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    next_assert( packet_object );
    next_assert( packet_data );
    next_assert( packet_bytes );

    next::WriteStream stream( packet_data, NEXT_MAX_PACKET_BYTES );

    typedef next::WriteStream Stream;

    serialize_bits( stream, packet_id, 8 );

    for ( int i = 0; i < 15; ++i )
    {
        uint8_t dummy = 0;
        serialize_bits( stream, dummy, 8 );
    }

    if ( encrypted_packet && encrypted_packet[packet_id] != 0 )
    {
        next_assert( sequence );
        next_assert( encrypt_private_key );
        serialize_uint64( stream, *sequence );
    }

    switch ( packet_id )
    {
        case NEXT_UPGRADE_REQUEST_PACKET:
        {
            NextUpgradeRequestPacket * packet = (NextUpgradeRequestPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "failed to write upgrade request packet" );
                return NEXT_ERROR;
            }
        }
        break;

        case NEXT_UPGRADE_RESPONSE_PACKET:
        {
            NextUpgradeResponsePacket * packet = (NextUpgradeResponsePacket*) packet_object;
            if ( !packet->Serialize( stream ) )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "failed to write upgrade response packet" );
                return NEXT_ERROR;
            }
        }
        break;

        case NEXT_UPGRADE_CONFIRM_PACKET:
        {
            NextUpgradeConfirmPacket * packet = (NextUpgradeConfirmPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "failed to write upgrade confirm packet" );
                return NEXT_ERROR;
            }
        }
        break;

        case NEXT_DIRECT_PING_PACKET:
        {
            NextDirectPingPacket * packet = (NextDirectPingPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "failed to write direct ping packet" );
                return NEXT_ERROR;
            }
        }
        break;

        case NEXT_DIRECT_PONG_PACKET:
        {
            NextDirectPongPacket * packet = (NextDirectPongPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "failed to write direct pong packet" );
                return NEXT_ERROR;
            }
        }
        break;

        case NEXT_CLIENT_STATS_PACKET:
        {
            NextClientStatsPacket * packet = (NextClientStatsPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "failed to write client stats packet" );
                return NEXT_ERROR;
            }
        }
        break;

        case NEXT_ROUTE_UPDATE_PACKET:
        {
            NextRouteUpdatePacket * packet = (NextRouteUpdatePacket*) packet_object;
            if ( !packet->Serialize( stream ) )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "failed to write route update packet" );
                return NEXT_ERROR;
            }
        }
        break;

        case NEXT_ROUTE_UPDATE_ACK_PACKET:
        {
            NextRouteUpdateAckPacket * packet = (NextRouteUpdateAckPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "failed to write route update ack packet" );
                return NEXT_ERROR;
            }
        }
        break;

        default:
            return NEXT_ERROR;
    }

    stream.Flush();

    *packet_bytes = stream.GetBytesProcessed();

    if ( signed_packet && signed_packet[packet_id] )
    {
        next_assert( sign_private_key );
        next_crypto_sign_state_t state;
        next_crypto_sign_init( &state );
        next_crypto_sign_update( &state, packet_data, 1 );
        next_crypto_sign_update( &state, packet_data + 16, *packet_bytes - 16 );
        next_crypto_sign_final_create( &state, packet_data + *packet_bytes, NULL, sign_private_key );
        *packet_bytes += NEXT_CRYPTO_SIGN_BYTES;
    }

    if ( encrypted_packet && encrypted_packet[packet_id] )
    {
        next_assert( !( signed_packet && signed_packet[packet_id] ) );

        uint8_t * additional = packet_data;
        uint8_t * nonce = packet_data + 16;
        uint8_t * message = packet_data + 16 + 8;
        int message_length = *packet_bytes - 16 - 8;

        unsigned long long encrypted_bytes = 0;

        next_crypto_aead_chacha20poly1305_encrypt( message, &encrypted_bytes,
                                                   message, message_length,
                                                   additional, 1,
                                                   NULL, nonce, encrypt_private_key );

        next_assert( encrypted_bytes == uint64_t(message_length) + NEXT_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES );

        *packet_bytes = 1 + 15 + 8 + encrypted_bytes;

        (*sequence)++;
    }

    *packet_bytes += 2;

    int packet_length = *packet_bytes;

    next_generate_chonkle( packet_data + 1, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );
    next_generate_pittle( packet_data + packet_length - 2, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, packet_length );

    return NEXT_OK;
}

bool next_is_payload_packet( uint8_t packet_id )
{
    return packet_id == NEXT_CLIENT_TO_SERVER_PACKET ||
           packet_id == NEXT_SERVER_TO_CLIENT_PACKET;
}

uint64_t next_clean_sequence( uint64_t sequence )
{
    uint64_t mask = ~( (1ULL<<63) | (1ULL<<62) );
    return sequence & mask;
}

int next_read_packet( uint8_t packet_id, uint8_t * packet_data, int begin, int end, void * packet_object, const int * signed_packet, const int * encrypted_packet, uint64_t * sequence, const uint8_t * sign_public_key, const uint8_t * encrypt_private_key, next_replay_protection_t * replay_protection )
{
    next_assert( packet_data );
    next_assert( packet_object );

    next::ReadStream stream( packet_data, end );

    uint8_t * dummy = (uint8_t*) alloca( begin );
    serialize_bytes( stream, dummy, begin );

    if ( signed_packet && signed_packet[packet_id] )
    {
        next_assert( sign_public_key );

        const int packet_bytes = end - begin;

        if ( packet_bytes < int( NEXT_CRYPTO_SIGN_BYTES ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "signed packet is too small to be valid" );
            return NEXT_ERROR;
        }

        next_crypto_sign_state_t state;
        next_crypto_sign_init( &state );
        next_crypto_sign_update( &state, &packet_id, 1 );
        next_crypto_sign_update( &state, packet_data + begin, packet_bytes - NEXT_CRYPTO_SIGN_BYTES );
        if ( next_crypto_sign_final_verify( &state, packet_data + end - NEXT_CRYPTO_SIGN_BYTES, sign_public_key ) != 0 )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "signed packet did not verify" );
            return NEXT_ERROR;
        }
    }

    if ( encrypted_packet && encrypted_packet[packet_id] )
    {
        next_assert( !( signed_packet && signed_packet[packet_id] ) );

        next_assert( sequence );
        next_assert( encrypt_private_key );
        next_assert( replay_protection );

        const int packet_bytes = end - begin;

        if ( packet_bytes <= (int) ( 8 + NEXT_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "encrypted packet is too small to be valid" );
            return NEXT_ERROR;
        }

        const uint8_t * p = packet_data + begin;

        *sequence = next_read_uint64( &p );

        uint8_t * nonce = packet_data + begin;
        uint8_t * message = packet_data + begin + 8;
        uint8_t * additional = &packet_id;

        int message_length = end - ( begin + 8 );

        unsigned long long decrypted_bytes;

        if ( next_crypto_aead_chacha20poly1305_decrypt( message, &decrypted_bytes,
                                                        NULL,
                                                        message, message_length,
                                                        additional, 1,
                                                        nonce, encrypt_private_key ) != 0 )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "encrypted packet failed to decrypt" );
            return NEXT_ERROR;
        }

        next_assert( decrypted_bytes == uint64_t(message_length) - NEXT_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES );

        serialize_bytes( stream, dummy, 8 );

        uint64_t clean_sequence = next_clean_sequence( *sequence );

        if ( next_replay_protection_already_received( replay_protection, clean_sequence ) )
            return NEXT_ERROR;
    }

    switch ( packet_id )
    {
        case NEXT_UPGRADE_REQUEST_PACKET:
        {
            NextUpgradeRequestPacket * packet = (NextUpgradeRequestPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_UPGRADE_RESPONSE_PACKET:
        {
            NextUpgradeResponsePacket * packet = (NextUpgradeResponsePacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_UPGRADE_CONFIRM_PACKET:
        {
            NextUpgradeConfirmPacket * packet = (NextUpgradeConfirmPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_DIRECT_PING_PACKET:
        {
            NextDirectPingPacket * packet = (NextDirectPingPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_DIRECT_PONG_PACKET:
        {
            NextDirectPongPacket * packet = (NextDirectPongPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_CLIENT_STATS_PACKET:
        {
            NextClientStatsPacket * packet = (NextClientStatsPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_ROUTE_UPDATE_PACKET:
        {
            NextRouteUpdatePacket * packet = (NextRouteUpdatePacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_ROUTE_UPDATE_ACK_PACKET:
        {
            NextRouteUpdateAckPacket * packet = (NextRouteUpdateAckPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        default:
            return NEXT_ERROR;
    }

    return (int) packet_id;
}

void next_post_validate_packet( uint8_t packet_id, const int * encrypted_packet, uint64_t * sequence, next_replay_protection_t * replay_protection )
{
    const bool payload_packet = next_is_payload_packet( packet_id );

    if ( payload_packet && encrypted_packet && encrypted_packet[packet_id] )
    {
        next_replay_protection_advance_sequence( replay_protection, *sequence );
    }
}

// -------------------------------------------------------------

// *le sigh* ...

void next_copy_string( char * dest, const char * source, size_t dest_size )
{
    next_assert( dest );
    next_assert( source );
    next_assert( dest_size >= 1 );
    memset( dest, 0, dest_size );
    for ( size_t i = 0; i < dest_size - 1; i++ )
    {
        if ( source[i] == '\0' )
            break;
        dest[i] = source[i];
    }
}

// -------------------------------------------------------------

static int next_signed_packets[256];

static int next_encrypted_packets[256];

void * next_global_context = NULL;

struct next_config_internal_t
{
    char server_backend_hostname[256];
    uint64_t client_customer_id;
    uint64_t server_customer_id;
    uint8_t customer_public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
    uint8_t customer_private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
    bool valid_customer_private_key;
    bool valid_customer_public_key;
    int socket_send_buffer_size;
    int socket_receive_buffer_size;
    bool disable_network_next;
    bool disable_autodetect;
};

static next_config_internal_t next_global_config;

void next_default_config( next_config_t * config )
{
    next_assert( config );
    memset( config, 0, sizeof(next_config_t) );
    next_copy_string( config->server_backend_hostname, NEXT_SERVER_BACKEND_HOSTNAME, sizeof(config->server_backend_hostname) );
    config->server_backend_hostname[sizeof(config->server_backend_hostname)-1] = '\0';
    config->socket_send_buffer_size = NEXT_DEFAULT_SOCKET_SEND_BUFFER_SIZE;
    config->socket_receive_buffer_size = NEXT_DEFAULT_SOCKET_RECEIVE_BUFFER_SIZE;
}

int next_init( void * context, next_config_t * config_in )
{
    next_assert( next_global_context == NULL );

    next_global_context = context;

    if ( next_platform_init() != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "failed to initialize platform" );
        return NEXT_ERROR;
    }

    if ( next_crypto_init() == -1 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "failed to initialize sodium" );
        return NEXT_ERROR;
    }

    const char * log_level_override = next_platform_getenv( "NEXT_LOG_LEVEL" );
    if ( log_level_override )
    {
        log_level = atoi( log_level_override );
        next_printf( NEXT_LOG_LEVEL_INFO, "log level overridden to %d", log_level );
    }

    next_config_internal_t config;

    memset( &config, 0, sizeof(next_config_internal_t) );

    config.socket_send_buffer_size = NEXT_DEFAULT_SOCKET_SEND_BUFFER_SIZE;
    config.socket_receive_buffer_size = NEXT_DEFAULT_SOCKET_RECEIVE_BUFFER_SIZE;

    const char * customer_public_key_env = next_platform_getenv( "NEXT_CUSTOMER_PUBLIC_KEY" );
    if ( customer_public_key_env )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "customer public key override: '%s'", customer_public_key_env );
    }

    const char * customer_public_key = customer_public_key_env ? customer_public_key_env : ( config_in ? config_in->customer_public_key : "" );
    if ( customer_public_key )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "customer public key is '%s'", customer_public_key );
        uint8_t decode_buffer[8+NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        if ( next_base64_decode_data( customer_public_key, decode_buffer, sizeof(decode_buffer) ) == sizeof(decode_buffer) )
        {
            const uint8_t * p = decode_buffer;
            config.client_customer_id = next_read_uint64( &p );
            memcpy( config.customer_public_key, decode_buffer + 8, NEXT_CRYPTO_SIGN_PUBLICKEYBYTES );
            next_printf( NEXT_LOG_LEVEL_INFO, "found valid customer public key: '%s'", customer_public_key );
            config.valid_customer_public_key = true;
        }
        else
        {
            if ( customer_public_key[0] != '\0' )
            {
                next_printf( NEXT_LOG_LEVEL_ERROR, "customer public key is invalid: '%s'", customer_public_key );
            }
        }
    }

    const char * customer_private_key_env = next_platform_getenv( "NEXT_CUSTOMER_PRIVATE_KEY" );
    if ( customer_private_key_env )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "customer private key override" );
    }

    const char * customer_private_key = customer_private_key_env ? customer_private_key_env : ( config_in ? config_in->customer_private_key : "" );
    if ( customer_private_key )
    {
        uint8_t decode_buffer[8+NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        if ( customer_private_key && next_base64_decode_data( customer_private_key, decode_buffer, sizeof(decode_buffer) ) == sizeof(decode_buffer) )
        {
            const uint8_t * p = decode_buffer;
            config.server_customer_id = next_read_uint64( &p );
            memcpy( config.customer_private_key, decode_buffer + 8, NEXT_CRYPTO_SIGN_SECRETKEYBYTES );
            config.valid_customer_private_key = true;
            next_printf( NEXT_LOG_LEVEL_INFO, "found valid customer private key" );
        }
        else
        {
            if ( customer_private_key[0] != '\0' )
            {
                next_printf( NEXT_LOG_LEVEL_ERROR, "customer private key is invalid" );
            }
        }
    }

    if ( config.valid_customer_private_key && config.valid_customer_public_key && config.client_customer_id != config.server_customer_id )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "mismatch between client and server customer id. please check the private and public keys are part of the same keypair!" );
        config.valid_customer_public_key = false;
        config.valid_customer_private_key = false;
        memset( config.customer_public_key, 0, sizeof(config.customer_public_key) );
        memset( config.customer_private_key, 0, sizeof(config.customer_private_key) );
    }

    next_copy_string( config.server_backend_hostname, config_in ? config_in->server_backend_hostname : NEXT_SERVER_BACKEND_HOSTNAME, sizeof(config.server_backend_hostname) );

    if ( config_in )
    {
        config.socket_send_buffer_size = config_in->socket_send_buffer_size;
        config.socket_receive_buffer_size = config_in->socket_receive_buffer_size;
    }

    config.disable_network_next = config_in ? config_in->disable_network_next : false;

    const char * next_disable_override = next_platform_getenv( "NEXT_DISABLE_NETWORK_NEXT" );
    {
        if ( next_disable_override != NULL )
        {
            int value = atoi( next_disable_override );
            if ( value > 0 )
            {
                config.disable_network_next = true;
            }
        }
    }

    if ( config.disable_network_next )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "network next is disabled" );
    }

    config.disable_autodetect = config_in ? config_in->disable_autodetect : false;

    const char * next_disable_autodetect_override = next_platform_getenv( "NEXT_DISABLE_AUTODETECT" );
    {
        if ( next_disable_autodetect_override != NULL )
        {
            int value = atoi( next_disable_autodetect_override );
            if ( value > 0 )
            {
                config.disable_autodetect = true;
            }
        }
    }

    if ( config.disable_autodetect )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "autodetect is disabled" );
    }

    const char * socket_send_buffer_size_override = next_platform_getenv( "NEXT_SOCKET_SEND_BUFFER_SIZE" );
    if ( socket_send_buffer_size_override != NULL )
    {
        int value = atoi( socket_send_buffer_size_override );
        if ( value > 0 )
        {
            next_printf( NEXT_LOG_LEVEL_INFO, "override socket send buffer size: %d", value );
            config.socket_send_buffer_size = value;
        }
    }

    const char * socket_receive_buffer_size_override = next_platform_getenv( "NEXT_SOCKET_RECEIVE_BUFFER_SIZE" );
    if ( socket_receive_buffer_size_override != NULL )
    {
        int value = atoi( socket_receive_buffer_size_override );
        if ( value > 0 )
        {
            next_printf( NEXT_LOG_LEVEL_INFO, "override socket receive buffer size: %d", value );
            config.socket_receive_buffer_size = value;
        }
    }

    const char * next_server_backend_hostname_override = next_platform_getenv( "NEXT_SERVER_BACKEND_HOSTNAME_SDK5" );

    if ( !next_server_backend_hostname_override ) 
    {
        next_server_backend_hostname_override = next_platform_getenv( "NEXT_SERVER_BACKEND_HOSTNAME" );
    }

    if ( !next_server_backend_hostname_override )
    {
        next_server_backend_hostname_override = next_platform_getenv( "NEXT_HOSTNAME" );
    }

    if ( next_server_backend_hostname_override )
    {

        next_printf( NEXT_LOG_LEVEL_INFO, "override server backend hostname: '%s'", next_server_backend_hostname_override );
        next_copy_string( config.server_backend_hostname, next_server_backend_hostname_override, sizeof(config.server_backend_hostname) );
    }

    const char * server_backend_public_key_env = next_platform_getenv( "NEXT_SERVER_BACKEND_PUBLIC_KEY" );
    if ( server_backend_public_key_env )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server backend public key override: %s", server_backend_public_key_env );

        if ( next_base64_decode_data( server_backend_public_key_env, next_server_backend_public_key, NEXT_CRYPTO_SIGN_PUBLICKEYBYTES ) == NEXT_CRYPTO_SIGN_PUBLICKEYBYTES )
        {
            next_printf( NEXT_LOG_LEVEL_INFO, "valid server backend public key" );
        }
        else
        {
            if ( server_backend_public_key_env[0] != '\0' )
            {
                next_printf( NEXT_LOG_LEVEL_ERROR, "server backend public key is invalid: \"%s\"", server_backend_public_key_env );
            }
        }
    }

    const char * router_public_key_env = next_platform_getenv( "NEXT_ROUTER_PUBLIC_KEY" );
    if ( router_public_key_env )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "router public key override: %s", router_public_key_env );

        if ( next_base64_decode_data( router_public_key_env, next_router_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES ) == NEXT_CRYPTO_BOX_PUBLICKEYBYTES )
        {
            next_printf( NEXT_LOG_LEVEL_INFO, "valid router public key" );
        }
        else
        {
            if ( router_public_key_env[0] != '\0' )
            {
                next_printf( NEXT_LOG_LEVEL_ERROR, "router public key is invalid: \"%s\"", router_public_key_env );
            }
        }
    }

    next_global_config = config;

    next_signed_packets[NEXT_UPGRADE_REQUEST_PACKET] = 1;
    next_signed_packets[NEXT_UPGRADE_CONFIRM_PACKET] = 1;

    next_signed_packets[NEXT_BACKEND_SERVER_INIT_REQUEST_PACKET] = 1;
    next_signed_packets[NEXT_BACKEND_SERVER_INIT_RESPONSE_PACKET] = 1;
    next_signed_packets[NEXT_BACKEND_SERVER_UPDATE_REQUEST_PACKET] = 1;
    next_signed_packets[NEXT_BACKEND_SERVER_UPDATE_RESPONSE_PACKET] = 1;
    next_signed_packets[NEXT_BACKEND_SESSION_UPDATE_REQUEST_PACKET] = 1;
    next_signed_packets[NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET] = 1;
    next_signed_packets[NEXT_BACKEND_MATCH_DATA_REQUEST_PACKET] = 1;
    next_signed_packets[NEXT_BACKEND_MATCH_DATA_RESPONSE_PACKET] = 1;

    next_encrypted_packets[NEXT_DIRECT_PING_PACKET] = 1;
    next_encrypted_packets[NEXT_DIRECT_PONG_PACKET] = 1;
    next_encrypted_packets[NEXT_CLIENT_STATS_PACKET] = 1;
    next_encrypted_packets[NEXT_ROUTE_UPDATE_PACKET] = 1;
    next_encrypted_packets[NEXT_ROUTE_UPDATE_ACK_PACKET] = 1;

    return NEXT_OK;
}

void next_term()
{
    next_platform_term();

    next_global_context = NULL;
}

// ---------------------------------------------------------------

struct next_queue_t
{
    NEXT_DECLARE_SENTINEL(0)

    void * context;
    int size;
    int num_entries;
    int start_index;
    void ** entries;

    NEXT_DECLARE_SENTINEL(1)
};

void next_queue_initialize_sentinels( next_queue_t * queue )
{
    (void) queue;
    next_assert( queue );
    NEXT_INITIALIZE_SENTINEL( queue, 0 )
    NEXT_INITIALIZE_SENTINEL( queue, 1 )
}

void next_queue_verify_sentinels( next_queue_t * queue )
{
    (void) queue;
    next_assert( queue );
    NEXT_VERIFY_SENTINEL( queue, 0 )
    NEXT_VERIFY_SENTINEL( queue, 1 )
}

void next_queue_destroy( next_queue_t * queue );

next_queue_t * next_queue_create( void * context, int size )
{
    next_queue_t * queue = (next_queue_t*) next_malloc( context, sizeof(next_queue_t) );
    next_assert( queue );
    if ( !queue )
        return NULL;

    next_queue_initialize_sentinels( queue );

    queue->context = context;
    queue->size = size;
    queue->num_entries = 0;
    queue->start_index = 0;
    queue->entries = (void**) next_malloc( context, size * sizeof(void*) );

    next_assert( queue->entries );

    if ( !queue->entries )
    {
        next_queue_destroy( queue );
        return NULL;
    }

    next_queue_verify_sentinels( queue );

    return queue;
}

void next_queue_clear( next_queue_t * queue );

void next_queue_destroy( next_queue_t * queue )
{
    next_queue_verify_sentinels( queue );

    next_queue_clear( queue );

    next_free( queue->context, queue->entries );

    clear_and_free( queue->context, queue, sizeof( queue ) );
}

void next_queue_clear( next_queue_t * queue )
{
    next_queue_verify_sentinels( queue );

    const int queue_size = queue->size;
    const int start_index = queue->start_index;

    for ( int i = 0; i < queue->num_entries; ++i )
    {
        const int index = (start_index + i ) % queue_size;
        next_free( queue->context, queue->entries[index] );
        queue->entries[index] = NULL;
    }

    queue->num_entries = 0;
    queue->start_index = 0;
}

int next_queue_push( next_queue_t * queue, void * entry )
{
    next_queue_verify_sentinels( queue );

    next_assert( entry );

    if ( queue->num_entries == queue->size )
    {
        next_free( queue->context, entry );
        return NEXT_ERROR;
    }

    int index = ( queue->start_index + queue->num_entries ) % queue->size;

    queue->entries[index] = entry;
    queue->num_entries++;

    return NEXT_OK;
}

void * next_queue_pop( next_queue_t * queue )
{
    next_queue_verify_sentinels( queue );

    if ( queue->num_entries == 0 )
        return NULL;

    void * entry = queue->entries[queue->start_index];

    queue->start_index = ( queue->start_index + 1 ) % queue->size;
    queue->num_entries--;

    return entry;
}

// ---------------------------------------------------------------

struct next_route_stats_t
{
    float rtt;                          // rtt (ms)
    float jitter;                       // jitter (ms)
    float packet_loss;                  // packet loss %
};

struct next_ping_history_entry_t
{
    uint64_t sequence;
    double time_ping_sent;
    double time_pong_received;
};

struct next_ping_history_t
{
    NEXT_DECLARE_SENTINEL(0)

    uint64_t sequence;

    NEXT_DECLARE_SENTINEL(1)

    next_ping_history_entry_t entries[NEXT_PING_HISTORY_ENTRY_COUNT];

    NEXT_DECLARE_SENTINEL(2)
};

void next_ping_history_initialize_sentinels( next_ping_history_t * history )
{
    (void) history;
    next_assert( history );
    NEXT_INITIALIZE_SENTINEL( history, 0 )
    NEXT_INITIALIZE_SENTINEL( history, 1 )
    NEXT_INITIALIZE_SENTINEL( history, 2 )
}

void next_ping_history_verify_sentinels( const next_ping_history_t * history )
{
    (void) history;
    next_assert( history );
    NEXT_VERIFY_SENTINEL( history, 0 )
    NEXT_VERIFY_SENTINEL( history, 1 )
    NEXT_VERIFY_SENTINEL( history, 2 )
}

void next_ping_history_clear( next_ping_history_t * history )
{
    next_assert( history );

    next_ping_history_initialize_sentinels( history );

    history->sequence = 0;

    for ( int i = 0; i < NEXT_PING_HISTORY_ENTRY_COUNT; ++i )
    {
        history->entries[i].sequence = 0xFFFFFFFFFFFFFFFFULL;
        history->entries[i].time_ping_sent = -1.0;
        history->entries[i].time_pong_received = -1.0;
    }

    next_ping_history_verify_sentinels( history );
}

uint64_t next_ping_history_ping_sent( next_ping_history_t * history, double time )
{
    next_ping_history_verify_sentinels( history );

    const int index = history->sequence % NEXT_PING_HISTORY_ENTRY_COUNT;

    next_ping_history_entry_t * entry = &history->entries[index];

    entry->sequence = history->sequence;
    entry->time_ping_sent = time;
    entry->time_pong_received = -1.0;

    history->sequence++;

    return entry->sequence;
}

void next_ping_history_pong_received( next_ping_history_t * history, uint64_t sequence, double time )
{
    next_ping_history_verify_sentinels( history );

    const int index = sequence % NEXT_PING_HISTORY_ENTRY_COUNT;

    next_ping_history_entry_t * entry = &history->entries[index];

    if ( entry->sequence == sequence )
    {
        entry->time_pong_received = time;
    }
}

void next_route_stats_from_ping_history( const next_ping_history_t * history, double start, double end, next_route_stats_t * stats, double safety = NEXT_PING_SAFETY )
{
    next_ping_history_verify_sentinels( history );

    next_assert( stats );

    if ( start < safety )
    {
        start = safety;
    }

    stats->rtt = 0.0f;
    stats->jitter = 0.0f;
    stats->packet_loss = 0.0f;

    // IMPORTANT: Instead of searching across the whole range then considering any ping with a pong older than ping safety
    // (typically one second) to be lost, look for the time of the most recent ping that has received a pong, subtract ping
    // safety from this, and then look for packet loss only in this range. This avoids turning every ping that receives a
    // pong more than 1 second later as packet loss, which was behavior we saw with previous versions of this code.

    double most_recent_ping_that_received_pong_time = 0.0;

    for ( int i = 0; i < NEXT_PING_HISTORY_ENTRY_COUNT; i++ )
    {
        const next_ping_history_entry_t * entry = &history->entries[i];

        if ( entry->time_ping_sent >= start && entry->time_ping_sent <= end && entry->time_pong_received >= entry->time_ping_sent )
        {
            if ( entry->time_pong_received > most_recent_ping_that_received_pong_time )
            {
                most_recent_ping_that_received_pong_time = entry->time_pong_received;
            }
        }
    }

    if ( most_recent_ping_that_received_pong_time > 0.0 )
    {
        end = most_recent_ping_that_received_pong_time - safety;
    }
    else
    {
        return;
    }

    // calculate ping stats

    double min_rtt = FLT_MAX;

    int num_pings_sent = 0;
    int num_pongs_received = 0;

    for ( int i = 0; i < NEXT_PING_HISTORY_ENTRY_COUNT; i++ )
    {
        const next_ping_history_entry_t * entry = &history->entries[i];

        if ( entry->time_ping_sent >= start && entry->time_ping_sent <= end )
        {
            num_pings_sent++;

            if ( entry->time_pong_received >= entry->time_ping_sent )
            {
                double rtt = 1000.0 * ( entry->time_pong_received - entry->time_ping_sent );

                if ( rtt < min_rtt )
                {
                    min_rtt = rtt;
                }

                num_pongs_received++;
            }
        }
    }

    if ( num_pings_sent > 0 && num_pongs_received > 0 )
    {
        next_assert( min_rtt >= 0.0 );

        stats->rtt = float( min_rtt );

        stats->packet_loss = (float) ( 100.0 * ( 1.0 - ( double( num_pongs_received ) / double( num_pings_sent ) ) ) );
    }

    // calculate jitter relative to min rtt

    int num_jitter_samples = 0;

    double stddev_rtt = 0.0;

    for ( int i = 0; i < NEXT_PING_HISTORY_ENTRY_COUNT; i++ )
    {
        const next_ping_history_entry_t * entry = &history->entries[i];

        if ( entry->time_ping_sent >= start && entry->time_ping_sent <= end )
        {
            if ( entry->time_pong_received > entry->time_ping_sent )
            {
                // pong received
                double rtt = 1000.0 * ( entry->time_pong_received - entry->time_ping_sent );
                double error = rtt - min_rtt;
                stddev_rtt += error * error;
                num_jitter_samples++;
            }
        }
    }

    if ( num_jitter_samples > 0 )
    {
        stats->jitter = (float) sqrt( stddev_rtt / num_jitter_samples );
    }

    next_ping_history_verify_sentinels( history );
}

// ---------------------------------------------------------------

struct next_relay_stats_t
{
    NEXT_DECLARE_SENTINEL(0)

    bool has_pings;
    int num_relays;

    NEXT_DECLARE_SENTINEL(1)

    uint64_t relay_ids[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(2)

    float relay_rtt[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(3)

    float relay_jitter[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(4)

    float relay_packet_loss[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(5)
};

void next_relay_stats_initialize_sentinels( next_relay_stats_t * stats )
{
    (void) stats;
    next_assert( stats );
    NEXT_INITIALIZE_SENTINEL( stats, 0 )
    NEXT_INITIALIZE_SENTINEL( stats, 1 )
    NEXT_INITIALIZE_SENTINEL( stats, 2 )
    NEXT_INITIALIZE_SENTINEL( stats, 3 )
    NEXT_INITIALIZE_SENTINEL( stats, 4 )
    NEXT_INITIALIZE_SENTINEL( stats, 5 )
}

void next_relay_stats_verify_sentinels( next_relay_stats_t * stats )
{
    (void) stats;
    next_assert( stats );
    NEXT_VERIFY_SENTINEL( stats, 0 )
    NEXT_VERIFY_SENTINEL( stats, 1 )
    NEXT_VERIFY_SENTINEL( stats, 2 )
    NEXT_VERIFY_SENTINEL( stats, 3 )
    NEXT_VERIFY_SENTINEL( stats, 4 )
    NEXT_VERIFY_SENTINEL( stats, 5 )
}

// ---------------------------------------------------------------

struct next_relay_manager_t
{
    NEXT_DECLARE_SENTINEL(0)

    void * context;
    int num_relays;

    NEXT_DECLARE_SENTINEL(1)

    uint64_t relay_ids[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(2)

    double relay_last_ping_time[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(3)

    next_address_t relay_addresses[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(4)

    next_ping_history_t relay_ping_history[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(5)
};

void next_relay_manager_initialize_sentinels( next_relay_manager_t * manager )
{
    (void) manager;

    next_assert( manager );

    NEXT_INITIALIZE_SENTINEL( manager, 0 )
    NEXT_INITIALIZE_SENTINEL( manager, 1 )
    NEXT_INITIALIZE_SENTINEL( manager, 2 )
    NEXT_INITIALIZE_SENTINEL( manager, 3 )
    NEXT_INITIALIZE_SENTINEL( manager, 4 )
    NEXT_INITIALIZE_SENTINEL( manager, 5 )

    for ( int i = 0; i < NEXT_MAX_NEAR_RELAYS; ++i )
        next_ping_history_initialize_sentinels( &manager->relay_ping_history[i] );
}

void next_relay_manager_verify_sentinels( next_relay_manager_t * manager )
{
    (void) manager;
#if NEXT_ENABLE_MEMORY_CHECKS
    next_assert( manager );
    NEXT_VERIFY_SENTINEL( manager, 0 )
    NEXT_VERIFY_SENTINEL( manager, 1 )
    NEXT_VERIFY_SENTINEL( manager, 2 )
    NEXT_VERIFY_SENTINEL( manager, 3 )
    NEXT_VERIFY_SENTINEL( manager, 4 )
    NEXT_VERIFY_SENTINEL( manager, 5 )
    for ( int i = 0; i < NEXT_MAX_NEAR_RELAYS; ++i )
        next_ping_history_verify_sentinels( &manager->relay_ping_history[i] );
#endif // #if NEXT_ENABLE_MEMORY_CHECKS
}

void next_relay_manager_reset( next_relay_manager_t * manager );

next_relay_manager_t * next_relay_manager_create( void * context )
{
    next_relay_manager_t * manager = (next_relay_manager_t*) next_malloc( context, sizeof(next_relay_manager_t) );
    if ( !manager )
        return NULL;

    memset( manager, 0, sizeof(next_relay_manager_t) );

    manager->context = context;

    next_relay_manager_initialize_sentinels( manager );

    next_relay_manager_reset( manager );

    next_relay_manager_verify_sentinels( manager );

    return manager;
}

void next_relay_manager_reset( next_relay_manager_t * manager )
{
    next_relay_manager_verify_sentinels( manager );

    manager->num_relays = 0;

    memset( manager->relay_ids, 0, sizeof(manager->relay_ids) );
    memset( manager->relay_last_ping_time, 0, sizeof(manager->relay_last_ping_time) );
    memset( manager->relay_addresses, 0, sizeof(manager->relay_addresses) );

    for ( int i = 0; i < NEXT_MAX_NEAR_RELAYS; ++i )
    {
        next_ping_history_clear( &manager->relay_ping_history[i] );
    }
}

void next_relay_manager_update( next_relay_manager_t * manager, int num_relays, const uint64_t * relay_ids, const next_address_t * relay_addresses )
{
    next_relay_manager_verify_sentinels( manager );

    next_assert( num_relays >= 0 );
    next_assert( num_relays <= NEXT_MAX_NEAR_RELAYS );
    next_assert( relay_ids );
    next_assert( relay_addresses );

    // reset relay manager

    next_relay_manager_reset( manager );

    // copy across all relay data

    manager->num_relays = num_relays;

    for ( int i = 0; i < num_relays; ++i )
    {
        manager->relay_ids[i] = relay_ids[i];
        manager->relay_addresses[i] = relay_addresses[i];
    }

    // make sure all ping times are evenly distributed to avoid clusters of ping packets

    double current_time = next_time();

    const double ping_time = 1.0 / NEXT_PING_RATE;

    for ( int i = 0; i < manager->num_relays; ++i )
    {
        manager->relay_last_ping_time[i] = current_time - ping_time + i * ping_time / manager->num_relays;
    }

    next_relay_manager_verify_sentinels( manager );
}

void next_relay_manager_send_pings( next_relay_manager_t * manager, next_platform_socket_t * socket, uint64_t session_id, const uint8_t * magic, const next_address_t * client_external_address )
{
    next_relay_manager_verify_sentinels( manager );

    next_assert( socket );

    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];

    double current_time = next_time();

    for ( int i = 0; i < manager->num_relays; ++i )
    {
        const double ping_time = 1.0 / NEXT_PING_RATE;

        if ( manager->relay_last_ping_time[i] + ping_time <= current_time )
        {
            uint64_t ping_sequence = next_ping_history_ping_sent( &manager->relay_ping_history[i], next_time() );

            // for the moment pass in a dummy ping token
            uint8_t ping_token[1024];
            memset( ping_token, 0, sizeof(ping_token) );

            uint8_t from_address_data[32];
            uint8_t to_address_data[32];
            uint16_t from_address_port;
            uint16_t to_address_port;
            int from_address_bytes;
            int to_address_bytes;

            next_address_data( client_external_address, from_address_data, &from_address_bytes, &from_address_port );
            next_address_data( &manager->relay_addresses[i], to_address_data, &to_address_bytes, &to_address_port );

            int packet_bytes = next_write_relay_ping_packet( packet_data, ping_token, ping_sequence, session_id, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port );

            next_assert( packet_bytes > 0 );

            next_assert( next_basic_packet_filter( packet_data, packet_bytes ) );
            next_assert( next_advanced_packet_filter( packet_data, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

            next_platform_socket_send_packet( socket, &manager->relay_addresses[i], packet_data, packet_bytes );

            manager->relay_last_ping_time[i] = current_time;
        }
    }
}

void next_relay_manager_process_pong( next_relay_manager_t * manager, const next_address_t * from, uint64_t sequence )
{
    next_relay_manager_verify_sentinels( manager );

    next_assert( from );

    for ( int i = 0; i < manager->num_relays; ++i )
    {
        if ( next_address_equal( from, &manager->relay_addresses[i] ) )
        {
            next_ping_history_pong_received( &manager->relay_ping_history[i], sequence, next_time() );
            return;
        }
    }
}

void next_relay_manager_get_stats( next_relay_manager_t * manager, next_relay_stats_t * stats )
{
    next_relay_manager_verify_sentinels( manager );

    next_assert( stats );

    double current_time = next_time();

    next_relay_stats_initialize_sentinels( stats );

    stats->num_relays = manager->num_relays;
    stats->has_pings = stats->num_relays > 0;

    for ( int i = 0; i < stats->num_relays; ++i )
    {
        next_route_stats_t route_stats;

        next_route_stats_from_ping_history( &manager->relay_ping_history[i], current_time - NEXT_CLIENT_STATS_WINDOW, current_time, &route_stats );

        stats->relay_ids[i] = manager->relay_ids[i];
        stats->relay_rtt[i] = route_stats.rtt;
        stats->relay_jitter[i] = route_stats.jitter;
        stats->relay_packet_loss[i] = route_stats.packet_loss;
    }

    next_relay_stats_verify_sentinels( stats );
}

void next_relay_manager_destroy( next_relay_manager_t * manager )
{
    next_relay_manager_verify_sentinels( manager );

    next_free( manager->context, manager );
}

// ---------------------------------------------------------------

struct next_route_token_t
{
    uint64_t expire_timestamp;
    uint64_t session_id;
    uint8_t session_version;
    int kbps_up;
    int kbps_down;
    next_address_t next_address;
    uint8_t private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];
};

void next_write_route_token( next_route_token_t * token, uint8_t * buffer, int buffer_length )
{
    (void) buffer_length;

    next_assert( token );
    next_assert( buffer );
    next_assert( buffer_length >= NEXT_ROUTE_TOKEN_BYTES );

    uint8_t * start = buffer;

    (void) start;

    next_write_uint64( &buffer, token->expire_timestamp );
    next_write_uint64( &buffer, token->session_id );
    next_write_uint8( &buffer, token->session_version );
    next_write_uint32( &buffer, token->kbps_up );
    next_write_uint32( &buffer, token->kbps_down );
    next_write_address( &buffer, &token->next_address );
    next_write_bytes( &buffer, token->private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );

    next_assert( buffer - start == NEXT_ROUTE_TOKEN_BYTES );
}

void next_read_route_token( next_route_token_t * token, const uint8_t * buffer )
{
    next_assert( token );
    next_assert( buffer );

    const uint8_t * start = buffer;

    (void) start;

    token->expire_timestamp = next_read_uint64( &buffer );
    token->session_id = next_read_uint64( &buffer );
    token->session_version = next_read_uint8( &buffer );
    token->kbps_up = next_read_uint32( &buffer );
    token->kbps_down = next_read_uint32( &buffer );
    next_read_address( &buffer, &token->next_address );
    next_read_bytes( &buffer, token->private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );
    next_assert( buffer - start == NEXT_ROUTE_TOKEN_BYTES );
}

int next_encrypt_route_token( uint8_t * sender_private_key, uint8_t * receiver_public_key, uint8_t * nonce, uint8_t * buffer, int buffer_length )
{
    next_assert( sender_private_key );
    next_assert( receiver_public_key );
    next_assert( buffer );
    next_assert( buffer_length >= (int) ( NEXT_ROUTE_TOKEN_BYTES + NEXT_CRYPTO_BOX_MACBYTES ) );

    (void) buffer_length;

    if ( next_crypto_box_easy( buffer, buffer, NEXT_ROUTE_TOKEN_BYTES, nonce, receiver_public_key, sender_private_key ) != 0 )
    {
        return NEXT_ERROR;
    }

    return NEXT_OK;
}

int next_decrypt_route_token( const uint8_t * sender_public_key, const uint8_t * receiver_private_key, const uint8_t * nonce, uint8_t * buffer )
{
    next_assert( sender_public_key );
    next_assert( receiver_private_key );
    next_assert( buffer );

    if ( next_crypto_box_open_easy( buffer, buffer, NEXT_ROUTE_TOKEN_BYTES + NEXT_CRYPTO_BOX_MACBYTES, nonce, sender_public_key, receiver_private_key ) != 0 )
    {
        return NEXT_ERROR;
    }

    return NEXT_OK;
}

int next_write_encrypted_route_token( uint8_t ** buffer, next_route_token_t * token, uint8_t * sender_private_key, uint8_t * receiver_public_key )
{
    next_assert( buffer );
    next_assert( token );
    next_assert( sender_private_key );
    next_assert( receiver_public_key );

    unsigned char nonce[NEXT_CRYPTO_BOX_NONCEBYTES];
    next_random_bytes( nonce, NEXT_CRYPTO_BOX_NONCEBYTES );

    uint8_t * start = *buffer;

    (void) start;

    next_write_bytes( buffer, nonce, NEXT_CRYPTO_BOX_NONCEBYTES );

    next_write_route_token( token, *buffer, NEXT_ROUTE_TOKEN_BYTES );

    if ( next_encrypt_route_token( sender_private_key, receiver_public_key, nonce, *buffer, NEXT_ROUTE_TOKEN_BYTES + NEXT_CRYPTO_BOX_NONCEBYTES ) != NEXT_OK )
        return NEXT_ERROR;

    *buffer += NEXT_ROUTE_TOKEN_BYTES + NEXT_CRYPTO_BOX_MACBYTES;

    next_assert( ( *buffer - start ) == NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES );

    return NEXT_OK;
}

int next_read_encrypted_route_token( uint8_t ** buffer, next_route_token_t * token, const uint8_t * sender_public_key, const uint8_t * receiver_private_key )
{
    next_assert( buffer );
    next_assert( token );
    next_assert( sender_public_key );
    next_assert( receiver_private_key );

    const uint8_t * nonce = *buffer;

    *buffer += NEXT_CRYPTO_BOX_NONCEBYTES;

    if ( next_decrypt_route_token( sender_public_key, receiver_private_key, nonce, *buffer ) != NEXT_OK )
    {
        return NEXT_ERROR;
    }

    next_read_route_token( token, *buffer );

    *buffer += NEXT_ROUTE_TOKEN_BYTES + NEXT_CRYPTO_BOX_MACBYTES;

    return NEXT_OK;
}

// -----------------------------------------------------------

struct next_continue_token_t
{
    uint64_t expire_timestamp;
    uint64_t session_id;
    uint8_t session_version;
};

void next_write_continue_token( next_continue_token_t * token, uint8_t * buffer, int buffer_length )
{
    (void) buffer_length;

    next_assert( token );
    next_assert( buffer );
    next_assert( buffer_length >= NEXT_CONTINUE_TOKEN_BYTES );

    uint8_t * start = buffer;

    (void) start;

    next_write_uint64( &buffer, token->expire_timestamp );
    next_write_uint64( &buffer, token->session_id );
    next_write_uint8( &buffer, token->session_version );

    next_assert( buffer - start == NEXT_CONTINUE_TOKEN_BYTES );
}

void next_read_continue_token( next_continue_token_t * token, const uint8_t * buffer )
{
    next_assert( token );
    next_assert( buffer );

    const uint8_t * start = buffer;

    (void) start;

    token->expire_timestamp = next_read_uint64( &buffer );
    token->session_id = next_read_uint64( &buffer );
    token->session_version = next_read_uint8( &buffer );

    next_assert( buffer - start == NEXT_CONTINUE_TOKEN_BYTES );
}

int next_encrypt_continue_token( uint8_t * sender_private_key, uint8_t * receiver_public_key, uint8_t * nonce, uint8_t * buffer, int buffer_length )
{
    next_assert( sender_private_key );
    next_assert( receiver_public_key );
    next_assert( buffer );
    next_assert( buffer_length >= (int) ( NEXT_CONTINUE_TOKEN_BYTES + NEXT_CRYPTO_BOX_MACBYTES ) );

    (void) buffer_length;

    if ( next_crypto_box_easy( buffer, buffer, NEXT_CONTINUE_TOKEN_BYTES, nonce, receiver_public_key, sender_private_key ) != 0 )
    {
        return NEXT_ERROR;
    }

    return NEXT_OK;
}

int next_decrypt_continue_token( const uint8_t * sender_public_key, const uint8_t * receiver_private_key, const uint8_t * nonce, uint8_t * buffer )
{
    next_assert( sender_public_key );
    next_assert( receiver_private_key );
    next_assert( buffer );

    if ( next_crypto_box_open_easy( buffer, buffer, NEXT_CONTINUE_TOKEN_BYTES + NEXT_CRYPTO_BOX_MACBYTES, nonce, sender_public_key, receiver_private_key ) != 0 )
    {
        return NEXT_ERROR;
    }

    return NEXT_OK;
}

int next_write_encrypted_continue_token( uint8_t ** buffer, next_continue_token_t * token, uint8_t * sender_private_key, uint8_t * receiver_public_key )
{
    next_assert( buffer );
    next_assert( token );
    next_assert( sender_private_key );
    next_assert( receiver_public_key );

    unsigned char nonce[NEXT_CRYPTO_BOX_NONCEBYTES];
    next_random_bytes( nonce, NEXT_CRYPTO_BOX_NONCEBYTES );

    uint8_t * start = *buffer;

    next_write_bytes( buffer, nonce, NEXT_CRYPTO_BOX_NONCEBYTES );

    next_write_continue_token( token, *buffer, NEXT_CONTINUE_TOKEN_BYTES );

    if ( next_encrypt_continue_token( sender_private_key, receiver_public_key, nonce, *buffer, NEXT_CONTINUE_TOKEN_BYTES + NEXT_CRYPTO_BOX_NONCEBYTES ) != NEXT_OK )
        return NEXT_ERROR;

    *buffer += NEXT_CONTINUE_TOKEN_BYTES + NEXT_CRYPTO_BOX_MACBYTES;

    (void) start;

    next_assert( ( *buffer - start ) == NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES );

    return NEXT_OK;
}

int next_read_encrypted_continue_token( uint8_t ** buffer, next_continue_token_t * token, const uint8_t * sender_public_key, const uint8_t * receiver_private_key )
{
    next_assert( buffer );
    next_assert( token );
    next_assert( sender_public_key );
    next_assert( receiver_private_key );

    const uint8_t * nonce = *buffer;

    *buffer += NEXT_CRYPTO_BOX_NONCEBYTES;

    if ( next_decrypt_continue_token( sender_public_key, receiver_private_key, nonce, *buffer ) != NEXT_OK )
    {
        return NEXT_ERROR;
    }

    next_read_continue_token( token, *buffer );

    *buffer += NEXT_CONTINUE_TOKEN_BYTES + NEXT_CRYPTO_BOX_MACBYTES;

    return NEXT_OK;
}

// ---------------------------------------------------------------

struct next_ping_token_t
{
    uint64_t expire_timestamp;
    next_address_t from_address;
    next_address_t to_address;
};

void next_write_ping_token( next_ping_token_t * token, uint8_t * buffer, int buffer_length )
{
    (void) buffer_length;

    next_assert( token );
    next_assert( buffer );
    next_assert( buffer_length >= NEXT_PING_TOKEN_BYTES );

    uint8_t * start = buffer;

    (void) start;

    next_write_uint64( &buffer, token->expire_timestamp );
    next_write_address( &buffer, &token->from_address );
    next_write_address( &buffer, &token->to_address );

    next_assert( buffer - start == NEXT_PING_TOKEN_BYTES );
}

void next_read_ping_token( next_ping_token_t * token, const uint8_t * buffer )
{
    next_assert( token );
    next_assert( buffer );

    const uint8_t * start = buffer;

    (void) start;

    token->expire_timestamp = next_read_uint64( &buffer );
    next_read_address( &buffer, &token->from_address );
    next_read_address( &buffer, &token->to_address );

    next_assert( buffer - start == NEXT_PING_TOKEN_BYTES );
}

int next_encrypt_ping_token( uint8_t * sender_private_key, uint8_t * receiver_public_key, uint8_t * nonce, uint8_t * buffer, int buffer_length )
{
    next_assert( sender_private_key );
    next_assert( receiver_public_key );
    next_assert( buffer );
    next_assert( buffer_length >= (int) ( NEXT_PING_TOKEN_BYTES + NEXT_CRYPTO_BOX_MACBYTES ) );

    (void) buffer_length;

    if ( next_crypto_box_easy( buffer, buffer, NEXT_PING_TOKEN_BYTES, nonce, receiver_public_key, sender_private_key ) != 0 )
    {
        return NEXT_ERROR;
    }

    return NEXT_OK;
}

int next_decrypt_ping_token( const uint8_t * sender_public_key, const uint8_t * receiver_private_key, const uint8_t * nonce, uint8_t * buffer )
{
    next_assert( sender_public_key );
    next_assert( receiver_private_key );
    next_assert( buffer );

    if ( next_crypto_box_open_easy( buffer, buffer, NEXT_PING_TOKEN_BYTES + NEXT_CRYPTO_BOX_MACBYTES, nonce, sender_public_key, receiver_private_key ) != 0 )
    {
        return NEXT_ERROR;
    }

    return NEXT_OK;
}

int next_write_encrypted_ping_token( uint8_t ** buffer, next_ping_token_t * token, uint8_t * sender_private_key, uint8_t * receiver_public_key )
{
    next_assert( buffer );
    next_assert( token );
    next_assert( sender_private_key );
    next_assert( receiver_public_key );

    unsigned char nonce[NEXT_CRYPTO_BOX_NONCEBYTES];
    next_random_bytes( nonce, NEXT_CRYPTO_BOX_NONCEBYTES );

    uint8_t * start = *buffer;

    (void) start;

    next_write_bytes( buffer, nonce, NEXT_CRYPTO_BOX_NONCEBYTES );

    next_write_ping_token( token, *buffer, NEXT_PING_TOKEN_BYTES );

    if ( next_encrypt_ping_token( sender_private_key, receiver_public_key, nonce, *buffer, NEXT_PING_TOKEN_BYTES + NEXT_CRYPTO_BOX_NONCEBYTES ) != NEXT_OK )
        return NEXT_ERROR;

    *buffer += NEXT_PING_TOKEN_BYTES + NEXT_CRYPTO_BOX_MACBYTES;

    next_assert( ( *buffer - start ) == NEXT_ENCRYPTED_PING_TOKEN_BYTES );

    return NEXT_OK;
}

int next_read_encrypted_ping_token( uint8_t ** buffer, next_ping_token_t * token, const uint8_t * sender_public_key, const uint8_t * receiver_private_key )
{
    next_assert( buffer );
    next_assert( token );
    next_assert( sender_public_key );
    next_assert( receiver_private_key );

    const uint8_t * nonce = *buffer;

    *buffer += NEXT_CRYPTO_BOX_NONCEBYTES;

    if ( next_decrypt_ping_token( sender_public_key, receiver_private_key, nonce, *buffer ) != NEXT_OK )
    {
        return NEXT_ERROR;
    }

    next_read_ping_token( token, *buffer );

    *buffer += NEXT_PING_TOKEN_BYTES + NEXT_CRYPTO_BOX_MACBYTES;

    return NEXT_OK;
}

// ----------------------------------------------------------------------
int next_peek_header( int direction, int packet_type, uint64_t * sequence, uint64_t * session_id, uint8_t * session_version, const uint8_t * buffer, int buffer_length )
{
    uint64_t packet_sequence;

    next_assert( buffer );

    if ( buffer_length < NEXT_HEADER_BYTES )
        return NEXT_ERROR;

    packet_sequence = next_read_uint64( &buffer );

    if ( direction == NEXT_DIRECTION_SERVER_TO_CLIENT )
    {
        if ( !( packet_sequence & ( 1ULL << 63) ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "high bit must be set" );
            return NEXT_ERROR;
        }
    }
    else
    {
        if ( packet_sequence & ( 1ULL << 63 ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "high bit must be clear" );
            return NEXT_ERROR;
        }
    }

    if ( packet_type == NEXT_PING_PACKET || packet_type == NEXT_PONG_PACKET || packet_type == NEXT_ROUTE_RESPONSE_PACKET || packet_type == NEXT_CONTINUE_RESPONSE_PACKET )
    {
        if ( !( packet_sequence & ( 1ULL << 62) ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "second highest bit must be set" );
            return NEXT_ERROR;
        }
    }
    else
    {
        if ( packet_sequence & ( 1ULL << 62 ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "second highest bit must be clear" );
            return NEXT_ERROR;
        }
    }

    *sequence = packet_sequence;
    *session_id = next_read_uint64( &buffer );
    *session_version = next_read_uint8( &buffer );

    return NEXT_OK;
}

int next_read_header( int direction, int packet_type, uint64_t * sequence, uint64_t * session_id, uint8_t * session_version, const uint8_t * private_key, uint8_t * buffer, int buffer_length )
{
    next_assert( private_key );
    next_assert( buffer );

    if ( buffer_length < NEXT_HEADER_BYTES )
    {
        return NEXT_ERROR;
    }

    const uint8_t * p = buffer;

    uint64_t packet_sequence = next_read_uint64( &p );

    if ( direction == NEXT_DIRECTION_SERVER_TO_CLIENT )
    {
        if ( !( packet_sequence & ( 1ULL << 63 ) ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "high bit must be set" );
            return NEXT_ERROR;
        }
    }
    else
    {
        if ( packet_sequence & ( 1ULL << 63 ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "high bit must be clear" );
            return NEXT_ERROR;
        }
    }

    if ( packet_type == NEXT_PING_PACKET || packet_type == NEXT_PONG_PACKET || packet_type == NEXT_ROUTE_RESPONSE_PACKET || packet_type == NEXT_CONTINUE_RESPONSE_PACKET )
    {
        if ( !( packet_sequence & ( 1ULL << 62 ) ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "second highest bit must be set" );
            return NEXT_ERROR;
        }
    }
    else
    {
        if ( packet_sequence & ( 1ULL << 62 ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "second highest bit must be clear" );
            return NEXT_ERROR;
        }
    }

    const uint8_t * additional = p;

    const int additional_length = 8 + 1;

    uint64_t packet_session_id = next_read_uint64( &p );
    uint8_t packet_session_version = next_read_uint8( &p );

    uint8_t nonce[12];
    {
        uint8_t * q = nonce;
        next_write_uint32( &q, packet_type );
        next_write_uint64( &q, packet_sequence );
    }

    unsigned long long decrypted_length;

    int result = next_crypto_aead_chacha20poly1305_ietf_decrypt( buffer + 17, &decrypted_length, NULL,
                                                                 buffer + 17, (unsigned long long) NEXT_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES,
                                                                 additional, (unsigned long long) additional_length,
                                                                 nonce, private_key );

    if ( result != 0 )
    {
        return NEXT_ERROR;
    }

    *sequence = packet_sequence;
    *session_id = packet_session_id;
    *session_version = packet_session_version;

    return NEXT_OK;
}

// ---------------------------------------------------------------

struct next_route_data_t
{
    NEXT_DECLARE_SENTINEL(0)

    bool current_route;
    double current_route_expire_time;
    uint64_t current_route_session_id;
    uint8_t current_route_session_version;
    int current_route_kbps_up;
    int current_route_kbps_down;
    next_address_t current_route_next_address;

    NEXT_DECLARE_SENTINEL(1)

    uint8_t current_route_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];

    NEXT_DECLARE_SENTINEL(2)

    bool previous_route;
    uint64_t previous_route_session_id;
    uint8_t previous_route_session_version;

    NEXT_DECLARE_SENTINEL(3)

    uint8_t previous_route_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];

    NEXT_DECLARE_SENTINEL(4)

    bool pending_route;
    double pending_route_start_time;
    double pending_route_last_send_time;
    uint64_t pending_route_session_id;
    uint8_t pending_route_session_version;
    int pending_route_kbps_up;
    int pending_route_kbps_down;
    int pending_route_request_packet_bytes;
    next_address_t pending_route_next_address;

    NEXT_DECLARE_SENTINEL(5)

    uint8_t pending_route_request_packet_data[NEXT_MAX_PACKET_BYTES];

    NEXT_DECLARE_SENTINEL(6)

    uint8_t pending_route_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];

    NEXT_DECLARE_SENTINEL(7)

    bool pending_continue;
    double pending_continue_start_time;
    double pending_continue_last_send_time;
    int pending_continue_request_packet_bytes;

    NEXT_DECLARE_SENTINEL(8)

    uint8_t pending_continue_request_packet_data[NEXT_MAX_PACKET_BYTES];

    NEXT_DECLARE_SENTINEL(9)
};

void next_route_data_initialize_sentinels( next_route_data_t * route_data )
{
    (void) route_data;
    next_assert( route_data );
    NEXT_INITIALIZE_SENTINEL( route_data, 0 )
    NEXT_INITIALIZE_SENTINEL( route_data, 1 )
    NEXT_INITIALIZE_SENTINEL( route_data, 2 )
    NEXT_INITIALIZE_SENTINEL( route_data, 3 )
    NEXT_INITIALIZE_SENTINEL( route_data, 4 )
    NEXT_INITIALIZE_SENTINEL( route_data, 5 )
    NEXT_INITIALIZE_SENTINEL( route_data, 6 )
    NEXT_INITIALIZE_SENTINEL( route_data, 7 )
    NEXT_INITIALIZE_SENTINEL( route_data, 8 )
    NEXT_INITIALIZE_SENTINEL( route_data, 9 )
}

void next_route_data_verify_sentinels( next_route_data_t * route_data )
{
    (void) route_data;
    next_assert( route_data );
    NEXT_VERIFY_SENTINEL( route_data, 0 )
    NEXT_VERIFY_SENTINEL( route_data, 1 )
    NEXT_VERIFY_SENTINEL( route_data, 2 )
    NEXT_VERIFY_SENTINEL( route_data, 3 )
    NEXT_VERIFY_SENTINEL( route_data, 4 )
    NEXT_VERIFY_SENTINEL( route_data, 5 )
    NEXT_VERIFY_SENTINEL( route_data, 6 )
    NEXT_VERIFY_SENTINEL( route_data, 7 )
    NEXT_VERIFY_SENTINEL( route_data, 8 )
    NEXT_VERIFY_SENTINEL( route_data, 9 )
}

struct next_route_manager_t
{
    NEXT_DECLARE_SENTINEL(0)

    void * context;
    uint64_t send_sequence;
    bool fallback_to_direct;
    next_route_data_t route_data;
    double last_route_update_time;
    uint32_t flags;

    NEXT_DECLARE_SENTINEL(1)
};

void next_route_manager_initialize_sentinels( next_route_manager_t * route_manager )
{
    (void) route_manager;
    next_assert( route_manager );
    NEXT_INITIALIZE_SENTINEL( route_manager, 0 )
    NEXT_INITIALIZE_SENTINEL( route_manager, 1 )
    next_route_data_initialize_sentinels( &route_manager->route_data );
}

void next_route_manager_verify_sentinels( next_route_manager_t * route_manager )
{
    (void) route_manager;
    next_assert( route_manager );
    NEXT_VERIFY_SENTINEL( route_manager, 0 )
    NEXT_VERIFY_SENTINEL( route_manager, 1 )
    next_route_data_verify_sentinels( &route_manager->route_data );
}

next_route_manager_t * next_route_manager_create( void * context )
{
    next_route_manager_t * route_manager = (next_route_manager_t*) next_malloc( context, sizeof(next_route_manager_t) );
    if ( !route_manager )
        return NULL;
    memset( route_manager, 0, sizeof(next_route_manager_t) );
    next_route_manager_initialize_sentinels( route_manager );
    route_manager->context = context;
    return route_manager;
}

void next_route_manager_reset( next_route_manager_t * route_manager )
{
    next_route_manager_verify_sentinels( route_manager );

    route_manager->send_sequence = 0;
    route_manager->fallback_to_direct = false;
    route_manager->last_route_update_time = 0.0;

    memset( &route_manager->route_data, 0, sizeof(next_route_data_t) );

    next_route_manager_initialize_sentinels( route_manager );

    route_manager->flags = 0;

    next_route_manager_verify_sentinels( route_manager );
}

void next_route_manager_fallback_to_direct( next_route_manager_t * route_manager, uint32_t flags )
{
    next_route_manager_verify_sentinels( route_manager );

    route_manager->flags |= flags;

    if ( route_manager->fallback_to_direct )
        return;

    route_manager->fallback_to_direct = true;

    next_printf( NEXT_LOG_LEVEL_INFO, "client fallback to direct" );

    route_manager->route_data.previous_route = route_manager->route_data.current_route;
    route_manager->route_data.previous_route_session_id = route_manager->route_data.current_route_session_id;
    route_manager->route_data.previous_route_session_version = route_manager->route_data.current_route_session_version;
    memcpy( route_manager->route_data.previous_route_private_key, route_manager->route_data.current_route_private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );

    route_manager->route_data.current_route = false;
}

void next_route_manager_direct_route( next_route_manager_t * route_manager, bool quiet )
{
    next_route_manager_verify_sentinels( route_manager );

    if ( route_manager->fallback_to_direct )
        return;

    if ( !quiet )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "client direct route" );
    }

    route_manager->route_data.previous_route = route_manager->route_data.current_route;
    route_manager->route_data.previous_route_session_id = route_manager->route_data.current_route_session_id;
    route_manager->route_data.previous_route_session_version = route_manager->route_data.current_route_session_version;
    memcpy( route_manager->route_data.previous_route_private_key, route_manager->route_data.current_route_private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );

    route_manager->route_data.current_route = false;
}

void next_route_manager_begin_next_route( next_route_manager_t * route_manager, int num_tokens, uint8_t * tokens, const uint8_t * public_key, const uint8_t * private_key, const uint8_t * magic, const next_address_t * client_external_address )
{
    next_route_manager_verify_sentinels( route_manager );

    next_assert( tokens );
    next_assert( num_tokens >= 2 );
    next_assert( num_tokens <= NEXT_MAX_TOKENS );

    if ( route_manager->fallback_to_direct )
        return;

    uint8_t * p = tokens;
    next_route_token_t route_token;
    if ( next_read_encrypted_route_token( &p, &route_token, public_key, private_key ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client received bad route token" );
        next_route_manager_fallback_to_direct( route_manager, NEXT_FLAGS_BAD_ROUTE_TOKEN );
        return;
    }

    next_printf( NEXT_LOG_LEVEL_INFO, "client next route" );

    route_manager->route_data.pending_route = true;
    route_manager->route_data.pending_route_start_time = next_time();
    route_manager->route_data.pending_route_last_send_time = -1000.0;
    route_manager->route_data.pending_route_next_address = route_token.next_address;
    route_manager->route_data.pending_route_session_id = route_token.session_id;
    route_manager->route_data.pending_route_session_version = route_token.session_version;
    route_manager->route_data.pending_route_kbps_up = route_token.kbps_up;
    route_manager->route_data.pending_route_kbps_down = route_token.kbps_down;

    memcpy( route_manager->route_data.pending_route_request_packet_data + 1, tokens + NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES, ( size_t(num_tokens) - 1 ) * NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES );
    memcpy( route_manager->route_data.pending_route_private_key, route_token.private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );

    const uint8_t * token_data = tokens + NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES;
    const int token_bytes = ( num_tokens - 1 ) * NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES;

    uint8_t from_address_data[32];
    uint8_t to_address_data[32];
    uint16_t from_address_port;
    uint16_t to_address_port;
    int from_address_bytes;
    int to_address_bytes;

    next_address_data( client_external_address, from_address_data, &from_address_bytes, &from_address_port );
    next_address_data( &route_token.next_address, to_address_data, &to_address_bytes, &to_address_port );

    route_manager->route_data.pending_route_request_packet_bytes = next_write_route_request_packet( route_manager->route_data.pending_route_request_packet_data, token_data, token_bytes, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port );

    next_assert( route_manager->route_data.pending_route_request_packet_bytes > 0 );
    next_assert( route_manager->route_data.pending_route_request_packet_bytes <= NEXT_MAX_PACKET_BYTES );

    const uint8_t * packet_data = route_manager->route_data.pending_route_request_packet_data;
    const int packet_bytes = route_manager->route_data.pending_route_request_packet_bytes;

    next_assert( next_basic_packet_filter( packet_data, packet_bytes ) );
    next_assert( next_advanced_packet_filter( packet_data, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

    (void) packet_data;
    (void) packet_bytes;
}

void next_route_manager_continue_next_route( next_route_manager_t * route_manager, int num_tokens, uint8_t * tokens, const uint8_t * public_key, const uint8_t * private_key, const uint8_t * magic, const next_address_t * client_external_address )
{
    next_route_manager_verify_sentinels( route_manager );

    next_assert( tokens );
    next_assert( num_tokens >= 2 );
    next_assert( num_tokens <= NEXT_MAX_TOKENS );

    if ( route_manager->fallback_to_direct )
        return;

    if ( !route_manager->route_data.current_route )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client has no route to continue" );
        next_route_manager_fallback_to_direct( route_manager, NEXT_FLAGS_NO_ROUTE_TO_CONTINUE );
        return;
    }

    if ( route_manager->route_data.pending_route || route_manager->route_data.pending_continue )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client previous update still pending" );
        next_route_manager_fallback_to_direct( route_manager, NEXT_FLAGS_PREVIOUS_UPDATE_STILL_PENDING );
        return;
    }

    uint8_t * p = tokens;
    next_continue_token_t continue_token;
    if ( next_read_encrypted_continue_token( &p, &continue_token, public_key, private_key ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client received bad continue token" );
        next_route_manager_fallback_to_direct( route_manager, NEXT_FLAGS_BAD_CONTINUE_TOKEN );
        return;
    }

    route_manager->route_data.pending_continue = true;
    route_manager->route_data.pending_continue_start_time = next_time();
    route_manager->route_data.pending_continue_last_send_time = -1000.0;

    uint8_t from_address_data[32];
    uint8_t to_address_data[32];
    uint16_t from_address_port;
    uint16_t to_address_port;
    int from_address_bytes;
    int to_address_bytes;

    next_address_data( client_external_address, from_address_data, &from_address_bytes, &from_address_port );
    next_address_data( &route_manager->route_data.current_route_next_address, to_address_data, &to_address_bytes, &to_address_port );

    const uint8_t * token_data = tokens + NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES;
    const int token_bytes = ( num_tokens - 1 ) * NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES;

    route_manager->route_data.pending_continue_request_packet_bytes = next_write_continue_request_packet( route_manager->route_data.pending_continue_request_packet_data, token_data, token_bytes, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port );

    next_assert( route_manager->route_data.pending_continue_request_packet_bytes >= 0 );
    next_assert( route_manager->route_data.pending_continue_request_packet_bytes <= NEXT_MAX_PACKET_BYTES );

    const uint8_t * packet_data = route_manager->route_data.pending_continue_request_packet_data;
    const int packet_bytes = route_manager->route_data.pending_continue_request_packet_bytes;

    next_assert( next_basic_packet_filter( packet_data, packet_bytes ) );
    next_assert( next_advanced_packet_filter( packet_data, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

    (void) packet_data;
    (void) packet_bytes;

    next_printf( NEXT_LOG_LEVEL_INFO, "client continues route" );
}

void next_route_manager_update( next_route_manager_t * route_manager, int update_type, int num_tokens, uint8_t * tokens, const uint8_t * public_key, const uint8_t * private_key, const uint8_t * magic, const next_address_t * client_external_address )
{
    next_route_manager_verify_sentinels( route_manager );

    next_assert( public_key );
    next_assert( private_key );

    if ( update_type == NEXT_UPDATE_TYPE_DIRECT )
    {
        next_route_manager_direct_route( route_manager, false );
    }
    else if ( update_type == NEXT_UPDATE_TYPE_ROUTE )
    {
        next_route_manager_begin_next_route( route_manager, num_tokens, tokens, public_key, private_key, magic, client_external_address );
    }
    else if ( update_type == NEXT_UPDATE_TYPE_CONTINUE )
    {
        next_route_manager_continue_next_route( route_manager, num_tokens, tokens, public_key, private_key, magic, client_external_address );
    }
}

bool next_route_manager_has_network_next_route( next_route_manager_t * route_manager )
{
    next_route_manager_verify_sentinels( route_manager );
    return route_manager->route_data.current_route;
}

uint64_t next_route_manager_next_send_sequence( next_route_manager_t * route_manager )
{
    next_route_manager_verify_sentinels( route_manager );
    return route_manager->send_sequence++;
}

bool next_route_manager_prepare_send_packet( next_route_manager_t * route_manager, uint64_t sequence, next_address_t * to, const uint8_t * payload_data, int payload_bytes, uint8_t * packet_data, int * packet_bytes, const uint8_t * magic, const next_address_t * client_external_address )
{
    next_route_manager_verify_sentinels( route_manager );

    if ( !route_manager->route_data.current_route )
        return false;

    next_assert( route_manager->route_data.current_route );
    next_assert( to );
    next_assert( payload_data );
    next_assert( payload_bytes );
    next_assert( packet_data );
    next_assert( packet_bytes );

    *to = route_manager->route_data.current_route_next_address;

    uint8_t from_address_data[32];
    uint8_t to_address_data[32];
    uint16_t from_address_port;
    uint16_t to_address_port;
    int from_address_bytes;
    int to_address_bytes;

    next_address_data( client_external_address, from_address_data, &from_address_bytes, &from_address_port );
    next_address_data( to, to_address_data, &to_address_bytes, &to_address_port );

    *packet_bytes = next_write_client_to_server_packet( packet_data, sequence, route_manager->route_data.current_route_session_id, route_manager->route_data.current_route_session_version, route_manager->route_data.current_route_private_key, payload_data, payload_bytes, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port );

    if ( *packet_bytes == 0 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client failed to write client to server packet header" );
        return false;
    }

    next_assert( next_basic_packet_filter( packet_data, *packet_bytes ) );
    next_assert( next_advanced_packet_filter( packet_data, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, *packet_bytes ) );

    next_assert( *packet_bytes < NEXT_MAX_PACKET_BYTES );

    return true;
}

bool next_route_manager_process_server_to_client_packet( next_route_manager_t * route_manager, uint8_t packet_type, uint8_t * packet_data, int packet_bytes, uint64_t * payload_sequence )
{
    next_route_manager_verify_sentinels( route_manager );

    next_assert( packet_data );
    next_assert( payload_sequence );

    uint64_t packet_sequence = 0;
    uint64_t packet_session_id = 0;
    uint8_t packet_session_version = 0;

    bool from_current_route = true;

    if ( next_read_header( NEXT_DIRECTION_SERVER_TO_CLIENT, packet_type, &packet_sequence, &packet_session_id, &packet_session_version, route_manager->route_data.current_route_private_key, packet_data, packet_bytes ) != NEXT_OK )
    {
        from_current_route = false;
        if ( next_read_header( NEXT_DIRECTION_SERVER_TO_CLIENT, packet_type, &packet_sequence, &packet_session_id, &packet_session_version, route_manager->route_data.previous_route_private_key, packet_data, packet_bytes ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored server to client packet. could not read header" );
            return false;
        }
    }

    if ( !route_manager->route_data.current_route && !route_manager->route_data.previous_route )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored server to client packet. no current or previous route" );
        return false;
    }

    if ( from_current_route )
    {
        if ( packet_session_id != route_manager->route_data.current_route_session_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored server to client packet. session id mismatch (current route)" );
            return false;
        }

        if ( packet_session_version != route_manager->route_data.current_route_session_version )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored server to client packet. session version mismatch (current route)" );
            return false;
        }
    }
    else
    {
        if ( packet_session_id != route_manager->route_data.previous_route_session_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored server to client packet. session id mismatch (previous route)" );
            return false;
        }

        if ( packet_session_version != route_manager->route_data.previous_route_session_version )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored server to client packet. session version mismatch (previous route)" );
            return false;
        }
    }

    *payload_sequence = packet_sequence;

    int payload_bytes = packet_bytes - NEXT_HEADER_BYTES;

    if ( payload_bytes > NEXT_MTU )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored server to client packet. too large (%d>%d)", payload_bytes, NEXT_MTU );
        return false;
    }

    (void) payload_bytes;

    return true;
}

void next_route_manager_check_for_timeouts( next_route_manager_t * route_manager )
{
    next_route_manager_verify_sentinels( route_manager );

    if ( route_manager->fallback_to_direct )
        return;

    const double current_time = next_time();

    if ( route_manager->last_route_update_time > 0.0 && route_manager->last_route_update_time + NEXT_CLIENT_ROUTE_TIMEOUT < current_time )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client route timed out" );
        next_route_manager_fallback_to_direct( route_manager, NEXT_FLAGS_ROUTE_TIMED_OUT );
        return;
    }

    if ( route_manager->route_data.current_route && route_manager->route_data.current_route_expire_time <= current_time )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client route expired" );
        next_route_manager_fallback_to_direct( route_manager, NEXT_FLAGS_ROUTE_EXPIRED );
        return;
    }

    if ( route_manager->route_data.pending_route && route_manager->route_data.pending_route_start_time + NEXT_ROUTE_REQUEST_TIMEOUT <= current_time )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client route request timed out" );
        next_route_manager_fallback_to_direct( route_manager, NEXT_FLAGS_ROUTE_REQUEST_TIMED_OUT );
        return;
    }

    if ( route_manager->route_data.pending_continue && route_manager->route_data.pending_continue_start_time + NEXT_CONTINUE_REQUEST_TIMEOUT <= current_time )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client continue request timed out" );
        next_route_manager_fallback_to_direct( route_manager, NEXT_FLAGS_CONTINUE_REQUEST_TIMED_OUT );
        return;
    }
}

bool next_route_manager_send_route_request( next_route_manager_t * route_manager, next_address_t * to, uint8_t * packet_data, int * packet_bytes )
{
    next_route_manager_verify_sentinels( route_manager );

    next_assert( to );
    next_assert( packet_data );
    next_assert( packet_bytes );

    if ( route_manager->fallback_to_direct )
        return false;

    if ( !route_manager->route_data.pending_route )
        return false;

    double current_time = next_time();

    if ( route_manager->route_data.pending_route_last_send_time + NEXT_ROUTE_REQUEST_SEND_TIME > current_time )
        return false;

    *to = route_manager->route_data.pending_route_next_address;
    route_manager->route_data.pending_route_last_send_time = current_time;
    *packet_bytes = route_manager->route_data.pending_route_request_packet_bytes;
    memcpy( packet_data, route_manager->route_data.pending_route_request_packet_data, route_manager->route_data.pending_route_request_packet_bytes );

    return true;
}

bool next_route_manager_send_continue_request( next_route_manager_t * route_manager, next_address_t * to, uint8_t * packet_data, int * packet_bytes )
{
    next_route_manager_verify_sentinels( route_manager );

    next_assert( to );
    next_assert( packet_data );
    next_assert( packet_bytes );

    if ( route_manager->fallback_to_direct )
        return false;

    if ( !route_manager->route_data.current_route || !route_manager->route_data.pending_continue )
        return false;

    double current_time = next_time();

    if ( route_manager->route_data.pending_continue_last_send_time + NEXT_CONTINUE_REQUEST_SEND_TIME > current_time )
        return false;

    *to = route_manager->route_data.current_route_next_address;
    route_manager->route_data.pending_continue_last_send_time = current_time;
    *packet_bytes = route_manager->route_data.pending_continue_request_packet_bytes;
    memcpy( packet_data, route_manager->route_data.pending_continue_request_packet_data, route_manager->route_data.pending_continue_request_packet_bytes );

    return true;
}

void next_route_manager_destroy( next_route_manager_t * route_manager )
{
    next_route_manager_verify_sentinels( route_manager );

    next_free( route_manager->context, route_manager );
}

// ---------------------------------------------------------------

#define NEXT_CLIENT_COMMAND_OPEN_SESSION            0
#define NEXT_CLIENT_COMMAND_CLOSE_SESSION           1
#define NEXT_CLIENT_COMMAND_DESTROY                 2
#define NEXT_CLIENT_COMMAND_REPORT_SESSION          3

struct next_client_command_t
{
    int type;
};

struct next_client_command_open_session_t : public next_client_command_t
{
    next_address_t server_address;
};

struct next_client_command_close_session_t : public next_client_command_t
{
    // ...
};

struct next_client_command_destroy_t : public next_client_command_t
{
    // ...
};

struct next_client_command_report_session_t : public next_client_command_t
{
    // ...
};

// ---------------------------------------------------------------

#define NEXT_CLIENT_NOTIFY_PACKET_RECEIVED          0
#define NEXT_CLIENT_NOTIFY_UPGRADED                 1
#define NEXT_CLIENT_NOTIFY_STATS_UPDATED            2
#define NEXT_CLIENT_NOTIFY_MAGIC_UPDATED            3
#define NEXT_CLIENT_NOTIFY_READY                    4

struct next_client_notify_t
{
    int type;
};

struct next_client_notify_packet_received_t : public next_client_notify_t
{
    bool direct;
    int payload_bytes;
    uint8_t payload_data[NEXT_MAX_PACKET_BYTES-1];
};

struct next_client_notify_upgraded_t : public next_client_notify_t
{
    uint64_t session_id;
    next_address_t client_external_address;
    uint8_t current_magic[8];
};

struct next_client_notify_stats_updated_t : public next_client_notify_t
{
    next_client_stats_t stats;
    bool fallback_to_direct;
};

struct next_client_notify_magic_updated_t : public next_client_notify_t
{
    uint8_t current_magic[8];
};

struct next_client_notify_ready_t : public next_client_notify_t
{
};

// ---------------------------------------------------------------

struct next_client_internal_t
{
    NEXT_DECLARE_SENTINEL(0)

    void * context;
    next_queue_t * command_queue;
    next_queue_t * notify_queue;
    next_platform_socket_t * socket;
    next_platform_mutex_t command_mutex;
    next_platform_mutex_t notify_mutex;
    next_address_t server_address;
    next_address_t client_external_address;     // IMPORTANT: only known post-upgrade
    uint16_t bound_port;
    bool session_open;
    bool upgraded;
    bool reported;
    bool fallback_to_direct;
    bool multipath;
    uint8_t open_session_sequence;
    uint64_t upgrade_sequence;
    uint64_t session_id;
    uint64_t special_send_sequence;
    uint64_t internal_send_sequence;
    double last_next_ping_time;
    double last_next_pong_time;
    double last_direct_ping_time;
    double last_direct_pong_time;
    double last_stats_update_time;
    double last_stats_report_time;
    double last_route_switch_time;
    double route_update_timeout_time;
    uint64_t route_update_sequence;
    uint8_t upcoming_magic[8];
    uint8_t current_magic[8];
    uint8_t previous_magic[8];

    NEXT_DECLARE_SENTINEL(1)

    next_platform_mutex_t packets_sent_mutex;
    uint64_t packets_sent;

    NEXT_DECLARE_SENTINEL(2)

    next_relay_manager_t * near_relay_manager;
    next_route_manager_t * route_manager;
    next_platform_mutex_t route_manager_mutex;

    NEXT_DECLARE_SENTINEL(3)

    next_packet_loss_tracker_t packet_loss_tracker;
    next_out_of_order_tracker_t out_of_order_tracker;
    next_jitter_tracker_t jitter_tracker;

    NEXT_DECLARE_SENTINEL(4)

    uint8_t customer_public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
    uint8_t client_kx_public_key[NEXT_CRYPTO_KX_PUBLICKEYBYTES];
    uint8_t client_kx_private_key[NEXT_CRYPTO_KX_SECRETKEYBYTES];
    uint8_t client_send_key[NEXT_CRYPTO_KX_SESSIONKEYBYTES];
    uint8_t client_receive_key[NEXT_CRYPTO_KX_SESSIONKEYBYTES];
    uint8_t client_route_public_key[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    uint8_t client_route_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];

    NEXT_DECLARE_SENTINEL(5)

    next_client_stats_t client_stats;

    NEXT_DECLARE_SENTINEL(6)

    next_relay_stats_t near_relay_stats;

    NEXT_DECLARE_SENTINEL(7)

    next_ping_history_t next_ping_history;
    next_ping_history_t direct_ping_history;

    NEXT_DECLARE_SENTINEL(8)

    next_replay_protection_t payload_replay_protection;
    next_replay_protection_t special_replay_protection;
    next_replay_protection_t internal_replay_protection;

    NEXT_DECLARE_SENTINEL(9)

    next_platform_mutex_t direct_bandwidth_mutex;
    float direct_bandwidth_usage_kbps_up;
    float direct_bandwidth_usage_kbps_down;

    NEXT_DECLARE_SENTINEL(10)

    next_platform_mutex_t next_bandwidth_mutex;
    bool next_bandwidth_over_limit;
    float next_bandwidth_usage_kbps_up;
    float next_bandwidth_usage_kbps_down;
    float next_bandwidth_envelope_kbps_up;
    float next_bandwidth_envelope_kbps_down;

    NEXT_DECLARE_SENTINEL(11)

    bool sending_upgrade_response;
    double upgrade_response_start_time;
    double last_upgrade_response_send_time;
    int upgrade_response_packet_bytes;
    uint8_t upgrade_response_packet_data[NEXT_MAX_PACKET_BYTES];

    NEXT_DECLARE_SENTINEL(12)

    uint64_t counters[NEXT_CLIENT_COUNTER_MAX];

    NEXT_DECLARE_SENTINEL(13)
};

void next_client_internal_initialize_sentinels( next_client_internal_t * client )
{
    (void) client;
    next_assert( client );
    NEXT_INITIALIZE_SENTINEL( client, 0 )
    NEXT_INITIALIZE_SENTINEL( client, 1 )
    NEXT_INITIALIZE_SENTINEL( client, 2 )
    NEXT_INITIALIZE_SENTINEL( client, 3 )
    NEXT_INITIALIZE_SENTINEL( client, 4 )
    NEXT_INITIALIZE_SENTINEL( client, 5 )
    NEXT_INITIALIZE_SENTINEL( client, 6 )
    NEXT_INITIALIZE_SENTINEL( client, 7 )
    NEXT_INITIALIZE_SENTINEL( client, 8 )
    NEXT_INITIALIZE_SENTINEL( client, 9 )
    NEXT_INITIALIZE_SENTINEL( client, 10 )
    NEXT_INITIALIZE_SENTINEL( client, 11 )
    NEXT_INITIALIZE_SENTINEL( client, 12 )
    NEXT_INITIALIZE_SENTINEL( client, 13 )

    next_relay_stats_initialize_sentinels( &client->near_relay_stats );

    next_ping_history_initialize_sentinels( &client->next_ping_history );
    next_ping_history_initialize_sentinels( &client->direct_ping_history );
}

void next_client_internal_verify_sentinels( next_client_internal_t * client )
{
    (void) client;

    next_assert( client );

    NEXT_VERIFY_SENTINEL( client, 0 )
    NEXT_VERIFY_SENTINEL( client, 1 )
    NEXT_VERIFY_SENTINEL( client, 2 )
    NEXT_VERIFY_SENTINEL( client, 3 )
    NEXT_VERIFY_SENTINEL( client, 4 )
    NEXT_VERIFY_SENTINEL( client, 5 )
    NEXT_VERIFY_SENTINEL( client, 6 )
    NEXT_VERIFY_SENTINEL( client, 7 )
    NEXT_VERIFY_SENTINEL( client, 8 )
    NEXT_VERIFY_SENTINEL( client, 9 )
    NEXT_VERIFY_SENTINEL( client, 10 )
    NEXT_VERIFY_SENTINEL( client, 11 )
    NEXT_VERIFY_SENTINEL( client, 12 )
    NEXT_VERIFY_SENTINEL( client, 13 )

    if ( client->command_queue )
        next_queue_verify_sentinels( client->command_queue );

    if ( client->notify_queue )
        next_queue_verify_sentinels( client->notify_queue );

    next_replay_protection_verify_sentinels( &client->payload_replay_protection );
    next_replay_protection_verify_sentinels( &client->special_replay_protection );
    next_replay_protection_verify_sentinels( &client->internal_replay_protection );

    next_relay_stats_verify_sentinels( &client->near_relay_stats );

    if ( client->near_relay_manager )
        next_relay_manager_verify_sentinels( client->near_relay_manager );

    next_ping_history_verify_sentinels( &client->next_ping_history );
    next_ping_history_verify_sentinels( &client->direct_ping_history );

    if ( client->route_manager )
        next_route_manager_verify_sentinels( client->route_manager );
}

void next_client_internal_destroy( next_client_internal_t * client );

next_client_internal_t * next_client_internal_create( void * context, const char * bind_address_string )
{
#if !NEXT_DEVELOPMENT
    next_printf( NEXT_LOG_LEVEL_INFO, "client sdk version is %s", NEXT_VERSION_FULL );
#endif // #if !NEXT_DEVELOPMENT

    next_printf( NEXT_LOG_LEVEL_INFO, "client buyer id is %" PRIx64, next_global_config.client_customer_id );

    next_address_t bind_address;
    if ( next_address_parse( &bind_address, bind_address_string ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client failed to parse bind address: %s", bind_address_string );
        return NULL;
    }

    next_client_internal_t * client = (next_client_internal_t*) next_malloc( context, sizeof(next_client_internal_t) );
    if ( !client )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "could not create internal client" );
        return NULL;
    }

    memset( client, 0, sizeof( next_client_internal_t) );

    next_client_internal_initialize_sentinels( client );

    client->context = context;

    memcpy( client->customer_public_key, next_global_config.customer_public_key, NEXT_CRYPTO_SIGN_PUBLICKEYBYTES );

    client->command_queue = next_queue_create( context, NEXT_COMMAND_QUEUE_LENGTH );
    if ( !client->command_queue )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create client command queue" );
        next_client_internal_destroy( client );
        return NULL;
    }

    client->notify_queue = next_queue_create( context, NEXT_NOTIFY_QUEUE_LENGTH );
    if ( !client->notify_queue )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create client notify queue" );
        next_client_internal_destroy( client );
        return NULL;
    }

    client->socket = next_platform_socket_create( client->context, &bind_address, NEXT_PLATFORM_SOCKET_BLOCKING, 0.1f, next_global_config.socket_send_buffer_size, next_global_config.socket_receive_buffer_size, true );
    if ( client->socket == NULL )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create socket" );
        next_client_internal_destroy( client );
        return NULL;
    }

    char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_printf( NEXT_LOG_LEVEL_INFO, "client bound to %s", next_address_to_string( &bind_address, address_string ) );
    client->bound_port = bind_address.port;

    int result = next_platform_mutex_create( &client->command_mutex );
    if ( result != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create command mutex" );
        next_client_internal_destroy( client );
        return NULL;
    }

    result = next_platform_mutex_create( &client->notify_mutex );
    if ( result != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create notify mutex" );
        next_client_internal_destroy( client );
        return NULL;
    }

    client->near_relay_manager = next_relay_manager_create( context );
    if ( !client->near_relay_manager )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create near relay manager" );
        next_client_internal_destroy( client );
        return NULL;
    }

    client->route_manager = next_route_manager_create( context );
    if ( !client->route_manager )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create route manager" );
        next_client_internal_destroy( client );
        return NULL;
    }

    result = next_platform_mutex_create( &client->route_manager_mutex );
    if ( result != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create client route manager mutex" );
        next_client_internal_destroy( client );
        return NULL;
    }

    result = next_platform_mutex_create( &client->direct_bandwidth_mutex );
    if ( result != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create direct bandwidth mutex" );
        next_client_internal_destroy( client );
        return NULL;
    }

    result = next_platform_mutex_create( &client->next_bandwidth_mutex );
    if ( result != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create next bandwidth mutex" );
        next_client_internal_destroy( client );
        return NULL;
    }

    next_ping_history_clear( &client->next_ping_history );
    next_ping_history_clear( &client->direct_ping_history );

    next_replay_protection_reset( &client->payload_replay_protection );
    next_replay_protection_reset( &client->special_replay_protection );
    next_replay_protection_reset( &client->internal_replay_protection );

    next_packet_loss_tracker_reset( &client->packet_loss_tracker );
    next_out_of_order_tracker_reset( &client->out_of_order_tracker );
    next_jitter_tracker_reset( &client->jitter_tracker );

    next_client_internal_verify_sentinels( client );

    client->special_send_sequence = 1;
    client->internal_send_sequence = 1;

    return client;
}

void next_client_internal_destroy( next_client_internal_t * client )
{
    next_client_internal_verify_sentinels( client );

    if ( client->socket )
    {
        next_platform_socket_destroy( client->socket );
    }
    if ( client->command_queue )
    {
        next_queue_destroy( client->command_queue );
    }
    if ( client->notify_queue )
    {
        next_queue_destroy( client->notify_queue );
    }
    if ( client->near_relay_manager )
    {
        next_relay_manager_destroy( client->near_relay_manager );
    }
    if ( client->route_manager )
    {
        next_route_manager_destroy( client->route_manager );
    }

    next_platform_mutex_destroy( &client->command_mutex );
    next_platform_mutex_destroy( &client->notify_mutex );
    next_platform_mutex_destroy( &client->route_manager_mutex );
    next_platform_mutex_destroy( &client->direct_bandwidth_mutex );
    next_platform_mutex_destroy( &client->next_bandwidth_mutex );

    clear_and_free( client->context, client, sizeof(next_client_internal_t) );
}

int next_client_internal_send_packet_to_server( next_client_internal_t * client, uint8_t packet_id, void * packet_object )
{
    next_client_internal_verify_sentinels( client );

    next_assert( packet_object );
    next_assert( client->session_open );

    if ( !client->session_open )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client can't send internal packet to server because no session is open" );
        return NEXT_ERROR;
    }

    int packet_bytes = 0;

    uint8_t buffer[NEXT_MAX_PACKET_BYTES];

    uint8_t from_address_data[32];
    uint8_t to_address_data[32];
    uint16_t from_address_port;
    uint16_t to_address_port;
    int from_address_bytes;
    int to_address_bytes;

    next_address_data( &client->client_external_address, from_address_data, &from_address_bytes, &from_address_port );
    next_address_data( &client->server_address, to_address_data, &to_address_bytes, &to_address_port );

    if ( next_write_packet( packet_id, packet_object, buffer, &packet_bytes, next_signed_packets, next_encrypted_packets, &client->internal_send_sequence, NULL, client->client_send_key, client->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client failed to write internal packet type %d", packet_id );
        return NEXT_ERROR;
    }

    next_assert( next_basic_packet_filter( buffer, sizeof(buffer) ) );
    next_assert( next_advanced_packet_filter( buffer, client->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

    next_platform_socket_send_packet( client->socket, &client->server_address, buffer, packet_bytes );

    return NEXT_OK;
}

void next_client_internal_process_network_next_packet( next_client_internal_t * client, const next_address_t * from, uint8_t * packet_data, int packet_bytes, double packet_receive_time )
{
    next_client_internal_verify_sentinels( client );

    next_assert( from );
    next_assert( packet_data );
    next_assert( packet_bytes > 0 );
    next_assert( packet_bytes <= NEXT_MAX_PACKET_BYTES );

    const bool from_server_address = client->server_address.type != 0 && next_address_equal( from, &client->server_address );

    const int packet_id = packet_data[0];

#if NEXT_ASSERT
    char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_printf( NEXT_LOG_LEVEL_SPAM, "client processing packet type %d from %s (%d bytes)", packet_id, next_address_to_string( &client->server_address, address_buffer ), packet_bytes );
#endif // #if NEXT_ASSERT

    // run packet filters
    {
        if ( !next_basic_packet_filter( packet_data, packet_bytes ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client basic packet filter dropped packet (%d)", packet_id );
            return;
        }

        uint8_t from_address_data[32];
        uint8_t to_address_data[32];
        uint16_t from_address_port = 0;
        uint16_t to_address_port = 0;
        int from_address_bytes = 0;
        int to_address_bytes = 0;

        next_address_data( from, from_address_data, &from_address_bytes, &from_address_port );
        next_address_data( &client->client_external_address, to_address_data, &to_address_bytes, &to_address_port );

        if ( packet_id != NEXT_UPGRADE_REQUEST_PACKET )
        {
            if ( !next_advanced_packet_filter( packet_data, client->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) )
            {
                if ( !next_advanced_packet_filter( packet_data, client->upcoming_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) )
                {
                    if ( !next_advanced_packet_filter( packet_data, client->previous_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) )
                    {
                        next_printf( NEXT_LOG_LEVEL_DEBUG, "client advanced packet filter dropped packet (%d)", packet_id );
                    }
                    return;
                }
            }
        }
        else
        {
            uint8_t magic[8];
            memset( magic, 0, sizeof(magic) );
            to_address_bytes = 0;
            to_address_port = 0;
            if ( !next_advanced_packet_filter( packet_data, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "client advanced packet filter dropped packet (upgrade request)" );
                return;
            }
        }
    }

    // upgrade request packet (not encrypted)

    if ( !client->upgraded && from_server_address && packet_id == NEXT_UPGRADE_REQUEST_PACKET )
    {
    	next_printf( NEXT_LOG_LEVEL_SPAM, "client processing upgrade request packet" );

        if ( !next_address_equal( from, &client->server_address ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored upgrade request packet from server. packet does not come from server address" );
            return;
        }

        if ( client->fallback_to_direct )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored upgrade request packet from server. in fallback to direct state" );
            return;
        }

        if ( next_global_config.disable_network_next )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored upgrade request packet from server. network next is disabled" );
            return;
        }

        NextUpgradeRequestPacket packet;
        int begin = 16;
        int end = packet_bytes - 2;
        if ( next_read_packet( NEXT_UPGRADE_REQUEST_PACKET, packet_data, begin, end, &packet, NULL, NULL, NULL, NULL, NULL, NULL ) != packet_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored upgrade request packet from server. failed to read" );
            return;
        }

        if ( packet.protocol_version != next_protocol_version() )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored upgrade request packet from server. protocol version mismatch" );
            return;
        }

        next_post_validate_packet( NEXT_UPGRADE_REQUEST_PACKET, NULL, NULL, NULL );

        next_printf( NEXT_LOG_LEVEL_DEBUG, "client received upgrade request packet from server" );

        next_printf( NEXT_LOG_LEVEL_DEBUG, "client initial magic: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x | %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x | %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x",
            packet.upcoming_magic[0],
            packet.upcoming_magic[1],
            packet.upcoming_magic[2],
            packet.upcoming_magic[3],
            packet.upcoming_magic[4],
            packet.upcoming_magic[5],
            packet.upcoming_magic[6],
            packet.upcoming_magic[7],
            packet.current_magic[0],
            packet.current_magic[1],
            packet.current_magic[2],
            packet.current_magic[3],
            packet.current_magic[4],
            packet.current_magic[5],
            packet.current_magic[6],
            packet.current_magic[7],
            packet.previous_magic[0],
            packet.previous_magic[1],
            packet.previous_magic[2],
            packet.previous_magic[3],
            packet.previous_magic[4],
            packet.previous_magic[5],
            packet.previous_magic[6],
            packet.previous_magic[7] );

        memcpy( client->upcoming_magic, packet.upcoming_magic, 8 );
        memcpy( client->current_magic, packet.current_magic, 8 );
        memcpy( client->previous_magic, packet.previous_magic, 8 );

        client->client_external_address = packet.client_address;

        char address_buffer[256];
        next_printf( NEXT_LOG_LEVEL_DEBUG, "client external address is %s", next_address_to_string( &client->client_external_address, address_buffer ) );

        NextUpgradeResponsePacket response;

        response.client_open_session_sequence = client->open_session_sequence;
        memcpy( response.client_kx_public_key, client->client_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES );
        memcpy( response.client_route_public_key, client->client_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES );
        memcpy( response.upgrade_token, packet.upgrade_token, NEXT_UPGRADE_TOKEN_BYTES );
        response.platform_id = next_platform_id();
        response.connection_type = next_platform_connection_type();

        if ( next_client_internal_send_packet_to_server( client, NEXT_UPGRADE_RESPONSE_PACKET, &response ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_WARN, "client failed to send upgrade response packet to server" );
            return;
        }

        next_printf( NEXT_LOG_LEVEL_DEBUG, "client sent upgrade response packet to server" );

        // IMPORTANT: Cache upgrade response and keep sending it until we get an upgrade confirm.
        // Without this, under very rare packet loss conditions it's possible for the client to get
        // stuck in an undefined state.

        uint8_t from_address_data[32];
        uint8_t to_address_data[32];
        uint16_t from_address_port = 0;
        uint16_t to_address_port = 0;
        int from_address_bytes = 0;
        int to_address_bytes = 0;

        next_address_data( &client->client_external_address, from_address_data, &from_address_bytes, &from_address_port );
        next_address_data( &client->server_address, to_address_data, &to_address_bytes, &to_address_port );

        client->upgrade_response_packet_bytes = 0;
        const int result = next_write_packet( NEXT_UPGRADE_RESPONSE_PACKET, &response, client->upgrade_response_packet_data, &client->upgrade_response_packet_bytes, NULL, NULL, NULL, NULL, NULL, client->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port );

        if ( result != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "client failed to write upgrade response packet" );
            return;
        }

#if NEXT_DEBUG

        const uint8_t * packet_data = client->upgrade_response_packet_data;
        const int packet_bytes = client->upgrade_response_packet_bytes;

        next_assert( packet_data );
        next_assert( packet_bytes > 0 );

        next_assert( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_assert( next_advanced_packet_filter( packet_data, client->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

#endif // #if NEXT_DEBUG

        client->sending_upgrade_response = true;
        client->upgrade_response_start_time = next_time();
        client->last_upgrade_response_send_time = next_time();

        return;
    }

    // upgrade confirm packet

    if ( !client->upgraded && packet_id == NEXT_UPGRADE_CONFIRM_PACKET )
    {
    	next_printf( NEXT_LOG_LEVEL_SPAM, "client processing upgrade confirm packet" );

        if ( !client->sending_upgrade_response )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored upgrade confirm packet from server. unexpected" );
            return;
        }

        if ( client->fallback_to_direct )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored upgrade request packet from server. in fallback to direct state" );
            return;
        }

        if ( !next_address_equal( from, &client->server_address ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored upgrade request packet from server. not from server address" );
            return;
        }

        NextUpgradeConfirmPacket packet;
        int begin = 16;
        int end = packet_bytes - 2;
        if ( next_read_packet( NEXT_UPGRADE_CONFIRM_PACKET, packet_data, begin, end, &packet, NULL, NULL, NULL, NULL, NULL, NULL ) != packet_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored upgrade request packet from server. could not read packet" );
            return;
        }

        if ( memcmp( packet.client_kx_public_key, client->client_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES ) != 0 )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored upgrade confirm packet from server. client public key does not match" );
            return;
        }

        if ( client->upgraded && client->upgrade_sequence >= packet.upgrade_sequence )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored upgrade confirm packet from server. client already upgraded" );
            return;
        }

        uint8_t client_send_key[NEXT_CRYPTO_KX_SESSIONKEYBYTES];
        uint8_t client_receive_key[NEXT_CRYPTO_KX_SESSIONKEYBYTES];
        if ( next_crypto_kx_client_session_keys( client_receive_key, client_send_key, client->client_kx_public_key, client->client_kx_private_key, packet.server_kx_public_key ) != 0 )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored upgrade confirm packet from server. could not generate session keys from server public key" );
            return;
        }

        next_printf( NEXT_LOG_LEVEL_DEBUG, "client received upgrade confirm packet from server" );

        next_post_validate_packet( NEXT_UPGRADE_CONFIRM_PACKET, NULL, NULL, NULL );

        client->upgraded = true;
        client->upgrade_sequence = packet.upgrade_sequence;
        client->session_id = packet.session_id;
        client->last_direct_pong_time = next_time();
        client->last_next_pong_time = next_time();
        memcpy( client->client_send_key, client_send_key, NEXT_CRYPTO_KX_SESSIONKEYBYTES );
        memcpy( client->client_receive_key, client_receive_key, NEXT_CRYPTO_KX_SESSIONKEYBYTES );

        next_client_notify_upgraded_t * notify = (next_client_notify_upgraded_t*) next_malloc( client->context, sizeof(next_client_notify_upgraded_t) );
        next_assert( notify );
        notify->type = NEXT_CLIENT_NOTIFY_UPGRADED;
        notify->session_id = client->session_id;
        notify->client_external_address = client->client_external_address;
        memcpy( notify->current_magic, client->current_magic, 8 );
        {
            next_platform_mutex_guard( &client->notify_mutex );
            next_queue_push( client->notify_queue, notify );
        }

        client->counters[NEXT_CLIENT_COUNTER_UPGRADE_SESSION]++;

        client->sending_upgrade_response = false;

        client->route_update_timeout_time = next_time() + NEXT_CLIENT_ROUTE_UPDATE_TIMEOUT;

        return;
    }

    // direct packet

    if ( packet_id == NEXT_DIRECT_PACKET && client->upgraded && from_server_address )
    {
    	next_printf( NEXT_LOG_LEVEL_SPAM, "client processing direct packet" );

        packet_data += 16;
        packet_bytes -= 18;

        if ( packet_bytes <= 9 )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored direct packet. packet is too small to be valid" );
            return;
        }

        if ( packet_bytes > NEXT_MTU + 9 )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored direct packet. packet is too large to be valid" );
            return;
        }

        const uint8_t * p = packet_data;

        uint8_t packet_session_sequence = next_read_uint8( &p );

        if ( packet_session_sequence != client->open_session_sequence )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored direct packet. session mismatch" );
            return;
        }

        uint64_t packet_sequence = next_read_uint64( &p );

        uint64_t clean_sequence = next_clean_sequence( packet_sequence );
        if ( next_replay_protection_already_received( &client->payload_replay_protection, clean_sequence ) )
            return;

        next_replay_protection_advance_sequence( &client->payload_replay_protection, clean_sequence );

        next_packet_loss_tracker_packet_received( &client->packet_loss_tracker, clean_sequence );

        next_out_of_order_tracker_packet_received( &client->out_of_order_tracker, clean_sequence );

        next_jitter_tracker_packet_received( &client->jitter_tracker, clean_sequence, packet_receive_time );

        next_client_notify_packet_received_t * notify = (next_client_notify_packet_received_t*) next_malloc( client->context, sizeof( next_client_notify_packet_received_t ) );
        notify->type = NEXT_CLIENT_NOTIFY_PACKET_RECEIVED;
        notify->direct = true;
        notify->payload_bytes = packet_bytes - 9;
        next_assert( notify->payload_bytes > 0 );
        memcpy( notify->payload_data, packet_data + 9, size_t(notify->payload_bytes) );
        {
            next_platform_mutex_guard( &client->notify_mutex );
            next_queue_push( client->notify_queue, notify );
        }
        client->counters[NEXT_CLIENT_COUNTER_PACKET_RECEIVED_DIRECT]++;

        return;
    }

    // -------------------
    // PACKETS FROM RELAYS
    // -------------------

    if ( packet_id == NEXT_ROUTE_RESPONSE_PACKET )
    {
    	next_printf( NEXT_LOG_LEVEL_SPAM, "client processing route response packet" );

        packet_data += 16;
        packet_bytes -= 18;

        if ( packet_bytes != NEXT_HEADER_BYTES )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored route response packet from relay. bad packet size" );
            return;
        }

        next_platform_mutex_acquire( &client->route_manager_mutex );
        uint8_t route_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];
        memcpy( route_private_key, client->route_manager->route_data.pending_route_private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );
        const bool fallback_to_direct = client->route_manager->fallback_to_direct;
        const bool pending_route = client->route_manager->route_data.pending_route;
        const uint64_t pending_route_session_id = client->route_manager->route_data.pending_route_session_id;
        const uint8_t pending_route_session_version = client->route_manager->route_data.pending_route_session_version;
        next_platform_mutex_release( &client->route_manager_mutex );

        uint64_t packet_sequence = 0;
        uint64_t packet_session_id = 0;
        uint8_t packet_session_version = 0;

        if ( next_read_header( NEXT_DIRECTION_SERVER_TO_CLIENT, packet_id, &packet_sequence, &packet_session_id, &packet_session_version, route_private_key, packet_data, packet_bytes ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored route response packet from relay. could not read header" );
            return;
        }

        if ( fallback_to_direct )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored route response packet from relay. in fallback to direct state" );
            return;
        }

        if ( !pending_route )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored route response packet from relay. no pending route" );
            return;
        }

        next_platform_mutex_guard( &client->route_manager_mutex );

        next_route_manager_t * route_manager = client->route_manager;

        uint64_t clean_sequence = next_clean_sequence( packet_sequence );

        next_replay_protection_t * replay_protection = &client->special_replay_protection;

        if ( next_replay_protection_already_received( replay_protection, clean_sequence ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored route response packet from relay. sequence already received (%" PRIx64 " vs. %" PRIx64 ")", clean_sequence, replay_protection->most_recent_sequence );
            return;
        }

        if ( packet_session_id != pending_route_session_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored route response packet from relay. session id mismatch" );
            return;
        }

        if ( packet_session_version != pending_route_session_version )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored route response packet from relay. session version mismatch" );
            return;
        }

        next_replay_protection_advance_sequence( replay_protection, clean_sequence );

        next_printf( NEXT_LOG_LEVEL_DEBUG, "client received route response from relay" );

        if ( route_manager->route_data.current_route )
        {
            route_manager->route_data.previous_route = route_manager->route_data.current_route;
            route_manager->route_data.previous_route_session_id = route_manager->route_data.current_route_session_id;
            route_manager->route_data.previous_route_session_version = route_manager->route_data.current_route_session_version;
            memcpy( route_manager->route_data.previous_route_private_key, route_manager->route_data.current_route_private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );
        }

        route_manager->route_data.current_route_session_id = route_manager->route_data.pending_route_session_id;
        route_manager->route_data.current_route_session_version = route_manager->route_data.pending_route_session_version;
        route_manager->route_data.current_route_kbps_up = route_manager->route_data.pending_route_kbps_up;
        route_manager->route_data.current_route_kbps_down = route_manager->route_data.pending_route_kbps_down;
        route_manager->route_data.current_route_next_address = route_manager->route_data.pending_route_next_address;
        memcpy( route_manager->route_data.current_route_private_key, route_manager->route_data.pending_route_private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );

        if ( !route_manager->route_data.current_route )
        {
            route_manager->route_data.current_route_expire_time = route_manager->route_data.pending_route_start_time + 2.0 * NEXT_SLICE_SECONDS;
        }
        else
        {
            route_manager->route_data.current_route_expire_time += 2.0 * NEXT_SLICE_SECONDS;
        }

        route_manager->route_data.current_route = true;
        route_manager->route_data.pending_route = false;

        next_printf( NEXT_LOG_LEVEL_DEBUG, "client network next route is confirmed" );

        client->last_route_switch_time = next_time();

        const bool route_established = route_manager->route_data.current_route;

        const int route_kbps_up = route_manager->route_data.current_route_kbps_up;
        const int route_kbps_down = route_manager->route_data.current_route_kbps_down;

        if ( route_established )
        {
            client->next_bandwidth_envelope_kbps_up = route_kbps_up;
            client->next_bandwidth_envelope_kbps_down = route_kbps_down;
        }
        else
        {
            client->next_bandwidth_envelope_kbps_up = 0;
            client->next_bandwidth_envelope_kbps_down = 0;
        }

        return;
    }

    // continue response packet

    if ( packet_id == NEXT_CONTINUE_RESPONSE_PACKET )
    {
    	next_printf( NEXT_LOG_LEVEL_SPAM, "client processing continue response packet" );

        packet_data += 16;
        packet_bytes -= 18;

        if ( packet_bytes != NEXT_HEADER_BYTES )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored continue response packet from relay. bad packet size" );
            return;
        }

        next_platform_mutex_acquire( &client->route_manager_mutex );
        uint8_t current_route_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];
        memcpy( current_route_private_key, client->route_manager->route_data.current_route_private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );
        const bool fallback_to_direct = client->route_manager->fallback_to_direct;
        const bool current_route = client->route_manager->route_data.current_route;
        const bool pending_continue = client->route_manager->route_data.pending_continue;
        const uint64_t current_route_session_id = client->route_manager->route_data.current_route_session_id;
        const uint8_t current_route_session_version = client->route_manager->route_data.current_route_session_version;
        next_platform_mutex_release( &client->route_manager_mutex );

        if ( fallback_to_direct )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored continue response packet from relay. in fallback to direct state" );
            return;
        }

        if ( !current_route )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored continue response packet from relay. no current route" );
            return;
        }

        if ( !pending_continue )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored continue response packet from relay. no pending continue" );
            return;
        }

        uint64_t packet_sequence = 0;
        uint64_t packet_session_id = 0;
        uint8_t packet_session_version = 0;

        if ( next_read_header( NEXT_DIRECTION_SERVER_TO_CLIENT, packet_id, &packet_sequence, &packet_session_id, &packet_session_version, current_route_private_key, packet_data, packet_bytes ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored continue response packet from relay. could not read header" );
            return;
        }

        uint64_t clean_sequence = next_clean_sequence( packet_sequence );

        next_replay_protection_t * replay_protection = &client->special_replay_protection;

        if ( next_replay_protection_already_received( replay_protection, clean_sequence ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored continue response packet from relay. sequence already received (%" PRIx64 " vs. %" PRIx64 ")", clean_sequence, replay_protection->most_recent_sequence );
            return;
        }

        if ( packet_session_id != current_route_session_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored continue response packet from relay. session id mismatch" );
            return;
        }

        if ( packet_session_version != current_route_session_version )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored continue response packet from relay. session version mismatch" );
            return;
        }

        next_replay_protection_advance_sequence( replay_protection, clean_sequence );

        next_printf( NEXT_LOG_LEVEL_DEBUG, "client received continue response from relay" );

        next_platform_mutex_acquire( &client->route_manager_mutex );
        client->route_manager->route_data.current_route_expire_time += NEXT_SLICE_SECONDS;
        client->route_manager->route_data.pending_continue = false;
        next_platform_mutex_release( &client->route_manager_mutex );

        next_printf( NEXT_LOG_LEVEL_DEBUG, "client continue network next route is confirmed" );

        return;
    }

    // server to client packet

    if ( packet_id == NEXT_SERVER_TO_CLIENT_PACKET )
    {
    	next_printf( NEXT_LOG_LEVEL_SPAM, "client processing server to client packet" );

        packet_data += 16;
        packet_bytes -= 18;

        uint64_t payload_sequence = 0;

        next_platform_mutex_acquire( &client->route_manager_mutex );
        const bool result = next_route_manager_process_server_to_client_packet( client->route_manager, packet_id, packet_data, packet_bytes, &payload_sequence );
        next_platform_mutex_release( &client->route_manager_mutex );

        if ( !result )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored server to client packet. could not verify" );
            return;
        }

        const bool already_received = next_replay_protection_already_received( &client->payload_replay_protection, payload_sequence ) != 0;

        if ( already_received && !client->multipath )
        {
            return;
        }

        if ( already_received && client->multipath )
        {
            client->counters[NEXT_CLIENT_COUNTER_PACKET_RECEIVED_NEXT]++;
            return;
        }

        uint64_t clean_sequence = next_clean_sequence( payload_sequence );

        next_replay_protection_advance_sequence( &client->payload_replay_protection, clean_sequence );

        next_packet_loss_tracker_packet_received( &client->packet_loss_tracker, clean_sequence );

        next_out_of_order_tracker_packet_received( &client->out_of_order_tracker, clean_sequence );

        next_jitter_tracker_packet_received( &client->jitter_tracker, clean_sequence, next_time() );

        next_client_notify_packet_received_t * notify = (next_client_notify_packet_received_t*) next_malloc( client->context, sizeof( next_client_notify_packet_received_t ) );
        notify->type = NEXT_CLIENT_NOTIFY_PACKET_RECEIVED;
        notify->direct = false;
        notify->payload_bytes = packet_bytes - NEXT_HEADER_BYTES;
        memcpy( notify->payload_data, packet_data + NEXT_HEADER_BYTES, size_t(packet_bytes) - NEXT_HEADER_BYTES );
        {
            next_platform_mutex_guard( &client->notify_mutex );
            next_queue_push( client->notify_queue, notify );
        }

        client->counters[NEXT_CLIENT_COUNTER_PACKET_RECEIVED_NEXT]++;

        return;
    }

    // next pong packet

    if ( packet_id == NEXT_PONG_PACKET )
    {
    	next_printf( NEXT_LOG_LEVEL_SPAM, "client processing next pong packet" );

        packet_data += 16;
        packet_bytes -= 18;

        uint64_t payload_sequence = 0;

        next_platform_mutex_acquire( &client->route_manager_mutex );
        const bool result = next_route_manager_process_server_to_client_packet( client->route_manager, packet_id, packet_data, packet_bytes, &payload_sequence );
        next_platform_mutex_release( &client->route_manager_mutex );

        if ( !result )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored server to client packet. could not verify" );
            return;
        }

        uint64_t clean_sequence = next_clean_sequence( payload_sequence );

        if ( next_replay_protection_already_received( &client->special_replay_protection, clean_sequence ) )
            return;

        next_replay_protection_advance_sequence( &client->special_replay_protection, clean_sequence );

        const uint8_t * p = packet_data + NEXT_HEADER_BYTES;

        uint64_t ping_sequence = next_read_uint64( &p );

        next_ping_history_pong_received( &client->next_ping_history, ping_sequence, next_time() );

        client->last_next_pong_time = next_time();

        return;
    }

    // relay pong packet

    if ( packet_id == NEXT_RELAY_PONG_PACKET )
    {
    	next_printf( NEXT_LOG_LEVEL_SPAM, "client processing relay pong packet" );

        if ( !client->upgraded )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored relay pong packet. not upgraded yet" );
            return;
        }

        packet_data += 16;
        packet_bytes -= 18;

        const uint8_t * p = packet_data;

        uint64_t ping_sequence = next_read_uint64( &p );
        uint64_t ping_session_id = next_read_uint64( &p );

        if ( ping_session_id != client->session_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignoring relay pong packet. session id does not match" );
            return;
        }

        next_relay_manager_process_pong( client->near_relay_manager, from, ping_sequence );

        return;
    }

    // -------------------
    // PACKETS FROM SERVER
    // -------------------

    if ( !next_address_equal( from, &client->server_address ) )
    {
    	next_printf( NEXT_LOG_LEVEL_SPAM, "client ignoring packet because it's not from the server" );
        return;
    }

    // direct pong packet

    if ( packet_id == NEXT_DIRECT_PONG_PACKET )
    {
    	next_printf( NEXT_LOG_LEVEL_SPAM, "client processing direct packet" );

        NextDirectPongPacket packet;

        uint64_t packet_sequence = 0;

        int begin = 16;
        int end = packet_bytes - 2;

        if ( next_read_packet( NEXT_DIRECT_PONG_PACKET, packet_data, begin, end, &packet, next_signed_packets, next_encrypted_packets, &packet_sequence, NULL, client->client_receive_key, &client->internal_replay_protection ) != packet_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored direct pong packet. could not read" );
            return;
        }

        next_ping_history_pong_received( &client->direct_ping_history, packet.ping_sequence, next_time() );

        next_post_validate_packet( NEXT_DIRECT_PONG_PACKET, next_encrypted_packets, &packet_sequence, &client->internal_replay_protection );

        client->last_direct_pong_time = next_time();

        return;
    }

    // route update packet

    if ( packet_id == NEXT_ROUTE_UPDATE_PACKET )
    {
    	next_printf( NEXT_LOG_LEVEL_SPAM, "client processing route update packet" );

        if ( client->fallback_to_direct )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored route update packet from server. in fallback to direct state (1)" );
            return;
        }

        NextRouteUpdatePacket packet;

        uint64_t packet_sequence = 0;

        int begin = 16;
        int end = packet_bytes - 2;

        if ( next_read_packet( NEXT_ROUTE_UPDATE_PACKET, packet_data, begin, end, &packet, next_signed_packets, next_encrypted_packets, &packet_sequence, NULL, client->client_receive_key, &client->internal_replay_protection ) != packet_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored route update packet. could not read" );
            return;
        }

        if ( packet.sequence < client->route_update_sequence )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored route update packet from server. sequence is old" );
            return;
        }

        next_post_validate_packet( NEXT_ROUTE_UPDATE_PACKET, next_encrypted_packets, &packet_sequence, &client->internal_replay_protection );

        bool fallback_to_direct = false;

        if ( packet.sequence > client->route_update_sequence )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client received route update packet from server" );

            if ( packet.has_debug )
            {
                next_printf( "--------------------------------------\n%s--------------------------------------", packet.debug );
            }

            if ( packet.has_near_relays )
            {
                // enable near relay pings
                next_printf( NEXT_LOG_LEVEL_INFO, "client pinging %d near relays", packet.num_near_relays );
                next_relay_manager_update( client->near_relay_manager, packet.num_near_relays, packet.near_relay_ids, packet.near_relay_addresses );
            }
            else
            {
                // disable near relay pings (and clear any ping data)
                if ( client->near_relay_manager->num_relays != 0 )
                {
                    next_printf( NEXT_LOG_LEVEL_INFO, "client near relay pings completed" );
                    next_relay_manager_update( client->near_relay_manager, 0, packet.near_relay_ids, packet.near_relay_addresses );
                }
            }

            next_platform_mutex_acquire( &client->route_manager_mutex );
            next_route_manager_update( client->route_manager, packet.update_type, packet.num_tokens, packet.tokens, next_router_public_key, client->client_route_private_key, client->current_magic, &client->client_external_address );
            fallback_to_direct = client->route_manager->fallback_to_direct;
            next_platform_mutex_release( &client->route_manager_mutex );

            if ( !client->fallback_to_direct && fallback_to_direct )
            {
                client->counters[NEXT_CLIENT_COUNTER_FALLBACK_TO_DIRECT]++;
            }

            client->fallback_to_direct = fallback_to_direct;

            if ( !fallback_to_direct )
            {
                if ( packet.multipath && !client->multipath )
                {
                    next_printf( NEXT_LOG_LEVEL_INFO, "client multipath enabled" );
                    client->multipath = true;
                    client->counters[NEXT_CLIENT_COUNTER_MULTIPATH]++;
                }

                client->route_update_sequence = packet.sequence;
                client->client_stats.packets_sent_server_to_client = packet.packets_sent_server_to_client;
                client->client_stats.packets_lost_client_to_server = packet.packets_lost_client_to_server;
                client->client_stats.packets_out_of_order_client_to_server = packet.packets_out_of_order_client_to_server;
                client->client_stats.jitter_client_to_server = packet.jitter_client_to_server;
                client->counters[NEXT_CLIENT_COUNTER_PACKETS_LOST_CLIENT_TO_SERVER] = packet.packets_lost_client_to_server;
                client->counters[NEXT_CLIENT_COUNTER_PACKETS_OUT_OF_ORDER_CLIENT_TO_SERVER] = packet.packets_out_of_order_client_to_server;
                client->route_update_timeout_time = next_time() + NEXT_CLIENT_ROUTE_UPDATE_TIMEOUT;

                if ( memcmp( client->upcoming_magic, packet.upcoming_magic, 8 ) != 0 )
                {
                    next_printf( NEXT_LOG_LEVEL_DEBUG, "client updated magic: %x,%x,%x,%x,%x,%x,%x,%x | %x,%x,%x,%x,%x,%x,%x,%x | %x,%x,%x,%x,%x,%x,%x,%x",
                        packet.upcoming_magic[0],
                        packet.upcoming_magic[1],
                        packet.upcoming_magic[2],
                        packet.upcoming_magic[3],
                        packet.upcoming_magic[4],
                        packet.upcoming_magic[5],
                        packet.upcoming_magic[6],
                        packet.upcoming_magic[7],

                        packet.current_magic[0],
                        packet.current_magic[1],
                        packet.current_magic[2],
                        packet.current_magic[3],
                        packet.current_magic[4],
                        packet.current_magic[5],
                        packet.current_magic[6],
                        packet.current_magic[7],

                        packet.previous_magic[0],
                        packet.previous_magic[1],
                        packet.previous_magic[2],
                        packet.previous_magic[3],
                        packet.previous_magic[4],
                        packet.previous_magic[5],
                        packet.previous_magic[6],
                        packet.previous_magic[7] );

                    memcpy( client->upcoming_magic, packet.upcoming_magic, 8 );
                    memcpy( client->current_magic, packet.current_magic, 8 );
                    memcpy( client->previous_magic, packet.previous_magic, 8 );

                    next_client_notify_magic_updated_t * notify = (next_client_notify_magic_updated_t*) next_malloc( client->context, sizeof(next_client_notify_magic_updated_t) );
                    next_assert( notify );
                    notify->type = NEXT_CLIENT_NOTIFY_MAGIC_UPDATED;
                    memcpy( notify->current_magic, client->current_magic, 8 );
                    {
                        next_platform_mutex_guard( &client->notify_mutex );
                        next_queue_push( client->notify_queue, notify );
                    }
                }
            }
        }

        if ( fallback_to_direct )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "client ignored route update packet from server. in fallback to direct state (2)" );
            return;
        }

        NextRouteUpdateAckPacket ack;
        ack.sequence = packet.sequence;

        if ( next_client_internal_send_packet_to_server( client, NEXT_ROUTE_UPDATE_ACK_PACKET, &ack ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_WARN, "client failed to send route update ack packet to server" );
            return;
        }

        next_printf( NEXT_LOG_LEVEL_DEBUG, "client sent route update ack packet to server" );

        return;
    }
}

void next_client_internal_process_passthrough_packet( next_client_internal_t * client, const next_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    next_client_internal_verify_sentinels( client );

	next_printf( NEXT_LOG_LEVEL_SPAM, "client processing passthrough packet" );

    next_assert( from );
    next_assert( packet_data );

    const bool from_server_address = client->server_address.type != 0 && next_address_equal( from, &client->server_address );

    if ( packet_bytes <= NEXT_MAX_PACKET_BYTES - 1 && from_server_address )
    {
        next_client_notify_packet_received_t * notify = (next_client_notify_packet_received_t*) next_malloc( client->context, sizeof( next_client_notify_packet_received_t ) );
        notify->type = NEXT_CLIENT_NOTIFY_PACKET_RECEIVED;
        notify->direct = true;
        notify->payload_bytes = packet_bytes;
        next_assert( notify->payload_bytes >= 0 );
        next_assert( notify->payload_bytes <= NEXT_MAX_PACKET_BYTES - 1 );
        memcpy( notify->payload_data, packet_data, size_t(packet_bytes) );
        {
            next_platform_mutex_guard( &client->notify_mutex );
            next_queue_push( client->notify_queue, notify );
        }
        client->counters[NEXT_CLIENT_COUNTER_PACKET_RECEIVED_PASSTHROUGH]++;
    }
}

#if NEXT_DEVELOPMENT
bool next_packet_loss = false;
#endif // #if NEXT_DEVELOPMENT

void next_client_internal_block_and_receive_packet( next_client_internal_t * client )
{
    next_client_internal_verify_sentinels( client );

    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];

    next_assert( ( size_t(packet_data) % 4 ) == 0 );

    next_address_t from;

    int packet_bytes = next_platform_socket_receive_packet( client->socket, &from, packet_data, NEXT_MAX_PACKET_BYTES );

    double packet_receive_time = next_time();

    next_assert( packet_bytes >= 0 );

    if ( packet_bytes <= 1 )
        return;

#if NEXT_DEVELOPMENT
    if ( next_packet_loss && ( rand() % 10 ) == 0 )
        return;
#endif // #if NEXT_DEVELOPMENT

    if ( packet_data[0] != NEXT_PASSTHROUGH_PACKET )
    {
        next_client_internal_process_network_next_packet( client, &from, packet_data, packet_bytes, packet_receive_time );
    }
    else
    {
        next_client_internal_process_passthrough_packet( client, &from, packet_data + 1, packet_bytes - 1 );
    }
}

bool next_client_internal_pump_commands( next_client_internal_t * client )
{
    next_client_internal_verify_sentinels( client );

    bool quit = false;

    while ( true )
    {
        void * entry = NULL;
        {
            next_platform_mutex_guard( &client->command_mutex );
            entry = next_queue_pop( client->command_queue );
        }

        if ( entry == NULL )
            break;

        next_client_command_t * command = (next_client_command_t*) entry;

        switch ( command->type )
        {
            case NEXT_CLIENT_COMMAND_OPEN_SESSION:
            {
                next_client_command_open_session_t * open_session_command = (next_client_command_open_session_t*) entry;
                client->server_address = open_session_command->server_address;
                client->session_open = true;
                client->open_session_sequence++;
                client->last_direct_ping_time = next_time();
                client->last_stats_update_time = next_time();
                client->last_stats_report_time = next_time() + next_random_float();
                next_crypto_kx_keypair( client->client_kx_public_key, client->client_kx_private_key );
                next_crypto_box_keypair( client->client_route_public_key, client->client_route_private_key );
                char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_INFO, "client opened session to %s", next_address_to_string( &open_session_command->server_address, buffer ) );
                client->counters[NEXT_CLIENT_COUNTER_OPEN_SESSION]++;
                next_platform_mutex_acquire( &client->route_manager_mutex );
                next_route_manager_reset( client->route_manager );
                next_route_manager_direct_route( client->route_manager, true );
                next_platform_mutex_release( &client->route_manager_mutex );

                // IMPORTANT: Fire back ready when the client is ready to start sending packets and we're all dialed in for this session
                next_client_notify_ready_t * notify = (next_client_notify_ready_t*) next_malloc( client->context, sizeof(next_client_notify_ready_t) );
                next_assert( notify );
                notify->type = NEXT_CLIENT_NOTIFY_READY;
                {
                    next_platform_mutex_guard( &client->notify_mutex );
                    next_queue_push( client->notify_queue, notify );
                }
            }
            break;

            case NEXT_CLIENT_COMMAND_CLOSE_SESSION:
            {
                if ( !client->session_open )
                    break;

                char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_INFO, "client closed session to %s", next_address_to_string( &client->server_address, buffer ) );

                memset( client->upcoming_magic, 0, 8 );
                memset( client->current_magic, 0, 8 );
                memset( client->previous_magic, 0, 8 );
                memset( &client->server_address, 0, sizeof(next_address_t) );
                memset( &client->client_external_address, 0, sizeof(next_address_t) );

                client->session_open = false;
                client->upgraded = false;
                client->reported = false;
                client->fallback_to_direct = false;
                client->multipath = false;
                client->upgrade_sequence = 0;
                client->session_id = 0;
                client->internal_send_sequence = 0;
                client->last_next_ping_time = 0.0;
                client->last_next_pong_time = 0.0;
                client->last_direct_ping_time = 0.0;
                client->last_direct_pong_time = 0.0;
                client->last_stats_update_time = 0.0;
                client->last_stats_report_time = 0.0;
                client->last_route_switch_time = 0.0;
                client->route_update_timeout_time = 0.0;
                client->route_update_sequence = 0;
                client->sending_upgrade_response = false;
                client->upgrade_response_packet_bytes = 0;
                memset( client->upgrade_response_packet_data, 0, sizeof(client->upgrade_response_packet_data) );
                client->upgrade_response_start_time = 0.0;
                client->last_upgrade_response_send_time = 0.0;

                client->packets_sent = 0;

                memset( &client->client_stats, 0, sizeof(next_client_stats_t) );
                memset( &client->near_relay_stats, 0, sizeof(next_relay_stats_t ) );
                next_relay_stats_initialize_sentinels( &client->near_relay_stats );

                next_relay_manager_reset( client->near_relay_manager );

                memset( client->client_kx_public_key, 0, NEXT_CRYPTO_KX_PUBLICKEYBYTES );
                memset( client->client_kx_private_key, 0, NEXT_CRYPTO_KX_SECRETKEYBYTES );
                memset( client->client_send_key, 0, NEXT_CRYPTO_KX_SESSIONKEYBYTES );
                memset( client->client_receive_key, 0, NEXT_CRYPTO_KX_SESSIONKEYBYTES );
                memset( client->client_route_public_key, 0, NEXT_CRYPTO_BOX_PUBLICKEYBYTES );
                memset( client->client_route_private_key, 0, NEXT_CRYPTO_BOX_SECRETKEYBYTES );

                next_ping_history_clear( &client->next_ping_history );
                next_ping_history_clear( &client->direct_ping_history );

                next_replay_protection_reset( &client->payload_replay_protection );
                next_replay_protection_reset( &client->special_replay_protection );
                next_replay_protection_reset( &client->internal_replay_protection );

                next_platform_mutex_acquire( &client->direct_bandwidth_mutex );
                client->direct_bandwidth_usage_kbps_up = 0;
                client->direct_bandwidth_usage_kbps_down = 0;
                next_platform_mutex_release( &client->direct_bandwidth_mutex );

                next_platform_mutex_acquire( &client->next_bandwidth_mutex );
                client->next_bandwidth_over_limit = false;
                client->next_bandwidth_usage_kbps_up = 0;
                client->next_bandwidth_usage_kbps_down = 0;
                client->next_bandwidth_envelope_kbps_up = 0;
                client->next_bandwidth_envelope_kbps_down = 0;
                next_platform_mutex_release( &client->next_bandwidth_mutex );

                next_platform_mutex_acquire( &client->route_manager_mutex );
                next_route_manager_reset( client->route_manager );
                next_platform_mutex_release( &client->route_manager_mutex );

                next_packet_loss_tracker_reset( &client->packet_loss_tracker );
                next_out_of_order_tracker_reset( &client->out_of_order_tracker );
                next_jitter_tracker_reset( &client->jitter_tracker );

                client->counters[NEXT_CLIENT_COUNTER_CLOSE_SESSION]++;
            }
            break;

            case NEXT_CLIENT_COMMAND_DESTROY:
            {
                quit = true;
            }
            break;

            case NEXT_CLIENT_COMMAND_REPORT_SESSION:
            {
                if ( client->session_id != 0 && !client->reported )
                {
                    next_printf( NEXT_LOG_LEVEL_INFO, "client reported session %" PRIx64, client->session_id );
                    client->reported = true;
                }
            }
            break;

            default: break;
        }

        next_free( client->context, command );
    }

    return quit;
}

#if NEXT_DEVELOPMENT
bool next_fake_fallback_to_direct = false;
float next_fake_direct_packet_loss = 0.0f;
float next_fake_direct_rtt = 0.0f;
float next_fake_next_packet_loss = 0.0f;
float next_fake_next_rtt = 0.0f;
#endif // #if !NEXT_DEVELOPMENT

void next_client_internal_update_stats( next_client_internal_t * client )
{
    next_client_internal_verify_sentinels( client );

    if ( next_global_config.disable_network_next )
        return;

    double current_time = next_time();

    if ( client->last_stats_update_time + ( 1.0 / NEXT_CLIENT_STATS_UPDATES_PER_SECOND ) < current_time )
    {
        next_platform_mutex_acquire( &client->route_manager_mutex );
        const bool network_next = client->route_manager->route_data.current_route;
        const bool fallback_to_direct = client->route_manager->fallback_to_direct;
        next_platform_mutex_release( &client->route_manager_mutex );

        client->client_stats.next = network_next;
        client->client_stats.upgraded = client->upgraded;
        client->client_stats.reported = client->reported;
        client->client_stats.fallback_to_direct = client->fallback_to_direct;
        client->client_stats.multipath = client->multipath;
        client->client_stats.platform_id = next_platform_id();
        client->client_stats.connection_type = next_platform_connection_type();

        double start_time = current_time - NEXT_CLIENT_STATS_WINDOW;
        if ( start_time < client->last_route_switch_time + NEXT_PING_SAFETY )
        {
            start_time = client->last_route_switch_time + NEXT_PING_SAFETY;
        }

        next_route_stats_t next_route_stats;
        next_route_stats_from_ping_history( &client->next_ping_history, current_time - NEXT_CLIENT_STATS_WINDOW, current_time, &next_route_stats );

        next_route_stats_t direct_route_stats;
        next_route_stats_from_ping_history( &client->direct_ping_history, current_time - NEXT_CLIENT_STATS_WINDOW, current_time, &direct_route_stats );

        next_platform_mutex_acquire( &client->direct_bandwidth_mutex );
        client->client_stats.direct_kbps_up = client->direct_bandwidth_usage_kbps_up;
        client->client_stats.direct_kbps_down = client->direct_bandwidth_usage_kbps_down;
        next_platform_mutex_release( &client->direct_bandwidth_mutex );

        if ( network_next )
        {
            client->client_stats.next_rtt = next_route_stats.rtt;
            client->client_stats.next_jitter = next_route_stats.jitter;
            client->client_stats.next_packet_loss = next_route_stats.packet_loss;
            next_platform_mutex_acquire( &client->next_bandwidth_mutex );
            client->client_stats.next_kbps_up = client->next_bandwidth_usage_kbps_up;
            client->client_stats.next_kbps_down = client->next_bandwidth_usage_kbps_down;
            next_platform_mutex_release( &client->next_bandwidth_mutex );
        }
        else
        {
            client->client_stats.next_rtt = 0.0f;
            client->client_stats.next_jitter = 0.0f;
            client->client_stats.next_packet_loss = 0.0f;
            client->client_stats.next_kbps_up = 0;
            client->client_stats.next_kbps_down = 0;
        }

        client->client_stats.direct_rtt = direct_route_stats.rtt;
        client->client_stats.direct_jitter = direct_route_stats.jitter;
        client->client_stats.direct_packet_loss = direct_route_stats.packet_loss;

        if ( direct_route_stats.packet_loss > client->client_stats.direct_max_packet_loss_seen )
        {
            client->client_stats.direct_max_packet_loss_seen = direct_route_stats.packet_loss;
        }

#if NEXT_DEVELOPMENT
        if ( !fallback_to_direct && next_fake_fallback_to_direct )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "client fakes fallback to direct" );
            next_platform_mutex_acquire( &client->route_manager_mutex );
            next_route_manager_fallback_to_direct( client->route_manager, NEXT_FLAGS_ROUTE_UPDATE_TIMED_OUT );
            next_platform_mutex_release( &client->route_manager_mutex );
        }
        client->client_stats.direct_rtt += next_fake_direct_rtt;
        client->client_stats.direct_packet_loss += next_fake_direct_packet_loss;
        client->client_stats.next_rtt += next_fake_next_rtt;
        client->client_stats.next_packet_loss += next_fake_next_packet_loss;
 #endif // #if NEXT_DEVELOPMENT

        if ( !fallback_to_direct )
        {
            const int packets_lost = next_packet_loss_tracker_update( &client->packet_loss_tracker );
            client->client_stats.packets_lost_server_to_client += packets_lost;
            client->counters[NEXT_CLIENT_COUNTER_PACKETS_LOST_SERVER_TO_CLIENT] += packets_lost;

            client->client_stats.packets_out_of_order_server_to_client = client->out_of_order_tracker.num_out_of_order_packets;
            client->counters[NEXT_CLIENT_COUNTER_PACKETS_OUT_OF_ORDER_SERVER_TO_CLIENT] = client->out_of_order_tracker.num_out_of_order_packets;

            client->client_stats.jitter_server_to_client = float( client->jitter_tracker.jitter * 1000.0 );
        }

        client->client_stats.packets_sent_client_to_server = client->packets_sent;

        next_relay_manager_get_stats( client->near_relay_manager, &client->near_relay_stats );

        next_client_notify_stats_updated_t * notify = (next_client_notify_stats_updated_t*) next_malloc( client->context, sizeof( next_client_notify_stats_updated_t ) );
        notify->type = NEXT_CLIENT_NOTIFY_STATS_UPDATED;
        notify->stats = client->client_stats;
        notify->fallback_to_direct = fallback_to_direct;
        {
            next_platform_mutex_guard( &client->notify_mutex );
            next_queue_push( client->notify_queue, notify );
        }

        client->last_stats_update_time = current_time;
    }

    if ( client->last_stats_report_time + 1.0 < current_time && client->client_stats.direct_rtt > 0.0f )
    {
        NextClientStatsPacket packet;

        packet.reported = client->reported;
        packet.fallback_to_direct = client->fallback_to_direct;
        packet.multipath = client->multipath;
        packet.platform_id = client->client_stats.platform_id;
        packet.connection_type = client->client_stats.connection_type;

        next_platform_mutex_acquire( &client->direct_bandwidth_mutex );
        packet.direct_kbps_up = (int) ceil( client->direct_bandwidth_usage_kbps_up );
        packet.direct_kbps_down = (int) ceil( client->direct_bandwidth_usage_kbps_down );
        next_platform_mutex_release( &client->direct_bandwidth_mutex );

        next_platform_mutex_acquire( &client->next_bandwidth_mutex );
        packet.next_bandwidth_over_limit = client->next_bandwidth_over_limit;
        packet.next_kbps_up = (int) ceil( client->next_bandwidth_usage_kbps_up );
        packet.next_kbps_down = (int) ceil( client->next_bandwidth_usage_kbps_down );
        client->next_bandwidth_over_limit = false;
        next_platform_mutex_release( &client->next_bandwidth_mutex );

        if ( !client->client_stats.next )
        {
            packet.next_kbps_up = 0;
            packet.next_kbps_down = 0;
        }

        packet.next = client->client_stats.next;
        packet.next_rtt = client->client_stats.next_rtt;
        packet.next_jitter = client->client_stats.next_jitter;
        packet.next_packet_loss = client->client_stats.next_packet_loss;

        packet.direct_rtt = client->client_stats.direct_rtt;
        packet.direct_jitter = client->client_stats.direct_jitter;
        packet.direct_packet_loss = client->client_stats.direct_packet_loss;
        packet.direct_max_packet_loss_seen = client->client_stats.direct_max_packet_loss_seen;

        if ( !client->fallback_to_direct )
        {
            packet.num_near_relays = client->near_relay_stats.num_relays;
            for ( int i = 0; i < packet.num_near_relays; ++i )
            {
                packet.near_relay_ids[i] = client->near_relay_stats.relay_ids[i];

                int rtt = (int) ceil( client->near_relay_stats.relay_rtt[i] );
                int jitter = (int) ceil( client->near_relay_stats.relay_jitter[i] );
                float packet_loss = client->near_relay_stats.relay_packet_loss[i];

                if ( rtt > 255 )
                    rtt = 255;

                if ( jitter > 255 )
                    jitter = 255;

                if ( packet_loss > 100 )
                    packet_loss = 100;

                packet.near_relay_rtt[i] = uint8_t( rtt );
                packet.near_relay_jitter[i] = uint8_t( jitter );
                packet.near_relay_packet_loss[i] = packet_loss;
            }
        }

        // todo
        if ( packet.num_near_relays )
        {
            printf( "------------------------------\n" );
            printf( "direct rtt = %d, jitter = %d, packet loss = %.2f, max packet loss seen = %.2f\n", int(packet.direct_rtt), int(packet.direct_jitter), packet.direct_packet_loss, packet.direct_max_packet_loss_seen );
            printf( "------------------------------\n" );
            for ( int i = 0; i < packet.num_near_relays; i++ )
            {
                printf( "%" PRIx64 ": rtt = %d, jitter = %d, packet loss = %.2f\n", packet.near_relay_ids[i], packet.near_relay_rtt[i], packet.near_relay_jitter[i], packet.near_relay_packet_loss[i] );
            }
            printf( "------------------------------\n" );
        }

        packet.packets_sent_client_to_server = client->packets_sent;

        packet.packets_lost_server_to_client = client->client_stats.packets_lost_server_to_client;
        packet.packets_out_of_order_server_to_client = client->client_stats.packets_out_of_order_server_to_client;
        packet.jitter_server_to_client = client->client_stats.jitter_server_to_client;

        if ( next_client_internal_send_packet_to_server( client, NEXT_CLIENT_STATS_PACKET, &packet ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "client failed to send stats packet to server" );
            return;
        }

        client->last_stats_report_time = current_time;
    }
}

void next_client_internal_update_direct_pings( next_client_internal_t * client )
{
    next_client_internal_verify_sentinels( client );

    if ( next_global_config.disable_network_next )
        return;

    if ( !client->upgraded )
        return;

    if ( client->fallback_to_direct )
        return;

    double current_time = next_time();

    if ( client->last_direct_pong_time + NEXT_CLIENT_SESSION_TIMEOUT < current_time )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client direct pong timed out. falling back to direct" );
        next_platform_mutex_acquire( &client->route_manager_mutex );
        next_route_manager_fallback_to_direct( client->route_manager, NEXT_FLAGS_DIRECT_PONG_TIMED_OUT );
        next_platform_mutex_release( &client->route_manager_mutex );
        return;
    }

    if ( client->last_direct_ping_time + ( 1.0 / NEXT_DIRECT_PINGS_PER_SECOND ) <= current_time )
    {
        NextDirectPingPacket packet;
        packet.ping_sequence = next_ping_history_ping_sent( &client->direct_ping_history, current_time );

        if ( next_client_internal_send_packet_to_server( client, NEXT_DIRECT_PING_PACKET, &packet ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "client failed to send direct ping packet to server" );
            return;
        }

        client->last_direct_ping_time = current_time;
    }
}

void next_client_internal_update_next_pings( next_client_internal_t * client )
{
    next_client_internal_verify_sentinels( client );

    if ( next_global_config.disable_network_next )
        return;

    if ( !client->upgraded )
        return;

    if ( client->fallback_to_direct )
        return;

    double current_time = next_time();

    next_platform_mutex_acquire( &client->route_manager_mutex );
    const bool has_next_route = client->route_manager->route_data.current_route;
    next_platform_mutex_release( &client->route_manager_mutex );

    if ( !has_next_route )
    {
        client->last_next_pong_time = current_time;
    }

    if ( client->last_next_pong_time + NEXT_CLIENT_SESSION_TIMEOUT < current_time )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client next pong timed out. falling back to direct" );
        next_platform_mutex_acquire( &client->route_manager_mutex );
        next_route_manager_fallback_to_direct( client->route_manager, NEXT_FLAGS_NEXT_PONG_TIMED_OUT );
        next_platform_mutex_release( &client->route_manager_mutex );
        return;
    }

    if ( client->last_next_ping_time + ( 1.0 / NEXT_PINGS_PER_SECOND ) <= current_time )
    {
        next_platform_mutex_acquire( &client->route_manager_mutex );
        const bool send_over_network_next = client->route_manager->route_data.current_route;
        next_platform_mutex_release( &client->route_manager_mutex );

        if ( !send_over_network_next )
            return;

        next_platform_mutex_acquire( &client->route_manager_mutex );
        const uint64_t session_id = client->route_manager->route_data.current_route_session_id;
        const uint8_t session_version = client->route_manager->route_data.current_route_session_version;
        const next_address_t to = client->route_manager->route_data.current_route_next_address;
        uint8_t private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];
        memcpy( private_key, client->route_manager->route_data.current_route_private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );
        next_platform_mutex_release( &client->route_manager_mutex );

        uint64_t sequence = client->special_send_sequence++;
        sequence |= (1ULL<<62);

        uint8_t packet_data[NEXT_MAX_PACKET_BYTES];

        uint8_t from_address_data[32];
        uint8_t to_address_data[32];
        uint16_t from_address_port;
        uint16_t to_address_port;
        int from_address_bytes;
        int to_address_bytes;

        next_address_data( &client->client_external_address, from_address_data, &from_address_bytes, &from_address_port );
        next_address_data( &to, to_address_data, &to_address_bytes, &to_address_port );

        const uint64_t ping_sequence = next_ping_history_ping_sent( &client->next_ping_history, current_time );

        int packet_bytes = next_write_ping_packet( packet_data, sequence, session_id, session_version, private_key, ping_sequence, client->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port );

        next_assert( packet_bytes > 0 );

        next_assert( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_assert( next_advanced_packet_filter( packet_data, client->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

        next_platform_socket_send_packet( client->socket, &to, packet_data, packet_bytes );

        client->last_next_ping_time = current_time;
    }
}

void next_client_internal_send_pings_to_near_relays( next_client_internal_t * client )
{
    next_client_internal_verify_sentinels( client );

    if ( next_global_config.disable_network_next )
        return;

    if ( !client->upgraded )
        return;

    if ( client->fallback_to_direct )
        return;

    next_relay_manager_send_pings( client->near_relay_manager, client->socket, client->session_id, client->current_magic, &client->client_external_address );
}

void next_client_internal_update_fallback_to_direct( next_client_internal_t * client )
{
    next_client_internal_verify_sentinels( client );

    if ( next_global_config.disable_network_next )
        return;

    next_platform_mutex_acquire( &client->route_manager_mutex );
    if ( client->upgraded )
    {
        next_route_manager_check_for_timeouts( client->route_manager );
    }
    const bool fallback_to_direct = client->route_manager->fallback_to_direct;
    next_platform_mutex_release( &client->route_manager_mutex );

    if ( !client->fallback_to_direct && fallback_to_direct )
    {
        client->counters[NEXT_CLIENT_COUNTER_FALLBACK_TO_DIRECT]++;
        client->fallback_to_direct = fallback_to_direct;
        return;
    }

    if ( !client->fallback_to_direct && client->upgraded && client->route_update_timeout_time > 0.0 )
    {
        if ( next_time() > client->route_update_timeout_time )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "client route update timeout. falling back to direct" );
            next_platform_mutex_acquire( &client->route_manager_mutex );
            next_route_manager_fallback_to_direct( client->route_manager, NEXT_FLAGS_ROUTE_UPDATE_TIMED_OUT );
            next_platform_mutex_release( &client->route_manager_mutex );
            client->counters[NEXT_CLIENT_COUNTER_FALLBACK_TO_DIRECT]++;
            client->fallback_to_direct = true;
        }
    }
}

void next_client_internal_update_route_manager( next_client_internal_t * client )
{
    next_client_internal_verify_sentinels( client );

    if ( next_global_config.disable_network_next )
        return;

    if ( !client->upgraded )
        return;

    if ( client->fallback_to_direct )
        return;

    next_address_t route_request_to;
    next_address_t continue_request_to;

    int route_request_packet_bytes;
    int continue_request_packet_bytes;

    uint8_t route_request_packet_data[NEXT_MAX_PACKET_BYTES];
    uint8_t continue_request_packet_data[NEXT_MAX_PACKET_BYTES];

    next_platform_mutex_acquire( &client->route_manager_mutex );
    const bool send_route_request = next_route_manager_send_route_request( client->route_manager, &route_request_to, route_request_packet_data, &route_request_packet_bytes );
    const bool send_continue_request = next_route_manager_send_continue_request( client->route_manager, &continue_request_to, continue_request_packet_data, &continue_request_packet_bytes );
    next_platform_mutex_release( &client->route_manager_mutex );

    if ( send_route_request )
    {
        char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
        next_printf( NEXT_LOG_LEVEL_DEBUG, "client sent route request to relay: %s", next_address_to_string( &route_request_to, buffer ) );
        next_platform_socket_send_packet( client->socket, &route_request_to, route_request_packet_data, route_request_packet_bytes );
    }

    if ( send_continue_request )
    {
        char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
        next_printf( NEXT_LOG_LEVEL_DEBUG, "client sent continue request to relay: %s", next_address_to_string( &continue_request_to, buffer ) );
        next_platform_socket_send_packet( client->socket, &continue_request_to, continue_request_packet_data, continue_request_packet_bytes );
    }
}

void next_client_internal_update_upgrade_response( next_client_internal_t * client )
{
    next_client_internal_verify_sentinels( client );

    if ( next_global_config.disable_network_next )
        return;

    if ( client->fallback_to_direct )
        return;

    if ( !client->sending_upgrade_response )
        return;

    const double current_time = next_time();

    if ( client->last_upgrade_response_send_time + 1.0 > current_time )
        return;

    next_assert( client->upgrade_response_packet_bytes > 0 );

    next_platform_socket_send_packet( client->socket, &client->server_address, client->upgrade_response_packet_data, client->upgrade_response_packet_bytes );

    next_printf( NEXT_LOG_LEVEL_DEBUG, "client sent cached upgrade response packet to server" );

    client->last_upgrade_response_send_time = current_time;

    if ( client->upgrade_response_start_time + 5.0 <= current_time )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "upgrade response timed out" );
        next_platform_mutex_acquire( &client->route_manager_mutex );
        next_route_manager_fallback_to_direct( client->route_manager, NEXT_FLAGS_UPGRADE_RESPONSE_TIMED_OUT );
        next_platform_mutex_release( &client->route_manager_mutex );
        client->fallback_to_direct = true;
    }
}

static void next_client_internal_thread_function( void * context )
{
    next_client_internal_t * client = (next_client_internal_t*) context;

    next_assert( client );

    bool quit = false;

    double last_update_time = next_time();

    while ( !quit )
    {
        next_client_internal_block_and_receive_packet( client );

        double current_time = next_time();

        if ( current_time > last_update_time + 0.01 )
        {
            next_client_internal_update_direct_pings( client );

            next_client_internal_update_next_pings( client );

            next_client_internal_send_pings_to_near_relays( client );

            next_client_internal_update_stats( client );

            next_client_internal_update_fallback_to_direct( client );

            next_client_internal_update_route_manager( client );

            next_client_internal_update_upgrade_response( client );

            quit = next_client_internal_pump_commands( client );

            last_update_time = current_time;
        }
    }
}

// ---------------------------------------------------------------

struct next_client_t
{
    NEXT_DECLARE_SENTINEL(0)

    void * context;
    int state;
    bool ready;
    bool upgraded;
    bool fallback_to_direct;
    uint8_t open_session_sequence;
    uint8_t current_magic[8];
    uint16_t bound_port;
    uint64_t session_id;
    next_address_t server_address;
    next_address_t client_external_address;
    next_client_internal_t * internal;
    next_platform_thread_t * thread;
    void (*packet_received_callback)( next_client_t * client, void * context, const struct next_address_t * from, const uint8_t * packet_data, int packet_bytes );
    NEXT_DECLARE_SENTINEL(1)

    next_client_stats_t client_stats;

    NEXT_DECLARE_SENTINEL(2)

    next_bandwidth_limiter_t direct_send_bandwidth;
    next_bandwidth_limiter_t direct_receive_bandwidth;
    next_bandwidth_limiter_t next_send_bandwidth;
    next_bandwidth_limiter_t next_receive_bandwidth;

    NEXT_DECLARE_SENTINEL(3)

    uint64_t counters[NEXT_CLIENT_COUNTER_MAX];

    NEXT_DECLARE_SENTINEL(4)
};

void next_client_initialize_sentinels( next_client_t * client )
{
    (void) client;
    next_assert( client );
    NEXT_INITIALIZE_SENTINEL( client, 0 )
    NEXT_INITIALIZE_SENTINEL( client, 1 )
    NEXT_INITIALIZE_SENTINEL( client, 2 )
    NEXT_INITIALIZE_SENTINEL( client, 3 )
    NEXT_INITIALIZE_SENTINEL( client, 4 )
}

void next_client_verify_sentinels( next_client_t * client )
{
    (void) client;
    next_assert( client );
    NEXT_VERIFY_SENTINEL( client, 0 )
    NEXT_VERIFY_SENTINEL( client, 1 )
    NEXT_VERIFY_SENTINEL( client, 2 )
    NEXT_VERIFY_SENTINEL( client, 3 )
    NEXT_VERIFY_SENTINEL( client, 4 )
}

void next_client_destroy( next_client_t * client );

next_client_t * next_client_create( void * context, const char * bind_address, void (*packet_received_callback)( next_client_t * client, void * context, const struct next_address_t * from, const uint8_t * packet_data, int packet_bytes ) )
{
    next_assert( bind_address );
    next_assert( packet_received_callback );

    next_client_t * client = (next_client_t*) next_malloc( context, sizeof(next_client_t) );
    if ( !client )
        return NULL;

    memset( client, 0, sizeof( next_client_t) );

    next_client_initialize_sentinels( client );

    client->context = context;
    client->packet_received_callback = packet_received_callback;

    client->internal = next_client_internal_create( client->context, bind_address );
    if ( !client->internal )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create internal client" );
        next_client_destroy( client );
        return NULL;
    }

    client->bound_port = client->internal->bound_port;

    client->thread = next_platform_thread_create( client->context, next_client_internal_thread_function, client->internal );
    next_assert( client->thread );
    if ( !client->thread )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create thread" );
        next_client_destroy( client );
        return NULL;
    }

    if ( next_platform_thread_high_priority( client->thread ) )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "client increased thread priority" );
    }

    next_bandwidth_limiter_reset( &client->direct_send_bandwidth );
    next_bandwidth_limiter_reset( &client->direct_receive_bandwidth );
    next_bandwidth_limiter_reset( &client->next_send_bandwidth );
    next_bandwidth_limiter_reset( &client->next_receive_bandwidth );

    next_client_verify_sentinels( client );

    return client;
}

uint16_t next_client_port( next_client_t * client )
{
    next_client_verify_sentinels( client );

    return client->bound_port;
}

void next_client_destroy( next_client_t * client )
{
    next_client_verify_sentinels( client );

    if ( client->thread )
    {
        next_client_command_destroy_t * command = (next_client_command_destroy_t*) next_malloc( client->context, sizeof( next_client_command_destroy_t ) );
        if ( !command )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "client destroy failed. could not create destroy command" );
            return;
        }
        command->type = NEXT_CLIENT_COMMAND_DESTROY;
        {
            next_platform_mutex_guard( &client->internal->command_mutex );
            next_queue_push( client->internal->command_queue, command );
        }

        next_platform_thread_join( client->thread );
        next_platform_thread_destroy( client->thread );
    }

    if ( client->internal )
    {
        next_client_internal_destroy( client->internal );
    }

    clear_and_free( client->context, client, sizeof(next_client_t) );
}

void next_client_open_session( next_client_t * client, const char * server_address_string )
{
    next_client_verify_sentinels( client );

    next_assert( client->internal );

    next_client_close_session( client );

    next_address_t server_address;
    if ( next_address_parse( &server_address, server_address_string ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client open session failed. could not parse server address: %s", server_address_string );
        client->state = NEXT_CLIENT_STATE_ERROR;
        return;
    }

    next_client_command_open_session_t * command = (next_client_command_open_session_t*) next_malloc( client->context, sizeof( next_client_command_open_session_t ) );
    if ( !command )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client open session failed. could not create open session command" );
        client->state = NEXT_CLIENT_STATE_ERROR;
        return;
    }

    command->type = NEXT_CLIENT_COMMAND_OPEN_SESSION;
    command->server_address = server_address;

    {
        next_platform_mutex_guard( &client->internal->command_mutex );
        next_queue_push( client->internal->command_queue, command );
    }

    client->state = NEXT_CLIENT_STATE_OPEN;
    client->server_address = server_address;
    client->open_session_sequence++;
}

NEXT_BOOL next_client_is_session_open( next_client_t * client )
{
    next_client_verify_sentinels( client );

    return client->state == NEXT_CLIENT_STATE_OPEN;
}

int next_client_state( next_client_t * client )
{
    next_client_verify_sentinels( client );

    return client->state;
}

void next_client_close_session( next_client_t * client )
{
    next_client_verify_sentinels( client );

    next_assert( client->internal );

    next_client_command_close_session_t * command = (next_client_command_close_session_t*) next_malloc( client->context, sizeof( next_client_command_close_session_t ) );
    if ( !command )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client close session failed. could not create close session command" );
        client->state = NEXT_CLIENT_STATE_ERROR;
        return;
    }

    command->type = NEXT_CLIENT_COMMAND_CLOSE_SESSION;
    {
        next_platform_mutex_guard( &client->internal->command_mutex );
        next_queue_push( client->internal->command_queue, command );
    }

    client->ready = false;
    client->upgraded = false;
    client->fallback_to_direct = false;
    client->session_id = 0;
    memset( &client->client_stats, 0, sizeof(next_client_stats_t ) );
    memset( &client->server_address, 0, sizeof(next_address_t) );
    memset( &client->client_external_address, 0, sizeof(next_address_t) );
    next_bandwidth_limiter_reset( &client->direct_send_bandwidth );
    next_bandwidth_limiter_reset( &client->direct_receive_bandwidth );
    next_bandwidth_limiter_reset( &client->next_send_bandwidth );
    next_bandwidth_limiter_reset( &client->next_receive_bandwidth );
    client->state = NEXT_CLIENT_STATE_CLOSED;
    memset( client->current_magic, 0, sizeof(client->current_magic) );
}

void next_client_update( next_client_t * client )
{
    next_client_verify_sentinels( client );

    while ( true )
    {
        void * entry = NULL;
        {
            next_platform_mutex_guard( &client->internal->notify_mutex );
            entry = next_queue_pop( client->internal->notify_queue );
        }

        if ( entry == NULL )
            break;

        next_client_notify_t * notify = (next_client_notify_t*) entry;

        switch ( notify->type )
        {
            case NEXT_CLIENT_NOTIFY_PACKET_RECEIVED:
            {
                next_client_notify_packet_received_t * packet_received = (next_client_notify_packet_received_t*) notify;

                client->packet_received_callback( client, client->context, &client->server_address, packet_received->payload_data, packet_received->payload_bytes );

                const int wire_packet_bits = next_wire_packet_bits( packet_received->payload_bytes );

                next_bandwidth_limiter_add_packet( &client->direct_receive_bandwidth, next_time(), 0, wire_packet_bits );

                double direct_kbps_down = next_bandwidth_limiter_usage_kbps( &client->direct_receive_bandwidth, next_time() );

                next_platform_mutex_acquire( &client->internal->direct_bandwidth_mutex );
                client->internal->direct_bandwidth_usage_kbps_down = direct_kbps_down;
                next_platform_mutex_release( &client->internal->direct_bandwidth_mutex );

                if ( !packet_received->direct )
                {
                    next_platform_mutex_acquire( &client->internal->next_bandwidth_mutex );
                    const int envelope_kbps_down = client->internal->next_bandwidth_envelope_kbps_down;
                    next_platform_mutex_release( &client->internal->next_bandwidth_mutex );

                    next_bandwidth_limiter_add_packet( &client->next_receive_bandwidth, next_time(), envelope_kbps_down, wire_packet_bits );

                    double next_kbps_down = next_bandwidth_limiter_usage_kbps( &client->next_receive_bandwidth, next_time() );

                    next_platform_mutex_acquire( &client->internal->next_bandwidth_mutex );
                    client->internal->next_bandwidth_usage_kbps_down = next_kbps_down;
                    next_platform_mutex_release( &client->internal->next_bandwidth_mutex );
                }
            }
            break;

            case NEXT_CLIENT_NOTIFY_UPGRADED:
            {
                next_client_notify_upgraded_t * upgraded = (next_client_notify_upgraded_t*) notify;
                client->upgraded = true;
                client->session_id = upgraded->session_id;
                client->client_external_address = upgraded->client_external_address;
                memcpy( client->current_magic, upgraded->current_magic, 8 );
                next_printf( NEXT_LOG_LEVEL_INFO, "client upgraded to session %" PRIx64, client->session_id );
            }
            break;

            case NEXT_CLIENT_NOTIFY_STATS_UPDATED:
            {
                next_client_notify_stats_updated_t * stats_updated = (next_client_notify_stats_updated_t*) notify;
                client->client_stats = stats_updated->stats;
                client->fallback_to_direct = stats_updated->fallback_to_direct;
            }
            break;

            case NEXT_CLIENT_NOTIFY_MAGIC_UPDATED:
            {
                next_client_notify_magic_updated_t * magic_updated = (next_client_notify_magic_updated_t*) notify;
                memcpy( client->current_magic, magic_updated->current_magic, 8 );
            }
            break;

            case NEXT_CLIENT_NOTIFY_READY:
            {
                client->ready = true;
            }
            break;

            default: break;
        }

        next_free( client->context, entry );
    }
}

NEXT_BOOL next_client_ready( next_client_t * client )
{
    next_assert( client );
    return client->ready ? NEXT_TRUE : NEXT_FALSE;
}

NEXT_BOOL next_client_fallback_to_direct( struct next_client_t * client )
{
    next_assert( client );
    return client->client_stats.fallback_to_direct;
}

void next_client_send_packet( next_client_t * client, const uint8_t * packet_data, int packet_bytes )
{
    next_client_verify_sentinels( client );

    next_assert( client->internal );
    next_assert( client->internal->socket );
    next_assert( packet_bytes > 0 );

    if ( client->state != NEXT_CLIENT_STATE_OPEN )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "client can't send packet because no session is open" );
        return;
    }

    if ( packet_bytes > NEXT_MAX_PACKET_BYTES - 1 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client can't send packet because packet is too large" );
        return;
    }

    if ( next_global_config.disable_network_next || client->fallback_to_direct )
    {
        next_client_send_packet_direct( client, packet_data, packet_bytes );
        return;
    }

#if NEXT_DEVELOPMENT
    if ( next_packet_loss && ( rand() % 10 ) == 0 )
        return;
#endif // #if NEXT_DEVELOPMENT

    if ( client->upgraded && packet_bytes <= NEXT_MTU )
    {
        next_platform_mutex_acquire( &client->internal->route_manager_mutex );
        const uint64_t send_sequence = next_route_manager_next_send_sequence( client->internal->route_manager );
        bool send_over_network_next = next_route_manager_has_network_next_route( client->internal->route_manager );
        bool send_direct = !send_over_network_next;
        next_platform_mutex_release( &client->internal->route_manager_mutex );

        bool multipath = client->client_stats.multipath;

        if ( send_over_network_next && multipath )
        {
            send_direct = true;
        }

        // track direct send bandwidth

        const int wire_packet_bits = next_wire_packet_bits( packet_bytes );

        next_bandwidth_limiter_add_packet( &client->direct_send_bandwidth, next_time(), 0, wire_packet_bits );

        double direct_usage_kbps_up = next_bandwidth_limiter_usage_kbps( &client->direct_send_bandwidth, next_time() );

        next_platform_mutex_acquire( &client->internal->direct_bandwidth_mutex );
        client->internal->direct_bandwidth_usage_kbps_up = direct_usage_kbps_up;
        next_platform_mutex_release( &client->internal->direct_bandwidth_mutex );

        // track next send backend and don't send over network next if we're over the bandwidth budget

        if ( send_over_network_next )
        {
            next_platform_mutex_acquire( &client->internal->next_bandwidth_mutex );
            const int next_envelope_kbps_up = client->internal->next_bandwidth_envelope_kbps_up;
            next_platform_mutex_release( &client->internal->next_bandwidth_mutex );

            bool over_budget = next_bandwidth_limiter_add_packet( &client->next_send_bandwidth, next_time(), next_envelope_kbps_up, wire_packet_bits );

            double next_usage_kbps_up = next_bandwidth_limiter_usage_kbps( &client->next_send_bandwidth, next_time() );

            next_platform_mutex_acquire( &client->internal->next_bandwidth_mutex );
            client->internal->next_bandwidth_usage_kbps_up = next_usage_kbps_up;
            if ( over_budget )
                client->internal->next_bandwidth_over_limit = true;
            next_platform_mutex_release( &client->internal->next_bandwidth_mutex );

            if ( over_budget )
            {
                next_printf( NEXT_LOG_LEVEL_WARN, "client exceeded bandwidth budget (%d kbps)", next_envelope_kbps_up );
                send_over_network_next = false;
                send_direct = true;
            }
        }

        if ( send_over_network_next )
        {
            // send over network next

            int next_packet_bytes = 0;
            next_address_t next_to;
            uint8_t next_packet_data[NEXT_MAX_PACKET_BYTES];

            next_platform_mutex_acquire( &client->internal->route_manager_mutex );
            bool result = next_route_manager_prepare_send_packet( client->internal->route_manager, send_sequence, &next_to, packet_data, packet_bytes, next_packet_data, &next_packet_bytes, client->current_magic, &client->client_external_address );
            next_platform_mutex_release( &client->internal->route_manager_mutex );

            if ( result )
            {
                next_platform_socket_send_packet( client->internal->socket, &next_to, next_packet_data, next_packet_bytes );
                client->counters[NEXT_CLIENT_COUNTER_PACKET_SENT_NEXT]++;
            }
            else
            {
                // could not send over network next
                send_direct = true;
            }
        }

        if ( send_direct )
        {
            // send direct from client to server

            uint8_t from_address_data[32];
            uint8_t to_address_data[32];
            uint16_t from_address_port;
            uint16_t to_address_port;
            int from_address_bytes;
            int to_address_bytes;

            next_address_data( &client->client_external_address, from_address_data, &from_address_bytes, &from_address_port );
            next_address_data( &client->server_address, to_address_data, &to_address_bytes, &to_address_port );

            uint8_t direct_packet_data[NEXT_MAX_PACKET_BYTES];

            const int direct_packet_bytes = next_write_direct_packet( direct_packet_data, client->open_session_sequence, send_sequence, packet_data, packet_bytes, client->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port );

            next_assert( direct_packet_bytes >= 0 );

            next_assert( next_basic_packet_filter( direct_packet_data, direct_packet_bytes ) );
            next_assert( next_advanced_packet_filter( direct_packet_data, client->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, direct_packet_bytes ) );

            (void) direct_packet_data;
            (void) direct_packet_bytes;

            next_platform_socket_send_packet( client->internal->socket, &client->server_address, direct_packet_data, direct_packet_bytes );

            client->counters[NEXT_CLIENT_COUNTER_PACKET_SENT_DIRECT]++;
        }

        client->internal->packets_sent++;
    }
    else
    {
        // passthrough packet

        next_client_send_packet_direct( client, packet_data, packet_bytes );
    }
}

void next_client_send_packet_direct( next_client_t * client, const uint8_t * packet_data, int packet_bytes )
{
    next_client_verify_sentinels( client );

    next_assert( client->internal );
    next_assert( client->internal->socket );
    next_assert( packet_bytes > 0 );

    if ( client->state != NEXT_CLIENT_STATE_OPEN )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "client can't send packet because no session is open" );
        return;
    }

    if ( packet_bytes <= 0 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client can't send packet because packet size <= 0" );
        return;
    }

    if ( packet_bytes > NEXT_MAX_PACKET_BYTES - 1 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client can't send packet because packet is too large" );
        return;
    }

    uint8_t buffer[NEXT_MAX_PACKET_BYTES];
    buffer[0] = NEXT_PASSTHROUGH_PACKET;
    memcpy( buffer + 1, packet_data, packet_bytes );
    next_platform_socket_send_packet( client->internal->socket, &client->server_address, buffer, packet_bytes + 1 );
    client->counters[NEXT_CLIENT_COUNTER_PACKET_SENT_PASSTHROUGH]++;

    client->internal->packets_sent++;
}

void next_client_send_packet_raw( next_client_t * client, const next_address_t * to_address, const uint8_t * packet_data, int packet_bytes )
{
    next_client_verify_sentinels( client );

    next_assert( client->internal );
    next_assert( client->internal->socket );
    next_assert( to_address );
    next_assert( packet_bytes > 0 );

    next_platform_socket_send_packet( client->internal->socket, to_address, packet_data, packet_bytes );
}

void next_client_report_session( next_client_t * client )
{
    next_client_verify_sentinels( client );

    next_client_command_report_session_t * command = (next_client_command_report_session_t*) next_malloc( client->context, sizeof( next_client_command_report_session_t ) );

    if ( !command )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "report session failed. could not create report session command" );
        return;
    }

    command->type = NEXT_CLIENT_COMMAND_REPORT_SESSION;
    {
        next_platform_mutex_guard( &client->internal->command_mutex );
        next_queue_push( client->internal->command_queue, command );
    }
}

uint64_t next_client_session_id( next_client_t * client )
{
    next_client_verify_sentinels( client );

    return client->session_id;
}

const next_client_stats_t * next_client_stats( next_client_t * client )
{
    next_client_verify_sentinels( client );

    return &client->client_stats;
}

const next_address_t * next_client_server_address( next_client_t * client )
{
    next_assert( client );
    return &client->server_address;
}

void next_client_counters( next_client_t * client, uint64_t * counters )
{
    next_client_verify_sentinels( client );
    uint64_t internal_counters[NEXT_CLIENT_COUNTER_MAX];
    memcpy( counters, client->counters, sizeof(uint64_t) * NEXT_CLIENT_COUNTER_MAX );
    memcpy( internal_counters, client->internal->counters, sizeof(uint64_t) * NEXT_CLIENT_COUNTER_MAX );
    for ( int i = 0; i < NEXT_CLIENT_COUNTER_MAX; ++i )
        counters[i] += internal_counters[i];
}

// ---------------------------------------------------------------

int next_address_parse( next_address_t * address, const char * address_string_in )
{
    next_assert( address );
    next_assert( address_string_in );

    if ( !address )
        return NEXT_ERROR;

    if ( !address_string_in )
        return NEXT_ERROR;

    memset( address, 0, sizeof( next_address_t ) );

    // first try to parse the string as an IPv6 address:
    // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
    // 2. otherwise try to parse as an IPv6 address using inet_pton

    char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH + NEXT_ADDRESS_BUFFER_SAFETY*2];

    char * address_string = buffer + NEXT_ADDRESS_BUFFER_SAFETY;
    next_copy_string( address_string, address_string_in, NEXT_MAX_ADDRESS_STRING_LENGTH );

    int address_string_length = (int) strlen( address_string );

    if ( address_string[0] == '[' )
    {
        const int base_index = address_string_length - 1;

        // note: no need to search past 6 characters as ":65535" is longest possible port value
        for ( int i = 0; i < 6; ++i )
        {
            const int index = base_index - i;
            if ( index < 0 )
            {
                return NEXT_ERROR;
            }
            if ( address_string[index] == ':' )
            {
                address->port = (uint16_t) ( atoi( &address_string[index + 1] ) );
                address_string[index-1] = '\0';
                break;
            }
            else if ( address_string[index] == ']' )
            {
                // no port number
                address->port = 0;
                address_string[index] = '\0';
                break;
            }
        }
        address_string += 1;
    }

    uint16_t addr6[8];
    if ( next_platform_inet_pton6( address_string, addr6 ) == NEXT_OK )
    {
        address->type = NEXT_ADDRESS_IPV6;
        for ( int i = 0; i < 8; ++i )
        {
            address->data.ipv6[i] = next_ntohs( addr6[i] );
        }
        return NEXT_OK;
    }

    // otherwise it's probably an IPv4 address:
    // 1. look for ":portnum", if found save the portnum and strip it out
    // 2. parse remaining ipv4 address via inet_pton

    address_string_length = (int) strlen( address_string );
    const int base_index = address_string_length - 1;
    for ( int i = 0; i < 6; ++i )
    {
        const int index = base_index - i;
        if ( index < 0 )
            break;
        if ( address_string[index] == ':' )
        {
            address->port = (uint16_t)( atoi( &address_string[index + 1] ) );
            address_string[index] = '\0';
        }
    }

    uint32_t addr4;
    if ( next_platform_inet_pton4( address_string, &addr4 ) == NEXT_OK )
    {
        address->type = NEXT_ADDRESS_IPV4;
        address->data.ipv4[3] = (uint8_t) ( ( addr4 & 0xFF000000 ) >> 24 );
        address->data.ipv4[2] = (uint8_t) ( ( addr4 & 0x00FF0000 ) >> 16 );
        address->data.ipv4[1] = (uint8_t) ( ( addr4 & 0x0000FF00 ) >> 8  );
        address->data.ipv4[0] = (uint8_t) ( ( addr4 & 0x000000FF )     );
        return NEXT_OK;
    }

    return NEXT_ERROR;
}

const char * next_address_to_string( const next_address_t * address, char * buffer )
{
    next_assert( buffer );

    if ( address->type == NEXT_ADDRESS_IPV6 )
    {
#if defined(WINVER) && WINVER <= 0x0502
        // ipv6 not supported
        buffer[0] = '\0';
        return buffer;
#else
        uint16_t ipv6_network_order[8];
        for ( int i = 0; i < 8; ++i )
            ipv6_network_order[i] = next_htons( address->data.ipv6[i] );
        char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
        next_platform_inet_ntop6( ipv6_network_order, address_string, sizeof( address_string ) );
        if ( address->port == 0 )
        {
            next_copy_string( buffer, address_string, NEXT_MAX_ADDRESS_STRING_LENGTH );
            return buffer;
        }
        else
        {
            if ( snprintf( buffer, NEXT_MAX_ADDRESS_STRING_LENGTH, "[%s]:%hu", address_string, address->port ) < 0 )
            {
                next_printf( NEXT_LOG_LEVEL_ERROR, "address string truncated: [%s]:%hu", address_string, address->port );
            }
            return buffer;
        }
#endif
    }
    else if ( address->type == NEXT_ADDRESS_IPV4 )
    {
        if ( address->port != 0 )
        {
            snprintf( buffer,
                      NEXT_MAX_ADDRESS_STRING_LENGTH,
                      "%d.%d.%d.%d:%d",
                      address->data.ipv4[0],
                      address->data.ipv4[1],
                      address->data.ipv4[2],
                      address->data.ipv4[3],
                      address->port );
        }
        else
        {
            snprintf( buffer,
                      NEXT_MAX_ADDRESS_STRING_LENGTH,
                      "%d.%d.%d.%d",
                      address->data.ipv4[0],
                      address->data.ipv4[1],
                      address->data.ipv4[2],
                      address->data.ipv4[3] );
        }
        return buffer;
    }
    else
    {
        snprintf( buffer, NEXT_MAX_ADDRESS_STRING_LENGTH, "%s", "NONE" );
        return buffer;
    }
}

NEXT_BOOL next_address_equal( const next_address_t * a, const next_address_t * b )
{
    next_assert( a );
    next_assert( b );

    if ( a->type != b->type )
        return NEXT_FALSE;

    if ( a->type == NEXT_ADDRESS_IPV4 )
    {
        if ( a->port != b->port )
            return NEXT_FALSE;

        for ( int i = 0; i < 4; ++i )
        {
            if ( a->data.ipv4[i] != b->data.ipv4[i] )
                return NEXT_FALSE;
        }
    }
    else if ( a->type == NEXT_ADDRESS_IPV6 )
    {
        if ( a->port != b->port )
            return NEXT_FALSE;

        for ( int i = 0; i < 8; ++i )
        {
            if ( a->data.ipv6[i] != b->data.ipv6[i] )
                return NEXT_FALSE;
        }
    }

    return NEXT_TRUE;
}

void next_address_anonymize( next_address_t * address )
{
    next_assert( address );
    if ( address->type == NEXT_ADDRESS_IPV4 )
    {
        address->data.ipv4[3] = 0;
    }
    else
    {
        address->data.ipv6[4] = 0;
        address->data.ipv6[5] = 0;
        address->data.ipv6[6] = 0;
        address->data.ipv6[7] = 0;
    }
    address->port = 0;
}

// ---------------------------------------------------------------

struct next_pending_session_entry_t
{
    NEXT_DECLARE_SENTINEL(0)

    next_address_t address;
    uint64_t session_id;
    uint64_t user_hash;
    uint64_t tags[NEXT_MAX_TAGS];
    int num_tags;
    double upgrade_time;
    double last_packet_send_time;
    uint8_t private_key[NEXT_CRYPTO_SECRETBOX_KEYBYTES];
    uint8_t upgrade_token[NEXT_UPGRADE_TOKEN_BYTES];

    NEXT_DECLARE_SENTINEL(1)
};

void next_pending_session_entry_initialize_sentinels( next_pending_session_entry_t * entry )
{
    (void) entry;
    next_assert( entry );
    NEXT_INITIALIZE_SENTINEL( entry, 0 )
    NEXT_INITIALIZE_SENTINEL( entry, 1 )
}

void next_pending_session_entry_verify_sentinels( next_pending_session_entry_t * entry )
{
    (void) entry;
    next_assert( entry );
    NEXT_VERIFY_SENTINEL( entry, 0 )
    NEXT_VERIFY_SENTINEL( entry, 1 )
}

struct next_pending_session_manager_t
{
    NEXT_DECLARE_SENTINEL(0)

    void * context;
    int size;
    int max_entry_index;
    next_address_t * addresses;
    next_pending_session_entry_t * entries;

    NEXT_DECLARE_SENTINEL(1)
};

void next_pending_session_manager_initialize_sentinels( next_pending_session_manager_t * session_manager )
{
    (void) session_manager;
    next_assert( session_manager );
    NEXT_INITIALIZE_SENTINEL( session_manager, 0 )
    NEXT_INITIALIZE_SENTINEL( session_manager, 1 )
}

void next_pending_session_manager_verify_sentinels( next_pending_session_manager_t * session_manager )
{
    (void) session_manager;
#if NEXT_ENABLE_MEMORY_CHECKS
    next_assert( session_manager );
    NEXT_VERIFY_SENTINEL( session_manager, 0 )
    NEXT_VERIFY_SENTINEL( session_manager, 1 )
    const int size = session_manager->size;
    for ( int i = 0; i < size; ++i )
    {
        if ( session_manager->addresses[i].type != 0 )
        {
            next_pending_session_entry_verify_sentinels( &session_manager->entries[i] );
        }
    }
#endif // #if NEXT_ENABLE_MEMORY_CHECKS
}

void next_pending_session_manager_destroy( next_pending_session_manager_t * pending_session_manager );

next_pending_session_manager_t * next_pending_session_manager_create( void * context, int initial_size )
{
    next_pending_session_manager_t * pending_session_manager = (next_pending_session_manager_t*) next_malloc( context, sizeof(next_pending_session_manager_t) );

    next_assert( pending_session_manager );
    if ( !pending_session_manager )
        return NULL;

    memset( pending_session_manager, 0, sizeof(next_pending_session_manager_t) );

    next_pending_session_manager_initialize_sentinels( pending_session_manager );

    pending_session_manager->context = context;
    pending_session_manager->size = initial_size;
    pending_session_manager->addresses = (next_address_t*) next_malloc( context, initial_size * sizeof(next_address_t) );
    pending_session_manager->entries = (next_pending_session_entry_t*) next_malloc( context, initial_size * sizeof(next_pending_session_entry_t) );

    next_assert( pending_session_manager->addresses );
    next_assert( pending_session_manager->entries );

    if ( pending_session_manager->addresses == NULL || pending_session_manager->entries == NULL )
    {
        next_pending_session_manager_destroy( pending_session_manager );
        return NULL;
    }

    memset( pending_session_manager->addresses, 0, initial_size * sizeof(next_address_t) );
    memset( pending_session_manager->entries, 0, initial_size * sizeof(next_pending_session_entry_t) );

    for ( int i = 0; i < initial_size; i++ )
        next_pending_session_entry_initialize_sentinels( &pending_session_manager->entries[i] );

    next_pending_session_manager_verify_sentinels( pending_session_manager );

    return pending_session_manager;
}

void next_pending_session_manager_destroy( next_pending_session_manager_t * pending_session_manager )
{
    next_pending_session_manager_verify_sentinels( pending_session_manager );

    next_free( pending_session_manager->context, pending_session_manager->addresses );
    next_free( pending_session_manager->context, pending_session_manager->entries );

    clear_and_free( pending_session_manager->context, pending_session_manager, sizeof(next_pending_session_manager_t) );
}

bool next_pending_session_manager_expand( next_pending_session_manager_t * pending_session_manager )
{
    next_pending_session_manager_verify_sentinels( pending_session_manager );

    int new_size = pending_session_manager->size * 2;

    next_address_t * new_addresses = (next_address_t*) next_malloc( pending_session_manager->context, new_size * sizeof(next_address_t) );

    next_pending_session_entry_t * new_entries = (next_pending_session_entry_t*) next_malloc( pending_session_manager->context, new_size * sizeof(next_pending_session_entry_t) );

    next_assert( pending_session_manager->addresses );
    next_assert( pending_session_manager->entries );

    if ( pending_session_manager->addresses == NULL || pending_session_manager->entries == NULL )
    {
        next_free( pending_session_manager->context, new_addresses );
        next_free( pending_session_manager->context, new_entries );
        return false;
    }

    memset( new_addresses, 0, new_size * sizeof(next_address_t) );
    memset( new_entries, 0, new_size * sizeof(next_pending_session_entry_t) );

    for ( int i = 0; i < new_size; ++i )
        next_pending_session_entry_initialize_sentinels( &new_entries[i] );

    int index = 0;
    const int current_size = pending_session_manager->size;
    for ( int i = 0; i < current_size; ++i )
    {
        if ( pending_session_manager->addresses[i].type != NEXT_ADDRESS_NONE )
        {
            memcpy( &new_addresses[index], &pending_session_manager->addresses[i], sizeof(next_address_t) );
            memcpy( &new_entries[index], &pending_session_manager->entries[i], sizeof(next_pending_session_entry_t) );
            index++;
        }
    }

    next_free( pending_session_manager->context, pending_session_manager->addresses );
    next_free( pending_session_manager->context, pending_session_manager->entries );

    pending_session_manager->addresses = new_addresses;
    pending_session_manager->entries = new_entries;
    pending_session_manager->size = new_size;
    pending_session_manager->max_entry_index = index - 1;

    next_pending_session_manager_verify_sentinels( pending_session_manager );

    return true;
}

next_pending_session_entry_t * next_pending_session_manager_add( next_pending_session_manager_t * pending_session_manager, const next_address_t * address, uint64_t session_id, const uint8_t * private_key, const uint8_t * upgrade_token, double current_time )
{
    next_pending_session_manager_verify_sentinels( pending_session_manager );

    next_assert( session_id != 0 );
    next_assert( address );
    next_assert( address->type != NEXT_ADDRESS_NONE );

    // first scan existing entries and see if we can insert there

    const int size = pending_session_manager->size;

    for ( int i = 0; i < size; ++i )
    {
        if ( pending_session_manager->addresses[i].type == NEXT_ADDRESS_NONE )
        {
            pending_session_manager->addresses[i] = *address;
            next_pending_session_entry_t * entry = &pending_session_manager->entries[i];
            entry->address = *address;
            entry->session_id = session_id;
            entry->upgrade_time = current_time;
            entry->last_packet_send_time = -1000.0;
            memcpy( entry->private_key, private_key, NEXT_CRYPTO_SECRETBOX_KEYBYTES );
            memcpy( entry->upgrade_token, upgrade_token, NEXT_UPGRADE_TOKEN_BYTES );
            if ( i > pending_session_manager->max_entry_index )
            {
                pending_session_manager->max_entry_index = i;
            }
            return entry;
        }
    }

    // ok, we need to grow, expand and add at the end (expand compacts existing entries)

    if ( !next_pending_session_manager_expand( pending_session_manager ) )
        return NULL;

    const int i = ++pending_session_manager->max_entry_index;
    pending_session_manager->addresses[i] = *address;
    next_pending_session_entry_t * entry = &pending_session_manager->entries[i];
    entry->address = *address;
    entry->session_id = session_id;
    entry->upgrade_time = current_time;
    entry->last_packet_send_time = -1000.0;
    memcpy( entry->private_key, private_key, NEXT_CRYPTO_SECRETBOX_KEYBYTES );
    memcpy( entry->upgrade_token, upgrade_token, NEXT_UPGRADE_TOKEN_BYTES );

    next_pending_session_manager_verify_sentinels( pending_session_manager );

    return entry;
}

void next_pending_session_manager_remove_at_index( next_pending_session_manager_t * pending_session_manager, int index )
{
    next_pending_session_manager_verify_sentinels( pending_session_manager );

    next_assert( index >= 0 );
    next_assert( index <= pending_session_manager->max_entry_index );

    const int max_index = pending_session_manager->max_entry_index;

    pending_session_manager->addresses[index].type = NEXT_ADDRESS_NONE;

    if ( index == max_index )
    {
        while ( index > 0 && pending_session_manager->addresses[index].type == NEXT_ADDRESS_NONE )
        {
            index--;
        }
        pending_session_manager->max_entry_index = index;
    }
}

void next_pending_session_manager_remove_by_address( next_pending_session_manager_t * pending_session_manager, const next_address_t * address )
{
    next_pending_session_manager_verify_sentinels( pending_session_manager );

    next_assert( address );

    const int max_index = pending_session_manager->max_entry_index;

    for ( int i = 0; i <= max_index; ++i )
    {
        if ( next_address_equal( address, &pending_session_manager->addresses[i] ) == 1 )
        {
            next_pending_session_manager_remove_at_index( pending_session_manager, i );
            return;
        }
    }
}

next_pending_session_entry_t * next_pending_session_manager_find( next_pending_session_manager_t * pending_session_manager, const next_address_t * address )
{
    next_pending_session_manager_verify_sentinels( pending_session_manager );

    next_assert( address );

    const int max_index = pending_session_manager->max_entry_index;

    for ( int i = 0; i <= max_index; ++i )
    {
        if ( next_address_equal( address, &pending_session_manager->addresses[i] ) == 1 )
        {
            return &pending_session_manager->entries[i];
        }
    }

    return NULL;
}

int next_pending_session_manager_num_entries( next_pending_session_manager_t * pending_session_manager )
{
    next_pending_session_manager_verify_sentinels( pending_session_manager );

    int num_entries = 0;

    const int max_index = pending_session_manager->max_entry_index;

    for ( int i = 0; i <= max_index; ++i )
    {
        if ( pending_session_manager->addresses[i].type != 0 )
        {
            num_entries++;
        }
    }

    return num_entries;
}

// ---------------------------------------------------------------

struct next_proxy_session_entry_t
{
    NEXT_DECLARE_SENTINEL(0)

    next_address_t address;
    uint64_t session_id;

    NEXT_DECLARE_SENTINEL(1)

    next_bandwidth_limiter_t send_bandwidth;

    NEXT_DECLARE_SENTINEL(2)
};

void next_proxy_session_entry_initialize_sentinels( next_proxy_session_entry_t * entry )
{
    (void) entry;
    next_assert( entry );
    NEXT_INITIALIZE_SENTINEL( entry, 0 )
    NEXT_INITIALIZE_SENTINEL( entry, 1 )
    NEXT_INITIALIZE_SENTINEL( entry, 2 )
}

void next_proxy_session_entry_verify_sentinels( next_proxy_session_entry_t * entry )
{
    (void) entry;
    next_assert( entry );
    NEXT_VERIFY_SENTINEL( entry, 0 )
    NEXT_VERIFY_SENTINEL( entry, 1 )
    NEXT_VERIFY_SENTINEL( entry, 2 )
}

struct next_proxy_session_manager_t
{
    NEXT_DECLARE_SENTINEL(0)

    void * context;
    int size;
    int max_entry_index;
    next_address_t * addresses;
    next_proxy_session_entry_t * entries;

    NEXT_DECLARE_SENTINEL(1)
};

void next_proxy_session_manager_initialize_sentinels( next_proxy_session_manager_t * session_manager )
{
    (void) session_manager;
    next_assert( session_manager );
    NEXT_INITIALIZE_SENTINEL( session_manager, 0 )
    NEXT_INITIALIZE_SENTINEL( session_manager, 1 )
}

void next_proxy_session_manager_verify_sentinels( next_proxy_session_manager_t * session_manager )
{
    (void) session_manager;
#if NEXT_ENABLE_MEMORY_CHECKS
    next_assert( session_manager );
    NEXT_VERIFY_SENTINEL( session_manager, 0 )
    NEXT_VERIFY_SENTINEL( session_manager, 1 )
    const int size = session_manager->size;
    for ( int i = 0; i < size; ++i )
    {
        if ( session_manager->addresses[i].type != 0 )
        {
            next_proxy_session_entry_verify_sentinels( &session_manager->entries[i] );
        }
    }
#endif // #if NEXT_ENABLE_MEMORY_CHECKS
}

void next_proxy_session_manager_destroy( next_proxy_session_manager_t * session_manager );

next_proxy_session_manager_t * next_proxy_session_manager_create( void * context, int initial_size )
{
    next_proxy_session_manager_t * session_manager = (next_proxy_session_manager_t*) next_malloc( context, sizeof(next_proxy_session_manager_t) );

    next_assert( session_manager );

    if ( !session_manager )
        return NULL;

    memset( session_manager, 0, sizeof(next_proxy_session_manager_t) );

    next_proxy_session_manager_initialize_sentinels( session_manager );

    session_manager->context = context;
    session_manager->size = initial_size;
    session_manager->addresses = (next_address_t*) next_malloc( context, initial_size * sizeof(next_address_t) );
    session_manager->entries = (next_proxy_session_entry_t*) next_malloc( context, initial_size * sizeof(next_proxy_session_entry_t) );

    next_assert( session_manager->addresses );
    next_assert( session_manager->entries );

    if ( session_manager->addresses == NULL || session_manager->entries == NULL )
    {
        next_proxy_session_manager_destroy( session_manager );
        return NULL;
    }

    memset( session_manager->addresses, 0, initial_size * sizeof(next_address_t) );
    memset( session_manager->entries, 0, initial_size * sizeof(next_proxy_session_entry_t) );

    for ( int i = 0; i < initial_size; ++i )
        next_proxy_session_entry_initialize_sentinels( &session_manager->entries[i] );

    next_proxy_session_manager_verify_sentinels( session_manager );

    return session_manager;
}

void next_proxy_session_manager_destroy( next_proxy_session_manager_t * session_manager )
{
    next_proxy_session_manager_verify_sentinels( session_manager );

    next_free( session_manager->context, session_manager->addresses );
    next_free( session_manager->context, session_manager->entries );

    clear_and_free( session_manager->context, session_manager, sizeof(next_proxy_session_manager_t) );
}

bool next_proxy_session_manager_expand( next_proxy_session_manager_t * session_manager )
{
    next_proxy_session_manager_verify_sentinels( session_manager );

    int new_size = session_manager->size * 2;
    next_address_t * new_addresses = (next_address_t*) next_malloc( session_manager->context, new_size * sizeof(next_address_t) );
    next_proxy_session_entry_t * new_entries = (next_proxy_session_entry_t*) next_malloc( session_manager->context, new_size * sizeof(next_proxy_session_entry_t) );

    next_assert( session_manager->addresses );
    next_assert( session_manager->entries );

    if ( session_manager->addresses == NULL || session_manager->entries == NULL )
    {
        next_free( session_manager->context, new_addresses );
        next_free( session_manager->context, new_entries );
        return false;
    }

    memset( new_addresses, 0, new_size * sizeof(next_address_t) );
    memset( new_entries, 0, new_size * sizeof(next_proxy_session_entry_t) );

    for ( int i = 0; i < new_size; ++i )
        next_proxy_session_entry_initialize_sentinels( &new_entries[i] );

    int index = 0;
    const int current_size = session_manager->size;
    for ( int i = 0; i < current_size; ++i )
    {
        if ( session_manager->addresses[i].type != NEXT_ADDRESS_NONE )
        {
            memcpy( &new_addresses[index], &session_manager->addresses[i], sizeof(next_address_t) );
            memcpy( &new_entries[index], &session_manager->entries[i], sizeof(next_proxy_session_entry_t) );
            index++;
        }
    }

    next_free( session_manager->context, session_manager->addresses );
    next_free( session_manager->context, session_manager->entries );

    session_manager->addresses = new_addresses;
    session_manager->entries = new_entries;
    session_manager->size = new_size;
    session_manager->max_entry_index = index - 1;

    next_proxy_session_manager_verify_sentinels( session_manager );

    return true;
}

next_proxy_session_entry_t * next_proxy_session_manager_add( next_proxy_session_manager_t * session_manager, const next_address_t * address, uint64_t session_id )
{
    next_proxy_session_manager_verify_sentinels( session_manager );

    next_assert( session_id != 0 );
    next_assert( address );
    next_assert( address->type != NEXT_ADDRESS_NONE );

    // first scan existing entries and see if we can insert there

    const int size = session_manager->size;

    for ( int i = 0; i < size; ++i )
    {
        if ( session_manager->addresses[i].type == NEXT_ADDRESS_NONE )
        {
            session_manager->addresses[i] = *address;
            next_proxy_session_entry_t * entry = &session_manager->entries[i];
            entry->address = *address;
            entry->session_id = session_id;
            next_bandwidth_limiter_reset( &entry->send_bandwidth );
            if ( i > session_manager->max_entry_index )
            {
                session_manager->max_entry_index = i;
            }
            return entry;
        }
    }

    // ok, we need to grow, expand and add at the end (expand compacts existing entries)

    if ( !next_proxy_session_manager_expand( session_manager ) )
        return NULL;

    const int i = ++session_manager->max_entry_index;
    session_manager->addresses[i] = *address;
    next_proxy_session_entry_t * entry = &session_manager->entries[i];
    entry->address = *address;
    entry->session_id = session_id;
    next_bandwidth_limiter_reset( &entry->send_bandwidth );

    next_proxy_session_manager_verify_sentinels( session_manager );

    return entry;
}

void next_proxy_session_manager_remove_at_index( next_proxy_session_manager_t * session_manager, int index )
{
    next_proxy_session_manager_verify_sentinels( session_manager );

    next_assert( index >= 0 );
    next_assert( index <= session_manager->max_entry_index );
    const int max_index = session_manager->max_entry_index;
    session_manager->addresses[index].type = NEXT_ADDRESS_NONE;
    if ( index == max_index )
    {
        while ( index > 0 && session_manager->addresses[index].type == NEXT_ADDRESS_NONE )
        {
            index--;
        }
        session_manager->max_entry_index = index;
    }

    next_proxy_session_manager_verify_sentinels( session_manager );
}

void next_proxy_session_manager_remove_by_address( next_proxy_session_manager_t * session_manager, const next_address_t * address )
{
    next_proxy_session_manager_verify_sentinels( session_manager );

    next_assert( address );

    const int max_index = session_manager->max_entry_index;
    for ( int i = 0; i <= max_index; ++i )
    {
        if ( next_address_equal( address, &session_manager->addresses[i] ) == 1 )
        {
            next_proxy_session_manager_remove_at_index( session_manager, i );
            next_proxy_session_manager_verify_sentinels( session_manager );
            return;
        }
    }
}

next_proxy_session_entry_t * next_proxy_session_manager_find( next_proxy_session_manager_t * session_manager, const next_address_t * address )
{
    next_proxy_session_manager_verify_sentinels( session_manager );

    next_assert( address );

    const int max_index = session_manager->max_entry_index;
    for ( int i = 0; i <= max_index; ++i )
    {
        if ( next_address_equal( address, &session_manager->addresses[i] ) == 1 )
        {
            return &session_manager->entries[i];
        }
    }

    return NULL;
}

int next_proxy_session_manager_num_entries( next_proxy_session_manager_t * session_manager )
{
    next_proxy_session_manager_verify_sentinels( session_manager );

    int num_entries = 0;

    const int max_index = session_manager->max_entry_index;
    for ( int i = 0; i <= max_index; ++i )
    {
        if ( session_manager->addresses[i].type != 0 )
        {
            num_entries++;
        }
    }

    return num_entries;
}

// ---------------------------------------------------------------

struct NextBackendServerInitRequestPacket
{
    int version_major;
    int version_minor;
    int version_patch;
    uint64_t customer_id;
    uint64_t request_id;
    uint64_t datacenter_id;
    char datacenter_name[NEXT_MAX_DATACENTER_NAME_LENGTH];

    NextBackendServerInitRequestPacket()
    {
        version_major = NEXT_VERSION_MAJOR_INT;
        version_minor = NEXT_VERSION_MINOR_INT;
        version_patch = NEXT_VERSION_PATCH_INT;
        customer_id = 0;
        request_id = 0;
        datacenter_id = 0;
        datacenter_name[0] = '\0';
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_bits( stream, version_major, 8 );
        serialize_bits( stream, version_minor, 8 );
        serialize_bits( stream, version_patch, 8 );
        serialize_uint64( stream, customer_id );
        serialize_uint64( stream, request_id );
        serialize_uint64( stream, datacenter_id );
        serialize_string( stream, datacenter_name, NEXT_MAX_DATACENTER_NAME_LENGTH );
        return true;
    }
};

// ---------------------------------------------------------------

struct NextBackendServerInitResponsePacket
{
    uint64_t request_id;
    uint32_t response;
    uint8_t upcoming_magic[8];
    uint8_t current_magic[8];
    uint8_t previous_magic[8];

    NextBackendServerInitResponsePacket()
    {
        memset( this, 0, sizeof(NextBackendServerInitResponsePacket) );
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_uint64( stream, request_id );
        serialize_bits( stream, response, 8 );
        serialize_bytes( stream, upcoming_magic, 8 );
        serialize_bytes( stream, current_magic, 8 );
        serialize_bytes( stream, previous_magic, 8 );
        return true;
    }
};

// ---------------------------------------------------------------

struct NextBackendServerUpdateRequestPacket
{
    int version_major;
    int version_minor;
    int version_patch;
    uint64_t customer_id;
    uint64_t request_id;
    uint64_t datacenter_id;
    uint32_t num_sessions;
    next_address_t server_address;

    NextBackendServerUpdateRequestPacket()
    {
        version_major = NEXT_VERSION_MAJOR_INT;
        version_minor = NEXT_VERSION_MINOR_INT;
        version_patch = NEXT_VERSION_PATCH_INT;
        customer_id = 0;
        request_id = 0;
        datacenter_id = 0;
        num_sessions = 0;
        memset( &server_address, 0, sizeof(next_address_t) );
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_bits( stream, version_major, 8 );
        serialize_bits( stream, version_minor, 8 );
        serialize_bits( stream, version_patch, 8 );
        serialize_uint64( stream, customer_id );
        serialize_uint64( stream, request_id );
        serialize_uint64( stream, datacenter_id );
        serialize_uint32( stream, num_sessions );
        serialize_address( stream, server_address );
        return true;
    }
};

// ---------------------------------------------------------------

struct NextBackendServerUpdateResponsePacket
{
    uint64_t request_id;
    uint8_t upcoming_magic[8];
    uint8_t current_magic[8];
    uint8_t previous_magic[8];

    NextBackendServerUpdateResponsePacket()
    {
        memset( this, 0, sizeof(NextBackendServerUpdateResponsePacket) );
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_uint64( stream, request_id );
        serialize_bytes( stream, upcoming_magic, 8 );
        serialize_bytes( stream, current_magic, 8 );
        serialize_bytes( stream, previous_magic, 8 );
        return true;
    }
};

// ---------------------------------------------------------------

struct NextBackendSessionUpdateRequestPacket
{
    int version_major;
    int version_minor;
    int version_patch;
    uint64_t customer_id;
    uint64_t datacenter_id;
    uint64_t session_id;
    uint32_t slice_number;
    uint32_t retry_number;
    int session_data_bytes;
    uint8_t session_data[NEXT_MAX_SESSION_DATA_BYTES];
    uint8_t session_data_signature[NEXT_CRYPTO_SIGN_BYTES];
    next_address_t client_address;
    next_address_t server_address;
    uint8_t client_route_public_key[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    uint8_t server_route_public_key[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    uint64_t user_hash;
    int platform_id;
    int connection_type;
    bool next;
    bool reported;
    bool fallback_to_direct;
    bool client_bandwidth_over_limit;
    bool server_bandwidth_over_limit;
    bool client_ping_timed_out;
    bool has_near_relay_pings;
    int num_tags;
    uint64_t tags[NEXT_MAX_TAGS];
    uint64_t server_events;
    float direct_rtt;
    float direct_jitter;
    float direct_packet_loss;
    float direct_max_packet_loss_seen;
    float next_rtt;
    float next_jitter;
    float next_packet_loss;
    int num_near_relays;
    uint64_t near_relay_ids[NEXT_MAX_NEAR_RELAYS];
    uint8_t near_relay_rtt[NEXT_MAX_NEAR_RELAYS];
    uint8_t near_relay_jitter[NEXT_MAX_NEAR_RELAYS];
    float near_relay_packet_loss[NEXT_MAX_NEAR_RELAYS];
    uint32_t direct_kbps_up;
    uint32_t direct_kbps_down;
    uint32_t next_kbps_up;
    uint32_t next_kbps_down;
    uint64_t packets_sent_client_to_server;
    uint64_t packets_sent_server_to_client;
    uint64_t packets_lost_client_to_server;
    uint64_t packets_lost_server_to_client;
    uint64_t packets_out_of_order_client_to_server;
    uint64_t packets_out_of_order_server_to_client;
    float jitter_client_to_server;
    float jitter_server_to_client;

    void Reset()
    {
        memset( this, 0, sizeof(NextBackendSessionUpdateRequestPacket) );
        version_major = NEXT_VERSION_MAJOR_INT;
        version_minor = NEXT_VERSION_MINOR_INT;
        version_patch = NEXT_VERSION_PATCH_INT;
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_bits( stream, version_major, 8 );
        serialize_bits( stream, version_minor, 8 );
        serialize_bits( stream, version_patch, 8 );

        serialize_uint64( stream, customer_id );
        serialize_uint64( stream, datacenter_id );
        serialize_uint64( stream, session_id );

        serialize_uint32( stream, slice_number );

        serialize_int( stream, retry_number, 0, NEXT_MAX_SESSION_UPDATE_RETRIES );

        serialize_int( stream, session_data_bytes, 0, NEXT_MAX_SESSION_DATA_BYTES );
        if ( session_data_bytes > 0 )
        {
            serialize_bytes( stream, session_data, session_data_bytes );
            serialize_bytes( stream, session_data_signature, NEXT_CRYPTO_SIGN_BYTES );
        }

        // IMPORTANT: Anonymize the client address before sending it up to our backend
        // This ensures that we are fully compliant with the GDPR and there is zero risk
        // the address will be accidentally stored or intecepted in transit
        if ( Stream::IsWriting )
        {
            next_address_anonymize( &client_address );
        }

        serialize_address( stream, client_address );

        serialize_address( stream, server_address );

        serialize_bytes( stream, client_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES );
        serialize_bytes( stream, server_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES );

        serialize_uint64( stream, user_hash );

        serialize_int( stream, platform_id, NEXT_PLATFORM_UNKNOWN, NEXT_PLATFORM_MAX );

        serialize_int( stream, connection_type, NEXT_CONNECTION_TYPE_UNKNOWN, NEXT_CONNECTION_TYPE_MAX );

        serialize_bool( stream, next );
        serialize_bool( stream, reported );
        serialize_bool( stream, fallback_to_direct );
        serialize_bool( stream, client_bandwidth_over_limit );
        serialize_bool( stream, server_bandwidth_over_limit );
        serialize_bool( stream, client_ping_timed_out );
        serialize_bool( stream, has_near_relay_pings );

        bool has_tags = Stream::IsWriting && slice_number == 0 && num_tags > 0;
        bool has_server_events = Stream::IsWriting && server_events != 0;
        bool has_lost_packets = Stream::IsWriting && ( packets_lost_client_to_server + packets_lost_server_to_client ) > 0;
        bool has_out_of_order_packets = Stream::IsWriting && ( packets_out_of_order_client_to_server + packets_out_of_order_server_to_client ) > 0;

        serialize_bool( stream, has_tags );
        serialize_bool( stream, has_server_events );
        serialize_bool( stream, has_lost_packets );
        serialize_bool( stream, has_out_of_order_packets );

        if ( has_tags )
        {
            serialize_int( stream, num_tags, 0, NEXT_MAX_TAGS );
            for ( int i = 0; i < num_tags; ++i )
            {
                serialize_uint64( stream, tags[i] );
            }
        }

        if ( has_server_events )
        {
            serialize_uint64( stream, server_events );
        }

        serialize_float( stream, direct_rtt );
        serialize_float( stream, direct_jitter );
        serialize_float( stream, direct_packet_loss );
        serialize_float( stream, direct_max_packet_loss_seen );

        if ( next )
        {
            serialize_float( stream, next_rtt );
            serialize_float( stream, next_jitter );
            serialize_float( stream, next_packet_loss );
        }

        if ( has_near_relay_pings )
        {
            serialize_int( stream, num_near_relays, 0, NEXT_MAX_NEAR_RELAYS );

            for ( int i = 0; i < num_near_relays; ++i )
            {
                serialize_uint64( stream, near_relay_ids[i] );
                if ( has_near_relay_pings )
                {
                    serialize_int( stream, near_relay_rtt[i], 0, 255 );
                    serialize_int( stream, near_relay_jitter[i], 0, 255 );
                    serialize_float( stream, near_relay_packet_loss[i] );
                }
            }
        }

        serialize_uint32( stream, direct_kbps_up );
        serialize_uint32( stream, direct_kbps_down );

        if ( next )
        {
            serialize_uint32( stream, next_kbps_up );
            serialize_uint32( stream, next_kbps_down );
        }

        serialize_uint64( stream, packets_sent_client_to_server );
        serialize_uint64( stream, packets_sent_server_to_client );

        if ( has_lost_packets )
        {
            serialize_uint64( stream, packets_lost_client_to_server );
            serialize_uint64( stream, packets_lost_server_to_client );
        }

        if ( has_out_of_order_packets )
        {
            serialize_uint64( stream, packets_out_of_order_client_to_server );
            serialize_uint64( stream, packets_out_of_order_server_to_client );
        }

        serialize_float( stream, jitter_client_to_server );
        serialize_float( stream, jitter_server_to_client );

        return true;
    }
};

// ---------------------------------------------------------------

struct NextBackendMatchDataRequestPacket
{
    int version_major;
    int version_minor;
    int version_patch;
    uint64_t customer_id;
    next_address_t server_address;
    uint64_t datacenter_id;
    uint64_t user_hash;
    uint64_t session_id;
    uint32_t retry_number;
    uint64_t match_id;
    int num_match_values;
    double match_values[NEXT_MAX_MATCH_VALUES];

    void Reset()
    {
        memset( this, 0, sizeof(NextBackendMatchDataRequestPacket) );
        version_major = NEXT_VERSION_MAJOR_INT;
        version_minor = NEXT_VERSION_MINOR_INT;
        version_patch = NEXT_VERSION_PATCH_INT;
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_bits( stream, version_major, 8 );
        serialize_bits( stream, version_minor, 8 );
        serialize_bits( stream, version_patch, 8 );
        serialize_uint64( stream, customer_id );
        serialize_address( stream, server_address );
        serialize_uint64( stream, datacenter_id );
        serialize_uint64( stream, user_hash );
        serialize_uint64( stream, session_id );
        serialize_uint32( stream, retry_number );
        serialize_uint64( stream, match_id );

        bool has_match_values = Stream::IsWriting && num_match_values > 0;

        serialize_bool( stream, has_match_values );

        if ( has_match_values )
        {
            serialize_int( stream, num_match_values, 0, NEXT_MAX_MATCH_VALUES );
            for ( int i = 0; i < num_match_values; ++i )
            {
                serialize_double( stream, match_values[i] );
            }
        }

        return true;
    }
};

// ---------------------------------------------------------------

struct NextBackendMatchDataResponsePacket
{
    uint64_t session_id;

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_uint64( stream, session_id );
        return true;
    }
};

// ---------------------------------------------------------------

struct next_session_entry_t
{
    NEXT_DECLARE_SENTINEL(0)

    next_address_t address;
    uint64_t session_id;
    uint8_t most_recent_session_version;
    uint64_t special_send_sequence;
    uint64_t internal_send_sequence;
    uint64_t stats_sequence;
    uint64_t user_hash;
    uint64_t tags[NEXT_MAX_TAGS];
    int num_tags;
    uint64_t previous_server_events;
    uint64_t current_server_events;
    uint8_t client_open_session_sequence;

    NEXT_DECLARE_SENTINEL(1)

    bool stats_reported;
    bool stats_multipath;
    bool stats_fallback_to_direct;
    bool stats_client_bandwidth_over_limit;
    bool stats_server_bandwidth_over_limit;
    bool stats_has_near_relay_pings;
    int stats_platform_id;
    int stats_connection_type;
    float stats_direct_kbps_up;
    float stats_direct_kbps_down;
    float stats_next_kbps_up;
    float stats_next_kbps_down;
    float stats_direct_rtt;
    float stats_direct_jitter;
    float stats_direct_packet_loss;
    float stats_direct_max_packet_loss_seen;
    bool stats_next;
    float stats_next_rtt;
    float stats_next_jitter;
    float stats_next_packet_loss;
    int stats_num_near_relays;

    NEXT_DECLARE_SENTINEL(2)

    uint64_t stats_near_relay_ids[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(3)

    uint8_t stats_near_relay_rtt[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(4)

    uint8_t stats_near_relay_jitter[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(5)

    float stats_near_relay_packet_loss[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(6)

    uint64_t stats_packets_sent_client_to_server;
    uint64_t stats_packets_sent_server_to_client;
    uint64_t stats_packets_lost_client_to_server;
    uint64_t stats_packets_lost_server_to_client;
    uint64_t stats_packets_out_of_order_client_to_server;
    uint64_t stats_packets_out_of_order_server_to_client;

    float stats_jitter_client_to_server;
    float stats_jitter_server_to_client;

    double next_tracker_update_time;
    double next_session_update_time;
    double next_session_resend_time;
    double last_client_stats_update;
    double last_upgraded_packet_receive_time;

    uint64_t update_sequence;
    bool update_dirty;
    bool waiting_for_update_response;
    bool multipath;
    double update_last_send_time;
    uint8_t update_type;
    int update_num_tokens;
    bool session_update_timed_out;

    NEXT_DECLARE_SENTINEL(7)

    uint8_t update_tokens[NEXT_MAX_TOKENS*NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES];

    NEXT_DECLARE_SENTINEL(8)

    bool update_has_near_relays;
    int update_num_near_relays;

    NEXT_DECLARE_SENTINEL(9)

    uint64_t update_near_relay_ids[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(10)

    next_address_t update_near_relay_addresses[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(11)

    NextBackendSessionUpdateRequestPacket session_update_request_packet;

    NEXT_DECLARE_SENTINEL(12)

    bool has_pending_route;
    uint8_t pending_route_session_version;
    uint64_t pending_route_expire_timestamp;
    double pending_route_expire_time;
    int pending_route_kbps_up;
    int pending_route_kbps_down;
    next_address_t pending_route_send_address;

    NEXT_DECLARE_SENTINEL(13)

    uint8_t pending_route_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];

    NEXT_DECLARE_SENTINEL(14)

    bool has_current_route;
    uint8_t current_route_session_version;
    uint64_t current_route_expire_timestamp;
    double current_route_expire_time;
    int current_route_kbps_up;
    int current_route_kbps_down;
    next_address_t current_route_send_address;

    NEXT_DECLARE_SENTINEL(15)

    uint8_t current_route_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];

    NEXT_DECLARE_SENTINEL(16)

    bool has_previous_route;
    next_address_t previous_route_send_address;

    NEXT_DECLARE_SENTINEL(17)

    uint8_t previous_route_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];

    NEXT_DECLARE_SENTINEL(18)

    uint8_t ephemeral_private_key[NEXT_CRYPTO_SECRETBOX_KEYBYTES];
    uint8_t send_key[NEXT_CRYPTO_KX_SESSIONKEYBYTES];
    uint8_t receive_key[NEXT_CRYPTO_KX_SESSIONKEYBYTES];
    uint8_t client_route_public_key[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];

    NEXT_DECLARE_SENTINEL(19)

    uint8_t upgrade_token[NEXT_UPGRADE_TOKEN_BYTES];

    NEXT_DECLARE_SENTINEL(20)

    next_replay_protection_t payload_replay_protection;
    next_replay_protection_t special_replay_protection;
    next_replay_protection_t internal_replay_protection;

    NEXT_DECLARE_SENTINEL(21)

    next_packet_loss_tracker_t packet_loss_tracker;
    next_out_of_order_tracker_t out_of_order_tracker;
    next_jitter_tracker_t jitter_tracker;

    NEXT_DECLARE_SENTINEL(22)

    bool mutex_multipath;
    int mutex_envelope_kbps_up;
    int mutex_envelope_kbps_down;
    uint64_t mutex_payload_send_sequence;
    uint64_t mutex_session_id;
    uint8_t mutex_session_version;
    bool mutex_send_over_network_next;
    next_address_t mutex_send_address;

    NEXT_DECLARE_SENTINEL(23)

    uint8_t mutex_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];

    NEXT_DECLARE_SENTINEL(24)

    int session_data_bytes;
    uint8_t session_data[NEXT_MAX_SESSION_DATA_BYTES];
    uint8_t session_data_signature[NEXT_CRYPTO_SIGN_BYTES];

    NEXT_DECLARE_SENTINEL(25)

    bool client_ping_timed_out;
    double last_client_direct_ping;
    double last_client_next_ping;

    NEXT_DECLARE_SENTINEL(26)

    bool has_debug;
    char debug[NEXT_MAX_SESSION_DEBUG];

    NEXT_DECLARE_SENTINEL(27)

    uint64_t match_id;
    double match_values[NEXT_MAX_MATCH_VALUES];
    int num_match_values;

    NextBackendMatchDataRequestPacket match_data_request_packet;

    bool has_match_data;
    double next_match_data_resend_time;
    bool waiting_for_match_data_response;
    bool match_data_response_received;

    NEXT_DECLARE_SENTINEL(28)

    uint32_t session_flush_update_sequence;
    bool session_update_flush;
    bool session_update_flush_finished;
    bool match_data_flush;
    bool match_data_flush_finished;

    NEXT_DECLARE_SENTINEL(29)

    int num_held_near_relays;
    uint64_t held_near_relay_ids[NEXT_MAX_NEAR_RELAYS];
    uint8_t held_near_relay_rtt[NEXT_MAX_NEAR_RELAYS];
    uint8_t held_near_relay_jitter[NEXT_MAX_NEAR_RELAYS];
    float held_near_relay_packet_loss[NEXT_MAX_NEAR_RELAYS];

    NEXT_DECLARE_SENTINEL(30)
};

void next_session_entry_initialize_sentinels( next_session_entry_t * entry )
{
    (void) entry;
    next_assert( entry );
    NEXT_INITIALIZE_SENTINEL( entry, 0 )
    NEXT_INITIALIZE_SENTINEL( entry, 1 )
    NEXT_INITIALIZE_SENTINEL( entry, 2 )
    NEXT_INITIALIZE_SENTINEL( entry, 3 )
    NEXT_INITIALIZE_SENTINEL( entry, 4 )
    NEXT_INITIALIZE_SENTINEL( entry, 5 )
    NEXT_INITIALIZE_SENTINEL( entry, 6 )
    NEXT_INITIALIZE_SENTINEL( entry, 7 )
    NEXT_INITIALIZE_SENTINEL( entry, 8 )
    NEXT_INITIALIZE_SENTINEL( entry, 9 )
    NEXT_INITIALIZE_SENTINEL( entry, 10 )
    NEXT_INITIALIZE_SENTINEL( entry, 11 )
    NEXT_INITIALIZE_SENTINEL( entry, 12 )
    NEXT_INITIALIZE_SENTINEL( entry, 13 )
    NEXT_INITIALIZE_SENTINEL( entry, 14 )
    NEXT_INITIALIZE_SENTINEL( entry, 15 )
    NEXT_INITIALIZE_SENTINEL( entry, 16 )
    NEXT_INITIALIZE_SENTINEL( entry, 17 )
    NEXT_INITIALIZE_SENTINEL( entry, 18 )
    NEXT_INITIALIZE_SENTINEL( entry, 19 )
    NEXT_INITIALIZE_SENTINEL( entry, 20 )
    NEXT_INITIALIZE_SENTINEL( entry, 21 )
    NEXT_INITIALIZE_SENTINEL( entry, 22 )
    NEXT_INITIALIZE_SENTINEL( entry, 23 )
    NEXT_INITIALIZE_SENTINEL( entry, 24 )
    NEXT_INITIALIZE_SENTINEL( entry, 25 )
    NEXT_INITIALIZE_SENTINEL( entry, 26 )
    NEXT_INITIALIZE_SENTINEL( entry, 27 )
    NEXT_INITIALIZE_SENTINEL( entry, 28 )
    NEXT_INITIALIZE_SENTINEL( entry, 29 )
    NEXT_INITIALIZE_SENTINEL( entry, 30 )
}

void next_session_entry_verify_sentinels( next_session_entry_t * entry )
{
    (void) entry;
    next_assert( entry );
    NEXT_VERIFY_SENTINEL( entry, 0 )
    NEXT_VERIFY_SENTINEL( entry, 1 )
    NEXT_VERIFY_SENTINEL( entry, 2 )
    NEXT_VERIFY_SENTINEL( entry, 3 )
    NEXT_VERIFY_SENTINEL( entry, 4 )
    NEXT_VERIFY_SENTINEL( entry, 5 )
    NEXT_VERIFY_SENTINEL( entry, 6 )
    NEXT_VERIFY_SENTINEL( entry, 7 )
    NEXT_VERIFY_SENTINEL( entry, 8 )
    NEXT_VERIFY_SENTINEL( entry, 9 )
    NEXT_VERIFY_SENTINEL( entry, 10 )
    NEXT_VERIFY_SENTINEL( entry, 11 )
    NEXT_VERIFY_SENTINEL( entry, 12 )
    NEXT_VERIFY_SENTINEL( entry, 13 )
    NEXT_VERIFY_SENTINEL( entry, 14 )
    NEXT_VERIFY_SENTINEL( entry, 15 )
    NEXT_VERIFY_SENTINEL( entry, 16 )
    NEXT_VERIFY_SENTINEL( entry, 17 )
    NEXT_VERIFY_SENTINEL( entry, 18 )
    NEXT_VERIFY_SENTINEL( entry, 19 )
    NEXT_VERIFY_SENTINEL( entry, 20 )
    NEXT_VERIFY_SENTINEL( entry, 21 )
    NEXT_VERIFY_SENTINEL( entry, 22 )
    NEXT_VERIFY_SENTINEL( entry, 23 )
    NEXT_VERIFY_SENTINEL( entry, 24 )
    NEXT_VERIFY_SENTINEL( entry, 25 )
    NEXT_VERIFY_SENTINEL( entry, 26 )
    NEXT_VERIFY_SENTINEL( entry, 27 )
    NEXT_VERIFY_SENTINEL( entry, 28 )
    NEXT_VERIFY_SENTINEL( entry, 29 )
    NEXT_INITIALIZE_SENTINEL( entry, 30 )
    next_replay_protection_verify_sentinels( &entry->payload_replay_protection );
    next_replay_protection_verify_sentinels( &entry->special_replay_protection );
    next_replay_protection_verify_sentinels( &entry->internal_replay_protection );
    next_packet_loss_tracker_verify_sentinels( &entry->packet_loss_tracker );
    next_out_of_order_tracker_verify_sentinels( &entry->out_of_order_tracker );
    next_jitter_tracker_verify_sentinels( &entry->jitter_tracker );
}

struct next_session_manager_t
{
    NEXT_DECLARE_SENTINEL(0)

    void * context;
    int size;
    int max_entry_index;
    uint64_t * session_ids;
    next_address_t * addresses;
    next_session_entry_t * entries;

    NEXT_DECLARE_SENTINEL(1)
};

void next_session_manager_initialize_sentinels( next_session_manager_t * session_manager )
{
    (void) session_manager;
    next_assert( session_manager );
    NEXT_INITIALIZE_SENTINEL( session_manager, 0 )
    NEXT_INITIALIZE_SENTINEL( session_manager, 1 )
}

void next_session_manager_verify_sentinels( next_session_manager_t * session_manager )
{
    (void) session_manager;
#if NEXT_ENABLE_MEMORY_CHECKS
    next_assert( session_manager );
    NEXT_VERIFY_SENTINEL( session_manager, 0 )
    NEXT_VERIFY_SENTINEL( session_manager, 1 )
    const int size = session_manager->size;
    for ( int i = 0; i < size; ++i )
    {
        if ( session_manager->session_ids[i] != 0 )
        {
            next_session_entry_verify_sentinels( &session_manager->entries[i] );
        }
    }
#endif // #if NEXT_ENABLE_MEMORY_CHECKS
}

void next_session_manager_destroy( next_session_manager_t * session_manager );

next_session_manager_t * next_session_manager_create( void * context, int initial_size )
{
    next_session_manager_t * session_manager = (next_session_manager_t*) next_malloc( context, sizeof(next_session_manager_t) );

    next_assert( session_manager );
    if ( !session_manager )
        return NULL;

    memset( session_manager, 0, sizeof(next_session_manager_t) );

    next_session_manager_initialize_sentinels( session_manager );

    session_manager->context = context;
    session_manager->size = initial_size;
    session_manager->session_ids = (uint64_t*) next_malloc( context, size_t(initial_size) * 8 );
    session_manager->addresses = (next_address_t*) next_malloc( context, size_t(initial_size) * sizeof(next_address_t) );
    session_manager->entries = (next_session_entry_t*) next_malloc( context, size_t(initial_size) * sizeof(next_session_entry_t) );

    next_assert( session_manager->session_ids );
    next_assert( session_manager->addresses );
    next_assert( session_manager->entries );

    if ( session_manager->session_ids == NULL || session_manager->addresses == NULL || session_manager->entries == NULL )
    {
        next_session_manager_destroy( session_manager );
        return NULL;
    }

    memset( session_manager->session_ids, 0, size_t(initial_size) * 8 );
    memset( session_manager->addresses, 0, size_t(initial_size) * sizeof(next_address_t) );
    memset( session_manager->entries, 0, size_t(initial_size) * sizeof(next_session_entry_t) );

    next_session_manager_verify_sentinels( session_manager );

    return session_manager;
}

void next_session_manager_destroy( next_session_manager_t * session_manager )
{
    next_session_manager_verify_sentinels( session_manager );

    next_free( session_manager->context, session_manager->session_ids );
    next_free( session_manager->context, session_manager->addresses );
    next_free( session_manager->context, session_manager->entries );

    clear_and_free( session_manager->context, session_manager, sizeof(next_session_manager_t) );
}

bool next_session_manager_expand( next_session_manager_t * session_manager )
{
    next_assert( session_manager );

    next_session_manager_verify_sentinels( session_manager );

    int new_size = session_manager->size * 2;

    uint64_t * new_session_ids = (uint64_t*) next_malloc( session_manager->context, size_t(new_size) * 8 );
    next_address_t * new_addresses = (next_address_t*) next_malloc( session_manager->context, size_t(new_size) * sizeof(next_address_t) );
    next_session_entry_t * new_entries = (next_session_entry_t*) next_malloc( session_manager->context, size_t(new_size) * sizeof(next_session_entry_t) );

    next_assert( new_session_ids );
    next_assert( new_addresses );
    next_assert( new_entries );

    if ( new_session_ids == NULL || new_addresses == NULL || new_entries == NULL )
    {
        next_free( session_manager->context, new_session_ids );
        next_free( session_manager->context, new_addresses );
        next_free( session_manager->context, new_entries );
        return false;
    }

    memset( new_session_ids, 0, size_t(new_size) * 8 );
    memset( new_addresses, 0, size_t(new_size) * sizeof(next_address_t) );
    memset( new_entries, 0, size_t(new_size) * sizeof(next_session_entry_t) );

    int index = 0;
    const int current_size = session_manager->size;
    for ( int i = 0; i < current_size; ++i )
    {
        if ( session_manager->session_ids[i] != 0 )
        {
            memcpy( &new_session_ids[index], &session_manager->session_ids[i], 8 );
            memcpy( &new_addresses[index], &session_manager->addresses[i], sizeof(next_address_t) );
            memcpy( &new_entries[index], &session_manager->entries[i], sizeof(next_session_entry_t) );
            index++;
        }
    }

    next_free( session_manager->context, session_manager->session_ids );
    next_free( session_manager->context, session_manager->addresses );
    next_free( session_manager->context, session_manager->entries );

    session_manager->session_ids = new_session_ids;
    session_manager->addresses = new_addresses;
    session_manager->entries = new_entries;
    session_manager->size = new_size;
    session_manager->max_entry_index = index - 1;

    return true;
}

void next_clear_session_entry( next_session_entry_t * entry, const next_address_t * address, uint64_t session_id )
{
    memset( entry, 0, sizeof(next_session_entry_t) );

    next_session_entry_initialize_sentinels( entry );

    entry->address = *address;
    entry->session_id = session_id;

    next_replay_protection_reset( &entry->payload_replay_protection );
    next_replay_protection_reset( &entry->special_replay_protection );
    next_replay_protection_reset( &entry->internal_replay_protection );

    next_packet_loss_tracker_reset( &entry->packet_loss_tracker );
    next_out_of_order_tracker_reset( &entry->out_of_order_tracker );
    next_jitter_tracker_reset( &entry->jitter_tracker );

    next_session_entry_verify_sentinels( entry );

    entry->special_send_sequence = 1;
    entry->internal_send_sequence = 1;

    const double current_time = next_time();

    entry->last_client_direct_ping = current_time;
    entry->last_client_next_ping = current_time;
}

next_session_entry_t * next_session_manager_add( next_session_manager_t * session_manager, const next_address_t * address, uint64_t session_id, const uint8_t * ephemeral_private_key, const uint8_t * upgrade_token, const uint64_t * tags, int num_tags )
{
    next_session_manager_verify_sentinels( session_manager );

    next_assert( session_id != 0 );
    next_assert( address );
    next_assert( address->type != NEXT_ADDRESS_NONE );
    next_assert( num_tags == 0 || tags );

    // first scan existing entries and see if we can insert there

    const int size = session_manager->size;

    for ( int i = 0; i < size; ++i )
    {
        if ( session_manager->session_ids[i] == 0 )
        {
            session_manager->session_ids[i] = session_id;
            session_manager->addresses[i] = *address;
            next_session_entry_t * entry = &session_manager->entries[i];
            next_clear_session_entry( entry, address, session_id );
            memcpy( entry->ephemeral_private_key, ephemeral_private_key, NEXT_CRYPTO_SECRETBOX_KEYBYTES );
            memcpy( entry->upgrade_token, upgrade_token, NEXT_UPGRADE_TOKEN_BYTES );
            entry->num_tags = num_tags;
            for ( int j = 0; j < num_tags; ++j )
            {
                entry->tags[j] = tags[j];
            }
            if ( i > session_manager->max_entry_index )
            {
                session_manager->max_entry_index = i;
            }
            return entry;
        }
    }

    // ok, we need to grow, expand and add at the end (expand compacts existing entries)

    if ( !next_session_manager_expand( session_manager ) )
        return NULL;

    const int i = ++session_manager->max_entry_index;

    session_manager->session_ids[i] = session_id;
    session_manager->addresses[i] = *address;
    next_session_entry_t * entry = &session_manager->entries[i];
    next_clear_session_entry( entry, address, session_id );
    memcpy( entry->ephemeral_private_key, ephemeral_private_key, NEXT_CRYPTO_SECRETBOX_KEYBYTES );
    memcpy( entry->upgrade_token, upgrade_token, NEXT_UPGRADE_TOKEN_BYTES );
    entry->num_tags = num_tags;
    for ( int j = 0; j < num_tags; ++j )
    {
        entry->tags[j] = tags[j];
    }

    next_session_manager_verify_sentinels( session_manager );

    return entry;
}

void next_session_manager_remove_at_index( next_session_manager_t * session_manager, int index )
{
    next_session_manager_verify_sentinels( session_manager );

    next_assert( index >= 0 );
    next_assert( index <= session_manager->max_entry_index );

    const int max_index = session_manager->max_entry_index;
    session_manager->session_ids[index] = 0;
    session_manager->addresses[index].type = NEXT_ADDRESS_NONE;
    if ( index == max_index )
    {
        while ( index > 0 && session_manager->session_ids[index] == 0 )
        {
            index--;
        }
        session_manager->max_entry_index = index;
    }

    next_session_manager_verify_sentinels( session_manager );
}

void next_session_manager_remove_by_address( next_session_manager_t * session_manager, const next_address_t * address )
{
    next_session_manager_verify_sentinels( session_manager );

    next_assert( address );

    const int max_index = session_manager->max_entry_index;
    for ( int i = 0; i <= max_index; ++i )
    {
        if ( next_address_equal( address, &session_manager->addresses[i] ) == 1 )
        {
            next_session_manager_remove_at_index( session_manager, i );
            return;
        }
    }

    next_session_manager_verify_sentinels( session_manager );
}

next_session_entry_t * next_session_manager_find_by_address( next_session_manager_t * session_manager, const next_address_t * address )
{
    next_session_manager_verify_sentinels( session_manager );
    next_assert( address );
    const int max_index = session_manager->max_entry_index;
    for ( int i = 0; i <= max_index; ++i )
    {
        if ( next_address_equal( address, &session_manager->addresses[i] ) == 1 )
        {
            return &session_manager->entries[i];
        }
    }
    return NULL;
}

next_session_entry_t * next_session_manager_find_by_session_id( next_session_manager_t * session_manager, uint64_t session_id )
{
    next_session_manager_verify_sentinels( session_manager );
    next_assert( session_id );
    if ( session_id == 0 )
    {
        return NULL;
    }
    const int max_index = session_manager->max_entry_index;
    for ( int i = 0; i <= max_index; ++i )
    {
        if ( session_id == session_manager->session_ids[i] )
        {
            return &session_manager->entries[i];
        }
    }
    return NULL;
}

int next_session_manager_num_entries( next_session_manager_t * session_manager )
{
    next_session_manager_verify_sentinels( session_manager );
    int num_entries = 0;
    const int max_index = session_manager->max_entry_index;
    for ( int i = 0; i <= max_index; ++i )
    {
        if ( session_manager->session_ids[i] != 0 )
        {
            num_entries++;
        }
    }
    return num_entries;
}

// ---------------------------------------------------------------

struct NextBackendSessionUpdateResponsePacket
{
    uint64_t session_id;
    uint32_t slice_number;
    int session_data_bytes;
    uint8_t session_data[NEXT_MAX_SESSION_DATA_BYTES];
    uint8_t session_data_signature[NEXT_CRYPTO_SIGN_BYTES];
    uint8_t response_type;
    bool has_near_relays;
    int num_near_relays;
    uint64_t near_relay_ids[NEXT_MAX_NEAR_RELAYS];
    next_address_t near_relay_addresses[NEXT_MAX_NEAR_RELAYS];
    int num_tokens;
    uint8_t tokens[NEXT_MAX_TOKENS*NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES];
    bool multipath;
    bool has_debug;
    char debug[NEXT_MAX_SESSION_DEBUG];

    NextBackendSessionUpdateResponsePacket()
    {
        memset( this, 0, sizeof(NextBackendSessionUpdateResponsePacket) );
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_uint64( stream, session_id );

        serialize_uint32( stream, slice_number );

        serialize_int( stream, session_data_bytes, 0, NEXT_MAX_SESSION_DATA_BYTES );
        if ( session_data_bytes > 0 )
        {
            serialize_bytes( stream, session_data, session_data_bytes );
            serialize_bytes( stream, session_data_signature, NEXT_CRYPTO_SIGN_BYTES );
        }

        serialize_int( stream, response_type, 0, NEXT_UPDATE_TYPE_CONTINUE );

        serialize_bool( stream, has_near_relays );

        if ( has_near_relays )
        {
            serialize_int( stream, num_near_relays, 0, NEXT_MAX_NEAR_RELAYS );
            for ( int i = 0; i < num_near_relays; ++i )
            {
                serialize_uint64( stream, near_relay_ids[i] );
                serialize_address( stream, near_relay_addresses[i] );
            }
        }

        if ( response_type != NEXT_UPDATE_TYPE_DIRECT )
        {
            serialize_bool( stream, multipath );
            serialize_int( stream, num_tokens, 0, NEXT_MAX_TOKENS );
        }

        if ( response_type == NEXT_UPDATE_TYPE_ROUTE )
        {
            serialize_bytes( stream, tokens, num_tokens * NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES );
        }

        if ( response_type == NEXT_UPDATE_TYPE_CONTINUE )
        {
            serialize_bytes( stream, tokens, num_tokens * NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES );
        }

        serialize_bool( stream, has_debug );
        if ( has_debug )
        {
            serialize_string( stream, debug, NEXT_MAX_SESSION_DEBUG );
        }

        return true;
    }
};

// ---------------------------------------------------------------

int next_write_backend_packet( uint8_t packet_id, void * packet_object, uint8_t * packet_data, int * packet_bytes, const int * signed_packet, const uint8_t * sign_private_key, const uint8_t * magic, const uint8_t * from_address, int from_address_bytes, uint16_t from_port, const uint8_t * to_address, int to_address_bytes, uint16_t to_port )
{
    next_assert( packet_object );
    next_assert( packet_data );
    next_assert( packet_bytes );

    next::WriteStream stream( packet_data, NEXT_MAX_PACKET_BYTES );

    typedef next::WriteStream Stream;

    serialize_bits( stream, packet_id, 8 );

    uint8_t dummy = 0;
    for ( int i = 0; i < 15; ++i )
    {
        serialize_bits( stream, dummy, 8 );
    }

    switch ( packet_id )
    {
        case NEXT_BACKEND_SERVER_INIT_REQUEST_PACKET:
        {
            NextBackendServerInitRequestPacket * packet = (NextBackendServerInitRequestPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_SERVER_INIT_RESPONSE_PACKET:
        {
            NextBackendServerInitResponsePacket * packet = (NextBackendServerInitResponsePacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_SERVER_UPDATE_REQUEST_PACKET:
        {
            NextBackendServerUpdateRequestPacket * packet = (NextBackendServerUpdateRequestPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_SERVER_UPDATE_RESPONSE_PACKET:
        {
            NextBackendServerUpdateResponsePacket * packet = (NextBackendServerUpdateResponsePacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_SESSION_UPDATE_REQUEST_PACKET:
        {
            NextBackendSessionUpdateRequestPacket * packet = (NextBackendSessionUpdateRequestPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET:
        {
            NextBackendSessionUpdateResponsePacket * packet = (NextBackendSessionUpdateResponsePacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_MATCH_DATA_REQUEST_PACKET:
        {
            NextBackendMatchDataRequestPacket * packet = (NextBackendMatchDataRequestPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_MATCH_DATA_RESPONSE_PACKET:
        {
            NextBackendMatchDataResponsePacket * packet = (NextBackendMatchDataResponsePacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        default:
            return NEXT_ERROR;
    }

    stream.Flush();

    *packet_bytes = stream.GetBytesProcessed();

    next_assert( *packet_bytes >= 0 );
    next_assert( *packet_bytes < NEXT_MAX_PACKET_BYTES );

    if ( signed_packet && signed_packet[packet_id] )
    {
        next_assert( sign_private_key );
        next_crypto_sign_state_t state;
        next_crypto_sign_init( &state );
        next_crypto_sign_update( &state, packet_data, 1 );
        next_crypto_sign_update( &state, packet_data + 16, size_t(*packet_bytes) - 16 );
        next_crypto_sign_final_create( &state, packet_data + *packet_bytes, NULL, sign_private_key );
        *packet_bytes += NEXT_CRYPTO_SIGN_BYTES;
    }

    *packet_bytes += 2;

    next_generate_chonkle( packet_data + 1, magic, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, *packet_bytes );
    next_generate_pittle( packet_data + *packet_bytes - 2, from_address, from_address_bytes, from_port, to_address, to_address_bytes, to_port, *packet_bytes );

    return NEXT_OK;
}

int next_read_backend_packet( uint8_t packet_id, uint8_t * packet_data, int begin, int end, void * packet_object, const int * signed_packet, const uint8_t * sign_public_key )
{
    next_assert( packet_data );
    next_assert( packet_object );

    next::ReadStream stream( packet_data, end );

    uint8_t * dummy = (uint8_t*) alloca( begin );
    serialize_bytes( stream, dummy, begin );

    if ( signed_packet && signed_packet[packet_id] )
    {
        next_assert( sign_public_key );

        const int packet_bytes = end - begin;

        if ( packet_bytes < int( NEXT_CRYPTO_SIGN_BYTES ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "signed backend packet is too small to be valid" );
            return NEXT_ERROR;
        }

        next_crypto_sign_state_t state;
        next_crypto_sign_init( &state );
        next_crypto_sign_update( &state, &packet_id, 1 );
        next_crypto_sign_update( &state, packet_data + begin, packet_bytes - NEXT_CRYPTO_SIGN_BYTES );
        if ( next_crypto_sign_final_verify( &state, packet_data + end - NEXT_CRYPTO_SIGN_BYTES, sign_public_key ) != 0 )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "signed backend packet did not verify" );
            return NEXT_ERROR;
        }
    }

    switch ( packet_id )
    {
        case NEXT_BACKEND_SERVER_INIT_REQUEST_PACKET:
        {
            NextBackendServerInitRequestPacket * packet = (NextBackendServerInitRequestPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_SERVER_INIT_RESPONSE_PACKET:
        {
            NextBackendServerInitResponsePacket * packet = (NextBackendServerInitResponsePacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_SERVER_UPDATE_REQUEST_PACKET:
        {
            NextBackendServerUpdateRequestPacket * packet = (NextBackendServerUpdateRequestPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_SERVER_UPDATE_RESPONSE_PACKET:
        {
            NextBackendServerUpdateResponsePacket * packet = (NextBackendServerUpdateResponsePacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_SESSION_UPDATE_REQUEST_PACKET:
        {
            NextBackendSessionUpdateRequestPacket * packet = (NextBackendSessionUpdateRequestPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET:
        {
            NextBackendSessionUpdateResponsePacket * packet = (NextBackendSessionUpdateResponsePacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_MATCH_DATA_REQUEST_PACKET:
        {
            NextBackendMatchDataRequestPacket * packet = (NextBackendMatchDataRequestPacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        case NEXT_BACKEND_MATCH_DATA_RESPONSE_PACKET:
        {
            NextBackendMatchDataResponsePacket * packet = (NextBackendMatchDataResponsePacket*) packet_object;
            if ( !packet->Serialize( stream ) )
                return NEXT_ERROR;
        }
        break;

        default:
            return NEXT_ERROR;
    }

    return (int) packet_id;
}

// ---------------------------------------------------------------

#define NEXT_SERVER_COMMAND_UPGRADE_SESSION                         0
#define NEXT_SERVER_COMMAND_TAG_SESSION                             1
#define NEXT_SERVER_COMMAND_SERVER_EVENT                            2
#define NEXT_SERVER_COMMAND_MATCH_DATA                              3
#define NEXT_SERVER_COMMAND_FLUSH                                   4
#define NEXT_SERVER_COMMAND_SET_PACKET_RECEIVE_CALLBACK             5
#define NEXT_SERVER_COMMAND_SET_SEND_PACKET_TO_ADDRESS_CALLBACK     6
#define NEXT_SERVER_COMMAND_SET_PAYLOAD_RECEIVE_CALLBACK            7

struct next_server_command_t
{
    int type;
};

struct next_server_command_upgrade_session_t : public next_server_command_t
{
    next_address_t address;
    uint64_t session_id;
    uint64_t user_hash;
};

struct next_server_command_tag_session_t : public next_server_command_t
{
    next_address_t address;
    uint64_t tags[NEXT_MAX_TAGS];
    int num_tags;
};

struct next_server_command_server_event_t : public next_server_command_t
{
    next_address_t address;
    uint64_t server_events;
};

struct next_server_command_match_data_t : public next_server_command_t
{
    next_address_t address;
    uint64_t match_id;
    double match_values[NEXT_MAX_MATCH_VALUES];
    int num_match_values;
};

struct next_server_command_flush_t : public next_server_command_t
{
    // ...
};

struct next_server_command_set_packet_receive_callback_t : public next_server_command_t
{
    void (*callback) ( void * data, next_address_t * from, uint8_t * packet_data, int * begin, int * end );
    void * callback_data;
};

struct next_server_command_set_send_packet_to_address_callback_t : public next_server_command_t
{
    int (*callback) ( void * data, const next_address_t * address, const uint8_t * packet_data, int packet_bytes );
    void * callback_data;
};

struct next_server_command_set_payload_receive_callback_t : public next_server_command_t
{
    int (*callback) ( void * data, const next_address_t * client_address, const uint8_t * payload_data, int payload_bytes );
    void * callback_data;
};

// ---------------------------------------------------------------

#define NEXT_SERVER_NOTIFY_PACKET_RECEIVED                      0
#define NEXT_SERVER_NOTIFY_PENDING_SESSION_TIMED_OUT            1
#define NEXT_SERVER_NOTIFY_SESSION_UPGRADED                     2
#define NEXT_SERVER_NOTIFY_SESSION_TIMED_OUT                    3
#define NEXT_SERVER_NOTIFY_INIT_TIMED_OUT                       4
#define NEXT_SERVER_NOTIFY_READY                                5
#define NEXT_SERVER_NOTIFY_FLUSH_FINISHED                       6
#define NEXT_SERVER_NOTIFY_MAGIC_UPDATED                        7
#define NEXT_SERVER_NOTIFY_DIRECT_ONLY                          8

struct next_server_notify_t
{
    int type;
};

struct next_server_notify_packet_received_t : public next_server_notify_t
{
    next_address_t from;
    int packet_bytes;
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
};

struct next_server_notify_pending_session_cancelled_t : public next_server_notify_t
{
    next_address_t address;
    uint64_t session_id;
};

struct next_server_notify_pending_session_timed_out_t : public next_server_notify_t
{
    next_address_t address;
    uint64_t session_id;
};

struct next_server_notify_session_upgraded_t : public next_server_notify_t
{
    next_address_t address;
    uint64_t session_id;
};

struct next_server_notify_session_timed_out_t : public next_server_notify_t
{
    next_address_t address;
    uint64_t session_id;
};

struct next_server_notify_init_timed_out_t : public next_server_notify_t
{
    // ...
};

struct next_server_notify_ready_t : public next_server_notify_t
{
    char datacenter_name[NEXT_MAX_DATACENTER_NAME_LENGTH];
};

struct next_server_notify_flush_finished_t : public next_server_notify_t
{
    // ...
};

struct next_server_notify_magic_updated_t : public next_server_notify_t
{
    uint8_t current_magic[8];
};

struct next_server_notify_direct_only_t : public next_server_notify_t
{
    // ...
};

// ---------------------------------------------------------------

struct next_server_internal_t
{
    NEXT_DECLARE_SENTINEL(0)

    void * context;
    int state;
    uint64_t customer_id;
    uint64_t datacenter_id;
    char datacenter_name[NEXT_MAX_DATACENTER_NAME_LENGTH];
    char autodetect_input[NEXT_MAX_DATACENTER_NAME_LENGTH];
    char autodetect_datacenter[NEXT_MAX_DATACENTER_NAME_LENGTH];
    bool autodetected_datacenter;

    NEXT_DECLARE_SENTINEL(1)

    uint8_t customer_private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];

    NEXT_DECLARE_SENTINEL(2)

    bool valid_customer_private_key;
    bool no_datacenter_specified;
    uint64_t upgrade_sequence;
    double next_resolve_hostname_time;
    next_address_t backend_address;
    next_address_t server_address;
    next_address_t bind_address;
    next_queue_t * command_queue;
    next_queue_t * notify_queue;
    next_platform_mutex_t session_mutex;
    next_platform_mutex_t command_mutex;
    next_platform_mutex_t notify_mutex;
    next_platform_socket_t * socket;
    next_pending_session_manager_t * pending_session_manager;
    next_session_manager_t * session_manager;

    NEXT_DECLARE_SENTINEL(3)

    bool resolving_hostname;
    bool resolve_hostname_finished;
    double resolve_hostname_start_time;
    next_address_t resolve_hostname_result;
    next_platform_mutex_t resolve_hostname_mutex;
    next_platform_thread_t * resolve_hostname_thread;

    NEXT_DECLARE_SENTINEL(4)

    bool autodetecting;
    bool autodetect_finished;
    bool autodetect_actually_did_something;
    bool autodetect_succeeded;
    double autodetect_start_time;
    char autodetect_result[NEXT_MAX_DATACENTER_NAME_LENGTH];
    next_platform_mutex_t autodetect_mutex;
    next_platform_thread_t * autodetect_thread;

    NEXT_DECLARE_SENTINEL(5)

    uint8_t server_kx_public_key[NEXT_CRYPTO_KX_PUBLICKEYBYTES];
    uint8_t server_kx_private_key[NEXT_CRYPTO_KX_SECRETKEYBYTES];
    uint8_t server_route_public_key[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    uint8_t server_route_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];

    NEXT_DECLARE_SENTINEL(6)

    uint8_t upcoming_magic[8];
    uint8_t current_magic[8];
    uint8_t previous_magic[8];

    NEXT_DECLARE_SENTINEL(7)

    uint64_t server_init_request_id;
    double server_init_resend_time;
    double server_init_timeout_time;
    bool received_init_response;

    NEXT_DECLARE_SENTINEL(8)

    uint64_t server_update_request_id;
    double server_update_last_time;
    double server_update_resend_time;
    int server_update_num_sessions;
    bool server_update_first;

    NEXT_DECLARE_SENTINEL(9)

    next_platform_mutex_t quit_mutex;
    bool quit;

    NEXT_DECLARE_SENTINEL(10)

    bool flushing;
    bool flushed;
    uint64_t num_session_updates_to_flush;
    uint64_t num_match_data_to_flush;
    uint64_t num_flushed_session_updates;
    uint64_t num_flushed_match_data;

    NEXT_DECLARE_SENTINEL(11)

    void (*packet_receive_callback) ( void * data, next_address_t * from, uint8_t * packet_data, int * begin, int * end );
    void * packet_receive_callback_data;

    int (*send_packet_to_address_callback)( void * data, const next_address_t * address, const uint8_t * packet_data, int packet_bytes );
    void * send_packet_to_address_callback_data;

    int (*payload_receive_callback)( void * data, const next_address_t * client_address, const uint8_t * payload_data, int payload_bytes );
    void * payload_receive_callback_data;

    NEXT_DECLARE_SENTINEL(12)
};

void next_server_internal_initialize_sentinels( next_server_internal_t * server )
{
    (void) server;
    next_assert( server );
    NEXT_INITIALIZE_SENTINEL( server, 0 )
    NEXT_INITIALIZE_SENTINEL( server, 1 )
    NEXT_INITIALIZE_SENTINEL( server, 2 )
    NEXT_INITIALIZE_SENTINEL( server, 3 )
    NEXT_INITIALIZE_SENTINEL( server, 4 )
    NEXT_INITIALIZE_SENTINEL( server, 5 )
    NEXT_INITIALIZE_SENTINEL( server, 6 )
    NEXT_INITIALIZE_SENTINEL( server, 7 )
    NEXT_INITIALIZE_SENTINEL( server, 8 )
    NEXT_INITIALIZE_SENTINEL( server, 9 )
    NEXT_INITIALIZE_SENTINEL( server, 10 )
    NEXT_INITIALIZE_SENTINEL( server, 11 )
    NEXT_INITIALIZE_SENTINEL( server, 12 )
}

void next_server_internal_verify_sentinels( next_server_internal_t * server )
{
    (void) server;
    next_assert( server );
    NEXT_VERIFY_SENTINEL( server, 0 )
    NEXT_VERIFY_SENTINEL( server, 1 )
    NEXT_VERIFY_SENTINEL( server, 2 )
    NEXT_VERIFY_SENTINEL( server, 3 )
    NEXT_VERIFY_SENTINEL( server, 4 )
    NEXT_VERIFY_SENTINEL( server, 5 )
    NEXT_VERIFY_SENTINEL( server, 6 )
    NEXT_VERIFY_SENTINEL( server, 7 )
    NEXT_VERIFY_SENTINEL( server, 8 )
    NEXT_VERIFY_SENTINEL( server, 9 )
    NEXT_VERIFY_SENTINEL( server, 10 )
    NEXT_VERIFY_SENTINEL( server, 11 )
    NEXT_VERIFY_SENTINEL( server, 12 )
    if ( server->session_manager )
        next_session_manager_verify_sentinels( server->session_manager );
    if ( server->pending_session_manager )
        next_pending_session_manager_verify_sentinels( server->pending_session_manager );
}

static void next_server_internal_resolve_hostname_thread_function( void * context );
static void next_server_internal_autodetect_thread_function( void * context );

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC || NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

bool next_autodetect_google( char * output )
{
    FILE * file;
    char buffer[1024*10];

    // are we running in google cloud?
#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    file = popen( "/bin/ls /usr/bin | grep google_ 2>/dev/null", "r" );
    if ( file == NULL )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: could not run ls" );
        return false;
    }

#elif NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    file = _popen( "dir \"C:\\Program Files (x86)\\Google\\Cloud SDK\\google-cloud-sdk\\bin\" | findstr gcloud", "r" );
    if ( file == NULL )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: could not run dir" );
        return false;
    }

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

    bool in_gcp = false;
    while ( fgets( buffer, sizeof(buffer), file ) != NULL )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: running in google cloud" );
        in_gcp = true;
        break;
    }

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    pclose( file );

#elif NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    _pclose( file );

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

    // we are not running in google cloud :(

    if ( !in_gcp )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: not in google cloud" );
        return false;
    }

    // we are running in google cloud, which zone are we in?

    char zone[256];
    zone[0] = '\0';

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    file = popen( "curl \"http://metadata.google.internal/computeMetadata/v1/instance/zone\" -H \"Metadata-Flavor: Google\" --max-time 10 -vs 2>/dev/null", "r" );
    if ( !file )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: could not run curl" );
        return false;
    }

#elif NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    file = _popen( "powershell Invoke-RestMethod -Uri http://metadata.google.internal/computeMetadata/v1/instance/zone -Headers @{'Metadata-Flavor' = 'Google'} -TimeoutSec 10", "r" );
    if ( !file )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: could not run powershell Invoke-RestMethod" );
        return false;
    }

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

    while ( fgets( buffer, sizeof(buffer), file ) != NULL )
    {
        size_t length = strlen( buffer );
        if ( length < 10 )
        {
            continue;
        }

        if ( buffer[0] != 'p' ||
             buffer[1] != 'r' ||
             buffer[2] != 'o' ||
             buffer[3] != 'j' ||
             buffer[4] != 'e' ||
             buffer[5] != 'c' ||
             buffer[6] != 't' ||
             buffer[7] != 's' ||
             buffer[8] != '/' )
        {
            continue;
        }

        bool found = false;
        size_t index = length - 1;
        while ( index > 10 && length  )
        {
            if ( buffer[index] == '/' )
            {
                found = true;
                break;
            }
            index--;
        }

        if ( !found )
        {
            continue;
        }

        next_copy_string( zone, buffer + index + 1, sizeof(zone) );

        size_t zone_length = strlen(zone);
        index = zone_length - 1;
        while ( index > 0 && ( zone[index] == '\n' || zone[index] == '\r' ) )
        {
            zone[index] = '\0';
            index--;
        }

        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: google zone is \"%s\"", zone );

        break;
    }

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    pclose( file );

#elif NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    _pclose( file );

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

    // we couldn't work out which zone we are in :(

    if ( zone[0] == '\0' )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: could not detect google zone" );
        return false;
    }

    // look up google zone -> network next datacenter via mapping in google cloud storage "google.txt" file

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    char cmd[1024];
    snprintf( cmd, sizeof(cmd), "curl \"https://storage.googleapis.com/network-next-sdk/google.txt?ts=%x\" --max-time 10 -vs 2>/dev/null", uint32_t(time(NULL)) );
    file = popen( cmd, "r" );
    if ( !file )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: could not run curl" );
        return false;
    }

#elif NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    char cmd[1024];
    snprintf( cmd, sizeof(cmd), "powershell Invoke-RestMethod -Uri \"https://storage.googleapis.com/network-next-sdk/google.txt?ts=%x\" -TimeoutSec 10", uint32_t(time(NULL)) );
    file = _popen( cmd, "r" );
    if ( !file )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: could not run powershell Invoke-RestMethod" );
        return false;
    }

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

    bool found = false;

    while ( fgets( buffer, sizeof(buffer), file ) != NULL )
    {
        const char * separators = ",\n\r";

        char * google_zone = strtok( buffer, separators );
        if ( google_zone == NULL )
        {
            continue;
        }

        char * google_datacenter = strtok( NULL, separators );
        if ( google_datacenter == NULL )
        {
            continue;
        }

        if ( strcmp( zone, google_zone ) == 0 )
        {
            next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: \"%s\" -> \"%s\"", zone, google_datacenter );
            strcpy( output, google_datacenter );
            found = true;
            break;
        }
    }

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    pclose( file );

#elif NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    _pclose( file );

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

    return found;
}

bool next_autodetect_amazon( char * output )
{
    FILE * file;
    char buffer[1024*10];

    // Get the AZID from instance metadata
    // This is necessary because only AZ IDs are the same across different customer accounts
    // See https://docs.aws.amazon.com/ram/latest/userguide/working-with-az-ids.html for details

    char azid[256];
    azid[0] = '\0';

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    file = popen( "curl \"http://169.254.169.254/latest/meta-data/placement/availability-zone-id\" --max-time 2 -vs 2>/dev/null", "r" );
    if ( !file )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: could not run curl" );
        return false;
    }

#elif NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    file = _popen ( "powershell Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/placement/availability-zone-id -TimeoutSec 2", "r" );
    if ( !file )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: could not run powershell Invoke-RestMethod" );
        return false;
    }

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

    while ( fgets( buffer, sizeof(buffer), file ) != NULL )
    {
        if ( strstr( buffer, "-az" ) == NULL )
        {
            continue;
        }

        strcpy( azid, buffer );

        size_t azid_length = strlen(azid);
        size_t index = azid_length - 1;
        while ( index > 0 && ( azid[index] == '\n' || azid[index] == '\r' ) )
        {
            azid[index] = '\0';
            index--;
        }

        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: azid is \"%s\"", azid );

        break;
    }

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    pclose( file );

#elif NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    _pclose( file );

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

    // we are probably not in AWS :(

    if ( azid[0] == '\0' )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: not in AWS" );
        return false;
    }

    // look up AZID -> network next datacenter via mapping in google cloud storage "amazon.txt" file

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    char cmd[1024];
    snprintf( cmd, sizeof(cmd), "curl \"https://storage.googleapis.com/network-next-sdk/amazon.txt?ts=%x\" --max-time 10 -vs 2>/dev/null", uint32_t(time(NULL)) );
    file = popen( cmd, "r" );
    if ( !file )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: could not run curl" );
        return false;
    }

#elif NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    char cmd[1024];
    snprintf( cmd, sizeof(cmd), "powershell Invoke-RestMethod -Uri \"https://storage.googleapis.com/network-next-sdk/amazon.txt?ts=%x\" -TimeoutSec 10", uint32_t(time(NULL)) );
    file = _popen ( cmd, "r" );
    if ( !file )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: could not run powershell Invoke-RestMethod" );
        return false;
    }

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

    bool found = false;

    while ( fgets( buffer, sizeof(buffer), file ) != NULL )
    {
        const char * separators = ",\n\r";

        char * amazon_zone = strtok( buffer, separators );
        if ( amazon_zone == NULL )
        {
            continue;
        }

        char * amazon_datacenter = strtok( NULL, separators );
        if ( amazon_datacenter == NULL )
        {
            continue;
        }

        if ( strcmp( azid, amazon_zone ) == 0 )
        {
            next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: \"%s\" -> \"%s\"", azid, amazon_datacenter );
            strcpy( output, amazon_datacenter );
            found = true;
            break;
        }
    }

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    pclose( file );

#elif NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    _pclose( file );

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

    return found;
}

// --------------------------------------------------------------------------------------------------------------

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#define ANICHOST        "whois.arin.net"
#define LNICHOST        "whois.lacnic.net"
#define RNICHOST        "whois.ripe.net"
#define PNICHOST        "whois.apnic.net"
#define BNICHOST        "whois.registro.br"
#define AFRINICHOST     "whois.afrinic.net"

const char *ip_whois[] = { LNICHOST, RNICHOST, PNICHOST, BNICHOST, AFRINICHOST, NULL };

bool next_whois( const char * address, const char * hostname, int recurse, char ** buffer, size_t & bytes_remaining )
{
    struct addrinfo *hostres, *res;
    char *nhost;
    int i, s;
    size_t c;

    struct addrinfo hints;
    int error;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = 0;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(hostname, "nicname", &hints, &hostres);
    if ( error != 0 )
    {
        return 0;
    }

    for (res = hostres; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0)
            continue;
        if (connect(s, res->ai_addr, res->ai_addrlen) == 0)
            break;
        close(s);
    }

    freeaddrinfo(hostres);

    if (res == NULL)
        return 0;

    FILE * sfi = fdopen( s, "r" );
    FILE * sfo = fdopen( s, "w" );
    if ( sfi == NULL || sfo == NULL )
        return 0;

    if (strcmp(hostname, "de.whois-servers.net") == 0) {
#ifdef __APPLE__
        fprintf(sfo, "-T dn -C UTF-8 %s\r\n", address);
#else
        fprintf(sfo, "-T dn,ace -C US-ASCII %s\r\n", address);
#endif
    } else {
        fprintf(sfo, "%s\r\n", address);
    }
    fflush(sfo);

    nhost = NULL;

    char buf[10*1024];

    while ( fgets(buf, sizeof(buf), sfi) )
    {
        size_t len = strlen(buf);

        if ( len < bytes_remaining )
        {
            memcpy( *buffer, buf, len );
            bytes_remaining -= len;
            *buffer += len;
        }

        if ( nhost == NULL )
        {
            if ( recurse && strcmp(hostname, ANICHOST) == 0 )
            {
                for (c = 0; c <= len; c++)
                {
                    buf[c] = tolower((int)buf[c]);
                }
                for (i = 0; ip_whois[i] != NULL; i++)
                {
                    if (strstr(buf, ip_whois[i]) != NULL)
                    {
                        int result = asprintf( &nhost, "%s", ip_whois[i] );  // note: nhost is allocated here
                        if ( result == -1 )
                        {
                            nhost = NULL;
                        }
                        break;
                    }
                }
            }
        }
    }

    close( s );
    fclose( sfo );
    fclose( sfi );

    bool result = true;

    if ( nhost != NULL)
    {
        result = next_whois( address, nhost, 0, buffer, bytes_remaining );
        free( nhost );
    }

    return result;
}

bool next_autodetect_multiplay( const char * input_datacenter, const char * address, char * output, size_t output_size )
{
    FILE * file;

    // are we in a multiplay datacenter?

    if ( strlen( input_datacenter ) <= 10 ||
         input_datacenter[0] != 'm' || 
         input_datacenter[1] != 'u' || 
         input_datacenter[2] != 'l' || 
         input_datacenter[3] != 't' || 
         input_datacenter[4] != 'i' || 
         input_datacenter[5] != 'p' || 
         input_datacenter[6] != 'l' || 
         input_datacenter[7] != 'a' || 
         input_datacenter[8] != 'y' || 
         input_datacenter[9] != '.' )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: not in multiplay" );
        return false;
    }

    // is this a non-autodetect multiplay datacenter? ("multiplay.[cityname].[number]")

    const int length = strlen( input_datacenter );

    int num_periods = 0;

    for ( int i = 0; i < length; ++i )
    {
        if ( input_datacenter[i] == '.' )
        {
            num_periods++;
            if ( num_periods > 1 )
            {
                strcpy( output, input_datacenter );
                return true;
            }
        }
    }

    // capture the city name using form multiplay.[cityname]

    const char * city = input_datacenter + 10;

    // try to read in cache of whois in whois.txt first

    bool have_cached_whois = false;
    char whois_buffer[1024*64];
    memset( whois_buffer, 0, sizeof(whois_buffer) );
    FILE * f = fopen( "whois.txt", "r");
    if ( f )
    {
        fseek( f, 0, SEEK_END );
        size_t fsize = ftell( f );
        fseek( f, 0, SEEK_SET );
        if ( fsize > sizeof(whois_buffer) - 1 )
        {
            fsize = sizeof(whois_buffer) - 1;
        }
        if ( fread( whois_buffer, fsize, 1, f ) == 1 )
        {
            next_printf( NEXT_LOG_LEVEL_INFO, "server successfully read cached whois.txt" );
            have_cached_whois = true;
        }
        fclose( f );
    }

    // if we couldn't read whois.txt, run whois locally and store the result to whois.txt

    if ( !have_cached_whois )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server running whois locally" );
        char * whois_output = &whois_buffer[0];
        size_t bytes_remaining = sizeof(whois_buffer) - 1;
        next_whois( address, ANICHOST, 1, &whois_output, bytes_remaining );
           FILE * f = fopen( "whois.txt", "w" );
           if ( f )
           {
               next_printf( NEXT_LOG_LEVEL_INFO, "server cached whois result to whois.txt" );
               fputs( whois_buffer, f );
               fflush( f );
               fclose( f );
           }
    }

    // check against multiplay supplier mappings

    bool found = false;
    char multiplay_line[1024];
    char multiplay_buffer[64*1024];
    multiplay_buffer[0] = '\0';
    char cmd[1024];
    snprintf( cmd, sizeof(cmd), "curl \"https://storage.googleapis.com/network-next-sdk/multiplay.txt?ts=%x\" --max-time 10 -vs 2>/dev/null", uint32_t(time(NULL)) );
    file = popen( cmd, "r" );
    if ( !file )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: could not run curl" );
        return false;
    }
    while ( fgets( multiplay_line, sizeof(multiplay_line), file ) != NULL ) 
    {
        strcat( multiplay_buffer, multiplay_line );

        if ( found )
            continue;

        const char * separators = ",\n\r\n";

        char * substring = strtok( multiplay_line, separators );
        if ( substring == NULL )
        {
            continue;
        }

        char * supplier = strtok( NULL, separators );
        if ( supplier == NULL )
        {
            continue;
        }

        next_printf( NEXT_LOG_LEVEL_DEBUG, "checking for supplier \"%s\" with substring \"%s\"", supplier, substring );

        if ( strstr( whois_buffer, substring ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "found supplier %s", supplier );
            snprintf( output, output_size, "%s.%s", supplier, city );
            found = true;
        }
    }
    pclose( file );

    // could not autodetect multiplay :(

    if ( !found )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "could not autodetect multiplay datacenter :(" );
        next_printf( "-------------------------\n%s-------------------------\n", multiplay_buffer );
        const char * separators = "\n\r\n";
        char * line = strtok( whois_buffer, separators );
        while ( line )
        {
            next_printf( "%s", line );
            line = strtok( NULL, separators );
        }
        next_printf( "-------------------------\n" );
        return false;
    }

    return found;
}

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

bool next_autodetect_datacenter( const char * input_datacenter, const char * public_address, char * output, size_t output_size )
{
#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC
    
    // we need curl to do any autodetect. bail if we don't have it

    next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: looking for curl" );

    int result = system( "curl >/dev/null 2>&1" );

    if ( result < 0 )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: curl not found" );
        return false;
    }

    next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: curl exists" );

#elif NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    // we need access to powershell and Invoke-RestMethod to do any autodetect. bail if we don't have it

    next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: looking for powershell Invoke-RestMethod" );

    int result = system( "powershell Invoke-RestMethod -? > NUL 2>&1" );

    if ( result > 0 )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: powershell Invoke-RestMethod not found" );
        return false;
    }

    next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter: powershell Invoke-RestMethod exists" );

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

    // google cloud

    bool google_result = next_autodetect_google( output );
    if ( google_result )
    {
        return true;
    }

    // amazon

    bool amazon_result = next_autodetect_amazon( output );
    if ( amazon_result )
    {
        return true;
    }

    // multiplay

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    bool multiplay_result = next_autodetect_multiplay( input_datacenter, public_address, output, output_size );
    if ( multiplay_result )
    {
        return true;
    }

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

    (void) input_datacenter;
    (void) public_address;
    (void) output_size;

    return false;
}

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC || NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

void next_server_internal_resolve_hostname( next_server_internal_t * server )
{
    if ( server->resolving_hostname )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server is already resolving hostname" );
        return;
    }

    server->resolve_hostname_thread = next_platform_thread_create( server->context, next_server_internal_resolve_hostname_thread_function, server );
    if ( !server->resolve_hostname_thread )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create resolve hostname thread" );
        return;
    }

    server->resolve_hostname_start_time = next_time();
    server->resolving_hostname = true;
    server->resolve_hostname_finished = false;
}

void next_server_internal_autodetect( next_server_internal_t * server )
{
    if ( server->autodetecting )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server is already autodetecting" );
        return;
    }

    server->autodetect_thread = next_platform_thread_create( server->context, next_server_internal_autodetect_thread_function, server );
    if ( !server->autodetect_thread )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create autodetect thread" );
        return;
    }

    server->autodetect_start_time = next_time();
    server->autodetecting = true;
}

void next_server_internal_initialize( next_server_internal_t * server )
{
    if ( server->state != NEXT_SERVER_STATE_INITIALIZED )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server initializing with backend" );

        server->state = NEXT_SERVER_STATE_INITIALIZING;
        server->server_init_timeout_time = next_time() + NEXT_SERVER_INIT_TIMEOUT;
    }
    
    next_server_internal_resolve_hostname( server );

    next_server_internal_autodetect( server );
}

void next_server_internal_destroy( next_server_internal_t * server );

static void next_server_internal_thread_function( void * context );

next_server_internal_t * next_server_internal_create( void * context, const char * server_address_string, const char * bind_address_string, const char * datacenter_string )
{
#if !NEXT_DEVELOPMENT
    next_printf( NEXT_LOG_LEVEL_INFO, "server sdk version is %s", NEXT_VERSION_FULL );
#endif // #if !NEXT_DEVELOPMENT

    next_assert( server_address_string );
    next_assert( bind_address_string );
    next_assert( datacenter_string );

    next_printf( NEXT_LOG_LEVEL_INFO, "server buyer id is %" PRIx64, next_global_config.server_customer_id );

    const char * server_address_override = next_platform_getenv( "NEXT_SERVER_ADDRESS" );
    if ( server_address_override )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server address override: '%s'", server_address_override );
        server_address_string = server_address_override;
    }

    next_address_t server_address;
    if ( next_address_parse( &server_address, server_address_string ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to parse server address: '%s'", server_address_string );
        return NULL;
    }

    const char * bind_address_override = next_platform_getenv( "NEXT_BIND_ADDRESS" );
    if ( bind_address_override )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server bind address override: '%s'", bind_address_override );
        bind_address_string = bind_address_override;
    }

    next_address_t bind_address;
    if ( next_address_parse( &bind_address, bind_address_string ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to parse bind address: '%s'", bind_address_string );
        return NULL;
    }

    next_server_internal_t * server = (next_server_internal_t*) next_malloc( context, sizeof(next_server_internal_t) );
    if ( !server )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create internal server" );
        return NULL;
    }

    memset( server, 0, sizeof( next_server_internal_t) );

    next_server_internal_initialize_sentinels( server );

    next_server_internal_verify_sentinels( server );

    server->context = context;
    server->customer_id = next_global_config.server_customer_id;
    memcpy( server->customer_private_key, next_global_config.customer_private_key, NEXT_CRYPTO_SIGN_SECRETKEYBYTES );
    server->valid_customer_private_key = next_global_config.valid_customer_private_key;

    const char * datacenter = datacenter_string;

    const char * datacenter_env = next_platform_getenv( "NEXT_DATACENTER" );

    if ( datacenter_env )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server datacenter override '%s'", datacenter_env );
        datacenter = datacenter_env;
    }

    next_assert( datacenter );

    next_copy_string( server->autodetect_input, datacenter, NEXT_MAX_DATACENTER_NAME_LENGTH );

    const bool datacenter_is_empty_string = datacenter[0] == '\0';

    const bool datacenter_is_cloud = datacenter[0] == 'c' &&
                                     datacenter[1] == 'l' &&
                                     datacenter[2] == 'o' &&
                                     datacenter[3] == 'u' &&
                                     datacenter[4] == 'd' &&
                                     datacenter[5] == '\n';

    if ( !datacenter_is_empty_string && !datacenter_is_cloud )
    {
        server->datacenter_id = next_datacenter_id( datacenter );
        next_copy_string( server->datacenter_name, datacenter, NEXT_MAX_DATACENTER_NAME_LENGTH );
        next_printf( NEXT_LOG_LEVEL_INFO, "server input datacenter is '%s' [%" PRIx64 "]", server->datacenter_name, server->datacenter_id );
    }
    else
    {
        server->no_datacenter_specified = true;
    }

    server->command_queue = next_queue_create( context, NEXT_COMMAND_QUEUE_LENGTH );
    if ( !server->command_queue )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create command queue" );
        next_server_internal_destroy( server );
        return NULL;
    }

    server->notify_queue = next_queue_create( context, NEXT_NOTIFY_QUEUE_LENGTH );
    if ( !server->notify_queue )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create notify queue" );
        next_server_internal_destroy( server );
        return NULL;
    }

    server->socket = next_platform_socket_create( server->context, &bind_address, NEXT_PLATFORM_SOCKET_BLOCKING, 0.1f, next_global_config.socket_send_buffer_size, next_global_config.socket_receive_buffer_size, true );
    if ( server->socket == NULL )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create server socket" );
        next_server_internal_destroy( server );
        return NULL;
    }

    if ( server_address.port == 0 )
    {
        server_address.port = bind_address.port;
    }

    char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_printf( NEXT_LOG_LEVEL_INFO, "server bound to %s", next_address_to_string( &bind_address, address_string ) );

    server->bind_address = bind_address;
    server->server_address = server_address;

    int result = next_platform_mutex_create( &server->session_mutex );
    if ( result != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create session mutex" );
        next_server_internal_destroy( server );
        return NULL;
    }

    result = next_platform_mutex_create( &server->command_mutex );

    if ( result != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create command mutex" );
        next_server_internal_destroy( server );
        return NULL;
    }

    result = next_platform_mutex_create( &server->notify_mutex );

    if ( result != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create notify mutex" );
        next_server_internal_destroy( server );
        return NULL;
    }

    result = next_platform_mutex_create( &server->resolve_hostname_mutex );

    if ( result != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create resolve hostname mutex" );
        next_server_internal_destroy( server );
        return NULL;
    }

    result = next_platform_mutex_create( &server->autodetect_mutex );
    
    if ( result != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create autodetect mutex" );
        next_server_internal_destroy( server );
        return NULL;
    }

    result = next_platform_mutex_create( &server->quit_mutex );

    if ( result != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create quit mutex" );
        next_server_internal_destroy( server );
        return NULL;
    }

    server->pending_session_manager = next_pending_session_manager_create( context, NEXT_INITIAL_PENDING_SESSION_SIZE );
    if ( server->pending_session_manager == NULL )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create pending session manager" );
        next_server_internal_destroy( server );
        return NULL;
    }

    server->session_manager = next_session_manager_create( context, NEXT_INITIAL_SESSION_SIZE );
    if ( server->session_manager == NULL )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create session manager" );
        next_server_internal_destroy( server );
        return NULL;
    }

    if ( !next_global_config.disable_network_next && server->valid_customer_private_key )
    {
        next_server_internal_initialize( server );
    }

    next_printf( NEXT_LOG_LEVEL_INFO, "server started on %s", next_address_to_string( &server_address, address_string ) );

    next_crypto_kx_keypair( server->server_kx_public_key, server->server_kx_private_key );

    next_crypto_box_keypair( server->server_route_public_key, server->server_route_private_key );

    server->server_update_last_time = next_time() - NEXT_SECONDS_BETWEEN_SERVER_UPDATES * next_random_float();

    server->server_update_first = true;

    return server;
}

void next_server_internal_destroy( next_server_internal_t * server )
{
    next_assert( server );

    next_server_internal_verify_sentinels( server );

    if ( server->socket )
    {
        next_platform_socket_destroy( server->socket );
    }
    if ( server->resolve_hostname_thread )
    {
        next_platform_thread_destroy( server->resolve_hostname_thread );
    }
    if ( server->command_queue )
    {
        next_queue_destroy( server->command_queue );
    }
    if ( server->notify_queue )
    {
        next_queue_destroy( server->notify_queue );
    }
    if ( server->session_manager )
    {
        next_session_manager_destroy( server->session_manager );
        server->session_manager = NULL;
    }
    if ( server->pending_session_manager )
    {
        next_pending_session_manager_destroy( server->pending_session_manager );
        server->pending_session_manager = NULL;
    }

    next_platform_mutex_destroy( &server->session_mutex );
    next_platform_mutex_destroy( &server->command_mutex );
    next_platform_mutex_destroy( &server->notify_mutex );
    next_platform_mutex_destroy( &server->resolve_hostname_mutex );
    next_platform_mutex_destroy( &server->autodetect_mutex );
    next_platform_mutex_destroy( &server->quit_mutex );

    next_server_internal_verify_sentinels( server );

    clear_and_free( server->context, server, sizeof(next_server_internal_t) );
}

void next_server_internal_quit( next_server_internal_t * server )
{
    next_assert( server );
    next_platform_mutex_guard( &server->quit_mutex );
    server->quit = true;
}

void next_server_internal_send_packet_to_address( next_server_internal_t * server, const next_address_t * address, const uint8_t * packet_data, int packet_bytes )
{
    next_server_internal_verify_sentinels( server );

    next_assert( address );
    next_assert( address->type != NEXT_ADDRESS_NONE );
    next_assert( packet_data );
    next_assert( packet_bytes > 0 );

    if ( server->send_packet_to_address_callback )
    {
        void * callback_data = server->send_packet_to_address_callback_data;
        if ( server->send_packet_to_address_callback( callback_data, address, packet_data, packet_bytes ) != 0 )
            return;
    }

    next_platform_socket_send_packet( server->socket, address, packet_data, packet_bytes );
}

void next_server_internal_send_packet_to_backend( next_server_internal_t * server, const uint8_t * packet_data, int packet_bytes )
{
    next_server_internal_verify_sentinels( server );

    next_assert( server->backend_address.type != NEXT_ADDRESS_NONE );
    next_assert( packet_data );
    next_assert( packet_bytes > 0 );

    next_platform_socket_send_packet( server->socket, &server->backend_address, packet_data, packet_bytes );
}

int next_server_internal_send_packet( next_server_internal_t * server, const next_address_t * to_address, uint8_t packet_id, void * packet_object )
{
    next_assert( server );
    next_assert( server->socket );
    next_assert( packet_object );

    next_server_internal_verify_sentinels( server );

    int packet_bytes = 0;

    uint8_t buffer[NEXT_MAX_PACKET_BYTES];

    uint64_t * sequence = NULL;
    uint8_t * send_key = NULL;

    uint8_t magic[8];
    if ( packet_id != NEXT_UPGRADE_REQUEST_PACKET )
    {
        memcpy( magic, server->current_magic, 8 );
    }
    else
    {
        memset( magic, 0, sizeof(magic) );
    }

    if ( next_encrypted_packets[packet_id] )
    {
        next_session_entry_t * session = next_session_manager_find_by_address( server->session_manager, to_address );

        if ( !session )
        {
            next_printf( NEXT_LOG_LEVEL_WARN, "server can't send encrypted packet to address. no session found" );
            return NEXT_ERROR;
        }

        sequence = &session->internal_send_sequence;
        send_key = session->send_key;
    }

    uint8_t from_address_data[32];
    uint8_t to_address_data[32];
    uint16_t from_address_port = 0;
    uint16_t to_address_port = 0;
    int from_address_bytes = 0;
    int to_address_bytes = 0;

    next_address_data( &server->server_address, from_address_data, &from_address_bytes, &from_address_port );

    // IMPORTANT: when the upgrade request packet is sent, the client doesn't know it's external address yet
    // so we must encode with a to address of zero bytes for the upgrade request packet
    if ( packet_id != NEXT_UPGRADE_REQUEST_PACKET )
    {
        next_address_data( to_address, to_address_data, &to_address_bytes, &to_address_port );
    }

    if ( next_write_packet( packet_id, packet_object, buffer, &packet_bytes, next_signed_packets, next_encrypted_packets, sequence, server->customer_private_key, send_key, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to write internal packet with id %d", packet_id );
        return NEXT_ERROR;
    }

    next_assert( packet_bytes > 0 );
    next_assert( next_basic_packet_filter( buffer, packet_bytes ) );
    next_assert( next_advanced_packet_filter( buffer, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

    next_server_internal_send_packet_to_address( server, to_address, buffer, packet_bytes );

    return NEXT_OK;
}

inline int next_sequence_greater_than( uint8_t s1, uint8_t s2 )
{
    return ( ( s1 > s2 ) && ( s1 - s2 <= 128 ) ) ||
           ( ( s1 < s2 ) && ( s2 - s1  > 128 ) );
}

next_session_entry_t * next_server_internal_process_client_to_server_packet( next_server_internal_t * server, uint8_t packet_type, uint8_t * packet_data, int packet_bytes )
{
    next_assert( server );
    next_assert( packet_data );

    next_server_internal_verify_sentinels( server );

    if ( packet_bytes <= NEXT_HEADER_BYTES )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored client to server packet. packet is too small to be valid" );
        return NULL;
    }

    uint64_t packet_sequence = 0;
    uint64_t packet_session_id = 0;
    uint8_t packet_session_version = 0;

    if ( next_peek_header( NEXT_DIRECTION_CLIENT_TO_SERVER, packet_type, &packet_sequence, &packet_session_id, &packet_session_version, packet_data, packet_bytes ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored client to server packet. could not peek header" );
        return NULL;
    }

    next_session_entry_t * entry = next_session_manager_find_by_session_id( server->session_manager, packet_session_id );
    if ( !entry )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored client to server packet. could not find session" );
        return NULL;
    }

    if ( !entry->has_pending_route && !entry->has_current_route && !entry->has_previous_route )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored client to server packet. session has no route" );
        return NULL;
    }

    next_assert( packet_type == NEXT_CLIENT_TO_SERVER_PACKET || packet_type == NEXT_PING_PACKET );

    next_replay_protection_t * replay_protection = ( packet_type == NEXT_CLIENT_TO_SERVER_PACKET ) ? &entry->payload_replay_protection : &entry->special_replay_protection;

    uint64_t clean_sequence = next_clean_sequence( packet_sequence );

    if ( next_replay_protection_already_received( replay_protection, clean_sequence ) )
        return NULL;

    if ( entry->has_pending_route && next_read_header( NEXT_DIRECTION_CLIENT_TO_SERVER, packet_type, &packet_sequence, &packet_session_id, &packet_session_version, entry->pending_route_private_key, packet_data, packet_bytes ) == NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "server promoted pending route for session %" PRIx64, entry->session_id );

        if ( entry->has_current_route )
        {
            entry->has_previous_route = true;
            entry->previous_route_send_address = entry->current_route_send_address;
            memcpy( entry->previous_route_private_key, entry->current_route_private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );
        }

        entry->has_pending_route = false;
        entry->has_current_route = true;
        entry->current_route_session_version = entry->pending_route_session_version;
        entry->current_route_expire_timestamp = entry->pending_route_expire_timestamp;
        entry->current_route_expire_time = entry->pending_route_expire_time;
        entry->current_route_kbps_up = entry->pending_route_kbps_up;
        entry->current_route_kbps_down = entry->pending_route_kbps_down;
        entry->current_route_send_address = entry->pending_route_send_address;
        memcpy( entry->current_route_private_key, entry->pending_route_private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );

        next_platform_mutex_acquire( &server->session_mutex );
        entry->mutex_envelope_kbps_up = entry->current_route_kbps_up;
        entry->mutex_envelope_kbps_down = entry->current_route_kbps_down;
        entry->mutex_send_over_network_next = true;
        entry->mutex_session_id = entry->session_id;
        entry->mutex_session_version = entry->current_route_session_version;
        entry->mutex_send_address = entry->current_route_send_address;
        memcpy( entry->mutex_private_key, entry->current_route_private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );
        next_platform_mutex_release( &server->session_mutex );
    }
    else
    {
        bool current_route_ok = false;
        bool previous_route_ok = false;

        if ( entry->has_current_route )
            current_route_ok = next_read_header( NEXT_DIRECTION_CLIENT_TO_SERVER, packet_type, &packet_sequence, &packet_session_id, &packet_session_version, entry->current_route_private_key, packet_data, packet_bytes ) == NEXT_OK;

        if ( entry->has_previous_route )
            previous_route_ok = next_read_header( NEXT_DIRECTION_CLIENT_TO_SERVER, packet_type, &packet_sequence, &packet_session_id, &packet_session_version, entry->previous_route_private_key, packet_data, packet_bytes ) == NEXT_OK;

        if ( !current_route_ok && !previous_route_ok )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored client to server packet. did not verify" );
            return NULL;
        }
    }

    next_replay_protection_advance_sequence( replay_protection, clean_sequence );

    if ( packet_type == NEXT_CLIENT_TO_SERVER_PACKET )
    {
        next_packet_loss_tracker_packet_received( &entry->packet_loss_tracker, clean_sequence );
        next_out_of_order_tracker_packet_received( &entry->out_of_order_tracker, clean_sequence );
        next_jitter_tracker_packet_received( &entry->jitter_tracker, clean_sequence, next_time() );
    }

    return entry;
}

void next_server_internal_update_route( next_server_internal_t * server )
{
    next_assert( server );

    next_server_internal_verify_sentinels( server );

    if ( server->flushing )
        return;

    if ( next_global_config.disable_network_next )
        return;

    const double current_time = next_time();

    const int max_index = server->session_manager->max_entry_index;

    for ( int i = 0; i <= max_index; ++i )
    {
        if ( server->session_manager->session_ids[i] == 0 )
            continue;

        next_session_entry_t * entry = &server->session_manager->entries[i];

        if ( entry->update_dirty && !entry->client_ping_timed_out && !entry->stats_fallback_to_direct && entry->update_last_send_time + NEXT_UPDATE_SEND_TIME <= current_time )
        {
            NextRouteUpdatePacket packet;
            memcpy( packet.upcoming_magic, server->upcoming_magic, 8 );
            memcpy( packet.current_magic, server->current_magic, 8 );
            memcpy( packet.previous_magic, server->previous_magic, 8 );
            packet.sequence = entry->update_sequence;
            packet.has_near_relays = entry->update_has_near_relays;
            if ( packet.has_near_relays )
            {
                packet.num_near_relays = entry->update_num_near_relays;
                memcpy( packet.near_relay_ids, entry->update_near_relay_ids, size_t(8) * entry->update_num_near_relays );
                memcpy( packet.near_relay_addresses, entry->update_near_relay_addresses, sizeof(next_address_t) * entry->update_num_near_relays );
            }
            packet.update_type = entry->update_type;
            packet.multipath = entry->multipath;
            packet.num_tokens = entry->update_num_tokens;
            if ( entry->update_type == NEXT_UPDATE_TYPE_ROUTE )
            {
                memcpy( packet.tokens, entry->update_tokens, NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES * size_t(entry->update_num_tokens) );
            }
            else if ( entry->update_type == NEXT_UPDATE_TYPE_CONTINUE )
            {
                memcpy( packet.tokens, entry->update_tokens, NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES * size_t(entry->update_num_tokens) );
            }
            packet.packets_lost_client_to_server = entry->stats_packets_lost_client_to_server;
            packet.packets_out_of_order_client_to_server = entry->stats_packets_out_of_order_client_to_server;
            packet.jitter_client_to_server = float( entry->stats_jitter_client_to_server );

            next_platform_mutex_acquire( &server->session_mutex );
            packet.packets_sent_server_to_client = entry->stats_packets_sent_server_to_client;
            next_platform_mutex_release( &server->session_mutex );

            packet.has_debug = entry->has_debug;
            memcpy( packet.debug, entry->debug, NEXT_MAX_SESSION_DEBUG );

            next_server_internal_send_packet( server, &entry->address, NEXT_ROUTE_UPDATE_PACKET, &packet );

            entry->update_last_send_time = current_time;

            next_printf( NEXT_LOG_LEVEL_DEBUG, "server sent route update packet to session %" PRIx64, entry->session_id );
        }
    }
}

void next_server_internal_update_pending_upgrades( next_server_internal_t * server )
{
    next_assert( server );

    next_server_internal_verify_sentinels( server );

    if ( next_global_config.disable_network_next )
        return;

    if ( server->flushing )
        return;

    if ( server->state == NEXT_SERVER_STATE_DIRECT_ONLY )
        return;

    const double current_time = next_time();

    const double packet_resend_time = 0.25;

    const int max_index = server->pending_session_manager->max_entry_index;

    for ( int i = 0; i <= max_index; ++i )
    {
        if ( server->pending_session_manager->addresses[i].type == NEXT_ADDRESS_NONE )
            continue;

        next_pending_session_entry_t * entry = &server->pending_session_manager->entries[i];

        if ( entry->upgrade_time + NEXT_UPGRADE_TIMEOUT <= current_time )
        {
            char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server upgrade request timed out for client %s", next_address_to_string( &entry->address, address_buffer ) );
            next_pending_session_manager_remove_at_index( server->pending_session_manager, i );
            next_server_notify_pending_session_timed_out_t * notify = (next_server_notify_pending_session_timed_out_t*) next_malloc( server->context, sizeof( next_server_notify_pending_session_timed_out_t ) );
            notify->type = NEXT_SERVER_NOTIFY_PENDING_SESSION_TIMED_OUT;
            notify->address = entry->address;
            notify->session_id = entry->session_id;
            {
                next_platform_mutex_guard( &server->notify_mutex );
                next_queue_push( server->notify_queue, notify );
            }
            continue;
        }

        if ( entry->last_packet_send_time + packet_resend_time <= current_time )
        {
            char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server sent upgrade request packet to client %s", next_address_to_string( &entry->address, address_buffer ) );

            entry->last_packet_send_time = current_time;

            NextUpgradeRequestPacket packet;
            packet.protocol_version = next_protocol_version();
            packet.session_id = entry->session_id;
            packet.client_address = entry->address;
            packet.server_address = server->server_address;
            memcpy( packet.server_kx_public_key, server->server_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES );
            memcpy( packet.upgrade_token, entry->upgrade_token, NEXT_UPGRADE_TOKEN_BYTES );
            memcpy( packet.upcoming_magic, server->upcoming_magic, 8 );
            memcpy( packet.current_magic, server->current_magic, 8 );
            memcpy( packet.previous_magic, server->previous_magic, 8 );

            next_server_internal_send_packet( server, &entry->address, NEXT_UPGRADE_REQUEST_PACKET, &packet );
        }
    }
}

void next_server_internal_update_sessions( next_server_internal_t * server )
{
    next_assert( server );

    next_server_internal_verify_sentinels( server );

    if ( next_global_config.disable_network_next )
        return;

    if ( server->state == NEXT_SERVER_STATE_DIRECT_ONLY )
        return;

    const double current_time = next_time();

    int index = 0;

    while ( index <= server->session_manager->max_entry_index )
    {
        if ( server->session_manager->session_ids[index] == 0 )
        {
            ++index;
            continue;
        }

        next_session_entry_t * entry = &server->session_manager->entries[index];

        if ( !entry->client_ping_timed_out &&
             entry->last_client_direct_ping + NEXT_SERVER_PING_TIMEOUT <= current_time &&
             entry->last_client_next_ping + NEXT_SERVER_PING_TIMEOUT <= current_time )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server client ping timed out for session %" PRIx64, entry->session_id );
            entry->client_ping_timed_out = true;
        }

        // IMPORTANT: Don't time out sessions during server flush. Otherwise the server flush might wait longer than necessary.
        if ( !server->flushing && entry->last_client_stats_update + NEXT_SERVER_SESSION_TIMEOUT <= current_time )
        {
            next_server_notify_session_timed_out_t * notify = (next_server_notify_session_timed_out_t*) next_malloc( server->context, sizeof( next_server_notify_session_timed_out_t ) );
            notify->type = NEXT_SERVER_NOTIFY_SESSION_TIMED_OUT;
            notify->address = entry->address;
            notify->session_id = entry->session_id;
            {
                next_platform_mutex_guard( &server->notify_mutex );
                next_queue_push( server->notify_queue, notify );
            }

            next_platform_mutex_acquire( &server->session_mutex );
            next_session_manager_remove_at_index( server->session_manager, index );
            next_platform_mutex_release( &server->session_mutex );

            continue;
        }

        if ( entry->has_current_route && entry->current_route_expire_time <= current_time )
        {
            // IMPORTANT: Only print this out as an error if it occurs *before* the client ping times out
            // otherwise we get red herring errors on regular client disconnect from server that make it
            // look like something is wrong when everything is fine...
            if ( !entry->client_ping_timed_out )
            {
                next_printf( NEXT_LOG_LEVEL_ERROR, "server network next route expired for session %" PRIx64, entry->session_id );
            }

            entry->has_current_route = false;
            entry->has_previous_route = false;
            entry->update_dirty = false;
            entry->waiting_for_update_response = false;

            next_platform_mutex_acquire( &server->session_mutex );
            entry->mutex_send_over_network_next = false;
            next_platform_mutex_release( &server->session_mutex );
        }

        index++;
    }
}

void next_server_internal_update_flush( next_server_internal_t * server )
{
    if ( !server->flushing )
        return;

    if ( server->flushed )
        return;

    if ( next_global_config.disable_network_next || server->state != NEXT_SERVER_STATE_INITIALIZED || 
         ( server->num_flushed_session_updates == server->num_session_updates_to_flush && server->num_flushed_match_data == server->num_match_data_to_flush ) )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "server internal flush completed" );
        
        server->flushed = true;

        next_server_notify_flush_finished_t * notify = (next_server_notify_flush_finished_t*) next_malloc( server->context, sizeof( next_server_notify_flush_finished_t ) );
        notify->type = NEXT_SERVER_NOTIFY_FLUSH_FINISHED;
        {
            next_platform_mutex_guard( &server->notify_mutex );
            next_queue_push( server->notify_queue, notify );
        }
    }
}

void next_server_internal_process_network_next_packet( next_server_internal_t * server, const next_address_t * from, uint8_t * packet_data, int begin, int end )
{
    next_assert( server );
    next_assert( from );
    next_assert( packet_data );
    next_assert( begin >= 0 );
    next_assert( end <= NEXT_MAX_PACKET_BYTES );

    next_server_internal_verify_sentinels( server );

    const int packet_id = packet_data[begin];

#if NEXT_ASSERT
    char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
	next_printf( NEXT_LOG_LEVEL_SPAM, "server received packet type %d from %s (%d bytes)", packet_id, next_address_to_string( from, address_buffer ), packet_bytes );
#endif // #if NEXT_ASSERT

    // run packet filters
    {
        if ( !next_basic_packet_filter( packet_data + begin, end - begin ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server basic packet filter dropped packet" );
            return;
        }

        uint8_t from_address_data[32];
        uint8_t to_address_data[32];
        uint16_t from_address_port;
        uint16_t to_address_port;
        int from_address_bytes;
        int to_address_bytes;

        next_address_data( from, from_address_data, &from_address_bytes, &from_address_port );
        next_address_data( &server->server_address, to_address_data, &to_address_bytes, &to_address_port );

        if ( packet_id != NEXT_BACKEND_SERVER_INIT_REQUEST_PACKET &&
             packet_id != NEXT_BACKEND_SERVER_INIT_RESPONSE_PACKET &&
             packet_id != NEXT_BACKEND_SERVER_UPDATE_REQUEST_PACKET &&
             packet_id != NEXT_BACKEND_SERVER_UPDATE_RESPONSE_PACKET &&
             packet_id != NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET && 
             packet_id != NEXT_BACKEND_MATCH_DATA_RESPONSE_PACKET )
        {
            if ( !next_advanced_packet_filter( packet_data + begin, server->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, end - begin ) )
            {
                if ( !next_advanced_packet_filter( packet_data + begin, server->upcoming_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, end - begin ) )
                {
                    if ( !next_advanced_packet_filter( packet_data + begin, server->previous_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, end - begin ) )
                    {
                        next_printf( NEXT_LOG_LEVEL_DEBUG, "server advanced packet filter dropped packet" );
                        return;
                    }
                }
            }
        }
        else
        {
            uint8_t magic[8];
            memset( magic, 0, sizeof(magic) );
            if ( !next_advanced_packet_filter( packet_data + begin, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, end - begin ) )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server advanced packet filter dropped packet (backend)" );
                return;
            }
        }
    }

    begin += 16;
    end -= 2;

    if ( server->state == NEXT_SERVER_STATE_INITIALIZING )
    {
        // server init response

        if ( packet_id == NEXT_BACKEND_SERVER_INIT_RESPONSE_PACKET )
        {
            if ( server->state != NEXT_SERVER_STATE_INITIALIZING )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored init response packet from backend. server is not initializing" );
                return;
            }

            NextBackendServerInitResponsePacket packet;

            if ( next_read_backend_packet( packet_id, packet_data, begin, end, &packet, next_signed_packets, next_server_backend_public_key ) != packet_id )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored server init response packet from backend. packet failed to read" );
                return;
            }

            if ( packet.request_id != server->server_init_request_id )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored server init response packet from backend. request id mismatch (got %" PRIx64 ", expected %" PRIx64 ")", packet.request_id, server->server_init_request_id );
                return;
            }

            next_printf( NEXT_LOG_LEVEL_INFO, "server received init response from backend" );

            if ( packet.response != NEXT_SERVER_INIT_RESPONSE_OK )
            {
                switch ( packet.response )
                {
                    case NEXT_SERVER_INIT_RESPONSE_UNKNOWN_CUSTOMER:
                        next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to initialize with backend. unknown customer" );
                        return;

                    case NEXT_SERVER_INIT_RESPONSE_UNKNOWN_DATACENTER:
                        next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to initialize with backend. unknown datacenter" );
                        return;

                    case NEXT_SERVER_INIT_RESPONSE_SDK_VERSION_TOO_OLD:
                        next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to initialize with backend. sdk version too old" );
                        return;

                    case NEXT_SERVER_INIT_RESPONSE_SIGNATURE_CHECK_FAILED:
                        next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to initialize with backend. signature check failed" );
                        return;

                    case NEXT_SERVER_INIT_RESPONSE_CUSTOMER_NOT_ACTIVE:
                        next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to initialize with backend. customer not active" );
                        return;

                    case NEXT_SERVER_INIT_RESPONSE_DATACENTER_NOT_ENABLED:
                        next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to initialize with backend. datacenter not enabled" );
                        return;

                    default:
                        next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to initialize with backend" );
                        return;
                }
            }

            next_printf( NEXT_LOG_LEVEL_INFO, "welcome to network next :)" );

            server->received_init_response = true;

            memcpy( server->upcoming_magic, packet.upcoming_magic, 8 );
            memcpy( server->current_magic, packet.current_magic, 8 );
            memcpy( server->previous_magic, packet.previous_magic, 8 );

            next_printf( NEXT_LOG_LEVEL_DEBUG, "server initial magic: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x | %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x | %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x",
                packet.upcoming_magic[0],
                packet.upcoming_magic[1],
                packet.upcoming_magic[2],
                packet.upcoming_magic[3],
                packet.upcoming_magic[4],
                packet.upcoming_magic[5],
                packet.upcoming_magic[6],
                packet.upcoming_magic[7],
                packet.current_magic[0],
                packet.current_magic[1],
                packet.current_magic[2],
                packet.current_magic[3],
                packet.current_magic[4],
                packet.current_magic[5],
                packet.current_magic[6],
                packet.current_magic[7],
                packet.previous_magic[0],
                packet.previous_magic[1],
                packet.previous_magic[2],
                packet.previous_magic[3],
                packet.previous_magic[4],
                packet.previous_magic[5],
                packet.previous_magic[6],
                packet.previous_magic[7] );

            next_server_notify_magic_updated_t * notify = (next_server_notify_magic_updated_t*) next_malloc( server->context, sizeof( next_server_notify_magic_updated_t ) );
            notify->type = NEXT_SERVER_NOTIFY_MAGIC_UPDATED;
            memcpy( notify->current_magic, server->current_magic, 8 );
            {
                next_platform_mutex_guard( &server->notify_mutex );
                next_queue_push( server->notify_queue, notify );
            }

            return;
        }
    }

    // don't process network next packets until the server is initialized

    if ( server->state != NEXT_SERVER_STATE_INITIALIZED )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored network next packet because it is not initialized" );
        return;
    }

    // direct packet

    if ( packet_id == NEXT_DIRECT_PACKET )
    {
        next_printf( NEXT_LOG_LEVEL_SPAM, "server processing direct packet" );

        const int packet_bytes = end - begin;

        if ( packet_bytes <= 9 )
        {
            char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored direct packet from %s. packet is too small to be valid", next_address_to_string( from, address_buffer ) );
            return;
        }

        if ( packet_bytes > NEXT_MTU + 9 )
        {
            char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored direct packet from %s. packet is too large to be valid", next_address_to_string( from, address_buffer ) );
            return;
        }

        const uint8_t * p = packet_data + begin;

        uint8_t packet_session_sequence = next_read_uint8( &p );

        uint64_t packet_sequence = next_read_uint64( &p );

        next_session_entry_t * entry = next_session_manager_find_by_address( server->session_manager, from );
        if ( !entry )
        {
            char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored direct packet from %s. could not find session for address", next_address_to_string( from, address_buffer ) );
            return;
        }

        if ( packet_session_sequence != entry->client_open_session_sequence )
        {
            char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored direct packet from %s. session mismatch", next_address_to_string( from, address_buffer ) );
            return;
        }

        uint64_t clean_sequence = next_clean_sequence( packet_sequence );

        if ( next_replay_protection_already_received( &entry->payload_replay_protection, clean_sequence ) )
            return;

        next_replay_protection_advance_sequence( &entry->payload_replay_protection, clean_sequence );

        next_packet_loss_tracker_packet_received( &entry->packet_loss_tracker, clean_sequence );

        next_out_of_order_tracker_packet_received( &entry->out_of_order_tracker, clean_sequence );

        next_jitter_tracker_packet_received( &entry->jitter_tracker, clean_sequence, next_time() );

        next_server_notify_packet_received_t * notify = (next_server_notify_packet_received_t*) next_malloc( server->context, sizeof( next_server_notify_packet_received_t ) );
        notify->type = NEXT_SERVER_NOTIFY_PACKET_RECEIVED;
        notify->from = *from;
        notify->packet_bytes = packet_bytes - 9;
        next_assert( notify->packet_bytes > 0 );
        next_assert( notify->packet_bytes <= NEXT_MTU );
        memcpy( notify->packet_data, packet_data + begin + 9, size_t(notify->packet_bytes) );
        {
            next_platform_mutex_guard( &server->notify_mutex );
            next_queue_push( server->notify_queue, notify );
        }

        return;
    }

    // backend server response

    if ( packet_id == NEXT_BACKEND_SERVER_UPDATE_RESPONSE_PACKET )
    {
        next_printf( NEXT_LOG_LEVEL_SPAM, "server processing server update response packet" );

        NextBackendServerUpdateResponsePacket packet;

        if ( next_read_backend_packet( packet_id, packet_data, begin, end, &packet, next_signed_packets, next_server_backend_public_key ) != packet_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored server update response packet from backend. packet failed to read" );
            return;
        }

        if ( packet.request_id != server->server_update_request_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored server update response packet from backend. request id does not match" );
            return;
        }

        next_printf( NEXT_LOG_LEVEL_DEBUG, "server received server update response packet from backend" );

        server->server_update_request_id = 0;
        server->server_update_resend_time = 0.0;

        if ( memcmp( packet.upcoming_magic, server->upcoming_magic, 8 ) != 0 )
        {
            memcpy( server->upcoming_magic, packet.upcoming_magic, 8 );
            memcpy( server->current_magic, packet.current_magic, 8 );
            memcpy( server->previous_magic, packet.previous_magic, 8 );

            next_printf( NEXT_LOG_LEVEL_DEBUG, "server updated magic: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x | %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x | %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x",
                packet.upcoming_magic[0],
                packet.upcoming_magic[1],
                packet.upcoming_magic[2],
                packet.upcoming_magic[3],
                packet.upcoming_magic[4],
                packet.upcoming_magic[5],
                packet.upcoming_magic[6],
                packet.upcoming_magic[7],
                packet.current_magic[0],
                packet.current_magic[1],
                packet.current_magic[2],
                packet.current_magic[3],
                packet.current_magic[4],
                packet.current_magic[5],
                packet.current_magic[6],
                packet.current_magic[7],
                packet.previous_magic[0],
                packet.previous_magic[1],
                packet.previous_magic[2],
                packet.previous_magic[3],
                packet.previous_magic[4],
                packet.previous_magic[5],
                packet.previous_magic[6],
                packet.previous_magic[7] );

            next_server_notify_magic_updated_t * notify = (next_server_notify_magic_updated_t*) next_malloc( server->context, sizeof( next_server_notify_magic_updated_t ) );
            notify->type = NEXT_SERVER_NOTIFY_MAGIC_UPDATED;
            memcpy( notify->current_magic, server->current_magic, 8 );
            {
                next_platform_mutex_guard( &server->notify_mutex );
                next_queue_push( server->notify_queue, notify );
            }
        }
    }

    // backend session response

    if ( packet_id == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET )
    {
        next_printf( NEXT_LOG_LEVEL_SPAM, "server processing session update response packet" );

        NextBackendSessionUpdateResponsePacket packet;

        if ( next_read_backend_packet( packet_id, packet_data, begin, end, &packet, next_signed_packets, next_server_backend_public_key ) != packet_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored session update response packet from backend. packet failed to read" );
            return;
        }

        next_session_entry_t * entry = next_session_manager_find_by_session_id( server->session_manager, packet.session_id );
        if ( !entry )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored session update response packet from backend. could not find session %" PRIx64, packet.session_id );
            return;
        }

        if ( !entry->waiting_for_update_response )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored session update response packet from backend. not waiting for session response" );
            return;
        }

        if ( packet.slice_number != entry->update_sequence - 1 )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored session update response packet from backend. wrong sequence number" );
            return;
        }

        const char * update_type = "???";

        switch ( packet.response_type )
        {
            case NEXT_UPDATE_TYPE_DIRECT:    update_type = "direct route";     break;
            case NEXT_UPDATE_TYPE_ROUTE:     update_type = "next route";       break;
            case NEXT_UPDATE_TYPE_CONTINUE:  update_type = "continue route";   break;
        }

        next_printf( NEXT_LOG_LEVEL_DEBUG, "server received session update response from backend for session %" PRIx64 " (%s)", entry->session_id, update_type );

        bool multipath = packet.multipath;

        if ( multipath && !entry->multipath )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server multipath enabled for session %" PRIx64, entry->session_id );
            entry->multipath = true;
            next_platform_mutex_acquire( &server->session_mutex );
            entry->mutex_multipath = true;
            next_platform_mutex_release( &server->session_mutex );
        }

        entry->update_dirty = true;

        entry->update_type = (uint8_t) packet.response_type;

        entry->update_num_tokens = packet.num_tokens;

        if ( packet.response_type == NEXT_UPDATE_TYPE_ROUTE )
        {
            memcpy( entry->update_tokens, packet.tokens, NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES * size_t(packet.num_tokens) );
        }
        else if ( packet.response_type == NEXT_UPDATE_TYPE_CONTINUE )
        {
            memcpy( entry->update_tokens, packet.tokens, NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES * size_t(packet.num_tokens) );
        }

        entry->update_has_near_relays = packet.has_near_relays;
        if ( packet.has_near_relays )
        {
            entry->update_num_near_relays = packet.num_near_relays;
            memcpy( entry->update_near_relay_ids, packet.near_relay_ids, 8 * size_t(packet.num_near_relays) );
            memcpy( entry->update_near_relay_addresses, packet.near_relay_addresses, sizeof(next_address_t) * size_t(packet.num_near_relays) );
        }

        entry->update_last_send_time = -1000.0;

        entry->session_data_bytes = packet.session_data_bytes;
        memcpy( entry->session_data, packet.session_data, packet.session_data_bytes );
        memcpy( entry->session_data_signature, packet.session_data_signature, NEXT_CRYPTO_SIGN_BYTES );

        entry->waiting_for_update_response = false;

        if ( packet.response_type == NEXT_UPDATE_TYPE_DIRECT )
        {
            bool session_transitions_to_direct = false;

            next_platform_mutex_acquire( &server->session_mutex );
            if ( entry->mutex_send_over_network_next )
            {
                entry->mutex_send_over_network_next = false;
                session_transitions_to_direct = true;
            }
            next_platform_mutex_release( &server->session_mutex );

            if ( session_transitions_to_direct )
            {
                entry->has_previous_route = entry->has_current_route;
                entry->has_current_route = false;
                entry->previous_route_send_address = entry->current_route_send_address;
                memcpy( entry->previous_route_private_key, entry->current_route_private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );
            }
        }

        entry->has_debug = packet.has_debug;
        memcpy( entry->debug, packet.debug, NEXT_MAX_SESSION_DEBUG );

        if ( entry->previous_server_events != 0 )
        {   
            char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server flushed game events %x to backend for session %" PRIx64 " at address %s", entry->previous_server_events, entry->session_id, next_address_to_string( from, address_buffer ));
            entry->previous_server_events = 0;
        }

        if ( entry->session_update_flush && entry->session_update_request_packet.client_ping_timed_out && packet.slice_number == entry->session_flush_update_sequence - 1 )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server flushed session update for session %" PRIx64 " to backend", entry->session_id );
            entry->session_update_flush_finished = true;
            server->num_flushed_session_updates++;
        }

        return;
    }

    // match data response

    if ( packet_id == NEXT_BACKEND_MATCH_DATA_RESPONSE_PACKET)
    {
        next_printf( NEXT_LOG_LEVEL_SPAM, "server processing match data response packet" );

        if ( server->state != NEXT_SERVER_STATE_INITIALIZED )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored session response packet from backend. server is not initialized" );
            return;
        }

        NextBackendMatchDataResponsePacket packet;
        memset( &packet, 0, sizeof(packet) );

        if ( next_read_backend_packet( packet_id, packet_data, begin, end, &packet, next_signed_packets, next_server_backend_public_key ) != packet_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored match data response packet from backend. packet failed to read" );
            return;
        }

        next_session_entry_t * entry = next_session_manager_find_by_session_id( server->session_manager, packet.session_id );
        if ( !entry )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored match data response packet from backend. could not find session %" PRIx64, packet.session_id );
            return;
        }

        if ( !entry->waiting_for_match_data_response )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored match data response packet from backend. not waiting for match data response" );
            return;
        }

        entry->match_data_response_received = true;
        entry->waiting_for_match_data_response = false;

        if ( entry->match_data_flush )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server flushed match data for session %" PRIx64 " to backend", entry->session_id );
            entry->match_data_flush_finished = true;
            server->num_flushed_match_data++;
        }
        else
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server successfully recorded match data for session %" PRIx64 " with backend", packet.session_id );
        }

        return;
    }

    // upgrade response packet

    if ( packet_id == NEXT_UPGRADE_RESPONSE_PACKET )
    {
        next_printf( NEXT_LOG_LEVEL_SPAM, "server processing upgrade response packet" );

        NextUpgradeResponsePacket packet;

        if ( next_read_packet( NEXT_UPGRADE_RESPONSE_PACKET, packet_data, begin, end, &packet, next_signed_packets, NULL, NULL, NULL, NULL, NULL ) != packet_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored upgrade response packet. did not read" );
            return;
        }

        NextUpgradeToken upgrade_token;

        // does the session already exist? if so we still need to reply with upgrade commit in case of server -> client packet loss

        bool upgraded = false;

        next_session_entry_t * existing_entry = next_session_manager_find_by_address( server->session_manager, from );

        if ( existing_entry )
        {
            if ( !upgrade_token.Read( packet.upgrade_token, existing_entry->ephemeral_private_key ) )
            {
                char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored upgrade response from %s. could not decrypt upgrade token (existing entry)", next_address_to_string( from, address_buffer ) );
                return;
            }

            if ( upgrade_token.session_id != existing_entry->session_id )
            {
                char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored upgrade response from %s. session id does not match existing entry", next_address_to_string( from, address_buffer ) );
                return;
            }

            if ( !next_address_equal( &upgrade_token.client_address, &existing_entry->address ) )
            {
                char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored upgrade response from %s. client address does not match existing entry", next_address_to_string( from, address_buffer ) );
                return;
            }
        }
        else
        {
            // session does not exist yet. look up pending upgrade entry...

            next_pending_session_entry_t * pending_entry = next_pending_session_manager_find( server->pending_session_manager, from );
            if ( pending_entry == NULL )
            {
                char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored upgrade response from %s. does not match any pending upgrade", next_address_to_string( from, address_buffer ) );
                return;
            }

            if ( !upgrade_token.Read( packet.upgrade_token, pending_entry->private_key ) )
            {
                char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored upgrade response from %s. could not decrypt upgrade token", next_address_to_string( from, address_buffer ) );
                return;
            }

            if ( upgrade_token.session_id != pending_entry->session_id )
            {
                char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored upgrade response from %s. session id does not match pending upgrade entry", next_address_to_string( from, address_buffer ) );
                return;
            }

            if ( !next_address_equal( &upgrade_token.client_address, &pending_entry->address ) )
            {
                char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored upgrade response from %s. client address does not match pending upgrade entry", next_address_to_string( from, address_buffer ) );
                return;
            }

            uint8_t server_send_key[NEXT_CRYPTO_KX_SESSIONKEYBYTES];
            uint8_t server_receive_key[NEXT_CRYPTO_KX_SESSIONKEYBYTES];
            if ( next_crypto_kx_server_session_keys( server_receive_key, server_send_key, server->server_kx_public_key, server->server_kx_private_key, packet.client_kx_public_key ) != 0 )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server could not generate session keys from client public key" );
                return;
            }

            // remove from pending upgrade

            next_pending_session_manager_remove_by_address( server->pending_session_manager, from );

            // add to established sessions

            next_platform_mutex_acquire( &server->session_mutex );
            next_session_entry_t * entry = next_session_manager_add( server->session_manager, &pending_entry->address, pending_entry->session_id, pending_entry->private_key, pending_entry->upgrade_token, pending_entry->tags, pending_entry->num_tags );
            next_platform_mutex_release( &server->session_mutex );
            if ( entry == NULL )
            {
                char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_ERROR, "server ignored upgrade response from %s. failed to add session", next_address_to_string( from, address_buffer ) );
                return;
            }

            memcpy( entry->send_key, server_send_key, NEXT_CRYPTO_KX_SESSIONKEYBYTES );
            memcpy( entry->receive_key, server_receive_key, NEXT_CRYPTO_KX_SESSIONKEYBYTES );
            memcpy( entry->client_route_public_key, packet.client_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES );
            entry->last_client_stats_update = next_time();
            entry->user_hash = pending_entry->user_hash;
            entry->client_open_session_sequence = packet.client_open_session_sequence;
            entry->stats_platform_id = packet.platform_id;
            entry->stats_connection_type = packet.connection_type;
            entry->last_upgraded_packet_receive_time = next_time();

            // notify session upgraded

            next_server_notify_session_upgraded_t * notify = (next_server_notify_session_upgraded_t*) next_malloc( server->context, sizeof( next_server_notify_session_upgraded_t ) );
            notify->type = NEXT_SERVER_NOTIFY_SESSION_UPGRADED;
            notify->address = entry->address;
            notify->session_id = entry->session_id;
            {
                next_platform_mutex_guard( &server->notify_mutex );
                next_queue_push( server->notify_queue, notify );
            }

            char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server received upgrade response packet from client %s", next_address_to_string( from, address_buffer ) );

            upgraded = true;
        }

        if ( !next_address_equal( &upgrade_token.client_address, from ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored upgrade response. client address does not match from address" );
            return;
        }

        if ( upgrade_token.expire_timestamp < uint64_t(next_time()) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored upgrade response. upgrade token expired" );
            return;
        }

        if ( !next_address_equal( &upgrade_token.client_address, from ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored upgrade response. client address does not match from address" );
            return;
        }

        if ( !next_address_equal( &upgrade_token.server_address, &server->server_address ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored upgrade response. server address does not match" );
            return;
        }

        next_post_validate_packet( NEXT_UPGRADE_RESPONSE_PACKET, NULL, NULL, NULL );
        
        if ( !upgraded )
        {
            char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server received upgrade response packet from %s", next_address_to_string( from, address_buffer ) );
        }

        // reply with upgrade confirm

        NextUpgradeConfirmPacket response;
        response.upgrade_sequence = server->upgrade_sequence++;
        response.session_id = upgrade_token.session_id;
        response.server_address = server->server_address;
        memcpy( response.client_kx_public_key, packet.client_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES );
        memcpy( response.server_kx_public_key, server->server_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES );

        if ( next_server_internal_send_packet( server, from, NEXT_UPGRADE_CONFIRM_PACKET, &response ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "server could not send upgrade confirm packet" );
            return;
        }

        char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
        next_printf( NEXT_LOG_LEVEL_DEBUG, "server sent upgrade confirm packet to client %s", next_address_to_string( from, address_buffer ) );

        return;
    }

    // -------------------
    // PACKETS FROM RELAYS
    // -------------------

    if ( packet_id == NEXT_ROUTE_REQUEST_PACKET )
    {
        next_printf( NEXT_LOG_LEVEL_SPAM, "server processing route request packet" );

        const int packet_bytes = end - begin;

        if ( packet_bytes != NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored route request packet. wrong size" );
            return;
        }

        uint8_t * buffer = packet_data + begin;
        next_route_token_t route_token;
        if ( next_read_encrypted_route_token( &buffer, &route_token, next_router_public_key, server->server_route_private_key ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored route request packet. bad route" );
            return;
        }

        next_session_entry_t * entry = next_session_manager_find_by_session_id( server->session_manager, route_token.session_id );
        if ( !entry )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored route request packet. could not find session %" PRIx64, route_token.session_id );
            return;
        }

        if ( entry->has_current_route && route_token.expire_timestamp < entry->current_route_expire_timestamp )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored route request packet. expire timestamp is older than current route" );
            return;
        }

        if ( entry->has_current_route && next_sequence_greater_than( entry->most_recent_session_version, route_token.session_version ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored route request packet. route is older than most recent session (%d vs. %d)", route_token.session_version, entry->most_recent_session_version );
            return;
        }

        next_printf( NEXT_LOG_LEVEL_DEBUG, "server received route request packet from relay for session %" PRIx64, route_token.session_id );

        if ( next_sequence_greater_than( route_token.session_version, entry->pending_route_session_version ) )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server added pending route for session %" PRIx64, route_token.session_id );
            entry->has_pending_route = true;
            entry->pending_route_session_version = route_token.session_version;
            entry->pending_route_expire_timestamp = route_token.expire_timestamp;
            entry->pending_route_expire_time = entry->has_current_route ? ( entry->current_route_expire_time + NEXT_SLICE_SECONDS * 2 ) : ( next_time() + NEXT_SLICE_SECONDS * 2 );
            entry->pending_route_kbps_up = route_token.kbps_up;
            entry->pending_route_kbps_down = route_token.kbps_down;
            entry->pending_route_send_address = *from;
            memcpy( entry->pending_route_private_key, route_token.private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );
            entry->most_recent_session_version = route_token.session_version;
        }

        uint64_t session_send_sequence = entry->special_send_sequence++;

        uint8_t from_address_data[4];
        uint8_t to_address_data[4];
        uint16_t from_address_port;
        uint16_t to_address_port;
        int from_address_bytes;
        int to_address_bytes;

        next_address_data( &server->server_address, from_address_data, &from_address_bytes, &from_address_port );
        next_address_data( from, to_address_data, &to_address_bytes, &to_address_port );

        uint8_t response_data[NEXT_MAX_PACKET_BYTES];

        int response_bytes = next_write_route_response_packet( response_data, session_send_sequence, entry->session_id, entry->pending_route_session_version, entry->pending_route_private_key, server->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port );

        next_assert( response_bytes > 0 );

        next_assert( next_basic_packet_filter( response_data, response_bytes ) );
        next_assert( next_advanced_packet_filter( response_data, server->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, response_bytes ) );

        next_server_internal_send_packet_to_address( server, from, response_data, response_bytes );

        next_printf( NEXT_LOG_LEVEL_DEBUG, "server sent route response packet to relay for session %" PRIx64, entry->session_id );

        return;
    }

    // continue request packet

    if ( packet_id == NEXT_CONTINUE_REQUEST_PACKET )
    {
        next_printf( NEXT_LOG_LEVEL_SPAM, "server processing continue request packet" );

        const int packet_bytes = end - begin;

        if ( packet_bytes != NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored continue request packet. wrong size" );
            return;
        }

        uint8_t * buffer = packet_data + begin;
        next_continue_token_t continue_token;
        if ( next_read_encrypted_continue_token( &buffer, &continue_token, next_router_public_key, server->server_route_private_key ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored continue request packet from relay. bad token" );
            return;
        }

        next_session_entry_t * entry = next_session_manager_find_by_session_id( server->session_manager, continue_token.session_id );
        if ( !entry )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored continue request packet from relay. could not find session %" PRIx64, continue_token.session_id );
            return;
        }

        if ( !entry->has_current_route )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored continue request packet from relay. session has no route to continue" );
            return;
        }

        if ( continue_token.session_version != entry->current_route_session_version )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored continue request packet from relay. session version does not match" );
            return;
        }

        if ( continue_token.expire_timestamp < entry->current_route_expire_timestamp )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored continue request packet from relay. expire timestamp is older than current route" );
            return;
        }

        next_printf( NEXT_LOG_LEVEL_DEBUG, "server received continue request packet from relay for session %" PRIx64, continue_token.session_id );

        entry->current_route_expire_timestamp = continue_token.expire_timestamp;
        entry->current_route_expire_time += NEXT_SLICE_SECONDS;
        entry->has_previous_route = false;

        uint64_t session_send_sequence = entry->special_send_sequence++;

        uint8_t from_address_data[4];
        uint8_t to_address_data[4];
        uint16_t from_address_port;
        uint16_t to_address_port;
        int from_address_bytes;
        int to_address_bytes;

        next_address_data( &server->server_address, from_address_data, &from_address_bytes, &from_address_port );
        next_address_data( from, to_address_data, &to_address_bytes, &to_address_port );

        uint8_t response_data[NEXT_MAX_PACKET_BYTES];

        int response_bytes = next_write_continue_response_packet( response_data, session_send_sequence, entry->session_id, entry->current_route_session_version, entry->current_route_private_key, server->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port );

        next_assert( response_bytes > 0 );

        next_assert( next_basic_packet_filter( response_data, response_bytes ) );
        next_assert( next_advanced_packet_filter( response_data, server->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, response_bytes ) );

        next_server_internal_send_packet_to_address( server, from, response_data, response_bytes );

        next_printf( NEXT_LOG_LEVEL_DEBUG, "server sent continue response packet to relay for session %" PRIx64, entry->session_id );

        return;
    }

    // client to server packet

    if ( packet_id == NEXT_CLIENT_TO_SERVER_PACKET )
    {
        next_printf( NEXT_LOG_LEVEL_SPAM, "server processing client to server packet" );

        const int packet_bytes = end - begin;

        if ( packet_bytes <= NEXT_HEADER_BYTES )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored client to server packet. packet too small to be valid" );
            return;
        }

        next_session_entry_t * entry = next_server_internal_process_client_to_server_packet( server, packet_id, packet_data + begin, packet_bytes );
        if ( !entry )
        {
            // IMPORTANT: There is no need to log this case, because next_server_internal_process_client_to_server_packet already
            // logs all cases where it returns NULL to the debug log. Logging here duplicates the log and incorrectly prints
            // out an error when the packet has already been received on the direct path, when multipath is enabled.
            return;
        }

        next_server_notify_packet_received_t * notify = (next_server_notify_packet_received_t*) next_malloc( server->context, sizeof( next_server_notify_packet_received_t ) );
        notify->type = NEXT_SERVER_NOTIFY_PACKET_RECEIVED;
        notify->from = entry->address;
        notify->packet_bytes = packet_bytes - NEXT_HEADER_BYTES;
        next_assert( notify->packet_bytes > 0 );
        next_assert( notify->packet_bytes <= NEXT_MTU );
        memcpy( notify->packet_data, packet_data + begin + NEXT_HEADER_BYTES, size_t(notify->packet_bytes) );
        {
            next_platform_mutex_guard( &server->notify_mutex );
            next_queue_push( server->notify_queue, notify );
        }

        return;
    }

    // ping packet

    if ( packet_id == NEXT_PING_PACKET )
    {
        next_printf( NEXT_LOG_LEVEL_SPAM, "server processing next ping packet" );

        const int packet_bytes = end - begin;

        if ( packet_bytes != NEXT_HEADER_BYTES + 8 )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored next ping packet. bad packet size" );
            return;
        }

        next_session_entry_t * entry = next_server_internal_process_client_to_server_packet( server, packet_id, packet_data + begin, packet_bytes );
        if ( !entry )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored next ping packet. did not verify" );
            return;
        }

        const uint8_t * p = packet_data + begin + NEXT_HEADER_BYTES;

        uint64_t ping_sequence = next_read_uint64( &p );

        entry->last_client_next_ping = next_time();

        uint64_t send_sequence = entry->special_send_sequence++;
        send_sequence |= uint64_t(1) << 63;
        send_sequence |= uint64_t(1) << 62;

        uint8_t from_address_data[4];
        uint8_t to_address_data[4];
        uint16_t from_address_port;
        uint16_t to_address_port;
        int from_address_bytes;
        int to_address_bytes;

        next_address_data( &server->server_address, from_address_data, &from_address_bytes, &from_address_port );
        next_address_data( from, to_address_data, &to_address_bytes, &to_address_port );

        uint8_t pong_packet_data[NEXT_MAX_PACKET_BYTES];

        int pong_packet_bytes = next_write_pong_packet( pong_packet_data, send_sequence, entry->session_id, entry->current_route_session_version, entry->current_route_private_key, ping_sequence, server->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port );

        next_assert( pong_packet_bytes > 0 );

        next_assert( next_basic_packet_filter( pong_packet_data, pong_packet_bytes ) );
        next_assert( next_advanced_packet_filter( pong_packet_data, server->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, pong_packet_bytes ) );

        next_server_internal_send_packet_to_address( server, from, pong_packet_data, pong_packet_bytes );

        return;
    }

    // ----------------------------------
    // ENCRYPTED CLIENT TO SERVER PACKETS
    // ----------------------------------

    next_session_entry_t * session = NULL;

    if ( next_encrypted_packets[packet_id] )
    {
        session = next_session_manager_find_by_address( server->session_manager, from );
        if ( !session )
        {
	        next_printf( NEXT_LOG_LEVEL_SPAM, "server dropped encrypted packet because it couldn't find any session for it" );
            return;
        }

        session->last_upgraded_packet_receive_time = next_time();
    }

    // direct ping packet

    if ( packet_id == NEXT_DIRECT_PING_PACKET )
    {
        next_printf( NEXT_LOG_LEVEL_SPAM, "server processing direct ping packet" );

        next_assert( session );

        if ( session == NULL )
            return;

        uint64_t packet_sequence = 0;

        NextDirectPingPacket packet;
        if ( next_read_packet( NEXT_DIRECT_PING_PACKET, packet_data, begin, end, &packet, next_signed_packets, next_encrypted_packets, &packet_sequence, NULL, session->receive_key, &session->internal_replay_protection ) != packet_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored direct ping packet. could not read" );
            return;
        }

        session->last_client_direct_ping = next_time();

        next_post_validate_packet( NEXT_DIRECT_PING_PACKET, next_encrypted_packets, &packet_sequence, &session->internal_replay_protection );

        NextDirectPongPacket response;
        response.ping_sequence = packet.ping_sequence;

        if ( next_server_internal_send_packet( server, from, NEXT_DIRECT_PONG_PACKET, &response ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server could not send upgrade confirm packet" );
            return;
        }

        return;
    }

    // client stats packet

    if ( packet_id == NEXT_CLIENT_STATS_PACKET )
    {
        next_printf( NEXT_LOG_LEVEL_SPAM, "server processing client stats packet" );

        next_assert( session );

        if ( session == NULL )
            return;

        NextClientStatsPacket packet;

        uint64_t packet_sequence = 0;

        if ( next_read_packet( NEXT_CLIENT_STATS_PACKET, packet_data, begin, end, &packet, next_signed_packets, next_encrypted_packets, &packet_sequence, NULL, session->receive_key, &session->internal_replay_protection ) != packet_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored client stats packet. could not read" );
            return;
        }

        next_post_validate_packet( NEXT_CLIENT_STATS_PACKET, next_encrypted_packets, &packet_sequence, &session->internal_replay_protection );

        if ( packet_sequence > session->stats_sequence )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server received client stats packet for session %" PRIx64, session->session_id );

            if ( !session->stats_fallback_to_direct && packet.fallback_to_direct )
            {
                next_printf( NEXT_LOG_LEVEL_INFO, "server session fell back to direct %" PRIx64, session->session_id );
            }

            session->stats_sequence = packet_sequence;

            session->stats_reported = packet.reported;
            session->stats_multipath = packet.multipath;
            session->stats_fallback_to_direct = packet.fallback_to_direct;
            if ( packet.next_bandwidth_over_limit )
            {
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server session sees client over next bandwidth limit %" PRIx64, session->session_id );
                session->stats_client_bandwidth_over_limit = true;
            }

            session->stats_platform_id = packet.platform_id;
            session->stats_connection_type = packet.connection_type;
            session->stats_direct_kbps_up = packet.direct_kbps_up;
            session->stats_direct_kbps_down = packet.direct_kbps_down;
            session->stats_next_kbps_up = packet.next_kbps_up;
            session->stats_next_kbps_down = packet.next_kbps_down;
            session->stats_direct_rtt = packet.direct_rtt;
            session->stats_direct_jitter = packet.direct_jitter;
            session->stats_direct_packet_loss = packet.direct_packet_loss;
            session->stats_direct_max_packet_loss_seen = packet.direct_max_packet_loss_seen;
            session->stats_next = packet.next;
            session->stats_next_rtt = packet.next_rtt;
            session->stats_next_jitter = packet.next_jitter;
            session->stats_next_packet_loss = packet.next_packet_loss;
            session->stats_has_near_relay_pings = packet.num_near_relays > 0;
            session->stats_num_near_relays = packet.num_near_relays;
            for ( int i = 0; i < packet.num_near_relays; ++i )
            {
                session->stats_near_relay_ids[i] = packet.near_relay_ids[i];
                session->stats_near_relay_rtt[i] = packet.near_relay_rtt[i];
                session->stats_near_relay_jitter[i] = packet.near_relay_jitter[i];
                session->stats_near_relay_packet_loss[i] = packet.near_relay_packet_loss[i];
            }
            session->stats_packets_sent_client_to_server = packet.packets_sent_client_to_server;
            session->stats_packets_lost_server_to_client = packet.packets_lost_server_to_client;
            session->stats_jitter_server_to_client = packet.jitter_server_to_client;
            session->last_client_stats_update = next_time();
        }

        return;
    }

    // route update ack packet

    if ( packet_id == NEXT_ROUTE_UPDATE_ACK_PACKET && session != NULL )
    {
        next_printf( NEXT_LOG_LEVEL_SPAM, "server processing route update ack packet" );

        NextRouteUpdateAckPacket packet;

        uint64_t packet_sequence = 0;

        if ( next_read_packet( NEXT_ROUTE_UPDATE_ACK_PACKET, packet_data, begin, end, &packet, next_signed_packets, next_encrypted_packets, &packet_sequence, NULL, session->receive_key, &session->internal_replay_protection ) != packet_id )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored client stats packet. could not read" );
            return;
        }

        if ( packet.sequence != session->update_sequence )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server ignored route update ack packet. wrong update sequence number" );
            return;
        }

        next_post_validate_packet( NEXT_ROUTE_UPDATE_ACK_PACKET, next_encrypted_packets, &packet_sequence, &session->internal_replay_protection );

        next_printf( NEXT_LOG_LEVEL_DEBUG, "server received route update ack from client for session %" PRIx64, session->session_id );

        if ( session->update_dirty )
        {
            session->update_dirty = false;
        }

        return;
    }
}

void next_server_internal_process_passthrough_packet( next_server_internal_t * server, const next_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    next_assert( server );
    next_assert( from );
    next_assert( packet_data );

    next_printf( NEXT_LOG_LEVEL_SPAM, "server processing passthrough packet" );

    next_server_internal_verify_sentinels( server );

    if ( packet_bytes > 0 && packet_bytes <= NEXT_MAX_PACKET_BYTES - 1 )
    {
        if ( server->payload_receive_callback )
        {
            void * callback_data = server->payload_receive_callback_data;
            if ( server->payload_receive_callback( callback_data, from, packet_data, packet_bytes ) )
                return;
        }

        next_server_notify_packet_received_t * notify = (next_server_notify_packet_received_t*) next_malloc( server->context, sizeof( next_server_notify_packet_received_t ) );
        notify->type = NEXT_SERVER_NOTIFY_PACKET_RECEIVED;
        notify->from = *from;
        notify->packet_bytes = packet_bytes;
        next_assert( packet_bytes > 0 );
        next_assert( packet_bytes <= NEXT_MAX_PACKET_BYTES - 1 );
        memcpy( notify->packet_data, packet_data, size_t(packet_bytes) );
        {
            next_platform_mutex_guard( &server->notify_mutex );
            next_queue_push( server->notify_queue, notify );
        }
    }
}

void next_server_internal_block_and_receive_packet( next_server_internal_t * server )
{
    next_server_internal_verify_sentinels( server );

    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];

    next_assert( ( size_t(packet_data) % 4 ) == 0 );

    next_address_t from;

    const int packet_bytes = next_platform_socket_receive_packet( server->socket, &from, packet_data, NEXT_MAX_PACKET_BYTES );

    if ( packet_bytes == 0 )
        return;

    next_assert( packet_bytes > 0 );

    int begin = 0;
    int end = packet_bytes;

    if ( server->packet_receive_callback )
    {
        void * callback_data = server->packet_receive_callback_data;

        server->packet_receive_callback( callback_data, &from, packet_data, &begin, &end );

        next_assert( begin >= 0 );
        next_assert( end <= NEXT_MAX_PACKET_BYTES );

        if ( end - begin <= 0 )
            return;        
    }

#if NEXT_DEVELOPMENT
    if ( next_packet_loss && ( rand() % 10 ) == 0 )
         return;
#endif // #if NEXT_DEVELOPMENT

    const uint8_t packet_type = packet_data[begin];

    if ( packet_type != NEXT_PASSTHROUGH_PACKET )
    {
        next_server_internal_process_network_next_packet( server, &from, packet_data, begin, end );
    }
    else
    {
        begin += 1;
        next_server_internal_process_passthrough_packet( server, &from, packet_data + begin, end - begin );
    }
}

void next_server_internal_upgrade_session( next_server_internal_t * server, const next_address_t * address, uint64_t session_id, uint64_t user_hash )
{
    next_assert( server );
    next_assert( address );

    next_server_internal_verify_sentinels( server );

    if ( server->state != NEXT_SERVER_STATE_INITIALIZED )
        return;

    if ( next_global_config.disable_network_next )
        return;

    next_assert( server->state == NEXT_SERVER_STATE_INITIALIZED || server->state == NEXT_SERVER_STATE_DIRECT_ONLY );

    if ( server->state == NEXT_SERVER_STATE_DIRECT_ONLY )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "server cannot upgrade client. direct only mode" );
        return;
    }

    char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];

    next_printf( NEXT_LOG_LEVEL_DEBUG, "server upgrading client %s to session %" PRIx64, next_address_to_string( address, buffer ), session_id );

    NextUpgradeToken upgrade_token;

    upgrade_token.session_id = session_id;
    upgrade_token.expire_timestamp = uint64_t( next_time() ) + 10;
    upgrade_token.client_address = *address;
    upgrade_token.server_address = server->server_address;

    unsigned char session_private_key[NEXT_CRYPTO_SECRETBOX_KEYBYTES];
    next_crypto_secretbox_keygen( session_private_key );

    uint8_t upgrade_token_data[NEXT_UPGRADE_TOKEN_BYTES];

    upgrade_token.Write( upgrade_token_data, session_private_key );

    next_pending_session_manager_remove_by_address( server->pending_session_manager, address );

    next_session_manager_remove_by_address( server->session_manager, address );

    next_pending_session_entry_t * entry = next_pending_session_manager_add( server->pending_session_manager, address, upgrade_token.session_id, session_private_key, upgrade_token_data, next_time() );

    if ( entry == NULL )
    {
        next_assert( !"could not add pending session entry. this should never happen!" );
        return;
    }

    entry->user_hash = user_hash;
}

void next_server_internal_tag_session( next_server_internal_t * server, const next_address_t * address, const uint64_t * tags, int num_tags )
{
    next_assert( server );
    next_assert( address );

    next_server_internal_verify_sentinels( server );

    if ( server->state != NEXT_SERVER_STATE_INITIALIZED )
        return;

    if ( next_global_config.disable_network_next )
        return;

    next_assert( server->state == NEXT_SERVER_STATE_INITIALIZED || server->state == NEXT_SERVER_STATE_DIRECT_ONLY );

    next_pending_session_entry_t * pending_entry = next_pending_session_manager_find( server->pending_session_manager, address );
    if ( pending_entry )
    {
        memset( pending_entry->tags, 0, sizeof(pending_entry->tags) );
        for ( int i = 0; i < num_tags; ++i )
        {
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server tags pending session entry %" PRIx64 " as %" PRIx64 " (internal)", pending_entry->session_id, tags[i] );
            pending_entry->tags[i] = tags[i];
        }
        pending_entry->num_tags = num_tags;
        return;
    }

    next_session_entry_t * entry = next_session_manager_find_by_address( server->session_manager, address );
    if ( entry )
    {
        char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
        next_printf( NEXT_LOG_LEVEL_DEBUG, "could not tag session %s. please tag a session immediately after you upgrade it", next_address_to_string( address, buffer ) );
        return;
    }

    char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_printf( NEXT_LOG_LEVEL_DEBUG, "server could not find any session to tag for address %s", next_address_to_string( address, buffer ) );
}

void next_server_internal_server_events( next_server_internal_t * server, const next_address_t * address, uint64_t server_events )
{
    next_assert( server );
    next_assert( address );

    next_server_internal_verify_sentinels( server );

    if ( server->state != NEXT_SERVER_STATE_INITIALIZED )
        return;

    if ( next_global_config.disable_network_next )
        return;

    next_session_entry_t * entry = next_session_manager_find_by_address( server->session_manager, address );
    if ( !entry )
    {
        char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
        next_printf( NEXT_LOG_LEVEL_DEBUG, "could not find session at address %s. not adding game event %x", next_address_to_string( address, buffer ), server_events );
        return;
    }

    entry->current_server_events |= server_events;
    char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_printf( NEXT_LOG_LEVEL_DEBUG, "server set event %x for session %" PRIx64 " at address %s", server_events, entry->session_id, next_address_to_string( address, buffer ) );
}

void next_server_internal_match_data( next_server_internal_t * server, const next_address_t * address, uint64_t match_id, const double * match_values, int num_match_values )
{
    next_assert( server );
    next_assert( address );

    next_server_internal_verify_sentinels( server );

    if ( server->state != NEXT_SERVER_STATE_INITIALIZED )
        return;

    if ( next_global_config.disable_network_next )
        return;

    next_session_entry_t * entry = next_session_manager_find_by_address( server->session_manager, address );    
    if ( !entry )
    {
        char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
        next_printf( NEXT_LOG_LEVEL_DEBUG, "could not find session at address %s. server not sending match data", next_address_to_string( address, buffer ) );
        return;
    }

    if ( entry->has_match_data || entry->waiting_for_match_data_response || entry->match_data_response_received )
    {
        char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
        next_printf( NEXT_LOG_LEVEL_WARN, "server already sent match data for session %" PRIx64 " at address %s", entry->session_id, next_address_to_string( address, buffer ) );
        return;
    }

    entry->match_id = match_id;
    entry->num_match_values = num_match_values;
    for ( int i = 0; i < num_match_values; ++i )
    {
        entry->match_values[i] = match_values[i];
    }
    entry->has_match_data = true;

    char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_printf( NEXT_LOG_LEVEL_DEBUG, "server adds match data for session %" PRIx64 " at address %s", entry->session_id, next_address_to_string( address, buffer ) );
}

void next_server_internal_flush_session_update( next_server_internal_t * server )
{
    next_assert( server );
    next_assert( server->session_manager );

    const int max_entry_index = server->session_manager->max_entry_index;

    for ( int i = 0; i <= max_entry_index; ++i )
    {
        if ( server->session_manager->session_ids[i] == 0 )
            continue;

        next_session_entry_t * session = &server->session_manager->entries[i];

        session->client_ping_timed_out = true;
        session->session_update_request_packet.client_ping_timed_out = true;

        // IMPORTANT: Make sure to only accept a backend session response for the next session update
        // sent out, not the current session update (if any is in flight). This way flush succeeds
        // even if it called in the middle of a session update in progress.
        session->session_flush_update_sequence = session->update_sequence + 1;
        session->session_update_flush = true;
        server->num_session_updates_to_flush++;
    }
}

void next_server_internal_flush_match_data( next_server_internal_t * server )
{
    next_assert( server );
    next_assert( server->session_manager );

    const int max_entry_index = server->session_manager->max_entry_index;

    for ( int i = 0; i <= max_entry_index; ++i )
    {
        if ( server->session_manager->session_ids[i] == 0 )
            continue;

        next_session_entry_t * session = &server->session_manager->entries[i];

        if ( ( !session->has_match_data ) || ( session->has_match_data && session->match_data_response_received ) )
            continue;

        session->match_data_flush = true;
        server->num_match_data_to_flush++;
    }
}

void next_server_internal_flush( next_server_internal_t * server )
{
    next_assert( server );
    next_assert( server->session_manager );

    next_server_internal_verify_sentinels( server );

    if ( next_global_config.disable_network_next )
    {
        server->flushing = true;
        server->flushed = true;
        return;
    }

    if ( server->flushing )
    {
        next_printf( NEXT_LOG_LEVEL_WARN, "server ignored flush. already flushed" );
        return;
    }

    server->flushing = true;

    next_server_internal_flush_session_update( server );

    next_server_internal_flush_match_data( server );

    next_printf( NEXT_LOG_LEVEL_DEBUG, "server flush started. %d session updates and %d match data to flush", server->num_session_updates_to_flush, server->num_match_data_to_flush );
}

void next_server_internal_pump_commands( next_server_internal_t * server )
{
    while ( true )
    {
        next_server_internal_verify_sentinels( server );

        void * entry = NULL;
        {
            next_platform_mutex_guard( &server->command_mutex );
            entry = next_queue_pop( server->command_queue );
        }

        if ( entry == NULL )
            break;

        next_server_command_t * command = (next_server_command_t*) entry;

        switch ( command->type )
        {
            case NEXT_SERVER_COMMAND_UPGRADE_SESSION:
            {
                next_server_command_upgrade_session_t * upgrade_session = (next_server_command_upgrade_session_t*) command;
                next_server_internal_upgrade_session( server, &upgrade_session->address, upgrade_session->session_id, upgrade_session->user_hash );
            }
            break;

            case NEXT_SERVER_COMMAND_TAG_SESSION:
            {
                next_server_command_tag_session_t * tag_session = (next_server_command_tag_session_t*) command;
                next_server_internal_tag_session( server, &tag_session->address, tag_session->tags, tag_session->num_tags );
            }
            break;

            case NEXT_SERVER_COMMAND_SERVER_EVENT:
            {
                next_server_command_server_event_t * event = (next_server_command_server_event_t*) command;
                next_server_internal_server_events( server, &event->address, event->server_events );
            }
            break;

            case NEXT_SERVER_COMMAND_MATCH_DATA:
            {
                next_server_command_match_data_t * match_data = (next_server_command_match_data_t*) command;
                next_server_internal_match_data( server, &match_data->address, match_data->match_id, match_data->match_values, match_data->num_match_values );
            }
            break;

            case NEXT_SERVER_COMMAND_FLUSH:
            {
                next_server_internal_flush( server );
            }
            break;

            case NEXT_SERVER_COMMAND_SET_PACKET_RECEIVE_CALLBACK:
            {
                next_server_command_set_packet_receive_callback_t * cmd = (next_server_command_set_packet_receive_callback_t*) command;
                server->packet_receive_callback = cmd->callback;
                server->packet_receive_callback_data = cmd->callback_data;
            }
            break;

            case NEXT_SERVER_COMMAND_SET_SEND_PACKET_TO_ADDRESS_CALLBACK:
            {
                next_server_command_set_send_packet_to_address_callback_t * cmd = (next_server_command_set_send_packet_to_address_callback_t*) command;
                server->send_packet_to_address_callback = cmd->callback;
                server->send_packet_to_address_callback_data = cmd->callback_data;
            }
            break;

            case NEXT_SERVER_COMMAND_SET_PAYLOAD_RECEIVE_CALLBACK:
            {
                next_server_command_set_payload_receive_callback_t * cmd = (next_server_command_set_payload_receive_callback_t*) command;
                server->payload_receive_callback = cmd->callback;
                server->payload_receive_callback_data = cmd->callback_data;
            }
            break;

            default: break;
        }

        next_free( server->context, command );
    }
}

static void next_server_internal_resolve_hostname_thread_function( void * context )
{
    next_assert( context );

    double start_time = next_time();

    next_server_internal_t * server = (next_server_internal_t*) context;

    const char * hostname = next_global_config.server_backend_hostname;
    const char * port = NEXT_SERVER_BACKEND_PORT;
    const char * override_port = next_platform_getenv( "NEXT_SERVER_BACKEND_PORT_SDK5" );
    if ( !override_port )
    {
        override_port = next_platform_getenv( "NEXT_SERVER_BACKEND_PORT" );
    }
    if ( !override_port )
    {
        override_port = next_platform_getenv( "NEXT_PORT" );
    }
    if ( override_port )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "override server backend port: '%s'", override_port );
        port = override_port;
    }

    next_printf( NEXT_LOG_LEVEL_INFO, "server resolving backend hostname '%s'", hostname );

    next_address_t address;

    bool success = false;

    // first try to parse the hostname directly as an address, this is a common case in testbeds and there's no reason to actually run a DNS resolve on it

    if ( next_address_parse( &address, hostname ) == NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "server backend hostname is an address" );
        next_assert( address.type == NEXT_ADDRESS_IPV4 || address.type == NEXT_ADDRESS_IPV6 );
        address.port = uint16_t( atoi(port) );
        success = true;
    }    
    else
    {
        // try to resolve the hostname, retry a few times if it doesn't succeed right away

        for ( int i = 0; i < 10; ++i )
        {
            if ( next_platform_hostname_resolve( hostname, port, &address ) == NEXT_OK )
            {
                next_assert( address.type == NEXT_ADDRESS_IPV4 || address.type == NEXT_ADDRESS_IPV6 );
                success = true;
                break;
            }
            else
            {
                next_printf( NEXT_LOG_LEVEL_WARN, "server failed to resolve hostname (%d)", i );
            }
        }
    }

    if ( !success )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to resolve backend hostname: %s", hostname );
        next_platform_mutex_guard( &server->resolve_hostname_mutex );
        server->resolve_hostname_finished = true;
        memset( &server->resolve_hostname_result, 0, sizeof(next_address_t) );
        return;
    }

#if NEXT_DEVELOPMENT
    if ( next_platform_getenv( "NEXT_FORCE_RESOLVE_HOSTNAME_TIMEOUT" ) )
    {
        next_sleep( NEXT_SERVER_RESOLVE_HOSTNAME_TIMEOUT * 2 );
    }
#endif // #if NEXT_DEVELOPMENT

    if ( next_time() - start_time > NEXT_SERVER_AUTODETECT_TIMEOUT )
    {
        // IMPORTANT: if we have timed out, don't grab the mutex or write results. 
        // our thread has been destroyed and if we are unlucky, the next_server_internal_t instance has as well.
        return;
    }

    next_platform_mutex_guard( &server->resolve_hostname_mutex );
    server->resolve_hostname_finished = true;
    server->resolve_hostname_result = address;
}

static bool next_server_internal_update_resolve_hostname( next_server_internal_t * server )
{
    next_assert( server );

    next_server_internal_verify_sentinels( server );

    if ( next_global_config.disable_network_next )
        return true;

    if ( !server->resolving_hostname )
        return true;

    bool finished = false;
    next_address_t result;
    memset( &result, 0, sizeof(next_address_t) );
    {
        next_platform_mutex_guard( &server->resolve_hostname_mutex );
        finished = server->resolve_hostname_finished;
        result = server->resolve_hostname_result;
    }

    if ( finished )
    {
        next_platform_thread_join( server->resolve_hostname_thread );
    }
    else
    {
        if ( next_time() < server->resolve_hostname_start_time + NEXT_SERVER_RESOLVE_HOSTNAME_TIMEOUT )
        {
            // keep waiting
            return false;
        }
        else
        {
            // but don't wait forever...
            next_printf( NEXT_LOG_LEVEL_INFO, "resolve hostname timed out" );
        }
    }
    
    next_platform_thread_destroy( server->resolve_hostname_thread );
    
    server->resolve_hostname_thread = NULL;
    server->resolving_hostname = false;
    server->backend_address = result;

    char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];

    if ( result.type != NEXT_ADDRESS_NONE )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server resolved backend hostname to %s", next_address_to_string( &result, address_buffer ) );
    }
    else
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server failed to resolve backend hostname" );
        server->resolving_hostname = false;
    }

    return true;
}

static void next_server_internal_autodetect_thread_function( void * context )
{
    next_assert( context );

    double start_time = next_time();

    next_server_internal_t * server = (next_server_internal_t*) context;

    bool autodetect_result = false;
    bool autodetect_actually_did_something = false;
    char autodetect_output[NEXT_MAX_DATACENTER_NAME_LENGTH];

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC || NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

    // autodetect datacenter is currently windows and linux only (mac is just for testing...)

    const char * autodetect_input = server->datacenter_name;
    
    char autodetect_address[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_address_t server_address_no_port = server->server_address;
    server_address_no_port.port = 0;
    next_address_to_string( &server_address_no_port, autodetect_address );

    if ( !next_global_config.disable_autodetect &&
         ( autodetect_input[0] == '\0' 
            ||
         ( autodetect_input[0] == 'c' &&
           autodetect_input[1] == 'l' &&
           autodetect_input[2] == 'o' &&
           autodetect_input[3] == 'u' &&
           autodetect_input[4] == 'd' &&
           autodetect_input[5] == '\0' ) 
            ||
         ( autodetect_input[0] == 'm' && 
           autodetect_input[1] == 'u' && 
           autodetect_input[2] == 'l' && 
           autodetect_input[3] == 't' && 
           autodetect_input[4] == 'i' && 
           autodetect_input[5] == 'p' && 
           autodetect_input[6] == 'l' && 
           autodetect_input[7] == 'a' && 
           autodetect_input[8] == 'y' && 
           autodetect_input[9] == '.' ) ) )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server attempting to autodetect datacenter" );

        autodetect_result = next_autodetect_datacenter( autodetect_input, autodetect_address, autodetect_output, sizeof(autodetect_output) );
        
        autodetect_actually_did_something = true;
    }

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC || NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

#if NEXT_DEVELOPMENT
    if ( next_platform_getenv( "NEXT_FORCE_AUTODETECT_TIMEOUT" ) )
    {
        next_sleep( NEXT_SERVER_AUTODETECT_TIMEOUT * 1.25 );
    }
#endif // #if NEXT_DEVELOPMENT

    if ( next_time() - start_time > NEXT_SERVER_RESOLVE_HOSTNAME_TIMEOUT )
    {
        // IMPORTANT: if we have timed out, don't grab the mutex or write results. 
        // our thread has been destroyed and if we are unlucky, the next_server_internal_t instance is as well.
        return;
    }

    next_platform_mutex_guard( &server->autodetect_mutex );
    next_copy_string( server->autodetect_result, autodetect_output, NEXT_MAX_DATACENTER_NAME_LENGTH );
    server->autodetect_finished = true;
    server->autodetect_succeeded = autodetect_result;
    server->autodetect_actually_did_something = autodetect_actually_did_something;
}

static bool next_server_internal_update_autodetect( next_server_internal_t * server )
{
    next_assert( server );

    next_server_internal_verify_sentinels( server );

    if ( next_global_config.disable_network_next )
        return true;

    if ( server->resolving_hostname )    // IMPORTANT: wait until resolving hostname is finished, before autodetect complete!
        return true;

    if ( !server->autodetecting )
        return true;

    bool finished = false;
    {
        next_platform_mutex_guard( &server->autodetect_mutex );
        finished = server->autodetect_finished;
    }

    if ( finished )
    {
        next_platform_thread_join( server->autodetect_thread );
    }
    else
    {
        if ( next_time() < server->autodetect_start_time + NEXT_SERVER_AUTODETECT_TIMEOUT )
        {
            // keep waiting
            return false;
        }
        else
        {
            // but don't wait forever...
            next_printf( NEXT_LOG_LEVEL_INFO, "autodetect timed out. sticking with '%s' [%" PRIx64 "]", server->datacenter_name, server->datacenter_id );
        }
    }
    
    next_platform_thread_destroy( server->autodetect_thread );
    
    server->autodetect_thread = NULL;
    server->autodetecting = false;

    if ( server->autodetect_actually_did_something )
    {
        if ( server->autodetect_succeeded )
        {
            memset( server->datacenter_name, 0, sizeof(server->datacenter_name) );
            next_copy_string( server->datacenter_name, server->autodetect_result, NEXT_MAX_DATACENTER_NAME_LENGTH );
            server->datacenter_id = next_datacenter_id( server->datacenter_name );
            next_printf( NEXT_LOG_LEVEL_INFO, "server autodetected datacenter '%s' [%" PRIx64 "]", server->datacenter_name, server->datacenter_id );
        }
        else
        {
            next_printf( NEXT_LOG_LEVEL_INFO, "server autodetect datacenter failed. sticking with '%s' [%" PRIx64 "]", server->datacenter_name, server->datacenter_id );
        }
    }

    return true;
}

void next_server_internal_update_init( next_server_internal_t * server )
{
    next_server_internal_verify_sentinels( server );

    next_assert( server );

    if ( next_global_config.disable_network_next )
        return;

    if ( server->state != NEXT_SERVER_STATE_INITIALIZING )
        return;

    // check for init timeout

    const double current_time = next_time();

    if ( server->server_init_timeout_time <= current_time )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server init timed out. falling back to direct mode only :(" );

        server->state = NEXT_SERVER_STATE_DIRECT_ONLY;

        next_server_notify_ready_t * notify_ready = (next_server_notify_ready_t*) next_malloc( server->context, sizeof( next_server_notify_ready_t ) );
        notify_ready->type = NEXT_SERVER_NOTIFY_READY;
        next_copy_string( notify_ready->datacenter_name, server->datacenter_name, NEXT_MAX_DATACENTER_NAME_LENGTH );

        next_server_notify_direct_only_t * notify_direct_only = (next_server_notify_direct_only_t*) next_malloc( server->context, sizeof(next_server_notify_direct_only_t) );
        next_assert( notify_direct_only );
        notify_direct_only->type = NEXT_SERVER_NOTIFY_DIRECT_ONLY;

        next_platform_mutex_guard( &server->notify_mutex );
        next_queue_push( server->notify_queue, notify_direct_only );
        next_queue_push( server->notify_queue, notify_ready );

        return;
    }

    // check for initializing -> initialized transition

    if ( server->resolve_hostname_finished && server->autodetect_finished && server->received_init_response )
    {
        next_assert( server->backend_address.type == NEXT_ADDRESS_IPV4 || server->backend_address.type == NEXT_ADDRESS_IPV6 );
        next_server_notify_ready_t * notify = (next_server_notify_ready_t*) next_malloc( server->context, sizeof( next_server_notify_ready_t ) );
        notify->type = NEXT_SERVER_NOTIFY_READY;
        next_copy_string( notify->datacenter_name, server->datacenter_name, NEXT_MAX_DATACENTER_NAME_LENGTH );
        {
            next_platform_mutex_guard( &server->notify_mutex );
            next_queue_push( server->notify_queue, notify );
        }
        server->state = NEXT_SERVER_STATE_INITIALIZED;
    }

    // wait until we have resolved the backend hostname

    if ( !server->resolve_hostname_finished )
        return;

    // wait until we have autodetected the datacenter

    if ( !server->autodetect_finished )
        return;

    // if we have started flushing, abort the init...

    if ( server->flushing )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server aborted init" );
        server->state = NEXT_SERVER_STATE_DIRECT_ONLY;
        next_server_notify_direct_only_t * notify_direct_only = (next_server_notify_direct_only_t*) next_malloc( server->context, sizeof(next_server_notify_direct_only_t) );
        next_assert( notify_direct_only );
        notify_direct_only->type = NEXT_SERVER_NOTIFY_DIRECT_ONLY;
        next_platform_mutex_guard( &server->notify_mutex );
        next_queue_push( server->notify_queue, notify_direct_only );
        return;
    }

    // send init request packets repeatedly until we get a response or time out...

    if ( server->server_init_request_id != 0 && server->server_init_resend_time > current_time )
        return;

    while ( server->server_init_request_id == 0 )
    {
        server->server_init_request_id = next_random_uint64();
    }

    server->server_init_resend_time = current_time + 1.0;

    NextBackendServerInitRequestPacket packet;

    packet.request_id = server->server_init_request_id;
    packet.customer_id = server->customer_id;
    packet.datacenter_id = server->datacenter_id;
    next_copy_string( packet.datacenter_name, server->datacenter_name, NEXT_MAX_DATACENTER_NAME_LENGTH );
    packet.datacenter_name[NEXT_MAX_DATACENTER_NAME_LENGTH-1] = '\0';

    uint8_t magic[8];
    memset( magic, 0, sizeof(magic) );

    uint8_t from_address_data[32];
    uint8_t to_address_data[32];
    uint16_t from_address_port;
    uint16_t to_address_port;
    int from_address_bytes;
    int to_address_bytes;

    next_address_data( &server->server_address, from_address_data, &from_address_bytes, &from_address_port );
    next_address_data( &server->backend_address, to_address_data, &to_address_bytes, &to_address_port );

    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];

    next_assert( ( size_t(packet_data) % 4 ) == 0 );

    int packet_bytes = 0;
    if ( next_write_backend_packet( NEXT_BACKEND_SERVER_INIT_REQUEST_PACKET, &packet, packet_data, &packet_bytes, next_signed_packets, server->customer_private_key, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to write server init request packet for backend" );
        return;
    }

    next_assert( next_basic_packet_filter( packet_data, packet_bytes ) );
    next_assert( next_advanced_packet_filter( packet_data, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

    next_server_internal_send_packet_to_backend( server, packet_data, packet_bytes );

    next_printf( NEXT_LOG_LEVEL_DEBUG, "server sent init request to backend" );
}

void next_server_internal_backend_update( next_server_internal_t * server )
{
    next_server_internal_verify_sentinels( server );

    next_assert( server );

    if ( next_global_config.disable_network_next )
        return;

    double current_time = next_time();

    // don't do anything until we resolve the backend hostname

    if ( server->resolving_hostname )
        return;

    // tracker updates

    const int max_entry_index = server->session_manager->max_entry_index;

    for ( int i = 0; i <= max_entry_index; ++i )
    {
        if ( server->session_manager->session_ids[i] == 0 )
            continue;

        next_session_entry_t * session = &server->session_manager->entries[i];

        if ( session->stats_fallback_to_direct )
            continue;

        if ( session->next_tracker_update_time <= current_time )
        {
            const int packets_lost = next_packet_loss_tracker_update( &session->packet_loss_tracker );
            session->stats_packets_lost_client_to_server += packets_lost;
            session->stats_packets_out_of_order_client_to_server = session->out_of_order_tracker.num_out_of_order_packets;
            session->stats_jitter_client_to_server = session->jitter_tracker.jitter * 1000.0;
            session->next_tracker_update_time = current_time + NEXT_SECONDS_BETWEEN_PACKET_LOSS_UPDATES;
        }
    }

    if ( server->state != NEXT_SERVER_STATE_INITIALIZED )
        return;

    // server update

    bool first_server_update = server->server_update_first;

    if ( server->state != NEXT_SERVER_STATE_DIRECT_ONLY && server->server_update_last_time + NEXT_SECONDS_BETWEEN_SERVER_UPDATES <= current_time )
    {
        if ( server->server_update_request_id != 0 )
        {
            next_printf( NEXT_LOG_LEVEL_INFO, "server update response timed out. falling back to direct mode only :(" );
            server->state = NEXT_SERVER_STATE_DIRECT_ONLY;
            next_server_notify_direct_only_t * notify_direct_only = (next_server_notify_direct_only_t*) next_malloc( server->context, sizeof(next_server_notify_direct_only_t) );
            next_assert( notify_direct_only );
            notify_direct_only->type = NEXT_SERVER_NOTIFY_DIRECT_ONLY;
            next_platform_mutex_guard( &server->notify_mutex );
            next_queue_push( server->notify_queue, notify_direct_only );
            return;
        }

        while ( server->server_update_request_id == 0 )
        {
            server->server_update_request_id = next_random_uint64();
        }

        server->server_update_resend_time = current_time + 1.0;
        server->server_update_num_sessions = next_session_manager_num_entries( server->session_manager );

        NextBackendServerUpdateRequestPacket packet;

        packet.request_id = server->server_update_request_id;
        packet.customer_id = server->customer_id;
        packet.datacenter_id = server->datacenter_id;
        packet.num_sessions = server->server_update_num_sessions;
        packet.server_address = server->server_address;

        uint8_t magic[8];
        memset( magic, 0, sizeof(magic) );

        uint8_t from_address_data[32];
        uint8_t to_address_data[32];
        uint16_t from_address_port;
        uint16_t to_address_port;
        int from_address_bytes;
        int to_address_bytes;

        next_address_data( &server->server_address, from_address_data, &from_address_bytes, &from_address_port );
        next_address_data( &server->backend_address, to_address_data, &to_address_bytes, &to_address_port );

        uint8_t packet_data[NEXT_MAX_PACKET_BYTES];

        next_assert( ( size_t(packet_data) % 4 ) == 0 );

        int packet_bytes = 0;
        if ( next_write_backend_packet( NEXT_BACKEND_SERVER_UPDATE_REQUEST_PACKET, &packet, packet_data, &packet_bytes, next_signed_packets, server->customer_private_key, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to write server update request packet for backend" );
            return;
        }

        next_assert( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_assert( next_advanced_packet_filter( packet_data, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

        next_server_internal_send_packet_to_backend( server, packet_data, packet_bytes );

        server->server_update_last_time = current_time;

        next_printf( NEXT_LOG_LEVEL_DEBUG, "server sent server update packet to backend (%d sessions)", packet.num_sessions );

        server->server_update_first = false;
    }

    if ( first_server_update )
        return;

    // server update resend

    if ( server->server_update_request_id && server->server_update_resend_time <= current_time )
    {
        NextBackendServerUpdateRequestPacket packet;

        packet.request_id = server->server_update_request_id;
        packet.customer_id = server->customer_id;
        packet.datacenter_id = server->datacenter_id;
        packet.num_sessions = server->server_update_num_sessions;
        packet.server_address = server->server_address;

        uint8_t magic[8];
        memset( magic, 0, sizeof(magic) );

        uint8_t from_address_data[32];
        uint8_t to_address_data[32];
        uint16_t from_address_port;
        uint16_t to_address_port;
        int from_address_bytes;
        int to_address_bytes;

        next_address_data( &server->server_address, from_address_data, &from_address_bytes, &from_address_port );
        next_address_data( &server->backend_address, to_address_data, &to_address_bytes, &to_address_port );

        uint8_t packet_data[NEXT_MAX_PACKET_BYTES];

        next_assert( ( size_t(packet_data) % 4 ) == 0 );

        int packet_bytes = 0;
        if ( next_write_backend_packet( NEXT_BACKEND_SERVER_UPDATE_REQUEST_PACKET, &packet, packet_data, &packet_bytes, next_signed_packets, server->customer_private_key, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port ) != NEXT_OK )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to write server update packet for backend" );
            return;
        }

        next_assert( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_assert( next_advanced_packet_filter( packet_data, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

        next_server_internal_send_packet_to_backend( server, packet_data, packet_bytes );

        next_printf( NEXT_LOG_LEVEL_DEBUG, "server resent server update packet to backend", packet.num_sessions );

        server->server_update_resend_time = current_time + 1.0;
    }

    // session updates

    for ( int i = 0; i <= max_entry_index; ++i )
    {
        if ( server->session_manager->session_ids[i] == 0 )
            continue;

        next_session_entry_t * session = &server->session_manager->entries[i];

        if ( !session->session_update_timed_out && ( ( session->next_session_update_time >= 0.0 && session->next_session_update_time <= current_time ) || ( session->session_update_flush && !session->session_update_flush_finished && !session->waiting_for_update_response ) ) )
        {
            NextBackendSessionUpdateRequestPacket packet;

            packet.Reset();

            packet.customer_id = server->customer_id;
            packet.datacenter_id = server->datacenter_id;
            packet.session_id = session->session_id;
            packet.slice_number = session->update_sequence++;
            packet.platform_id = session->stats_platform_id;
            packet.user_hash = session->user_hash;
            packet.num_tags = session->num_tags;
            for ( int j = 0; j < session->num_tags; ++j )
            {
                packet.tags[j] = session->tags[j];
            }
            session->previous_server_events = session->current_server_events;
            session->current_server_events = 0;
            packet.server_events = session->previous_server_events;
            packet.reported = session->stats_reported;
            packet.fallback_to_direct = session->stats_fallback_to_direct;
            packet.client_bandwidth_over_limit = session->stats_client_bandwidth_over_limit;
            packet.server_bandwidth_over_limit = session->stats_server_bandwidth_over_limit;
            packet.client_ping_timed_out = session->client_ping_timed_out;
            packet.connection_type = session->stats_connection_type;
            packet.direct_kbps_up = session->stats_direct_kbps_up;
            packet.direct_kbps_down = session->stats_direct_kbps_down;
            packet.next_kbps_up = session->stats_next_kbps_up;
            packet.next_kbps_down = session->stats_next_kbps_down;
            packet.packets_sent_client_to_server = session->stats_packets_sent_client_to_server;
            next_platform_mutex_acquire( &server->session_mutex );
            packet.packets_sent_server_to_client = session->stats_packets_sent_server_to_client;
            next_platform_mutex_release( &server->session_mutex );

            // IMPORTANT: hold near relay stats for the rest of the session
            if ( session->num_held_near_relays == 0 && session->stats_num_near_relays != 0 )
            {
                session->num_held_near_relays = session->stats_num_near_relays;
                for ( int j = 0; j < session->stats_num_near_relays; j++ )
                {
                    session->held_near_relay_ids[j] = session->stats_near_relay_ids[j];    
                    session->held_near_relay_rtt[j] = session->stats_near_relay_rtt[j];
                    session->held_near_relay_jitter[j] = session->stats_near_relay_jitter[j];
                    session->held_near_relay_packet_loss[j] = session->stats_near_relay_packet_loss[j];    
                }
            }

            packet.packets_lost_client_to_server = session->stats_packets_lost_client_to_server;
            packet.packets_lost_server_to_client = session->stats_packets_lost_server_to_client;
            packet.packets_out_of_order_client_to_server = session->stats_packets_out_of_order_client_to_server;
            packet.packets_out_of_order_server_to_client = session->stats_packets_out_of_order_server_to_client;
            packet.jitter_client_to_server = session->stats_jitter_client_to_server;
            packet.jitter_server_to_client = session->stats_jitter_server_to_client;
            packet.next = session->stats_next;
            packet.next_rtt = session->stats_next_rtt;
            packet.next_jitter = session->stats_next_jitter;
            packet.next_packet_loss = session->stats_next_packet_loss;
            packet.direct_rtt = session->stats_direct_rtt;
            packet.direct_jitter = session->stats_direct_jitter;
            packet.direct_packet_loss = session->stats_direct_packet_loss;
            packet.direct_max_packet_loss_seen = session->stats_direct_max_packet_loss_seen;
            packet.has_near_relay_pings = session->num_held_near_relays != 0;
            packet.num_near_relays = session->num_held_near_relays;
            for ( int j = 0; j < packet.num_near_relays; ++j )
            {
                packet.near_relay_ids[j] = session->held_near_relay_ids[j];
                packet.near_relay_rtt[j] = session->held_near_relay_rtt[j];
                packet.near_relay_jitter[j] = session->held_near_relay_jitter[j];
                packet.near_relay_packet_loss[j] = session->held_near_relay_packet_loss[j];
            }
            packet.client_address = session->address;
            packet.server_address = server->server_address;
            memcpy( packet.client_route_public_key, session->client_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES );
            memcpy( packet.server_route_public_key, server->server_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES );

            next_assert( session->session_data_bytes >= 0 );
            next_assert( session->session_data_bytes <= NEXT_MAX_SESSION_DATA_BYTES );
            packet.session_data_bytes = session->session_data_bytes;
            memcpy( packet.session_data, session->session_data, session->session_data_bytes );
            memcpy( packet.session_data_signature, session->session_data_signature, NEXT_CRYPTO_SIGN_BYTES );

            session->session_update_request_packet = packet;

            uint8_t magic[8];
            memset( magic, 0, sizeof(magic) );

            uint8_t from_address_data[32];
            uint8_t to_address_data[32];
            uint16_t from_address_port;
            uint16_t to_address_port;
            int from_address_bytes;
            int to_address_bytes;

            next_address_data( &server->server_address, from_address_data, &from_address_bytes, &from_address_port );
            next_address_data( &server->backend_address, to_address_data, &to_address_bytes, &to_address_port );

            uint8_t packet_data[NEXT_MAX_PACKET_BYTES];

            next_assert( ( size_t(packet_data) % 4 ) == 0 );

            int packet_bytes = 0;
            if ( next_write_backend_packet( NEXT_BACKEND_SESSION_UPDATE_REQUEST_PACKET, &packet, packet_data, &packet_bytes, next_signed_packets, server->customer_private_key, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port ) != NEXT_OK )
            {
                next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to write server init request packet for backend" );
                return;
            }

            next_assert( next_basic_packet_filter( packet_data, packet_bytes ) );
            next_assert( next_advanced_packet_filter( packet_data, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

            next_server_internal_send_packet_to_backend( server, packet_data, packet_bytes );

            next_printf( NEXT_LOG_LEVEL_DEBUG, "server sent session update packet to backend for session %" PRIx64, session->session_id );

            if ( session->next_session_update_time == 0.0 )
            {
                session->next_session_update_time = current_time + NEXT_SECONDS_BETWEEN_SESSION_UPDATES;
            }
            else
            {
                session->next_session_update_time += NEXT_SECONDS_BETWEEN_SESSION_UPDATES;
            }

            session->stats_client_bandwidth_over_limit = false;
            session->stats_server_bandwidth_over_limit = false;

            session->next_session_resend_time = current_time + NEXT_SESSION_UPDATE_RESEND_TIME;

            session->waiting_for_update_response = true;
        }

        if ( session->waiting_for_update_response && session->next_session_resend_time <= current_time )
        {
            session->session_update_request_packet.retry_number++;

            next_printf( NEXT_LOG_LEVEL_DEBUG, "server resent session update packet to backend for session %" PRIx64 " (%d)", session->session_id, session->session_update_request_packet.retry_number );

            uint8_t magic[8];
            memset( magic, 0, sizeof(magic) );

            uint8_t from_address_data[32];
            uint8_t to_address_data[32];
            uint16_t from_address_port;
            uint16_t to_address_port;
            int from_address_bytes;
            int to_address_bytes;

            next_address_data( &server->server_address, from_address_data, &from_address_bytes, &from_address_port );
            next_address_data( &server->backend_address, to_address_data, &to_address_bytes, &to_address_port );

            uint8_t packet_data[NEXT_MAX_PACKET_BYTES];

            next_assert( ( size_t(packet_data) % 4 ) == 0 );

            int packet_bytes = 0;
            if ( next_write_backend_packet( NEXT_BACKEND_SESSION_UPDATE_REQUEST_PACKET, &session->session_update_request_packet, packet_data, &packet_bytes, next_signed_packets, server->customer_private_key, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port ) != NEXT_OK )
            {
                next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to write server init request packet for backend" );
                return;
            }

            next_assert( next_basic_packet_filter( packet_data, packet_bytes ) );
            next_assert( next_advanced_packet_filter( packet_data, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

            next_server_internal_send_packet_to_backend( server, packet_data, packet_bytes );

            session->next_session_resend_time += NEXT_SESSION_UPDATE_RESEND_TIME;
        }

        if ( !session->session_update_timed_out && session->waiting_for_update_response && session->next_session_update_time - NEXT_SECONDS_BETWEEN_SESSION_UPDATES + NEXT_SESSION_UPDATE_TIMEOUT <= current_time )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "server timed out waiting for backend response for session %" PRIx64, session->session_id );
            session->waiting_for_update_response = false;
            session->next_session_update_time = -1.0;
            session->session_update_timed_out = true;

            // IMPORTANT: Send packets direct from now on for this session
            next_platform_mutex_acquire( &server->session_mutex );
            session->mutex_send_over_network_next = false;
            next_platform_mutex_release( &server->session_mutex );
        }
    }

    // match data

    for ( int i = 0; i <= max_entry_index; ++i )
    {
        if ( server->session_manager->session_ids[i] == 0 )
            continue;

        next_session_entry_t * session = &server->session_manager->entries[i];

        if ( !session->has_match_data || session->match_data_response_received )
            continue;

        if ( ( session->next_match_data_resend_time == 0.0 && !session->waiting_for_match_data_response) || ( session->match_data_flush && !session->waiting_for_match_data_response ) )
        {
            NextBackendMatchDataRequestPacket packet;
            
            packet.Reset();
            
            packet.customer_id = server->customer_id;
            packet.datacenter_id = server->datacenter_id;
            packet.server_address = server->server_address;
            packet.user_hash = session->user_hash;
            packet.session_id = session->session_id;
            packet.match_id = session->match_id;
            packet.num_match_values = session->num_match_values;
            next_assert( packet.num_match_values <= NEXT_MAX_MATCH_VALUES );
            for ( int j = 0; j < session->num_match_values; ++j )
            {
                packet.match_values[j] = session->match_values[j];
            }

            session->match_data_request_packet = packet;

            uint8_t magic[8];
            memset( magic, 0, sizeof(magic) );

            uint8_t from_address_data[32];
            uint8_t to_address_data[32];
            uint16_t from_address_port;
            uint16_t to_address_port;
            int from_address_bytes;
            int to_address_bytes;

            next_address_data( &server->server_address, from_address_data, &from_address_bytes, &from_address_port );
            next_address_data( &server->backend_address, to_address_data, &to_address_bytes, &to_address_port );

            uint8_t packet_data[NEXT_MAX_PACKET_BYTES];

            next_assert( ( size_t(packet_data) % 4 ) == 0 );

            int packet_bytes = 0;
            if ( next_write_backend_packet( NEXT_BACKEND_MATCH_DATA_REQUEST_PACKET, &session->match_data_request_packet, packet_data, &packet_bytes, next_signed_packets, server->customer_private_key, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port ) != NEXT_OK )
            {
                next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to write match data request packet for backend" );
                return;
            }

            next_assert( next_basic_packet_filter( packet_data, packet_bytes ) );
            next_assert( next_advanced_packet_filter( packet_data, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

            next_server_internal_send_packet_to_backend( server, packet_data, packet_bytes );
            
            next_printf( NEXT_LOG_LEVEL_DEBUG, "server sent match data packet to backend for session %" PRIx64, session->session_id );

            session->next_match_data_resend_time = ( session->match_data_flush ) ? current_time + NEXT_MATCH_DATA_FLUSH_RESEND_TIME : current_time + NEXT_MATCH_DATA_RESEND_TIME;

            session->waiting_for_match_data_response = true;
        }

        if ( session->waiting_for_match_data_response && session->next_match_data_resend_time <= current_time )
        {
            session->match_data_request_packet.retry_number++;

            next_printf( NEXT_LOG_LEVEL_DEBUG, "server resent match data packet to backend for session %" PRIx64 " (%d)", session->session_id, session->match_data_request_packet.retry_number );

            uint8_t magic[8];
            memset( magic, 0, sizeof(magic) );

            uint8_t from_address_data[32];
            uint8_t to_address_data[32];
            uint16_t from_address_port;
            uint16_t to_address_port;
            int from_address_bytes;
            int to_address_bytes;

            next_address_data( &server->server_address, from_address_data, &from_address_bytes, &from_address_port );
            next_address_data( &server->backend_address, to_address_data, &to_address_bytes, &to_address_port );

            uint8_t packet_data[NEXT_MAX_PACKET_BYTES];

            next_assert( ( size_t(packet_data) % 4 ) == 0 );

            int packet_bytes = 0;
            if ( next_write_backend_packet( NEXT_BACKEND_MATCH_DATA_REQUEST_PACKET, &session->match_data_request_packet, packet_data, &packet_bytes, next_signed_packets, server->customer_private_key, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port ) != NEXT_OK )
            {
                next_printf( NEXT_LOG_LEVEL_ERROR, "server failed to write match data request packet for backend" );
                return;
            }

            next_assert( next_basic_packet_filter( packet_data, packet_bytes ) );
            next_assert( next_advanced_packet_filter( packet_data, magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, packet_bytes ) );

            next_server_internal_send_packet_to_backend( server, packet_data, packet_bytes );

            session->next_match_data_resend_time += ( session->match_data_flush && !session->match_data_flush_finished ) ? NEXT_MATCH_DATA_FLUSH_RESEND_TIME : NEXT_MATCH_DATA_RESEND_TIME;
        }
    }
}

static void next_server_internal_thread_function( void * context )
{
    next_assert( context );

    next_server_internal_t * server = (next_server_internal_t*) context;

    double last_update_time = next_time();

    while ( !server->quit )
    {
        next_server_internal_block_and_receive_packet( server );

        double current_time = next_time();

        if ( current_time >= last_update_time + 0.1 )
        {
            next_server_internal_update_flush( server );

            next_server_internal_update_resolve_hostname( server );

            next_server_internal_update_autodetect( server );

            next_server_internal_update_init( server );

            next_server_internal_update_pending_upgrades( server );

            next_server_internal_update_route( server );

            next_server_internal_update_sessions( server );

            next_server_internal_backend_update( server );

            next_server_internal_pump_commands( server );

            last_update_time = current_time;
        }
    }
}

// ---------------------------------------------------------------

struct next_server_t
{
    NEXT_DECLARE_SENTINEL(0)

    void * context;
    next_server_internal_t * internal;
    next_platform_thread_t * thread;
    next_proxy_session_manager_t * pending_session_manager;
    next_proxy_session_manager_t * session_manager;
    next_address_t address;
    uint16_t bound_port;
    bool ready;
    char datacenter_name[NEXT_MAX_DATACENTER_NAME_LENGTH];
    bool flushing;
    bool flushed;
    bool direct_only;

    NEXT_DECLARE_SENTINEL(1)

    uint8_t current_magic[8];

    NEXT_DECLARE_SENTINEL(2)

    void (*packet_received_callback)( next_server_t * server, void * context, const next_address_t * from, const uint8_t * packet_data, int packet_bytes );
    int (*send_packet_to_address_callback)( void * data, const next_address_t * address, const uint8_t * packet_data, int packet_bytes );
    void * send_packet_to_address_callback_data;

    NEXT_DECLARE_SENTINEL(3)
};

void next_server_initialize_sentinels( next_server_t * server )
{
    (void) server;
    next_assert( server );
    NEXT_INITIALIZE_SENTINEL( server, 0 )
    NEXT_INITIALIZE_SENTINEL( server, 1 )
    NEXT_INITIALIZE_SENTINEL( server, 2 )
    NEXT_INITIALIZE_SENTINEL( server, 3 )
}

void next_server_verify_sentinels( next_server_t * server )
{
    (void) server;
    next_assert( server );
    NEXT_VERIFY_SENTINEL( server, 0 )
    NEXT_VERIFY_SENTINEL( server, 1 )
    NEXT_VERIFY_SENTINEL( server, 2 )
    NEXT_VERIFY_SENTINEL( server, 3 )
    if ( server->session_manager )
        next_proxy_session_manager_verify_sentinels( server->session_manager );
    if ( server->pending_session_manager )
        next_proxy_session_manager_verify_sentinels( server->pending_session_manager );
}

void next_server_destroy( next_server_t * server );

next_server_t * next_server_create( void * context, const char * server_address, const char * bind_address, const char * datacenter, void (*packet_received_callback)( next_server_t * server, void * context, const next_address_t * from, const uint8_t * packet_data, int packet_bytes ) )
{
    next_assert( server_address );
    next_assert( bind_address );
    next_assert( packet_received_callback );

    next_server_t * server = (next_server_t*) next_malloc( context, sizeof(next_server_t) );
    if ( !server )
        return NULL;

    memset( server, 0, sizeof( next_server_t) );

    next_server_initialize_sentinels( server );

    server->context = context;

    server->internal = next_server_internal_create( context, server_address, bind_address, datacenter );
    if ( !server->internal )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create internal server" );
        next_server_destroy( server );
        return NULL;
    }

    server->address = server->internal->server_address;
    server->bound_port = server->internal->server_address.port;

    server->thread = next_platform_thread_create( server->context, next_server_internal_thread_function, server->internal );
    if ( !server->thread )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create server thread" );
        next_server_destroy( server );
        return NULL;
    }

    if ( next_platform_thread_high_priority( server->thread ) )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server increased thread priority" );
    }

    server->pending_session_manager = next_proxy_session_manager_create( context, NEXT_INITIAL_PENDING_SESSION_SIZE );
    if ( server->pending_session_manager == NULL )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create pending session manager (proxy)" );
        next_server_destroy( server );
        return NULL;
    }

    server->session_manager = next_proxy_session_manager_create( context, NEXT_INITIAL_SESSION_SIZE );
    if ( server->session_manager == NULL )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create session manager (proxy)" );
        next_server_destroy( server );
        return NULL;
    }

    server->context = context;
    server->packet_received_callback = packet_received_callback;

    next_server_verify_sentinels( server );

    return server;
}

uint16_t next_server_port( next_server_t * server )
{
    next_server_verify_sentinels( server );

    return server->bound_port;
}

next_address_t next_server_address( next_server_t * server )
{
    next_server_verify_sentinels( server );

    return server->address;
}

void next_server_destroy( next_server_t * server )
{
    next_server_verify_sentinels( server );

    if ( server->pending_session_manager )
    {
        next_proxy_session_manager_destroy( server->pending_session_manager );
    }

    if ( server->session_manager )
    {
        next_proxy_session_manager_destroy( server->session_manager );
    }

    if ( server->thread )
    {
        next_server_internal_quit( server->internal );
        next_platform_thread_join( server->thread );
        next_platform_thread_destroy( server->thread );
    }

    if ( server->internal )
    {
        next_server_internal_destroy( server->internal );
    }

    clear_and_free( server->context, server, sizeof(next_server_t) );
}

void next_server_update( next_server_t * server )
{
    next_server_verify_sentinels( server );

    while ( true )
    {
        void * queue_entry = NULL;
        {
            next_platform_mutex_guard( &server->internal->notify_mutex );
            queue_entry = next_queue_pop( server->internal->notify_queue );
        }

        if ( queue_entry == NULL )
            break;

        next_server_notify_t * notify = (next_server_notify_t*) queue_entry;

        switch ( notify->type )
        {
            case NEXT_SERVER_NOTIFY_PACKET_RECEIVED:
            {
                next_server_notify_packet_received_t * packet_received = (next_server_notify_packet_received_t*) notify;
                next_assert( packet_received->packet_data );
                next_assert( packet_received->packet_bytes > 0 );
                next_assert( packet_received->packet_bytes <= NEXT_MAX_PACKET_BYTES - 1 );
                server->packet_received_callback( server, server->context, &packet_received->from, packet_received->packet_data, packet_received->packet_bytes );
            }
            break;

            case NEXT_SERVER_NOTIFY_SESSION_UPGRADED:
            {
                next_server_notify_session_upgraded_t * session_upgraded = (next_server_notify_session_upgraded_t*) notify;
                char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_INFO, "server upgraded client %s to session %" PRIx64, next_address_to_string( &session_upgraded->address, address_buffer ), session_upgraded->session_id );
                next_proxy_session_entry_t * proxy_entry = next_proxy_session_manager_find( server->pending_session_manager, &session_upgraded->address );
                if ( proxy_entry && proxy_entry->session_id == session_upgraded->session_id )
                {
                    next_proxy_session_manager_remove_by_address( server->session_manager, &session_upgraded->address );
                    next_proxy_session_manager_remove_by_address( server->pending_session_manager, &session_upgraded->address );
                    proxy_entry = next_proxy_session_manager_add( server->session_manager, &session_upgraded->address, session_upgraded->session_id );
                }
            }
            break;

            case NEXT_SERVER_NOTIFY_PENDING_SESSION_TIMED_OUT:
            {
                next_server_notify_pending_session_timed_out_t * pending_session_timed_out = (next_server_notify_pending_session_timed_out_t*) notify;
                char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_DEBUG, "server timed out pending upgrade of client %s to session %" PRIx64, next_address_to_string( &pending_session_timed_out->address, address_buffer ), pending_session_timed_out->session_id );
                next_proxy_session_entry_t * pending_entry = next_proxy_session_manager_find( server->pending_session_manager, &pending_session_timed_out->address );
                if ( pending_entry && pending_entry->session_id == pending_session_timed_out->session_id )
                {
                    next_proxy_session_manager_remove_by_address( server->pending_session_manager, &pending_session_timed_out->address );
                    next_proxy_session_manager_remove_by_address( server->session_manager, &pending_session_timed_out->address );
                }
            }
            break;

            case NEXT_SERVER_NOTIFY_SESSION_TIMED_OUT:
            {
                next_server_notify_session_timed_out_t * session_timed_out = (next_server_notify_session_timed_out_t*) notify;
                char address_buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
                next_printf( NEXT_LOG_LEVEL_INFO, "server timed out client %s from session %" PRIx64, next_address_to_string( &session_timed_out->address, address_buffer ), session_timed_out->session_id );
                next_proxy_session_entry_t * proxy_session_entry = next_proxy_session_manager_find( server->session_manager, &session_timed_out->address );
                if ( proxy_session_entry && proxy_session_entry->session_id == session_timed_out->session_id )
                {
                    next_proxy_session_manager_remove_by_address( server->session_manager, &session_timed_out->address );
                }
            }
            break;

            case NEXT_SERVER_NOTIFY_READY:
            {
                next_server_notify_ready_t * ready = (next_server_notify_ready_t*) notify;
                next_copy_string( server->datacenter_name, ready->datacenter_name, NEXT_MAX_DATACENTER_NAME_LENGTH );
                server->ready = true;
                next_printf( NEXT_LOG_LEVEL_INFO, "server datacenter is '%s'", ready->datacenter_name );
                next_printf( NEXT_LOG_LEVEL_INFO, "server is ready to receive client connections" );
            }
            break;

            case NEXT_SERVER_NOTIFY_FLUSH_FINISHED:
            {
                server->flushed = true;
            }
            break;

            case NEXT_SERVER_NOTIFY_MAGIC_UPDATED:
            {
                next_server_notify_magic_updated_t * magic_updated = (next_server_notify_magic_updated_t*) notify;

                memcpy( server->current_magic, magic_updated->current_magic, 8 );

                next_printf( NEXT_LOG_LEVEL_DEBUG, "server current magic: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x",
                    server->current_magic[0],
                    server->current_magic[1],
                    server->current_magic[2],
                    server->current_magic[3],
                    server->current_magic[4],
                    server->current_magic[5],
                    server->current_magic[6],
                    server->current_magic[7] );
            }
            break;

            case NEXT_SERVER_NOTIFY_DIRECT_ONLY:
            {
                server->direct_only = true;
            }
            break;

            default: break;
        }

        next_free( server->context, queue_entry );
    }
}

uint64_t next_generate_session_id()
{
    uint64_t session_id = 0;
    while ( session_id == 0 )
    {
        next_random_bytes( (uint8_t*) &session_id, 8 );
    }
    return session_id;
}

uint64_t next_server_upgrade_session( next_server_t * server, const next_address_t * address, const char * user_id )
{
    next_server_verify_sentinels( server );

    next_assert( server->internal );

    // send upgrade session command to internal server

    next_server_command_upgrade_session_t * command = (next_server_command_upgrade_session_t*) next_malloc( server->context, sizeof( next_server_command_upgrade_session_t ) );
    if ( !command )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server upgrade session failed. could not create upgrade session command" );
        return 0;
    }

    uint64_t session_id = next_generate_session_id();

    uint64_t user_hash = ( user_id != NULL ) ? next_hash_string( user_id ) : 0;

    command->type = NEXT_SERVER_COMMAND_UPGRADE_SESSION;
    command->address = *address;
    command->user_hash = user_hash;
    command->session_id = session_id;

    {
        next_platform_mutex_guard( &server->internal->command_mutex );
        next_queue_push( server->internal->command_queue, command );
    }

    // remove any existing entry for this address. latest upgrade takes precedence

    next_proxy_session_manager_remove_by_address( server->session_manager, address );
    next_proxy_session_manager_remove_by_address( server->pending_session_manager, address );

    // add a new pending session entry for this address

    next_proxy_session_entry_t * entry = next_proxy_session_manager_add( server->pending_session_manager, address, session_id );

    if ( entry == NULL )
    {
        next_assert( !"could not add pending session entry. this should never happen!" );
        return 0;
    }

    return session_id;
}

void next_server_tag_session( next_server_t * server, const next_address_t * address, const char * tag )
{
    if ( tag[0] != '\0' )
    {
        // one tag
        const char ** tags = &tag;
        next_server_tag_session_multiple( server, address, tags, 1 );
    }
    else
    {
        // clear tags
        next_server_tag_session_multiple( server, address, NULL, 0 );
    }
}

void next_server_tag_session_multiple( next_server_t * server, const next_address_t * address, const char ** tags, int num_tags )
{
    next_server_verify_sentinels( server );

    next_assert( server->internal );
    next_assert( num_tags >= 0 );
    next_assert( num_tags <= NEXT_MAX_TAGS );

    // send tag session command to internal server

    next_server_command_tag_session_t * command = (next_server_command_tag_session_t*) next_malloc( server->context, sizeof( next_server_command_tag_session_t ) );
    if ( !command )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server tag session failed. could not create tag session command" );
        return;
    }

    command->type = NEXT_SERVER_COMMAND_TAG_SESSION;
    command->address = *address;
    memset( command->tags, 0, sizeof(command->tags) );
    for ( int i = 0; i < num_tags; ++i )
    {
        uint64_t tag_id = next_tag_id( tags[i] );
        char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
        next_printf( NEXT_LOG_LEVEL_INFO, "server tagged %s as '%s' [%" PRIx64 "]", next_address_to_string( address, address_string ), tags[i], tag_id );
        command->tags[i] = next_tag_id( tags[i] );
    }
    command->num_tags = num_tags;
    if ( num_tags == 0 )
    {
        char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
        next_printf( NEXT_LOG_LEVEL_INFO, "server cleared tags for %s", next_address_to_string( address, address_string ) );
    }

    {
        next_platform_mutex_guard( &server->internal->command_mutex );
        next_queue_push( server->internal->command_queue, command );
    }
}

NEXT_BOOL next_server_session_upgraded( next_server_t * server, const next_address_t * address )
{
    next_server_verify_sentinels( server );

    next_assert( server->internal );

    next_proxy_session_entry_t * pending_entry = next_proxy_session_manager_find( server->pending_session_manager, address );
    if ( pending_entry != NULL )
        return NEXT_TRUE;

    next_proxy_session_entry_t * entry = next_proxy_session_manager_find( server->session_manager, address );
    if ( entry != NULL )
        return NEXT_TRUE;

    return NEXT_FALSE;
}

void next_server_send_packet_to_address( next_server_t * server, const next_address_t * address, const uint8_t * packet_data, int packet_bytes )
{
    next_server_verify_sentinels( server );

    next_assert( address );
    next_assert( address->type != NEXT_ADDRESS_NONE );
    next_assert( packet_data );
    next_assert( packet_bytes > 0 );

    if ( server->send_packet_to_address_callback )
    {
        void * callback_data = server->send_packet_to_address_callback_data;
        if ( server->send_packet_to_address_callback( callback_data, address, packet_data, packet_bytes ) != 0 )
            return;
    }

    next_platform_socket_send_packet( server->internal->socket, address, packet_data, packet_bytes );
}

void next_server_send_packet( next_server_t * server, const next_address_t * to_address, const uint8_t * packet_data, int packet_bytes )
{
    next_server_verify_sentinels( server );

    next_assert( to_address );
    next_assert( packet_data );
    next_assert( packet_bytes > 0 );

    if ( next_global_config.disable_network_next )
    {
        next_server_send_packet_direct( server, to_address, packet_data, packet_bytes );
        return;
    }

    if ( packet_bytes > NEXT_MAX_PACKET_BYTES - 1 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server can't send packet because packet size is too large" );
        return;
    }

    next_proxy_session_entry_t * entry = next_proxy_session_manager_find( server->session_manager, to_address );

    bool send_over_network_next = false;
    bool send_upgraded_direct = false;

    if ( entry && packet_bytes <= NEXT_MTU )
    {
        bool multipath = false;
        int envelope_kbps_down = 0;
        uint8_t open_session_sequence = 0;
        uint64_t send_sequence = 0;
        uint64_t session_id = 0;
        uint8_t session_version = 0;
        next_address_t session_address;
        double last_upgraded_packet_receive_time = 0.0;
        uint8_t session_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];

        next_platform_mutex_acquire( &server->internal->session_mutex );
        next_session_entry_t * internal_entry = next_session_manager_find_by_address( server->internal->session_manager, to_address );
        if ( internal_entry )
        {
            last_upgraded_packet_receive_time = internal_entry->last_upgraded_packet_receive_time;
        }
        next_platform_mutex_release( &server->internal->session_mutex );

        // IMPORTANT: If we haven't received any upgraded packets in the last second send passthrough packets.
        // This makes reconnect robust when a client reconnects using the same port number.
        if ( !internal_entry || last_upgraded_packet_receive_time + 1.0 < next_time() )
        {
            next_server_send_packet_direct( server, to_address, packet_data, packet_bytes );
            return;
        }

        next_platform_mutex_acquire( &server->internal->session_mutex );
        multipath = internal_entry->mutex_multipath;
        envelope_kbps_down = internal_entry->mutex_envelope_kbps_down;
        send_over_network_next = internal_entry->mutex_send_over_network_next;
        send_upgraded_direct = !send_over_network_next;
        send_sequence = internal_entry->mutex_payload_send_sequence++;
        send_sequence |= uint64_t(1) << 63;
        open_session_sequence = internal_entry->client_open_session_sequence;
        session_id = internal_entry->mutex_session_id;
        session_version = internal_entry->mutex_session_version;
        session_address = internal_entry->mutex_send_address;
        memcpy( session_private_key, internal_entry->mutex_private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES );
        internal_entry->stats_packets_sent_server_to_client++;
        next_platform_mutex_release( &server->internal->session_mutex );

        if ( multipath )
        {
            send_upgraded_direct = true;
        }

        if ( send_over_network_next )
        {
            const int wire_packet_bits = next_wire_packet_bits( packet_bytes );

            bool over_budget = next_bandwidth_limiter_add_packet( &entry->send_bandwidth, next_time(), envelope_kbps_down, wire_packet_bits );

            if ( over_budget )
            {
                next_printf( NEXT_LOG_LEVEL_WARN, "server exceeded bandwidth budget for session %" PRIx64 " (%d kbps)", session_id, envelope_kbps_down );
                next_platform_mutex_acquire( &server->internal->session_mutex );
                internal_entry->stats_server_bandwidth_over_limit = true;
                next_platform_mutex_release( &server->internal->session_mutex );
                send_over_network_next = false;
                if ( !multipath )
                {
                    send_upgraded_direct = true;
                }
            }
        }

        if ( send_over_network_next )
        {
            // send over network next

            uint8_t from_address_data[32];
            uint8_t to_address_data[32];
            uint16_t from_address_port;
            uint16_t to_address_port;
            int from_address_bytes;
            int to_address_bytes;

            next_address_data( &server->address, from_address_data, &from_address_bytes, &from_address_port );
            next_address_data( &session_address, to_address_data, &to_address_bytes, &to_address_port );

            uint8_t next_packet_data[NEXT_MAX_PACKET_BYTES];

            int next_packet_bytes = next_write_server_to_client_packet( next_packet_data, send_sequence, session_id, session_version, session_private_key, packet_data, packet_bytes, server->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port );

            next_assert( next_packet_bytes > 0 );

            next_assert( next_basic_packet_filter( next_packet_data, next_packet_bytes ) );
            next_assert( next_advanced_packet_filter( next_packet_data, server->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, next_packet_bytes ) );

            next_server_send_packet_to_address( server, &session_address, next_packet_data, next_packet_bytes );
        }

        if ( send_upgraded_direct )
        {
            // direct packet

            uint8_t from_address_data[32];
            uint8_t to_address_data[32];
            uint16_t from_address_port = 0;
            uint16_t to_address_port = 0;
            int from_address_bytes = 0;
            int to_address_bytes = 0;

            next_address_data( &server->address, from_address_data, &from_address_bytes, &from_address_port );
            next_address_data( to_address, to_address_data, &to_address_bytes, &to_address_port );

            uint8_t direct_packet_data[NEXT_MAX_PACKET_BYTES];

            int direct_packet_bytes = next_write_direct_packet( direct_packet_data, open_session_sequence, send_sequence, packet_data, packet_bytes, server->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port );

            next_assert( direct_packet_bytes >= 27 );
            next_assert( direct_packet_bytes <= NEXT_MTU + 27 );
            next_assert( direct_packet_data[0] == NEXT_DIRECT_PACKET );

            next_assert( next_basic_packet_filter( direct_packet_data, direct_packet_bytes ) );
            next_assert( next_advanced_packet_filter( direct_packet_data, server->current_magic, from_address_data, from_address_bytes, from_address_port, to_address_data, to_address_bytes, to_address_port, direct_packet_bytes ) );

            next_server_send_packet_to_address( server, to_address, direct_packet_data, direct_packet_bytes );
        }
    }
    else
    {
        // passthrough packet

        next_server_send_packet_direct( server, to_address, packet_data, packet_bytes );
    }
}

void next_server_send_packet_direct( next_server_t * server, const next_address_t * to_address, const uint8_t * packet_data, int packet_bytes )
{
    next_server_verify_sentinels( server );

    next_assert( to_address );
    next_assert( to_address->type != NEXT_ADDRESS_NONE );
    next_assert( packet_data );
    next_assert( packet_bytes > 0 );

    if ( packet_bytes > NEXT_MAX_PACKET_BYTES - 1 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server can't send packet because packet size is too large\n" );
        return;
    }

    uint8_t buffer[NEXT_MAX_PACKET_BYTES];
    buffer[0] = NEXT_PASSTHROUGH_PACKET;
    memcpy( buffer + 1, packet_data, packet_bytes );
    next_server_send_packet_to_address( server, to_address, buffer, packet_bytes + 1 );
}

void next_server_send_packet_raw( struct next_server_t * server, const struct next_address_t * to_address, const uint8_t * packet_data, int packet_bytes )
{
    next_server_verify_sentinels( server );

    next_assert( to_address );
    next_assert( packet_data );
    next_assert( packet_bytes > 0 );

    next_platform_socket_send_packet( server->internal->socket, to_address, packet_data, packet_bytes );
}

NEXT_BOOL next_server_stats( next_server_t * server, const next_address_t * address, next_server_stats_t * stats )
{
    next_assert( server );
    next_assert( address );
    next_assert( stats );

    next_platform_mutex_guard( &server->internal->session_mutex );

    next_session_entry_t * entry = next_session_manager_find_by_address( server->internal->session_manager, address );
    if ( !entry )
        return NEXT_FALSE;

    stats->address = *address;
    stats->session_id = entry->session_id;
    stats->user_hash = entry->user_hash;
    stats->platform_id = entry->stats_platform_id;
    stats->connection_type = entry->stats_connection_type;
    stats->next = entry->stats_next;
    stats->multipath = entry->stats_multipath;
    stats->reported = entry->stats_reported;
    stats->fallback_to_direct = entry->stats_fallback_to_direct;
    stats->direct_rtt = entry->stats_direct_rtt;
    stats->direct_jitter = entry->stats_direct_jitter;
    stats->direct_packet_loss = entry->stats_direct_packet_loss;
    stats->direct_max_packet_loss_seen = entry->stats_direct_max_packet_loss_seen;
    stats->next_rtt = entry->stats_next_rtt;
    stats->next_jitter = entry->stats_next_jitter;
    stats->next_packet_loss = entry->stats_next_packet_loss;
    stats->direct_kbps_up = entry->stats_direct_kbps_up;
    stats->direct_kbps_down = entry->stats_direct_kbps_down;
    stats->next_kbps_up = entry->stats_next_kbps_up;
    stats->next_kbps_down = entry->stats_next_kbps_down;
    stats->packets_sent_client_to_server = entry->stats_packets_sent_client_to_server;
    stats->packets_sent_server_to_client = entry->stats_packets_sent_server_to_client;
    stats->packets_lost_client_to_server = entry->stats_packets_lost_client_to_server;
    stats->packets_lost_server_to_client = entry->stats_packets_lost_server_to_client;
    stats->packets_out_of_order_client_to_server = entry->stats_packets_out_of_order_client_to_server;
    stats->packets_out_of_order_server_to_client = entry->stats_packets_out_of_order_server_to_client;
    stats->jitter_client_to_server = entry->stats_jitter_client_to_server;
    stats->jitter_server_to_client = entry->stats_jitter_server_to_client;
    stats->num_tags = entry->num_tags;
    memcpy( stats->tags, entry->tags, sizeof(stats->tags) );

    return NEXT_TRUE;
}

NEXT_BOOL next_server_ready( next_server_t * server ) 
{
    next_server_verify_sentinels( server );

    if ( server->ready ) 
    {
        return NEXT_TRUE;
    }

    return NEXT_FALSE;
}

const char * next_server_datacenter( next_server_t * server )
{
    next_server_verify_sentinels( server );

    return server->datacenter_name;
}

void next_server_event( struct next_server_t * server, const struct next_address_t * address, uint64_t server_events )
{
    next_assert( server );
    next_assert( address );
    next_assert( server->internal );

    if ( server->flushing )
    {
        next_printf( NEXT_LOG_LEVEL_WARN, "ignoring game event. server is flushed" );
        return;
    }
    
    // send game event command to internal server

    next_server_command_server_event_t * command = (next_server_command_server_event_t*) next_malloc( server->context, sizeof( next_server_command_server_event_t ) );
    if ( !command )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "game event failed. could not create game event command" );
        return;
    }

    command->type = NEXT_SERVER_COMMAND_SERVER_EVENT;
    command->address = *address;
    command->server_events = server_events;

    {    
        next_platform_mutex_guard( &server->internal->command_mutex );
        next_queue_push( server->internal->command_queue, command );
    }
}

void next_server_match( struct next_server_t * server, const struct next_address_t * address, const char * match_id, const double * match_values, int num_match_values )
{
    next_server_verify_sentinels( server );

    next_assert( server );
    next_assert( address );
    next_assert( server->internal );
    next_assert( num_match_values >= 0 );
    next_assert( num_match_values <= NEXT_MAX_MATCH_VALUES );

    if ( server->flushing )
    {
        next_printf( NEXT_LOG_LEVEL_WARN, "ignoring server match. server is flushed" );
        return;
    }

    // send match data command to internal server

    next_server_command_match_data_t * command = (next_server_command_match_data_t*) next_malloc( server->context, sizeof( next_server_command_match_data_t ) );
    if ( !command )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server match data failed. could not create match data command" );
        return;
    }

    command->type = NEXT_SERVER_COMMAND_MATCH_DATA;
    command->address = *address;
    command->match_id = next_hash_string( match_id );
    memset( command->match_values, 0, sizeof(command->match_values) );
    for ( int i = 0; i < num_match_values; ++i )
    {
        command->match_values[i] = match_values[i];
    }
    command->num_match_values = num_match_values;

    {
        next_platform_mutex_guard( &server->internal->command_mutex );
        next_queue_push( server->internal->command_queue, command );
    }
}

void next_server_flush( struct next_server_t * server )
{
    next_assert( server );

    if ( next_global_config.disable_network_next == true )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "ignoring server flush. network next is disabled" );
        return;
    }

    if ( server->flushing )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "ignoring server flush. server is already flushed" );
        return;
    }

    // send flush command to internal server

    next_server_command_flush_t * command = (next_server_command_flush_t*) next_malloc( server->context, sizeof( next_server_command_flush_t ) );
    if ( !command )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server flush failed. could not create server flush command" );
        return;
    }

    command->type = NEXT_SERVER_COMMAND_FLUSH;

    {    
        next_platform_mutex_guard( &server->internal->command_mutex );
        next_queue_push( server->internal->command_queue, command );
    }

    server->flushing = true;

    next_printf( NEXT_LOG_LEVEL_INFO, "server flush started" );

    double flush_timeout = next_time() + NEXT_SERVER_FLUSH_TIMEOUT;

    while ( !server->flushed && next_time() < flush_timeout )
    {
        next_server_update( server );
        
        next_sleep( 0.1 );
    }

    if ( next_time() > flush_timeout )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server flush timed out :(" );
    }
    else
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "server flush finished" );    
    }
}

void next_server_set_packet_receive_callback( struct next_server_t * server, void (*callback) ( void * data, next_address_t * from, uint8_t * packet_data, int * begin, int * end ), void * callback_data )
{
    next_assert( server );

    next_server_command_set_packet_receive_callback_t * command = (next_server_command_set_packet_receive_callback_t*) next_malloc( server->context, sizeof( next_server_command_set_packet_receive_callback_t ) );
    if ( !command )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server set packet receive callback failed. could not create command" );
        return;
    }

    command->type = NEXT_SERVER_COMMAND_SET_PACKET_RECEIVE_CALLBACK;
    command->callback = callback;
    command->callback_data = callback_data;

    {    
        next_platform_mutex_guard( &server->internal->command_mutex );
        next_queue_push( server->internal->command_queue, command );
    }
}

void next_server_set_send_packet_to_address_callback( struct next_server_t * server, int (*callback) ( void * data, const next_address_t * from, const uint8_t * packet_data, int packet_bytes ), void * callback_data )
{
    next_assert( server );

    server->send_packet_to_address_callback = callback;
    server->send_packet_to_address_callback_data = callback_data;

    next_server_command_set_send_packet_to_address_callback_t * command = (next_server_command_set_send_packet_to_address_callback_t*) next_malloc( server->context, sizeof( next_server_command_set_send_packet_to_address_callback_t ) );
    if ( !command )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server set send packet to address callback failed. could not create command" );
        return;
    }

    command->type = NEXT_SERVER_COMMAND_SET_SEND_PACKET_TO_ADDRESS_CALLBACK;
    command->callback = callback;
    command->callback_data = callback_data;

    {    
        next_platform_mutex_guard( &server->internal->command_mutex );
        next_queue_push( server->internal->command_queue, command );
    }
}

void next_server_set_payload_receive_callback( struct next_server_t * server, int (*callback) ( void * data, const next_address_t * client_address, const uint8_t * payload_data, int payload_bytes ), void * callback_data )
{
    next_assert( server );

    next_server_command_set_payload_receive_callback_t * command = (next_server_command_set_payload_receive_callback_t*) next_malloc( server->context, sizeof( next_server_command_set_payload_receive_callback_t ) );
    if ( !command )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server set payload receive callback failed. could not create command" );
        return;
    }

    command->type = NEXT_SERVER_COMMAND_SET_PAYLOAD_RECEIVE_CALLBACK;
    command->callback = callback;
    command->callback_data = callback_data;

    {    
        next_platform_mutex_guard( &server->internal->command_mutex );
        next_queue_push( server->internal->command_queue, command );
    }
}

NEXT_BOOL next_server_direct_only( struct next_server_t * server )
{
    next_assert( server );
    return server->direct_only;
}

// ---------------------------------------------------------------

int next_mutex_create( next_mutex_t * mutex )
{
    next_assert( mutex );
    next_assert( sizeof(next_platform_mutex_t) <= sizeof(next_mutex_t) );
    next_platform_mutex_t * platform_mutex = (next_platform_mutex_t*) mutex;
    return next_platform_mutex_create( platform_mutex );
}

void next_mutex_acquire( next_mutex_t * mutex )
{
    next_assert( mutex );
    next_platform_mutex_t * platform_mutex = (next_platform_mutex_t*) mutex;
    next_platform_mutex_acquire( platform_mutex );
}

void next_mutex_release( next_mutex_t * mutex )
{
    next_assert( mutex );
    next_platform_mutex_t * platform_mutex = (next_platform_mutex_t*) mutex;
    next_platform_mutex_release( platform_mutex );
}

void next_mutex_destroy( next_mutex_t * mutex )
{
    next_assert( mutex );
    next_platform_mutex_t * platform_mutex = (next_platform_mutex_t*) mutex;
    next_platform_mutex_destroy( platform_mutex );
}

// ---------------------------------------------------------------

#if NEXT_COMPILE_WITH_TESTS

static void next_check_handler( const char * condition,
                                const char * function,
                                const char * file,
                                int line )
{
    printf( "check failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
    fflush( stdout );
#ifndef NDEBUG
    #if defined( __GNUC__ )
        __builtin_trap();
    #elif defined( _MSC_VER )
        __debugbreak();
    #endif
#endif
    exit( 1 );
}

#define next_check( condition )                                                                             \
do                                                                                                          \
{                                                                                                           \
    if ( !(condition) )                                                                                     \
    {                                                                                                       \
        next_check_handler( #condition, (const char*) __FUNCTION__, (const char*) __FILE__, __LINE__ );     \
    }                                                                                                       \
} while(0)

void test_time()
{
    double start = next_time();
    next_sleep( 0.1 );
    double finish = next_time();
    next_check( finish > start );
}

void test_endian()
{
    uint32_t value = 0x11223344;
    char bytes[4];
    memcpy( bytes, &value, 4 );

#if NEXT_LITTLE_ENDIAN

    next_check( bytes[0] == 0x44 );
    next_check( bytes[1] == 0x33 );
    next_check( bytes[2] == 0x22 );
    next_check( bytes[3] == 0x11 );

#else // #if NEXT_LITTLE_ENDIAN

    next_check( bytes[3] == 0x44 );
    next_check( bytes[2] == 0x33 );
    next_check( bytes[1] == 0x22 );
    next_check( bytes[0] == 0x11 );

#endif // #if NEXT_LITTLE_ENDIAN
}

void test_base64()
{
    const char * input = "a test string. let's see if it works properly";
    char encoded[1024];
    char decoded[1024];
    next_check( next_base64_encode_string( input, encoded, sizeof(encoded) ) > 0 );
    next_check( next_base64_decode_string( encoded, decoded, sizeof(decoded) ) > 0 );
    next_check( strcmp( decoded, input ) == 0 );
    next_check( next_base64_decode_string( encoded, decoded, 10 ) == 0 );
}

void test_fnv1a()
{
    uint64_t hash = next_datacenter_id( "local" );
    next_check( hash == 0x249f1fb6f3a680e8ULL );
}

void test_queue()
{
    const int QueueSize = 64;
    const int EntrySize = 1024;

    next_queue_t * queue = next_queue_create( NULL, QueueSize );

    next_check( queue->num_entries == 0 );
    next_check( queue->start_index == 0 );

    // attempting to pop a packet off an empty queue should return NULL

    next_check( next_queue_pop( queue ) == NULL );

    // add some entries to the queue and make sure they pop off in the correct order
    {
        const int NumEntries = 50;

        void * entries[NumEntries];

        int i;
        for ( i = 0; i < NumEntries; ++i )
        {
            entries[i] = next_malloc( NULL, EntrySize );
            memset( entries[i], 0, EntrySize );
            next_check( next_queue_push( queue, entries[i] ) == NEXT_OK );
        }

        next_check( queue->num_entries == NumEntries );

        for ( i = 0; i < NumEntries; ++i )
        {
            void * entry = next_queue_pop( queue );
            next_check( entry == entries[i] );
            next_free( NULL, entry );
        }
    }

    // after all entries are popped off, the queue is empty, so calls to pop should return NULL

    next_check( queue->num_entries == 0 );

    next_check( next_queue_pop( queue ) == NULL );

    // test that the queue can be filled to max capacity

    void * entries[QueueSize];

    int i;
    for ( i = 0; i < QueueSize; ++i )
    {
        entries[i] = next_malloc( NULL, EntrySize );
        next_check( next_queue_push( queue, entries[i] ) == NEXT_OK );
    }

    next_check( queue->num_entries == QueueSize );

    // when the queue is full, attempting to push an entry should fail

    next_check( next_queue_push( queue, next_malloc( NULL, 100 ) ) == NEXT_ERROR );

    // make sure all packets pop off in the correct order

    for ( i = 0; i < QueueSize; ++i )
    {
        void * entry = next_queue_pop( queue );
        next_check( entry == entries[i] );
        next_free( NULL, entry );
    }

    // add some entries again

    for ( i = 0; i < QueueSize; ++i )
    {
        entries[i] = next_malloc( NULL, EntrySize );
        next_check( next_queue_push( queue, entries[i] ) == NEXT_OK );
    }

    // clear the queue and make sure that all entries are freed

    next_queue_clear( queue );

    next_check( queue->start_index == 0 );
    next_check( queue->num_entries == 0 );
    for ( i = 0; i < QueueSize; ++i )
        next_check( queue->entries[i] == NULL );

    // destroy the queue

    next_queue_destroy( queue );
}

using namespace next;

void test_bitpacker()
{
    const int BufferSize = 256;

    uint8_t buffer[BufferSize];

    BitWriter writer( buffer, BufferSize );

    next_check( writer.GetData() == buffer );
    next_check( writer.GetBitsWritten() == 0 );
    next_check( writer.GetBytesWritten() == 0 );
    next_check( writer.GetBitsAvailable() == BufferSize * 8 );

    writer.WriteBits( 0, 1 );
    writer.WriteBits( 1, 1 );
    writer.WriteBits( 10, 8 );
    writer.WriteBits( 255, 8 );
    writer.WriteBits( 1000, 10 );
    writer.WriteBits( 50000, 16 );
    writer.WriteBits( 9999999, 32 );
    writer.FlushBits();

    const int bitsWritten = 1 + 1 + 8 + 8 + 10 + 16 + 32;

    next_check( writer.GetBytesWritten() == 10 );
    next_check( writer.GetBitsWritten() == bitsWritten );
    next_check( writer.GetBitsAvailable() == BufferSize * 8 - bitsWritten );

    const int bytesWritten = writer.GetBytesWritten();

    next_check( bytesWritten == 10 );

    memset( buffer + bytesWritten, 0, size_t(BufferSize) - bytesWritten );

    BitReader reader( buffer, bytesWritten );

    next_check( reader.GetBitsRead() == 0 );
    next_check( reader.GetBitsRemaining() == bytesWritten * 8 );

    uint32_t a = reader.ReadBits( 1 );
    uint32_t b = reader.ReadBits( 1 );
    uint32_t c = reader.ReadBits( 8 );
    uint32_t d = reader.ReadBits( 8 );
    uint32_t e = reader.ReadBits( 10 );
    uint32_t f = reader.ReadBits( 16 );
    uint32_t g = reader.ReadBits( 32 );

    next_check( a == 0 );
    next_check( b == 1 );
    next_check( c == 10 );
    next_check( d == 255 );
    next_check( e == 1000 );
    next_check( f == 50000 );
    next_check( g == 9999999 );

    next_check( reader.GetBitsRead() == bitsWritten );
    next_check( reader.GetBitsRemaining() == bytesWritten * 8 - bitsWritten );
}

const int MaxItems = 11;

struct TestData
{
    TestData()
    {
        memset( this, 0, sizeof( TestData ) );
    }

    int a,b,c;
    uint32_t d : 8;
    uint32_t e : 8;
    uint32_t f : 8;
    bool g;
    int numItems;
    int items[MaxItems];
    float float_value;
    double double_value;
    uint64_t uint64_value;
    uint8_t bytes[17];
    char string[256];
    next_address_t address_a, address_b, address_c;
};

struct TestContext
{
    int min;
    int max;
};

struct TestObject
{
    TestData data;

    void Init()
    {
        data.a = 1;
        data.b = -2;
        data.c = 150;
        data.d = 55;
        data.e = 255;
        data.f = 127;
        data.g = true;

        data.numItems = MaxItems / 2;
        for ( int i = 0; i < data.numItems; ++i )
            data.items[i] = i + 10;

        data.float_value = 3.1415926f;
        data.double_value = 1 / 3.0;
        data.uint64_value = 0x1234567898765432L;

        for ( int i = 0; i < (int) sizeof( data.bytes ); ++i )
            data.bytes[i] = ( i * 37 ) % 255;

        strcpy( data.string, "hello world!" );

        memset( &data.address_a, 0, sizeof(next_address_t) );

        next_address_parse( &data.address_b, "127.0.0.1:50000" );

        next_address_parse( &data.address_c, "[::1]:50000" );
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        const TestContext & context = *(const TestContext*) stream.GetContext();

        serialize_int( stream, data.a, context.min, context.max );
        serialize_int( stream, data.b, context.min, context.max );

        serialize_int( stream, data.c, -100, 10000 );

        serialize_bits( stream, data.d, 6 );
        serialize_bits( stream, data.e, 8 );
        serialize_bits( stream, data.f, 7 );

        serialize_align( stream );

        serialize_bool( stream, data.g );

        serialize_int( stream, data.numItems, 0, MaxItems - 1 );
        for ( int i = 0; i < data.numItems; ++i )
            serialize_bits( stream, data.items[i], 8 );

        serialize_float( stream, data.float_value );

        serialize_double( stream, data.double_value );

        serialize_uint64( stream, data.uint64_value );

        serialize_bytes( stream, data.bytes, sizeof( data.bytes ) );

        serialize_string( stream, data.string, sizeof( data.string ) );

        serialize_address( stream, data.address_a );
        serialize_address( stream, data.address_b );
        serialize_address( stream, data.address_c );

        return true;
    }

    bool operator == ( const TestObject & other ) const
    {
        return memcmp( &data, &other.data, sizeof( TestData ) ) == 0;
    }

    bool operator != ( const TestObject & other ) const
    {
        return ! ( *this == other );
    }
};

void test_stream()
{
    const int BufferSize = 1024;

    uint8_t buffer[BufferSize];

    TestContext context;
    context.min = -10;
    context.max = +10;

    WriteStream writeStream( buffer, BufferSize );

    TestObject writeObject;
    writeObject.Init();
    writeStream.SetContext( &context );
    writeObject.Serialize( writeStream );
    writeStream.Flush();

    const int bytesWritten = writeStream.GetBytesProcessed();

    memset( buffer + bytesWritten, 0, size_t(BufferSize) - bytesWritten );

    TestObject readObject;

    ReadStream readStream( buffer, bytesWritten );
    readStream.SetContext( &context );
    readObject.Serialize( readStream );

    next_check( readObject == writeObject );
}

static bool equal_within_tolerance( float a, float b, float tolerance = 0.001f )
{
    return fabs(double(a)-double(b)) <= tolerance;
}

void test_bits_required()
{
    next_check( bits_required( 0, 0 ) == 0 );
    next_check( bits_required( 0, 1 ) == 1 );
    next_check( bits_required( 0, 2 ) == 2 );
    next_check( bits_required( 0, 3 ) == 2 );
    next_check( bits_required( 0, 4 ) == 3 );
    next_check( bits_required( 0, 5 ) == 3 );
    next_check( bits_required( 0, 6 ) == 3 );
    next_check( bits_required( 0, 7 ) == 3 );
    next_check( bits_required( 0, 8 ) == 4 );
    next_check( bits_required( 0, 255 ) == 8 );
    next_check( bits_required( 0, 65535 ) == 16 );
    next_check( bits_required( 0, 4294967295U ) == 32 );
}

void test_address()
{
    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "[" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "[]" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "[]:" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, ":" ) == NEXT_ERROR );
#if !defined(WINVER) || WINVER > 0x502 // windows xp sucks
        next_check( next_address_parse( &address, "1" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "12" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "123" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "1234" ) == NEXT_ERROR );
#endif
        next_check( next_address_parse( &address, "1234.0.12313.0000" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "1234.0.12313.0000.0.0.0.0.0" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "." ) == NEXT_ERROR );
        next_check( next_address_parse( &address, ".." ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "..." ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "...." ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "....." ) == NEXT_ERROR );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "107.77.207.77" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV4 );
        next_check( address.port == 0 );
        next_check( address.data.ipv4[0] == 107 );
        next_check( address.data.ipv4[1] == 77 );
        next_check( address.data.ipv4[2] == 207 );
        next_check( address.data.ipv4[3] == 77 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "127.0.0.1" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV4 );
        next_check( address.port == 0 );
        next_check( address.data.ipv4[0] == 127 );
        next_check( address.data.ipv4[1] == 0 );
        next_check( address.data.ipv4[2] == 0 );
        next_check( address.data.ipv4[3] == 1 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "107.77.207.77:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV4 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv4[0] == 107 );
        next_check( address.data.ipv4[1] == 77 );
        next_check( address.data.ipv4[2] == 207 );
        next_check( address.data.ipv4[3] == 77 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "127.0.0.1:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV4 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv4[0] == 127 );
        next_check( address.data.ipv4[1] == 0 );
        next_check( address.data.ipv4[2] == 0 );
        next_check( address.data.ipv4[3] == 1 );
    }

#if NEXT_PLATFORM_HAS_IPV6
    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "fe80::202:b3ff:fe1e:8329" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 0 );
        next_check( address.data.ipv6[0] == 0xfe80 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0202 );
        next_check( address.data.ipv6[5] == 0xb3ff );
        next_check( address.data.ipv6[6] == 0xfe1e );
        next_check( address.data.ipv6[7] == 0x8329 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "::" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 0 );
        next_check( address.data.ipv6[0] == 0x0000 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0000 );
        next_check( address.data.ipv6[5] == 0x0000 );
        next_check( address.data.ipv6[6] == 0x0000 );
        next_check( address.data.ipv6[7] == 0x0000 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "::1" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 0 );
        next_check( address.data.ipv6[0] == 0x0000 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0000 );
        next_check( address.data.ipv6[5] == 0x0000 );
        next_check( address.data.ipv6[6] == 0x0000 );
        next_check( address.data.ipv6[7] == 0x0001 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "[fe80::202:b3ff:fe1e:8329]:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv6[0] == 0xfe80 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0202 );
        next_check( address.data.ipv6[5] == 0xb3ff );
        next_check( address.data.ipv6[6] == 0xfe1e );
        next_check( address.data.ipv6[7] == 0x8329 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "[::]:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv6[0] == 0x0000 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0000 );
        next_check( address.data.ipv6[5] == 0x0000 );
        next_check( address.data.ipv6[6] == 0x0000 );
        next_check( address.data.ipv6[7] == 0x0000 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "[::1]:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv6[0] == 0x0000 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0000 );
        next_check( address.data.ipv6[5] == 0x0000 );
        next_check( address.data.ipv6[6] == 0x0000 );
        next_check( address.data.ipv6[7] == 0x0001 );
    }
#endif // #if NEXT_PLATFORM_HAS_IPV6
}

void test_replay_protection()
{
    next_replay_protection_t replay_protection;

    int i;
    for ( i = 0; i < 2; ++i )
    {
        next_replay_protection_reset( &replay_protection );

        next_check( replay_protection.most_recent_sequence == 0 );

        // the first time we receive packets, they should not be already received

        #define MAX_SEQUENCE ( NEXT_REPLAY_PROTECTION_BUFFER_SIZE * 4 )

        uint64_t sequence;
        for ( sequence = 0; sequence < MAX_SEQUENCE; ++sequence )
        {
            next_check( next_replay_protection_already_received( &replay_protection, sequence ) == 0 );
            next_replay_protection_advance_sequence( &replay_protection, sequence );
        }

        // old packets outside buffer should be considered already received

        next_check( next_replay_protection_already_received( &replay_protection, 0 ) == 1 );

        // packets received a second time should be detected as already received

        for ( sequence = MAX_SEQUENCE - 10; sequence < MAX_SEQUENCE; ++sequence )
        {
            next_check( next_replay_protection_already_received( &replay_protection, sequence ) == 1 );
        }

        // jumping ahead to a much higher sequence should be considered not already received

        next_check( next_replay_protection_already_received( &replay_protection, MAX_SEQUENCE + NEXT_REPLAY_PROTECTION_BUFFER_SIZE ) == 0 );

        // old packets should be considered already received

        for ( sequence = 0; sequence < MAX_SEQUENCE; ++sequence )
        {
            next_check( next_replay_protection_already_received( &replay_protection, sequence ) == 1 );
        }
    }
}

void test_ping_stats()
{
    // default ping history is 100% packet loss
    {
        static next_ping_history_t history;
        next_ping_history_clear( &history );

        next_route_stats_t route_stats;
        next_route_stats_from_ping_history( &history, 10.0, 100.0, &route_stats );

        next_check( route_stats.rtt == 0.0f );
        next_check( route_stats.jitter == 0.0f );
        next_check( route_stats.packet_loss == 0.0f );
    }

    // add some pings without pong response, packet loss should be 0%, but latency is 0ms indicating no responses yet (not routable)
    {
        static next_ping_history_t history;
        next_ping_history_clear( &history );

        for ( int i = 0; i < NEXT_PING_HISTORY_ENTRY_COUNT; ++i )
        {
            next_ping_history_ping_sent( &history, 10 + i * 0.01 );
        }

        next_route_stats_t route_stats;
        next_route_stats_from_ping_history( &history, 10.0, 100.0, &route_stats );

        next_check( route_stats.rtt == 0.0f );
        next_check( route_stats.jitter == 0.0f );
        next_check( route_stats.packet_loss == 0.0f );
    }

    // add some pings and set them to have a pong response, packet loss should be 0%
    {
        static next_ping_history_t history;
        next_ping_history_clear( &history );

        const double expected_rtt = 0.1;

        for ( int i = 0; i < NEXT_PING_HISTORY_ENTRY_COUNT; ++i )
        {
            uint64_t sequence = next_ping_history_ping_sent( &history, 10 + i * 0.1 );
            next_ping_history_pong_received( &history, sequence, 10 + i * 0.1 + expected_rtt );
        }

        next_route_stats_t route_stats;
        next_route_stats_from_ping_history( &history, 1.0, 100.0, &route_stats );

        next_check( equal_within_tolerance( route_stats.rtt, expected_rtt * 1000.0 ) );
        next_check( equal_within_tolerance( route_stats.jitter, 0.0 ) );
        next_check( route_stats.packet_loss == 0.0 );
    }

    // add some pings and set them to have a pong response, but leave the last second of pings without response. 
    // packet loss should be zero because ping safety stops us considering packets 1 second young from having PL
    {
        static next_ping_history_t history;
        next_ping_history_clear( &history );

        const double expected_rtt = 0.1;

        const double delta_time = 10.0 / NEXT_PING_HISTORY_ENTRY_COUNT;

        for ( int i = 0; i < NEXT_PING_HISTORY_ENTRY_COUNT; ++i )
        {
            const double ping_send_time = 10 + i * delta_time;
            const double pong_recv_time = ping_send_time + expected_rtt;

            if ( ping_send_time > 9.0 )
            {
                uint64_t sequence = next_ping_history_ping_sent( &history, ping_send_time );
                next_ping_history_pong_received( &history, sequence, pong_recv_time );
            }
        }

        next_route_stats_t route_stats;
        next_route_stats_from_ping_history( &history, 1.0, 100.0, &route_stats );

        next_check( equal_within_tolerance( route_stats.rtt, expected_rtt * 1000.0 ) );
        next_check( equal_within_tolerance( route_stats.jitter, 0.0 ) );
        next_check( route_stats.packet_loss == 0.0 );
    }

    // drop 1 in every 2 packets. packet loss should be 50%
    {
        static next_ping_history_t history;
        next_ping_history_clear( &history );

        const double expected_rtt = 0.1;

        for ( int i = 0; i < NEXT_PING_HISTORY_ENTRY_COUNT; ++i )
        {
            uint64_t sequence = next_ping_history_ping_sent( &history, 10 + i * 0.1 );
            if ( i & 1 )
                next_ping_history_pong_received( &history, sequence, 10 + i * 0.1 + expected_rtt );
        }

        next_route_stats_t route_stats;
        next_route_stats_from_ping_history( &history, 1.0, 100.0, &route_stats );

        next_check( equal_within_tolerance( route_stats.rtt, expected_rtt * 1000.0 ) );
        next_check( equal_within_tolerance( route_stats.jitter, 0.0 ) );
        next_check( equal_within_tolerance( route_stats.packet_loss, 50.0, 2.0 ) );
    }

    // drop 1 in every 10 packets. packet loss should be ~10%
    {
        static next_ping_history_t history;
        next_ping_history_clear( &history );

        const double expected_rtt = 0.1;

        for ( int i = 0; i < NEXT_PING_HISTORY_ENTRY_COUNT; ++i )
        {
            uint64_t sequence = next_ping_history_ping_sent( &history, 10 + i * 0.1 );
            if ( ( i % 10 ) )
                next_ping_history_pong_received( &history, sequence, 10 + i * 0.1 + expected_rtt );
        }

        next_route_stats_t route_stats;
        next_route_stats_from_ping_history( &history, 1.0, 100.0, &route_stats );

        next_check( equal_within_tolerance( route_stats.rtt, expected_rtt * 1000.0f ) );
        next_check( equal_within_tolerance( route_stats.jitter, 0.0 ) );
        next_check( equal_within_tolerance( route_stats.packet_loss, 10.0f, 2.0f ) );
    }

    // drop 9 in every 10 packets. packet loss should be ~90%
    {
        static next_ping_history_t history;
        next_ping_history_clear( &history );

        const double expected_rtt = 0.1;

        for ( int i = 0; i < NEXT_PING_HISTORY_ENTRY_COUNT; ++i )
        {
            uint64_t sequence = next_ping_history_ping_sent( &history, 10 + i * 0.1 );
            if ( ( i % 10 ) == 0 )
                next_ping_history_pong_received( &history, sequence, 10 + i * 0.1 + expected_rtt );
        }

        next_route_stats_t route_stats;
        next_route_stats_from_ping_history( &history, 1.0, 100.0, &route_stats );

        next_check( equal_within_tolerance( route_stats.rtt, expected_rtt * 1000.0f ) );
        next_check( equal_within_tolerance( route_stats.jitter, 0.0f ) );
        next_check( equal_within_tolerance( route_stats.packet_loss, 90.0f, 2.0f ) );
    }
}

void test_random_bytes()
{
    const int BufferSize = 64;
    uint8_t buffer[BufferSize];
    next_random_bytes( buffer, BufferSize );
    for ( int i = 0; i < 100; ++i )
    {
        uint8_t next_buffer[BufferSize];
        next_random_bytes( next_buffer, BufferSize );
        next_check( memcmp( buffer, next_buffer, BufferSize ) != 0 );
        memcpy( buffer, next_buffer, BufferSize );
    }
}

void test_random_float()
{
    for ( int i = 0; i < 1000; ++i )
    {
        float value = next_random_float();
        next_check( value >= 0.0f );
        next_check( value <= 1.0f );
    }
}

void test_crypto_box()
{
    #define CRYPTO_BOX_MESSAGE (const unsigned char *) "test"
    #define CRYPTO_BOX_MESSAGE_LEN 4
    #define CRYPTO_BOX_CIPHERTEXT_LEN ( NEXT_CRYPTO_BOX_MACBYTES + CRYPTO_BOX_MESSAGE_LEN )

    unsigned char sender_publickey[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    unsigned char sender_secretkey[NEXT_CRYPTO_BOX_SECRETKEYBYTES];
    next_crypto_box_keypair( sender_publickey, sender_secretkey );

    unsigned char receiver_publickey[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    unsigned char receiver_secretkey[NEXT_CRYPTO_BOX_SECRETKEYBYTES];
    next_crypto_box_keypair( receiver_publickey, receiver_secretkey );

    unsigned char nonce[NEXT_CRYPTO_BOX_NONCEBYTES];
    unsigned char ciphertext[CRYPTO_BOX_CIPHERTEXT_LEN];
    next_random_bytes( nonce, sizeof nonce );
    next_check( next_crypto_box_easy( ciphertext, CRYPTO_BOX_MESSAGE, CRYPTO_BOX_MESSAGE_LEN, nonce, receiver_publickey, sender_secretkey ) == 0 );

    unsigned char decrypted[CRYPTO_BOX_MESSAGE_LEN];
    next_check( next_crypto_box_open_easy( decrypted, ciphertext, CRYPTO_BOX_CIPHERTEXT_LEN, nonce, sender_publickey, receiver_secretkey ) == 0 );

    next_check( memcmp( decrypted, CRYPTO_BOX_MESSAGE, CRYPTO_BOX_MESSAGE_LEN ) == 0 );
}

void test_crypto_secret_box()
{
    #define CRYPTO_SECRET_BOX_MESSAGE ((const unsigned char *) "test")
    #define CRYPTO_SECRET_BOX_MESSAGE_LEN 4
    #define CRYPTO_SECRET_BOX_CIPHERTEXT_LEN (NEXT_CRYPTO_SECRETBOX_MACBYTES + CRYPTO_SECRET_BOX_MESSAGE_LEN)

    unsigned char key[NEXT_CRYPTO_SECRETBOX_KEYBYTES];
    unsigned char nonce[NEXT_CRYPTO_SECRETBOX_NONCEBYTES];
    unsigned char ciphertext[CRYPTO_SECRET_BOX_CIPHERTEXT_LEN];

    next_crypto_secretbox_keygen( key );
    next_random_bytes( nonce, NEXT_CRYPTO_SECRETBOX_NONCEBYTES );
    next_crypto_secretbox_easy( ciphertext, CRYPTO_SECRET_BOX_MESSAGE, CRYPTO_SECRET_BOX_MESSAGE_LEN, nonce, key );

    unsigned char decrypted[CRYPTO_SECRET_BOX_MESSAGE_LEN];
    next_check( next_crypto_secretbox_open_easy( decrypted, ciphertext, CRYPTO_SECRET_BOX_CIPHERTEXT_LEN, nonce, key ) == 0 );
}

void test_crypto_aead()
{
    #define CRYPTO_AEAD_MESSAGE (const unsigned char *) "test"
    #define CRYPTO_AEAD_MESSAGE_LEN 4
    #define CRYPTO_AEAD_ADDITIONAL_DATA (const unsigned char *) "123456"
    #define CRYPTO_AEAD_ADDITIONAL_DATA_LEN 6

    unsigned char nonce[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES];
    unsigned char key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
    unsigned char ciphertext[CRYPTO_AEAD_MESSAGE_LEN + NEXT_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES];
    unsigned long long ciphertext_len;

    next_crypto_aead_chacha20poly1305_keygen( key );
    next_random_bytes( nonce, sizeof(nonce) );

    next_crypto_aead_chacha20poly1305_encrypt( ciphertext, &ciphertext_len,
                                               CRYPTO_AEAD_MESSAGE, CRYPTO_AEAD_MESSAGE_LEN,
                                               CRYPTO_AEAD_ADDITIONAL_DATA, CRYPTO_AEAD_ADDITIONAL_DATA_LEN,
                                               NULL, nonce, key );

    unsigned char decrypted[CRYPTO_AEAD_MESSAGE_LEN];
    unsigned long long decrypted_len;
    next_check( next_crypto_aead_chacha20poly1305_decrypt( decrypted, &decrypted_len,
                                                      NULL,
                                                      ciphertext, ciphertext_len,
                                                      CRYPTO_AEAD_ADDITIONAL_DATA,
                                                      CRYPTO_AEAD_ADDITIONAL_DATA_LEN,
                                                      nonce, key) == 0 );
}

void test_crypto_aead_ietf()
{
    #define CRYPTO_AEAD_IETF_MESSAGE (const unsigned char *) "test"
    #define CRYPTO_AEAD_IETF_MESSAGE_LEN 4
    #define CRYPTO_AEAD_IETF_ADDITIONAL_DATA (const unsigned char *) "123456"
    #define CRYPTO_AEAD_IETF_ADDITIONAL_DATA_LEN 6

    unsigned char nonce[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES];
    unsigned char key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES];
    unsigned char ciphertext[CRYPTO_AEAD_IETF_MESSAGE_LEN + NEXT_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];
    unsigned long long ciphertext_len;

    next_crypto_aead_chacha20poly1305_ietf_keygen( key );
    next_random_bytes( nonce, sizeof(nonce) );

    next_crypto_aead_chacha20poly1305_ietf_encrypt( ciphertext, &ciphertext_len, CRYPTO_AEAD_IETF_MESSAGE, CRYPTO_AEAD_IETF_MESSAGE_LEN, CRYPTO_AEAD_IETF_ADDITIONAL_DATA, CRYPTO_AEAD_IETF_ADDITIONAL_DATA_LEN, NULL, nonce, key);

    unsigned char decrypted[CRYPTO_AEAD_IETF_MESSAGE_LEN];
    unsigned long long decrypted_len;
    next_check( next_crypto_aead_chacha20poly1305_ietf_decrypt( decrypted, &decrypted_len, NULL, ciphertext, ciphertext_len, CRYPTO_AEAD_IETF_ADDITIONAL_DATA, CRYPTO_AEAD_IETF_ADDITIONAL_DATA_LEN, nonce, key ) == 0 );
}

void test_crypto_sign_detached()
{
    #define MESSAGE_PART1 ((const unsigned char *) "Arbitrary data to hash")
    #define MESSAGE_PART1_LEN 22

    #define MESSAGE_PART2 ((const unsigned char *) "is longer than expected")
    #define MESSAGE_PART2_LEN 23

    unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
    unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
    next_crypto_sign_keypair( public_key, private_key );

    next_crypto_sign_state_t state;

    unsigned char signature[NEXT_CRYPTO_SIGN_BYTES];

    next_crypto_sign_init( &state );
    next_crypto_sign_update( &state, MESSAGE_PART1, MESSAGE_PART1_LEN );
    next_crypto_sign_update( &state, MESSAGE_PART2, MESSAGE_PART2_LEN );
    next_crypto_sign_final_create( &state, signature, NULL, private_key );

    next_crypto_sign_init( &state );
    next_crypto_sign_update( &state, MESSAGE_PART1, MESSAGE_PART1_LEN );
    next_crypto_sign_update( &state, MESSAGE_PART2, MESSAGE_PART2_LEN );
    next_check( next_crypto_sign_final_verify( &state, signature, public_key ) == 0 );
}

void test_crypto_key_exchange()
{
    uint8_t client_public_key[NEXT_CRYPTO_KX_PUBLICKEYBYTES];
    uint8_t client_private_key[NEXT_CRYPTO_KX_SECRETKEYBYTES];
    next_crypto_kx_keypair( client_public_key, client_private_key );

    uint8_t server_public_key[NEXT_CRYPTO_KX_PUBLICKEYBYTES];
    uint8_t server_private_key[NEXT_CRYPTO_KX_SECRETKEYBYTES];
    next_crypto_kx_keypair( server_public_key, server_private_key );

    uint8_t client_send_key[NEXT_CRYPTO_KX_SESSIONKEYBYTES];
    uint8_t client_receive_key[NEXT_CRYPTO_KX_SESSIONKEYBYTES];
    next_check( next_crypto_kx_client_session_keys( client_receive_key, client_send_key, client_public_key, client_private_key, server_public_key ) == 0 );

    uint8_t server_send_key[NEXT_CRYPTO_KX_SESSIONKEYBYTES];
    uint8_t server_receive_key[NEXT_CRYPTO_KX_SESSIONKEYBYTES];
    next_check( next_crypto_kx_server_session_keys( server_receive_key, server_send_key, server_public_key, server_private_key, client_public_key ) == 0 );

    next_check( memcmp( client_send_key, server_receive_key, NEXT_CRYPTO_KX_SESSIONKEYBYTES ) == 0 );
    next_check( memcmp( server_send_key, client_receive_key, NEXT_CRYPTO_KX_SESSIONKEYBYTES ) == 0 );
}

void test_basic_read_and_write()
{
    uint8_t buffer[1024];

    uint8_t * p = buffer;
    next_write_uint8( &p, 105 );
    next_write_uint16( &p, 10512 );
    next_write_uint32( &p, 105120000 );
    next_write_uint64( &p, 105120000000000000LL );
    next_write_float32( &p, 100.0f );
    next_write_float64( &p, 100000000000000.0 );
    next_write_bytes( &p, (uint8_t*)"hello", 6 );

    const uint8_t * q = buffer;

    uint8_t a = next_read_uint8( &q );
    uint16_t b = next_read_uint16( &q );
    uint32_t c = next_read_uint32( &q );
    uint64_t d = next_read_uint64( &q );
    float e = next_read_float32( &q );
    double f = next_read_float64( &q );
    uint8_t g[6];
    next_read_bytes( &q, g, 6 );

    next_check( a == 105 );
    next_check( b == 10512 );
    next_check( c == 105120000 );
    next_check( d == 105120000000000000LL );
    next_check( e == 100.0f );
    next_check( f == 100000000000000.0 );
    next_check( memcmp( g, "hello", 6 ) == 0 );
}

void test_address_read_and_write()
{
    struct next_address_t a, b, c;

    memset( &a, 0, sizeof(a) );
    memset( &b, 0, sizeof(b) );
    memset( &c, 0, sizeof(c) );

    next_address_parse( &b, "127.0.0.1:50000" );

    next_address_parse( &c, "[::1]:50000" );

    uint8_t buffer[1024];

    uint8_t * p = buffer;

    next_write_address( &p, &a );
    next_write_address( &p, &b );
    next_write_address( &p, &c );

    struct next_address_t read_a, read_b, read_c;

    const uint8_t * q = buffer;

    next_read_address( &q, &read_a );
    next_read_address( &q, &read_b );
    next_read_address( &q, &read_c );

    next_check( next_address_equal( &a, &read_a ) );
    next_check( next_address_equal( &b, &read_b ) );
    next_check( next_address_equal( &c, &read_c ) );
}

void test_platform_socket()
{
    // non-blocking socket (ipv4)
    {
        next_address_t bind_address;
        next_address_t local_address;
        next_address_parse( &bind_address, "0.0.0.0" );
        next_address_parse( &local_address, "127.0.0.1" );
        next_platform_socket_t * socket = next_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0, 64*1024, 64*1024, true );
        local_address.port = bind_address.port;
        next_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        next_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        next_address_t from;
        while ( next_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) ) )
        {
            next_check( next_address_equal( &from, &local_address ) );
        }
        next_platform_socket_destroy( socket );
    }

    // blocking socket with timeout (ipv4)
    {
        next_address_t bind_address;
        next_address_t local_address;
        next_address_parse( &bind_address, "0.0.0.0" );
        next_address_parse( &local_address, "127.0.0.1" );
        next_platform_socket_t * socket = next_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_BLOCKING, 0.01f, 64*1024, 64*1024, true );
        local_address.port = bind_address.port;
        next_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        next_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        next_address_t from;
        while ( next_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) ) )
        {
            next_check( next_address_equal( &from, &local_address ) );
        }
        next_platform_socket_destroy( socket );
    }

    // blocking socket with no timeout (ipv4)
    {
        next_address_t bind_address;
        next_address_t local_address;
        next_address_parse( &bind_address, "0.0.0.0" );
        next_address_parse( &local_address, "127.0.0.1" );
        next_platform_socket_t * socket = next_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_BLOCKING, -1.0f, 64*1024, 64*1024, true );
        local_address.port = bind_address.port;
        next_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        next_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        next_address_t from;
        next_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) );
        next_check( next_address_equal( &from, &local_address ) );
        next_platform_socket_destroy( socket );
    }

    // non-blocking socket (ipv6)
#if NEXT_PLATFORM_HAS_IPV6
    {
        next_address_t bind_address;
        next_address_t local_address;
        next_address_parse( &bind_address, "[::]" );
        next_address_parse( &local_address, "[::1]" );
        next_platform_socket_t * socket = next_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0, 64*1024, 64*1024, true );
        local_address.port = bind_address.port;
        next_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        next_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        next_address_t from;
        while ( next_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) ) )
        {
            next_check( next_address_equal( &from, &local_address ) );
        }
        next_platform_socket_destroy( socket );
    }

    // blocking socket with timeout (ipv6)
    {
        next_address_t bind_address;
        next_address_t local_address;
        next_address_parse( &bind_address, "[::]" );
        next_address_parse( &local_address, "[::1]" );
        next_platform_socket_t * socket = next_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_BLOCKING, 0.01f, 64*1024, 64*1024, true );
        local_address.port = bind_address.port;
        next_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        next_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        next_address_t from;
        while ( next_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) ) )
        {
            next_check( next_address_equal( &from, &local_address ) );
        }
        next_platform_socket_destroy( socket );
    }

    // blocking socket with no timeout (ipv6)
    {
        next_address_t bind_address;
        next_address_t local_address;
        next_address_parse( &bind_address, "[::]" );
        next_address_parse( &local_address, "[::1]" );
        next_platform_socket_t * socket = next_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_BLOCKING, -1.0f, 64*1024, 64*1024, true );
        local_address.port = bind_address.port;
        next_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        next_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        next_address_t from;
        next_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) );
        next_check( next_address_equal( &from, &local_address ) );
        next_platform_socket_destroy( socket );
    }
#endif
}

static bool threads_work = false;

static void test_thread_function(void*)
{
    threads_work = true;
}

void test_platform_thread()
{
    next_platform_thread_t * thread = next_platform_thread_create( NULL, test_thread_function, NULL );
    next_check( thread );
    next_platform_thread_join( thread );
    next_platform_thread_destroy( thread );
    next_check( threads_work );
}

void test_platform_mutex()
{
    next_platform_mutex_t mutex;
    int result = next_platform_mutex_create( &mutex );
    next_check( result == NEXT_OK );
    next_platform_mutex_acquire( &mutex );
    next_platform_mutex_release( &mutex );
    {
        next_platform_mutex_guard( &mutex );
        // ...
    }
    next_platform_mutex_destroy( &mutex );
}

static int num_client_packets_received = 0;

static void test_client_packet_received_callback( next_client_t * client, void * context, const next_address_t * from, const uint8_t * packet_data, int packet_bytes )
{
    (void) client;
    (void) context;
    (void) from;
    (void) packet_data;
    (void) packet_bytes;
    num_client_packets_received++;
}

void test_client_ipv4()
{
    next_client_t * client = next_client_create( NULL, "0.0.0.0:0", test_client_packet_received_callback );
    next_check( client );
    next_check( next_client_port( client ) != 0 );
    next_client_open_session( client, "127.0.0.1:12345" );
    uint8_t packet[256];
    memset( packet, 0, sizeof(packet) );
    next_client_send_packet( client, packet, sizeof(packet) );
    next_client_update( client );
    next_client_close_session( client );
    next_client_destroy( client );
}

static int num_server_packets_received = 0;

static void test_server_packet_received_callback( next_server_t * server, void * context, const next_address_t * from, const uint8_t * packet_data, int packet_bytes )
{
    (void) server; (void) context;
    next_server_send_packet( server, from, packet_data, packet_bytes );
    num_server_packets_received++;
}

#if defined(NEXT_PLATFORM_CAN_RUN_SERVER)

void test_server_ipv4()
{
    next_server_t * server = next_server_create( NULL, "127.0.0.1:0", "0.0.0.0:0", "local", test_server_packet_received_callback );
    next_check( server );
    next_check( next_server_port( server ) != 0 );
    next_address_t address;
    next_address_parse( &address, "127.0.0.1" );
    address.port = server->bound_port;
    uint8_t packet[256];
    memset( packet, 0, sizeof(packet) );
    next_server_send_packet( server, &address, packet, sizeof(packet) );
    next_server_update( server );
    next_server_flush( server );
    next_server_destroy( server );
}

#endif // #if defined(NEXT_PLATFORM_CAN_RUN_SERVER)

#if defined(NEXT_PLATFORM_HAS_IPV6)

void test_client_ipv6()
{
    next_client_t * client = next_client_create( NULL, "[::0]:0", test_client_packet_received_callback );
    next_check( client );
    next_check( next_client_port( client ) != 0 );
    next_client_open_session( client, "[::1]:12345" );
    uint8_t packet[256];
    memset( packet, 0, sizeof(packet) );
    next_client_send_packet( client, packet, sizeof(packet) );
    next_client_update( client );
    next_client_close_session( client );
    next_client_destroy( client );
}

#if defined(NEXT_PLATFORM_CAN_RUN_SERVER)

void test_server_ipv6()
{
    next_server_t * server = next_server_create( NULL, "[::1]:0", "[::0]:0", "local", test_server_packet_received_callback );
    next_check( server );
    next_check( next_server_port(server) != 0 );
    next_address_t address;
    next_address_parse( &address, "::1" );
    address.port = server->bound_port;
    uint8_t packet[256];
    memset( packet, 0, sizeof(packet) );
    next_server_send_packet( server, &address, packet, sizeof(packet) );
    next_server_update( server );
    next_server_flush( server );
    next_server_destroy( server );
}

#endif // #if defined(NEXT_PLATFORM_CAN_RUN_SERVER)

#endif // #if defined(NEXT_PLATFORM_HAS_IPV6)

void test_upgrade_token()
{
    NextUpgradeToken in, out;

    next_random_bytes( (uint8_t*) &in.session_id, 8 );
    next_random_bytes( (uint8_t*) &in.expire_timestamp, 8 );
    next_address_parse( &in.client_address, "127.0.0.1:40000" );
    next_address_parse( &in.server_address, "127.0.0.1:50000" );

    unsigned char private_key[NEXT_CRYPTO_SECRETBOX_KEYBYTES];
    next_crypto_secretbox_keygen( private_key );

    uint8_t buffer[NEXT_UPGRADE_TOKEN_BYTES];

    in.Write( buffer, private_key );

    next_check( out.Read( buffer, private_key ) == true );

    next_check( memcmp( &in, &out, sizeof(NextUpgradeToken) ) == 0 );
}

void test_route_token()
{
    uint8_t buffer[NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES];

    next_route_token_t input_token;
    memset( &input_token, 0, sizeof( input_token ) );

    input_token.expire_timestamp = 1234241431241LL;
    input_token.session_id = 1234241431241LL;
    input_token.session_version = 5;
    input_token.next_address.type = NEXT_ADDRESS_IPV4;
    input_token.next_address.data.ipv4[0] = 127;
    input_token.next_address.data.ipv4[1] = 0;
    input_token.next_address.data.ipv4[2] = 0;
    input_token.next_address.data.ipv4[3] = 1;
    input_token.next_address.port = 40000;

    next_write_route_token( &input_token, buffer, NEXT_ROUTE_TOKEN_BYTES );

    unsigned char sender_public_key[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    unsigned char sender_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];
    next_crypto_box_keypair( sender_public_key, sender_private_key );

    unsigned char receiver_public_key[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    unsigned char receiver_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];
    next_crypto_box_keypair( receiver_public_key, receiver_private_key );

    unsigned char nonce[NEXT_CRYPTO_BOX_NONCEBYTES];
    next_random_bytes( nonce, NEXT_CRYPTO_BOX_NONCEBYTES );

    next_check( next_encrypt_route_token( sender_private_key, receiver_public_key, nonce, buffer, sizeof( buffer ) ) == NEXT_OK );

    next_check( next_decrypt_route_token( sender_public_key, receiver_private_key, nonce, buffer ) == NEXT_OK );

    next_route_token_t output_token;

    next_read_route_token( &output_token, buffer );

    next_check( input_token.expire_timestamp == output_token.expire_timestamp );
    next_check( input_token.session_id == output_token.session_id );
    next_check( input_token.session_version == output_token.session_version );
    next_check( input_token.kbps_up == output_token.kbps_up );
    next_check( input_token.kbps_down == output_token.kbps_down );
    next_check( memcmp( input_token.private_key, output_token.private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES ) == 0 );
    next_check( next_address_equal( &input_token.next_address, &output_token.next_address ) == 1 );

    uint8_t * p = buffer;

    next_check( next_write_encrypted_route_token( &p, &input_token, sender_private_key, receiver_public_key ) == NEXT_OK );

    p = buffer;

    next_check( next_read_encrypted_route_token( &p, &output_token, sender_public_key, receiver_private_key ) == NEXT_OK );

    next_check( input_token.expire_timestamp == output_token.expire_timestamp );
    next_check( input_token.session_id == output_token.session_id );
    next_check( input_token.session_version == output_token.session_version );
    next_check( input_token.kbps_up == output_token.kbps_up );
    next_check( input_token.kbps_down == output_token.kbps_down );
    next_check( memcmp( input_token.private_key, output_token.private_key, NEXT_CRYPTO_BOX_SECRETKEYBYTES ) == 0 );
    next_check( next_address_equal( &input_token.next_address, &output_token.next_address ) == 1 );
}

void test_continue_token()
{
    uint8_t buffer[NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES];

    next_continue_token_t input_token;
    memset( &input_token, 0, sizeof( input_token ) );

    input_token.expire_timestamp = 1234241431241LL;
    input_token.session_id = 1234241431241LL;
    input_token.session_version = 5;

    next_write_continue_token( &input_token, buffer, NEXT_CONTINUE_TOKEN_BYTES );

    unsigned char sender_public_key[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    unsigned char sender_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];
    next_crypto_box_keypair( sender_public_key, sender_private_key );

    unsigned char receiver_public_key[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    unsigned char receiver_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];
    next_crypto_box_keypair( receiver_public_key, receiver_private_key );

    unsigned char nonce[NEXT_CRYPTO_BOX_NONCEBYTES];
    next_random_bytes( nonce, NEXT_CRYPTO_BOX_NONCEBYTES );

    next_check( next_encrypt_continue_token( sender_private_key, receiver_public_key, nonce, buffer, sizeof( buffer ) ) == NEXT_OK );

    next_check( next_decrypt_continue_token( sender_public_key, receiver_private_key, nonce, buffer ) == NEXT_OK );

    next_continue_token_t output_token;

    next_read_continue_token( &output_token, buffer );

    next_check( input_token.expire_timestamp == output_token.expire_timestamp );
    next_check( input_token.session_id == output_token.session_id );
    next_check( input_token.session_version == output_token.session_version );

    uint8_t * p = buffer;

    next_check( next_write_encrypted_continue_token( &p, &input_token, sender_private_key, receiver_public_key ) == NEXT_OK );

    p = buffer;

    memset( &output_token, 0, sizeof(output_token) );

    next_check( next_read_encrypted_continue_token( &p, &output_token, sender_public_key, receiver_private_key ) == NEXT_OK );

    next_check( input_token.expire_timestamp == output_token.expire_timestamp );
    next_check( input_token.session_id == output_token.session_id );
}

void test_ping_token()
{
    uint8_t buffer[NEXT_ENCRYPTED_PING_TOKEN_BYTES];

    next_ping_token_t input_token;
    memset( &input_token, 0, sizeof( input_token ) );

    input_token.expire_timestamp = 1234241431241LL;
    next_address_parse( &input_token.from_address, "127.0.0.1:40000" );
    next_address_parse( &input_token.to_address, "127.0.0.1:50000" );

    next_write_ping_token( &input_token, buffer, NEXT_PING_TOKEN_BYTES );

    unsigned char sender_public_key[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    unsigned char sender_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];
    next_crypto_box_keypair( sender_public_key, sender_private_key );

    unsigned char receiver_public_key[NEXT_CRYPTO_BOX_PUBLICKEYBYTES];
    unsigned char receiver_private_key[NEXT_CRYPTO_BOX_SECRETKEYBYTES];
    next_crypto_box_keypair( receiver_public_key, receiver_private_key );

    unsigned char nonce[NEXT_CRYPTO_BOX_NONCEBYTES];
    next_random_bytes( nonce, NEXT_CRYPTO_BOX_NONCEBYTES );

    next_check( next_encrypt_ping_token( sender_private_key, receiver_public_key, nonce, buffer, sizeof( buffer ) ) == NEXT_OK );

    next_check( next_decrypt_ping_token( sender_public_key, receiver_private_key, nonce, buffer ) == NEXT_OK );

    next_ping_token_t output_token;

    next_read_ping_token( &output_token, buffer );

    next_check( input_token.expire_timestamp == output_token.expire_timestamp );
    next_check( next_address_equal( &input_token.from_address, &output_token.from_address ) == 1 );
    next_check( next_address_equal( &input_token.to_address, &output_token.to_address ) == 1 );

    uint8_t * p = buffer;

    next_check( next_write_encrypted_ping_token( &p, &input_token, sender_private_key, receiver_public_key ) == NEXT_OK );

    p = buffer;

    next_check( next_read_encrypted_ping_token( &p, &output_token, sender_public_key, receiver_private_key ) == NEXT_OK );

    next_check( input_token.expire_timestamp == output_token.expire_timestamp );
    next_check( next_address_equal( &input_token.from_address, &output_token.from_address ) == 1 );
    next_check( next_address_equal( &input_token.to_address, &output_token.to_address ) == 1 );
}

void test_pittle()
{
    uint8_t output[256];
    memset( output, 0, sizeof(output) );
    for ( int i = 0; i < 10000; ++i )
    {
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );
        int packet_length = 1 + ( i % 1500 );
        next_generate_pittle( output, from_address, 4, from_port, to_address, 4, to_port, packet_length );
        next_check( output[0] != 0 );
        next_check( output[1] != 0 );
    }
}

void test_chonkle()
{
    uint8_t output[1500];
    memset( output, 0, sizeof(output) );
    output[0] = 1;
    for ( int i = 0; i < 10000; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );
        int packet_length = 18 + ( i % ( sizeof(output) - 18 ) );
        next_generate_chonkle( output + 1, magic, from_address, 4, from_port, to_address, 4, to_port, packet_length );
        next_check( next_basic_packet_filter( output, sizeof(output) ) );
    }
}

void test_abi()
{
    uint8_t output[256];
    memset( output, 0, sizeof(output) );

    uint8_t magic[8];
    magic[0] = 1;
    magic[1] = 2;
    magic[2] = 3;
    magic[3] = 4;
    magic[4] = 5;
    magic[5] = 6;
    magic[6] = 7;
    magic[7] = 8;

    uint8_t from_address[4];
    from_address[0] = 1;
    from_address[1] = 2;
    from_address[2] = 3;
    from_address[3] = 4;

    uint8_t to_address[4];
    to_address[0] = 4;
    to_address[1] = 3;
    to_address[2] = 2;
    to_address[3] = 1;

    uint16_t from_port = 1000;
    uint16_t to_port = 5000;

    int packet_length = 1000;

    next_generate_pittle( output, from_address, 4, from_port, to_address, 4, to_port, packet_length );

    next_check( output[0] == 71 );
    next_check( output[1] == 201 );

    next_generate_chonkle( output, magic, from_address, 4, from_port, to_address, 4, to_port, packet_length );

    next_check( output[0] == 45 );
    next_check( output[1] == 203 );
    next_check( output[2] == 67 );
    next_check( output[3] == 96 );
    next_check( output[4] == 78 );
    next_check( output[5] == 180 );
    next_check( output[6] == 127 );
    next_check( output[7] == 7 );
}

void test_pittle_and_chonkle()
{
    uint8_t output[1500];
    memset( output, 0, sizeof(output) );
    output[0] = 1;
    for ( int i = 0; i < 10000; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );
        int packet_length = 18 + ( i % ( sizeof(output) - 18 ) );
        next_generate_chonkle( output + 1, magic, from_address, 4, from_port, to_address, 4, to_port, packet_length );
        next_generate_pittle( output + packet_length - 2, from_address, 4, from_port, to_address, 4, to_port, packet_length );
        next_check( next_basic_packet_filter( output, sizeof(output) ) );
        next_check( next_advanced_packet_filter( output, magic, from_address, 4, from_port, to_address, 4, to_port, packet_length ) );
    }
}

void test_basic_packet_filter()
{
    uint8_t output[256];
    memset( output, 0, sizeof(output) );
    uint64_t pass = 0;
    uint64_t iterations = 100;
    srand( 100 );
    for ( int i = 0; i < int(iterations); ++i )
    {
        for ( int j = 0; j < int(sizeof(output)); ++j )
        {
            output[j] = uint8_t( rand() % 256 );
        }
        if ( next_basic_packet_filter( output, rand() % sizeof(output) ) )
        {
            pass++;
        }
    }
    next_check( pass == 0 );
}

void test_advanced_packet_filter()
{
    uint8_t output[256];
    memset( output, 0, sizeof(output) );
    uint64_t pass = 0;
    uint64_t iterations = 100;
    srand( 100 );
    for ( int i = 0; i < int(iterations); ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );
        int packet_length = 18 + ( i % ( sizeof(output) - 18 ) );
        for ( int j = 0; j < int(sizeof(output)); ++j )
        {
            output[j] = uint8_t( rand() % 256 );
        }
        if ( next_advanced_packet_filter( output, magic, from_address, 4, from_port, to_address, 4, to_port, packet_length ) )
        {
            pass++;
        }
    }
    next_check( pass == 0 );
}

void test_passthrough()
{
    uint8_t output[256];
    memset( output, 0, sizeof(output) );
    uint8_t magic[8];
    uint8_t from_address[4];
    uint8_t to_address[4];
    next_random_bytes( magic, 8 );
    next_random_bytes( from_address, 4 );
    next_random_bytes( to_address, 4 );
    uint16_t from_port = uint16_t( 1000 );
    uint16_t to_port = uint16_t( 5000 );
    int packet_length = sizeof(output);
    next_check( next_basic_packet_filter( output, packet_length ) );
    next_check( next_advanced_packet_filter( output, magic, from_address, 4, from_port, to_address, 4, to_port, packet_length ) );
}

void test_address_data_none()
{
    next_address_t address;
    memset( &address, 0, sizeof(address) );
    next_check( address.type == NEXT_ADDRESS_NONE );
    uint8_t address_data[32];
    int address_bytes = 0;
    uint16_t address_port = 0;
    next_address_data( &address, address_data, &address_bytes, &address_port );
    next_check( address_bytes == 0 );
    next_check( address_port == 0 );
}

void test_address_data_ipv4()
{
    next_address_t address;
    next_address_parse( &address, "127.0.0.1:50000" );
    next_check( address.type == NEXT_ADDRESS_IPV4 );
    uint8_t address_data[32];
    int address_bytes = 0;
    uint16_t address_port = 0;
    next_address_data( &address, address_data, &address_bytes, &address_port );
    next_check( address_data[0] == 127 );
    next_check( address_data[1] == 0 );
    next_check( address_data[2] == 0 );
    next_check( address_data[3] == 1 );
    next_check( address_bytes == 4 );
    next_check( address_port == 50000 );
}

#if NEXT_PLATFORM_HAS_IPV6

void test_address_data_ipv6()
{
    next_address_t address;
    next_address_parse( &address, "[2001:db8:3333:4444:5555:6666:7777:8888]:50000" );
    next_check( address.type == NEXT_ADDRESS_IPV6 );
    uint8_t address_data[32];
    int address_bytes = 0;
    uint16_t address_port = 0;
    next_address_data( &address, address_data, &address_bytes, &address_port );
    next_check( address_data[0] == 32 );
    next_check( address_data[1] == 1 );
    next_check( address_data[2] == 13 );
    next_check( address_data[3] == 184 );
    next_check( address_data[4] == 51 );
    next_check( address_data[5] == 51 );
    next_check( address_data[6] == 68 );
    next_check( address_data[7] == 68 );
    next_check( address_data[8] == 85 );
    next_check( address_data[9] == 85 );
    next_check( address_data[10] == 102 );
    next_check( address_data[11] == 102 );
    next_check( address_data[12] == 119 );
    next_check( address_data[13] == 119 );
    next_check( address_data[14] == 136 );
    next_check( address_data[15] == 136 );
    next_check( address_bytes == 16 );
    next_check( address_port == 50000 );
}

#endif // #if NEXT_PLATFORM_HAS_IPV6

void test_direct_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        uint8_t open_session_sequence = uint8_t( i + 10 );
        uint64_t send_sequence = i;

        uint8_t game_packet_data[NEXT_MTU];
        int game_packet_bytes = rand() % NEXT_MTU;
        for ( int j = 0; j < game_packet_bytes; j++ ) { game_packet_data[j] = uint8_t( rand() % 256 ); }

        int packet_bytes = next_write_direct_packet( packet_data, open_session_sequence, send_sequence, game_packet_data, game_packet_bytes, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( packet_bytes >= 0 );
        next_check( packet_bytes <= NEXT_MTU + 27 );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        next_check( packet_data[0] == NEXT_DIRECT_PACKET );
        next_check( memcmp( packet_data + 25, game_packet_data, game_packet_bytes ) == 0 );
    }
}

void test_direct_ping_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        uint64_t in_sequence = i;

        static next_replay_protection_t replay_protection;
        next_replay_protection_reset( &replay_protection );

        NextDirectPingPacket in;
        in.ping_sequence = i + 1000;
        int packet_bytes = 0;
        int result = next_write_packet( NEXT_DIRECT_PING_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, next_encrypted_packets, &in_sequence, NULL, private_key, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( result == NEXT_OK );
        next_check( packet_bytes == 1 + 15 + 8 + 8 + NEXT_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES + 2 );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        NextDirectPingPacket out;
        uint64_t out_sequence = 0;
        const int begin = 16;
        const int end = packet_bytes - 2;
        int packet_type = next_read_packet( NEXT_DIRECT_PING_PACKET, packet_data, begin, end, &out, next_signed_packets, next_encrypted_packets, &out_sequence, NULL, private_key, &replay_protection );

        next_check( packet_type == NEXT_DIRECT_PING_PACKET );

        next_check( in.ping_sequence == out.ping_sequence );

        next_check( in_sequence == out_sequence + 1 );
    }
}

void test_direct_pong_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        uint64_t in_sequence = i;

        static next_replay_protection_t replay_protection;
        next_replay_protection_reset( &replay_protection );

        NextDirectPongPacket in;
        in.ping_sequence = i + 1000;
        int packet_bytes = 0;
        int result = next_write_packet( NEXT_DIRECT_PONG_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, next_encrypted_packets, &in_sequence, NULL, private_key, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( result == NEXT_OK );
        next_check( packet_bytes == 1 + 15 + 8 + 8 + NEXT_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES + 2 );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        NextDirectPongPacket out;
        uint64_t out_sequence = 0;
        const int begin = 16;
        const int end = packet_bytes - 2;
        int packet_type = next_read_packet( NEXT_DIRECT_PONG_PACKET, packet_data, begin, end, &out, next_signed_packets, next_encrypted_packets, &out_sequence, NULL, private_key, &replay_protection );

        next_check( packet_type == NEXT_DIRECT_PONG_PACKET );

        next_check( in.ping_sequence == out.ping_sequence );

        next_check( in_sequence == out_sequence + 1 );
    }
}

void test_upgrade_request_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];

    uint64_t iterations = 100;
    
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        static NextUpgradeRequestPacket in, out;
        in.protocol_version = next_protocol_version();
        in.session_id = 1231234127431LL;
        next_address_parse( &in.client_address, "127.0.0.1:50000" );
        next_address_parse( &in.server_address, "127.0.0.1:12345" );
        next_random_bytes( in.server_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES );
        next_random_bytes( in.upgrade_token, NEXT_UPGRADE_TOKEN_BYTES );
        next_random_bytes( in.upcoming_magic, 8 );
        next_random_bytes( in.current_magic, 8 );
        next_random_bytes( in.previous_magic, 8 );

        int packet_bytes = 0;
        int result = next_write_packet( NEXT_UPGRADE_REQUEST_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, NULL, NULL, private_key, NULL, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( result == NEXT_OK );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        int packet_type = next_read_packet( NEXT_UPGRADE_REQUEST_PACKET, packet_data, begin, end, &out, next_signed_packets, NULL, NULL, public_key, NULL, NULL );

        next_check( packet_type == NEXT_UPGRADE_REQUEST_PACKET );

        next_check( in.protocol_version == out.protocol_version );
        next_check( in.session_id == out.session_id );
        next_check( next_address_equal( &in.client_address, &out.client_address ) );
        next_check( next_address_equal( &in.server_address, &out.server_address ) );
        next_check( memcmp( in.server_kx_public_key, out.server_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES ) == 0 );
        next_check( memcmp( in.upgrade_token, out.upgrade_token, NEXT_UPGRADE_TOKEN_BYTES ) == 0 );
        next_check( memcmp( in.upcoming_magic, out.upcoming_magic, 8 ) == 0 );
        next_check( memcmp( in.current_magic, out.current_magic, 8 ) == 0 );
        next_check( memcmp( in.previous_magic, out.previous_magic, 8 ) == 0 );
    }
}

void test_upgrade_response_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextUpgradeResponsePacket in, out;
        next_random_bytes( in.client_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES );
        next_random_bytes( in.client_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES );
        next_random_bytes( in.upgrade_token, NEXT_UPGRADE_TOKEN_BYTES );
        in.platform_id = NEXT_PLATFORM_WINDOWS;
        in.connection_type = NEXT_CONNECTION_TYPE_CELLULAR;

        int packet_bytes = 0;
        int result = next_write_packet( NEXT_UPGRADE_RESPONSE_PACKET, &in, packet_data, &packet_bytes, NULL, NULL, NULL, NULL, NULL, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( result == NEXT_OK );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        int packet_type = next_read_packet( NEXT_UPGRADE_RESPONSE_PACKET, packet_data, begin, end, &out, NULL, NULL, NULL, NULL, NULL, NULL );

        next_check( packet_type == NEXT_UPGRADE_RESPONSE_PACKET );

        next_check( memcmp( in.client_kx_public_key, out.client_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES ) == 0 );
        next_check( memcmp( in.client_route_public_key, out.client_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES ) == 0 );
        next_check( memcmp( in.upgrade_token, out.upgrade_token, NEXT_UPGRADE_TOKEN_BYTES ) == 0 );
        next_check( in.platform_id == out.platform_id );
        next_check( in.connection_type == out.connection_type );
    }
}

void test_upgrade_confirm_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        static NextUpgradeConfirmPacket in, out;
        in.upgrade_sequence = 1000;
        in.session_id = 1231234127431LL;
        next_address_parse( &in.server_address, "127.0.0.1:12345" );
        next_random_bytes( in.client_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES );
        next_random_bytes( in.server_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES );

        int packet_bytes = 0;
        int result = next_write_packet( NEXT_UPGRADE_CONFIRM_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, NULL, NULL, private_key, NULL, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( result == NEXT_OK );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        int packet_type = next_read_packet( NEXT_UPGRADE_CONFIRM_PACKET, packet_data, begin, end, &out, next_signed_packets, NULL, NULL, public_key, NULL, NULL );

        next_check( packet_type == NEXT_UPGRADE_CONFIRM_PACKET );

        next_check( in.upgrade_sequence == out.upgrade_sequence );
        next_check( in.session_id == out.session_id );
        next_check( next_address_equal( &in.server_address, &out.server_address ) );
        next_check( memcmp( in.client_kx_public_key, out.client_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES ) == 0 );
        next_check( memcmp( in.server_kx_public_key, out.server_kx_public_key, NEXT_CRYPTO_KX_PUBLICKEYBYTES ) == 0 );
    }
}

void test_route_request_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        uint8_t token_data[1024];
        int token_bytes = rand() % sizeof(token_data);
        for ( int j = 0; j < token_bytes; j++ ) { token_data[j] = uint8_t( rand() % 256 ); }

        int packet_bytes = next_write_route_request_packet( packet_data, token_data, token_bytes, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( packet_bytes > 0 );
        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        next_check( packet_data[0] == NEXT_ROUTE_REQUEST_PACKET );
        next_check( memcmp( packet_data + 16, token_data, token_bytes ) == 0 );
    }
}

void test_header()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint64_t send_sequence = i + 1000;
        uint64_t session_id = 0x12314141LL;
        uint8_t session_version = uint8_t(i%256);
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        next_check( next_write_header( NEXT_DIRECTION_CLIENT_TO_SERVER, NEXT_CLIENT_TO_SERVER_PACKET, send_sequence, session_id, session_version, private_key, packet_data ) == NEXT_OK );

        uint64_t read_packet_sequence = 0;
        uint64_t read_packet_session_id = 0;
        uint8_t read_packet_session_version = 0;

        next_check( next_read_header( NEXT_DIRECTION_CLIENT_TO_SERVER, NEXT_CLIENT_TO_SERVER_PACKET, &read_packet_sequence, &read_packet_session_id, &read_packet_session_version, private_key, packet_data, NEXT_HEADER_BYTES ) == NEXT_OK );

        next_check( read_packet_sequence == send_sequence );
        next_check( read_packet_session_id == session_id );
        next_check( read_packet_session_version == session_version );
    }
}

void test_route_response_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        uint64_t send_sequence = i + 1000;
        uint64_t session_id = 0x12314141LL;
        uint8_t session_version = uint8_t(i%256);
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        int packet_bytes = next_write_route_response_packet( packet_data, send_sequence, session_id, session_version, private_key, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( packet_bytes > 0 );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        next_check( packet_data[0] == NEXT_ROUTE_RESPONSE_PACKET );

        uint64_t read_packet_sequence = 0;
        uint64_t read_packet_session_id = 0;
        uint8_t read_packet_session_version = 0;

        uint8_t * read_packet_data = packet_data + 16;
        int read_packet_bytes = packet_bytes - 16;

        next_check( next_read_header( NEXT_DIRECTION_SERVER_TO_CLIENT, NEXT_ROUTE_RESPONSE_PACKET, &read_packet_sequence, &read_packet_session_id, &read_packet_session_version, private_key, read_packet_data, read_packet_bytes ) == NEXT_OK );

        next_check( read_packet_sequence == ( send_sequence | 0xC000000000000000LL ) );
        next_check( read_packet_session_id == session_id );
        next_check( read_packet_session_version == session_version );
    }
}

void test_client_to_server_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        uint64_t send_sequence = i + 1000;
        uint64_t session_id = 0x12314141LL;
        uint8_t session_version = uint8_t(i%256);
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        uint8_t game_packet_data[NEXT_MTU];
        int game_packet_bytes = rand() % NEXT_MTU;
        for ( int j = 0; j < game_packet_bytes; j++ ) { game_packet_data[j] = uint8_t( rand() % 256 ); }

        int packet_bytes = next_write_client_to_server_packet( packet_data, send_sequence, session_id, session_version, private_key, game_packet_data, game_packet_bytes, magic, from_address, 4, from_port, to_address, 4, to_port );
        next_check( packet_bytes > 0 );
        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        next_check( packet_data[0] == NEXT_CLIENT_TO_SERVER_PACKET );

        next_check( memcmp( packet_data + 1 + 15 + NEXT_HEADER_BYTES, game_packet_data, game_packet_bytes ) == 0 );

        uint64_t read_packet_sequence = 0;
        uint64_t read_packet_session_id = 0;
        uint8_t read_packet_session_version = 0;

        uint8_t * read_packet_data = packet_data + 16;
        int read_packet_bytes = packet_bytes - 16;

        next_check( next_read_header( NEXT_DIRECTION_CLIENT_TO_SERVER, NEXT_CLIENT_TO_SERVER_PACKET, &read_packet_sequence, &read_packet_session_id, &read_packet_session_version, private_key, read_packet_data, read_packet_bytes ) == NEXT_OK );

        next_check( read_packet_sequence == send_sequence );
        next_check( read_packet_session_id == session_id );
        next_check( read_packet_session_version == session_version );
    }
}

void test_server_to_client_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        uint64_t send_sequence = i + 1000;
        uint64_t session_id = 0x12314141LL;
        uint8_t session_version = uint8_t(i%256);
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        uint8_t game_packet_data[NEXT_MTU];
        int game_packet_bytes = rand() % NEXT_MTU;
        for ( int j = 0; j < game_packet_bytes; j++ ) { game_packet_data[j] = uint8_t( rand() % 256 ); }

        int packet_bytes = next_write_server_to_client_packet( packet_data, send_sequence, session_id, session_version, private_key, game_packet_data, game_packet_bytes, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( packet_bytes > 0 );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        next_check( packet_data[0] == NEXT_SERVER_TO_CLIENT_PACKET );

        next_check( memcmp( packet_data + 1 + 15 + NEXT_HEADER_BYTES, game_packet_data, game_packet_bytes ) == 0 );

        uint64_t read_packet_sequence = 0;
        uint64_t read_packet_session_id = 0;
        uint8_t read_packet_session_version = 0;

        uint8_t * read_packet_data = packet_data + 16;
        int read_packet_bytes = packet_bytes - 16;

        next_check( next_read_header( NEXT_DIRECTION_SERVER_TO_CLIENT, NEXT_SERVER_TO_CLIENT_PACKET, &read_packet_sequence, &read_packet_session_id, &read_packet_session_version, private_key, read_packet_data, read_packet_bytes ) == NEXT_OK );

        next_check( read_packet_sequence == ( send_sequence | (0x1LL<< 63) ) );
        next_check( read_packet_session_id == session_id );
        next_check( read_packet_session_version == session_version );
    }
}

void test_ping_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        uint64_t send_sequence = i + 1000;
        uint64_t session_id = 0x12314141LL;
        uint8_t session_version = uint8_t(i%256);
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        uint64_t ping_sequence = i;
        int packet_bytes = next_write_ping_packet( packet_data, send_sequence, session_id, session_version, private_key, ping_sequence, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( packet_bytes > 0 );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        next_check( packet_data[0] == NEXT_PING_PACKET );

        uint64_t read_packet_sequence = 0;
        uint64_t read_packet_session_id = 0;
        uint8_t read_packet_session_version = 0;

        uint8_t * read_packet_data = packet_data + 16;
        int read_packet_bytes = packet_bytes - 16;

        next_check( next_read_header( NEXT_DIRECTION_CLIENT_TO_SERVER, NEXT_PING_PACKET, &read_packet_sequence, &read_packet_session_id, &read_packet_session_version, private_key, read_packet_data, read_packet_bytes ) == NEXT_OK );

        next_check( read_packet_sequence == ( send_sequence | (1LL<<62) ) );
        next_check( read_packet_session_id == session_id );
        next_check( read_packet_session_version == session_version );
    }
}

void test_pong_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        uint64_t send_sequence = i + 1000;
        uint64_t session_id = 0x12314141LL;
        uint8_t session_version = uint8_t(i%256);
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];

        next_random_bytes( private_key, sizeof(private_key) );

        uint64_t ping_sequence = i;
        int packet_bytes = next_write_pong_packet( packet_data, send_sequence, session_id, session_version, private_key, ping_sequence, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( packet_bytes > 0 );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        next_check( packet_data[0] == NEXT_PONG_PACKET );

        uint64_t read_packet_sequence = 0;
        uint64_t read_packet_session_id = 0;
        uint8_t read_packet_session_version = 0;

        uint8_t * read_packet_data = packet_data + 16;
        int read_packet_bytes = packet_bytes - 16;

        next_check( next_read_header( NEXT_DIRECTION_SERVER_TO_CLIENT, NEXT_PONG_PACKET, &read_packet_sequence, &read_packet_session_id, &read_packet_session_version, private_key, read_packet_data, read_packet_bytes ) == NEXT_OK );

        next_check( read_packet_sequence == ( send_sequence | 0xC000000000000000LL ) );
        next_check( read_packet_session_id == session_id );
        next_check( read_packet_session_version == session_version );
    }
}

void test_continue_request_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );
        uint8_t token_data[256];
        int token_bytes = rand() % sizeof(token_data);
        for ( int j = 0; j < token_bytes; j++ ) { token_data[j] = uint8_t( rand() % 256 ); }
        int packet_bytes = next_write_continue_request_packet( packet_data, token_data, token_bytes, magic, from_address, 4, from_port, to_address, 4, to_port );
        next_check( packet_bytes >= 0 );
        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );
        next_check( packet_data[0] == NEXT_CONTINUE_REQUEST_PACKET );
        next_check( memcmp( packet_data + 16, token_data, token_bytes ) == 0 );
    }
}

void test_continue_response_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        uint64_t send_sequence = i + 1000;
        uint64_t session_id = 0x12314141LL;
        uint8_t session_version = uint8_t(i%256);
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        int packet_bytes = next_write_continue_response_packet( packet_data, send_sequence, session_id, session_version, private_key, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( packet_bytes > 0 );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        next_check( packet_data[0] == NEXT_CONTINUE_RESPONSE_PACKET );

        uint64_t read_packet_sequence = 0;
        uint64_t read_packet_session_id = 0;
        uint8_t read_packet_session_version = 0;

        uint8_t * read_packet_data = packet_data + 16;
        int read_packet_bytes = packet_bytes - 16;

        next_check( next_read_header( NEXT_DIRECTION_SERVER_TO_CLIENT, NEXT_CONTINUE_RESPONSE_PACKET, &read_packet_sequence, &read_packet_session_id, &read_packet_session_version, private_key, read_packet_data, read_packet_bytes ) == NEXT_OK );

        next_check( read_packet_sequence == ( send_sequence | 0xC000000000000000LL ) );
        next_check( read_packet_session_id == session_id );
        next_check( read_packet_session_version == session_version );
    }
}

void test_client_stats_packet_with_near_relays()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextClientStatsPacket in, out;
        in.reported = true;
        in.fallback_to_direct = true;
        in.platform_id = NEXT_PLATFORM_WINDOWS;
        in.connection_type = NEXT_CONNECTION_TYPE_CELLULAR;
        in.direct_rtt = 50.0f;
        in.direct_jitter = 10.0f;
        in.direct_packet_loss = 0.1f;
        in.direct_max_packet_loss_seen = 0.25f;
        in.next = true;
        in.next_rtt = 50.0f;
        in.next_jitter = 5.0f;
        in.next_packet_loss = 0.01f;
        in.num_near_relays = NEXT_MAX_NEAR_RELAYS;
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            in.near_relay_ids[j] = uint64_t(10000000) + j;
            in.near_relay_rtt[j] = 5 * j;
            in.near_relay_jitter[j] = 0.01f * j;
            in.near_relay_packet_loss[j] = j;
        }
        in.packets_lost_server_to_client = 1000;

        static next_replay_protection_t replay_protection;
        next_replay_protection_reset( &replay_protection );
        uint64_t in_sequence = 1000;

        int packet_bytes = 0;
        next_check( next_write_packet( NEXT_CLIENT_STATS_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, next_encrypted_packets, &in_sequence, NULL, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        next_check( packet_data[0] == NEXT_CLIENT_STATS_PACKET );
        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        uint64_t out_sequence = 0;
        const int begin = 16;
        const int end = packet_bytes - 2;
        next_check( next_read_packet( NEXT_CLIENT_STATS_PACKET, packet_data, begin, end, &out, next_signed_packets, next_encrypted_packets, &out_sequence, NULL, private_key, &replay_protection ) == NEXT_CLIENT_STATS_PACKET );

        next_check( in_sequence == out_sequence + 1 );
        next_check( in.reported == out.reported );
        next_check( in.fallback_to_direct == out.fallback_to_direct );
        next_check( in.platform_id == out.platform_id );
        next_check( in.connection_type == out.connection_type );
        next_check( in.direct_rtt == out.direct_rtt );
        next_check( in.direct_jitter == out.direct_jitter );
        next_check( in.direct_packet_loss == out.direct_packet_loss );
        next_check( in.direct_max_packet_loss_seen == out.direct_max_packet_loss_seen );
        next_check( in.next == out.next );
        next_check( in.next_rtt == out.next_rtt );
        next_check( in.next_jitter == out.next_jitter );
        next_check( in.next_packet_loss == out.next_packet_loss );
        next_check( in.num_near_relays == out.num_near_relays );
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            next_check( in.near_relay_ids[j] == out.near_relay_ids[j] );
            next_check( in.near_relay_rtt[j] == out.near_relay_rtt[j] );
            next_check( in.near_relay_jitter[j] == out.near_relay_jitter[j] );
            next_check( in.near_relay_packet_loss[j] == out.near_relay_packet_loss[j] );
        }
        next_check( in.packets_sent_client_to_server == out.packets_sent_client_to_server );
        next_check( in.packets_lost_server_to_client == out.packets_lost_server_to_client );
    }
}

void test_client_stats_packet_without_near_relays()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextClientStatsPacket in, out;
        in.reported = true;
        in.fallback_to_direct = true;
        in.platform_id = NEXT_PLATFORM_WINDOWS;
        in.connection_type = NEXT_CONNECTION_TYPE_CELLULAR;
        in.direct_rtt = 50.0f;
        in.direct_jitter = 10.0f;
        in.direct_packet_loss = 0.1f;
        in.direct_max_packet_loss_seen = 0.25f;
        in.next = true;
        in.next_rtt = 50.0f;
        in.next_jitter = 5.0f;
        in.next_packet_loss = 0.01f;
        in.num_near_relays = 0;
        in.packets_lost_server_to_client = 1000;

        static next_replay_protection_t replay_protection;
        next_replay_protection_reset( &replay_protection );
        uint64_t in_sequence = 1000;

        int packet_bytes = 0;
        next_check( next_write_packet( NEXT_CLIENT_STATS_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, next_encrypted_packets, &in_sequence, NULL, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        next_check( packet_data[0] == NEXT_CLIENT_STATS_PACKET );
        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        uint64_t out_sequence = 0;
        const int begin = 16;
        const int end = packet_bytes - 2;
        next_check( next_read_packet( NEXT_CLIENT_STATS_PACKET, packet_data, begin, end, &out, next_signed_packets, next_encrypted_packets, &out_sequence, NULL, private_key, &replay_protection ) == NEXT_CLIENT_STATS_PACKET );

        next_check( in_sequence == out_sequence + 1 );
        next_check( in.reported == out.reported );
        next_check( in.fallback_to_direct == out.fallback_to_direct );
        next_check( in.platform_id == out.platform_id );
        next_check( in.connection_type == out.connection_type );
        next_check( in.direct_rtt == out.direct_rtt );
        next_check( in.direct_jitter == out.direct_jitter );
        next_check( in.direct_packet_loss == out.direct_packet_loss );
        next_check( in.direct_max_packet_loss_seen == out.direct_max_packet_loss_seen );
        next_check( in.next == out.next );
        next_check( in.next_rtt == out.next_rtt );
        next_check( in.next_jitter == out.next_jitter );
        next_check( in.next_packet_loss == out.next_packet_loss );
        next_check( in.num_near_relays == out.num_near_relays );
        next_check( in.packets_sent_client_to_server == out.packets_sent_client_to_server );
        next_check( in.packets_lost_server_to_client == out.packets_lost_server_to_client );
    }
}

void test_route_update_packet_direct()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextRouteUpdatePacket in, out;

        in.sequence = 100000;
        in.has_near_relays = true;
        in.num_near_relays = NEXT_MAX_NEAR_RELAYS;
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            char relay_name[32];
            char relay_address[256];
            snprintf( relay_name, sizeof(relay_name), "relay%d", j );
            snprintf( relay_address, sizeof(relay_address), "127.0.0.1:%d", 40000 + j );
            in.near_relay_ids[j] = next_relay_id( relay_name );
            next_address_parse( &in.near_relay_addresses[j], relay_address );
        }
        in.update_type = NEXT_UPDATE_TYPE_DIRECT;
        in.packets_sent_server_to_client = 11000;
        in.packets_lost_client_to_server = 10000;
        in.packets_out_of_order_client_to_server = 9000;
        next_random_bytes( in.upcoming_magic, 8 );
        next_random_bytes( in.current_magic, 8 );
        next_random_bytes( in.previous_magic, 8 );
        in.jitter_client_to_server = 0.1f;
        in.has_debug = true;
        strcpy( in.debug, "debug time" );

        static next_replay_protection_t replay_protection;
        next_replay_protection_reset( &replay_protection );
        uint64_t in_sequence = 1000;

        int packet_bytes = 0;
        next_check( next_write_packet( NEXT_ROUTE_UPDATE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, next_encrypted_packets, &in_sequence, NULL, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        next_check( packet_data[0] == NEXT_ROUTE_UPDATE_PACKET );
        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        uint64_t out_sequence = 0;
        const int begin = 16;
        const int end = packet_bytes - 2;
        next_check( next_read_packet( NEXT_ROUTE_UPDATE_PACKET, packet_data, begin, end, &out, next_signed_packets, next_encrypted_packets, &out_sequence, NULL, private_key, &replay_protection ) == NEXT_ROUTE_UPDATE_PACKET );

        next_check( in_sequence == out_sequence + 1 );
        next_check( in.sequence == out.sequence );
        next_check( in.has_near_relays == out.has_near_relays );
        next_check( in.num_near_relays == out.num_near_relays );
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            next_check( in.near_relay_ids[j] == out.near_relay_ids[j] );
            next_check( next_address_equal( &in.near_relay_addresses[j], &out.near_relay_addresses[j] ) );
        }
        next_check( in.update_type == out.update_type );
        next_check( in.packets_sent_server_to_client == out.packets_sent_server_to_client );
        next_check( in.packets_lost_client_to_server == out.packets_lost_client_to_server );
        next_check( in.packets_out_of_order_client_to_server == out.packets_out_of_order_client_to_server );
        next_check( memcmp( in.upcoming_magic, out.upcoming_magic, 8 ) == 0 );
        next_check( memcmp( in.current_magic, out.current_magic, 8 ) == 0 );
        next_check( memcmp( in.previous_magic, out.previous_magic, 8 ) == 0 );
        next_check( in.jitter_client_to_server == out.jitter_client_to_server );
        next_check( in.has_debug == out.has_debug );
        next_check( strcmp( in.debug, out.debug ) == 0 );
    }
}

void test_route_update_packet_new_route()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextRouteUpdatePacket in, out;
        in.sequence = 100000;
        in.has_near_relays = true;
        in.num_near_relays = NEXT_MAX_NEAR_RELAYS;
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            char relay_name[32];
            char relay_address[256];
            snprintf( relay_name, sizeof(relay_name), "relay%d", j );
            snprintf( relay_address, sizeof(relay_address), "127.0.0.1:%d", 40000 + j );
            in.near_relay_ids[j] = next_relay_id( relay_name );
            next_address_parse( &in.near_relay_addresses[j], relay_address );
        }
        in.update_type = NEXT_UPDATE_TYPE_ROUTE;
        in.multipath = true;
        in.num_tokens = NEXT_MAX_TOKENS;
        next_random_bytes( in.tokens, NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES * NEXT_MAX_TOKENS );
        in.packets_sent_server_to_client = 11000;
        in.packets_lost_client_to_server = 10000;
        in.packets_out_of_order_client_to_server = 9000;
        next_random_bytes( in.upcoming_magic, 8 );
        next_random_bytes( in.current_magic, 8 );
        next_random_bytes( in.previous_magic, 8 );
        in.jitter_client_to_server = 0.25f;

        static next_replay_protection_t replay_protection;
        next_replay_protection_reset( &replay_protection );

        int packet_bytes = 0;
        uint64_t in_sequence = 1000;
        next_check( next_write_packet( NEXT_ROUTE_UPDATE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, next_encrypted_packets, &in_sequence, NULL, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        next_check( packet_data[0] == NEXT_ROUTE_UPDATE_PACKET );
        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        uint64_t out_sequence = 0;
        const int begin = 16;
        const int end = packet_bytes - 2;
        next_check( next_read_packet( NEXT_ROUTE_UPDATE_PACKET, packet_data, begin, end, &out, next_signed_packets, next_encrypted_packets, &out_sequence, NULL, private_key, &replay_protection ) == NEXT_ROUTE_UPDATE_PACKET );

        next_check( in_sequence == out_sequence + 1 );
        next_check( in.sequence == out.sequence );
        next_check( in.has_near_relays == out.has_near_relays );
        next_check( in.num_near_relays == out.num_near_relays );
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            next_check( in.near_relay_ids[j] == out.near_relay_ids[j] );
            next_check( next_address_equal( &in.near_relay_addresses[j], &out.near_relay_addresses[j] ) );
        }
        next_check( in.update_type == out.update_type );
        next_check( in.multipath == out.multipath );
        next_check( in.num_tokens == out.num_tokens );
        next_check( memcmp( in.tokens, out.tokens, NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES * NEXT_MAX_TOKENS ) == 0 );
        next_check( in.packets_sent_server_to_client == out.packets_sent_server_to_client );
        next_check( in.packets_lost_client_to_server == out.packets_lost_client_to_server );
        next_check( in.packets_out_of_order_client_to_server == out.packets_out_of_order_client_to_server );
        next_check( memcmp( in.upcoming_magic, out.upcoming_magic, 8 ) == 0 );
        next_check( memcmp( in.current_magic, out.current_magic, 8 ) == 0 );
        next_check( memcmp( in.previous_magic, out.previous_magic, 8 ) == 0 );
        next_check( in.jitter_client_to_server == out.jitter_client_to_server );
    }
}

void test_route_update_packet_continue_route()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextRouteUpdatePacket in, out;
        in.sequence = 100000;
        in.has_near_relays = true;
        in.num_near_relays = NEXT_MAX_NEAR_RELAYS;
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            char relay_name[32];
            char relay_address[256];
            snprintf( relay_name, sizeof(relay_name), "relay%d", j );
            snprintf( relay_address, sizeof(relay_address), "127.0.0.1:%d", 40000 + j );
            in.near_relay_ids[j] = next_relay_id( relay_name );
            next_address_parse( &in.near_relay_addresses[j], relay_address );
        }
        in.update_type = NEXT_UPDATE_TYPE_CONTINUE;
        in.multipath = true;
        in.num_tokens = NEXT_MAX_TOKENS;
        next_random_bytes( in.tokens, NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES * NEXT_MAX_TOKENS );
        in.packets_lost_client_to_server = 10000;

        static next_replay_protection_t replay_protection;
        next_replay_protection_reset( &replay_protection );

        int packet_bytes = 0;
        uint64_t in_sequence = 1000;
        next_check( next_write_packet( NEXT_ROUTE_UPDATE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, next_encrypted_packets, &in_sequence, NULL, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        next_check( packet_data[0] == NEXT_ROUTE_UPDATE_PACKET );
        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        uint64_t out_sequence = 0;
        const int begin = 16;
        const int end = packet_bytes - 2;
        next_check( next_read_packet( NEXT_ROUTE_UPDATE_PACKET, packet_data, begin, end, &out, next_signed_packets, next_encrypted_packets, &out_sequence, NULL, private_key, &replay_protection ) == NEXT_ROUTE_UPDATE_PACKET );

        next_check( in_sequence == out_sequence + 1 );
        next_check( in.sequence == out.sequence );
        next_check( in.has_near_relays == out.has_near_relays );
        next_check( in.num_near_relays == out.num_near_relays );
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            next_check( in.near_relay_ids[j] == out.near_relay_ids[j] );
            next_check( next_address_equal( &in.near_relay_addresses[j], &out.near_relay_addresses[j] ) );
        }
        next_check( in.update_type == out.update_type );
        next_check( in.multipath == out.multipath );
        next_check( in.num_tokens == out.num_tokens );
        next_check( memcmp( in.tokens, out.tokens, NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES * NEXT_MAX_TOKENS ) == 0 );
        next_check( in.packets_lost_client_to_server == out.packets_lost_client_to_server );
        next_check( memcmp( in.upcoming_magic, out.upcoming_magic, 8 ) == 0 );
        next_check( memcmp( in.current_magic, out.current_magic, 8 ) == 0 );
        next_check( memcmp( in.previous_magic, out.previous_magic, 8 ) == 0 );
    }
}

void test_route_update_ack_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t private_key[NEXT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
        next_random_bytes( private_key, sizeof(private_key) );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextRouteUpdateAckPacket in, out;
        in.sequence = 100000;

        static next_replay_protection_t replay_protection;
        next_replay_protection_reset( &replay_protection );

        int packet_bytes = 0;
        uint64_t in_sequence = 1000;
        next_check( next_write_packet( NEXT_ROUTE_UPDATE_ACK_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, next_encrypted_packets, &in_sequence, NULL, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        next_check( packet_data[0] == NEXT_ROUTE_UPDATE_ACK_PACKET );
        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        uint64_t out_sequence = 0;
        const int begin = 16;
        const int end = packet_bytes - 2;
        next_check( next_read_packet( NEXT_ROUTE_UPDATE_ACK_PACKET, packet_data, begin, end, &out, next_signed_packets, next_encrypted_packets, &out_sequence, NULL, private_key, &replay_protection ) == NEXT_ROUTE_UPDATE_ACK_PACKET );

        next_check( in_sequence == out_sequence + 1 );
        next_check( in.sequence == out.sequence );
    }
}

void test_relay_ping_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        uint8_t ping_token[NEXT_ENCRYPTED_PING_TOKEN_BYTES];
        next_random_bytes( ping_token, NEXT_ENCRYPTED_PING_TOKEN_BYTES );

        uint64_t ping_sequence = i;
        uint64_t ping_session_id = 0x12345;

        int packet_bytes = next_write_relay_ping_packet( packet_data, ping_token, ping_sequence, ping_session_id, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( packet_bytes >= 0 );
        next_check( packet_bytes <= NEXT_MTU + 27 );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        next_check( packet_data[0] == NEXT_RELAY_PING_PACKET );

        const uint8_t * p = packet_data + 16;
        uint64_t read_ping_sequence = next_read_uint64( &p );
        uint64_t read_ping_session_id = next_read_uint64( &p );

        next_check( read_ping_sequence == ping_sequence );
        next_check( read_ping_session_id == ping_session_id );

        next_check( memcmp( packet_data + 1 + 15 + 8 + 8, ping_token, NEXT_ENCRYPTED_PING_TOKEN_BYTES ) == 0 );
    }
}

void test_relay_pong_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        uint64_t pong_sequence = i;
        uint64_t pong_session_id = 0x123456;

        int packet_bytes = next_write_relay_pong_packet( packet_data, pong_sequence, pong_session_id, magic, from_address, 4, from_port, to_address, 4, to_port );

        next_check( packet_bytes >= 0 );
        next_check( packet_bytes <= NEXT_MTU + 27 );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        next_check( packet_data[0] == NEXT_RELAY_PONG_PACKET );

        const uint8_t * p = packet_data + 16;
        uint64_t read_pong_sequence = next_read_uint64( &p );
        uint64_t read_pong_session_id = next_read_uint64( &p );

        next_check( read_pong_sequence == pong_sequence );
        next_check( read_pong_session_id == pong_session_id );
    }
}

void test_server_init_request_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendServerInitRequestPacket in, out;
        in.request_id = next_random_uint64();
        in.customer_id = 1231234127431LL;
        in.datacenter_id = next_datacenter_id( "local" );
        strcpy( in.datacenter_name, "local" );

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SERVER_INIT_REQUEST_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SERVER_INIT_REQUEST_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SERVER_INIT_REQUEST_PACKET );

        next_check( in.request_id == out.request_id );
        next_check( in.version_major == out.version_major );
        next_check( in.version_minor == out.version_minor );
        next_check( in.version_patch == out.version_patch );
        next_check( in.customer_id == out.customer_id );
        next_check( in.datacenter_id == out.datacenter_id );
        next_check( strcmp( in.datacenter_name, out.datacenter_name ) == 0 );
    }
}

void test_server_init_response_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendServerInitResponsePacket in, out;
        in.request_id = next_random_uint64();
        in.response = NEXT_SERVER_INIT_RESPONSE_OK;
        next_random_bytes( in.upcoming_magic, 8 );
        next_random_bytes( in.current_magic, 8 );
        next_random_bytes( in.previous_magic, 8 );

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SERVER_INIT_RESPONSE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SERVER_INIT_RESPONSE_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SERVER_INIT_RESPONSE_PACKET );

        next_check( in.request_id == out.request_id );
        next_check( in.response == out.response );
        next_check( memcmp( in.upcoming_magic, out.upcoming_magic, 8 ) == 0 );
        next_check( memcmp( in.current_magic, out.current_magic, 8 ) == 0 );
        next_check( memcmp( in.previous_magic, out.previous_magic, 8 ) == 0 );
    }
}

void test_server_update_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendServerUpdateRequestPacket in, out;
        in.request_id = next_random_uint64();
        in.customer_id = next_random_uint64();
        in.datacenter_id = next_random_uint64();
        in.num_sessions = 1000;
        next_address_parse( &in.server_address, "127.0.0.1:40000" );

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SERVER_UPDATE_REQUEST_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SERVER_UPDATE_REQUEST_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SERVER_UPDATE_REQUEST_PACKET );

        next_check( in.version_major == out.version_major );
        next_check( in.version_minor == out.version_minor );
        next_check( in.version_patch == out.version_patch );
        next_check( in.request_id == out.request_id );
        next_check( in.customer_id == out.customer_id );
        next_check( in.datacenter_id == out.datacenter_id );
        next_check( in.num_sessions == out.num_sessions );
        next_check( next_address_equal( &in.server_address, &out.server_address ) );
    }
}

void test_server_response_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendServerUpdateResponsePacket in, out;
        in.request_id = next_random_uint64();
        next_random_bytes( in.upcoming_magic, 8 );
        next_random_bytes( in.current_magic, 8 );
        next_random_bytes( in.previous_magic, 8 );

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SERVER_UPDATE_RESPONSE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SERVER_UPDATE_RESPONSE_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SERVER_UPDATE_RESPONSE_PACKET );

        next_check( in.request_id == out.request_id );
        next_check( memcmp( in.upcoming_magic, out.upcoming_magic, 8 ) == 0 );
        next_check( memcmp( in.current_magic, out.current_magic, 8 ) == 0 );
        next_check( memcmp( in.previous_magic, out.previous_magic, 8 ) == 0 );
    }
}

void test_session_update_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendSessionUpdateRequestPacket in, out;
        in.slice_number = 0;
        in.customer_id = 1231234127431LL;
        in.datacenter_id = 111222454443LL;
        in.session_id = 1234342431431LL;
        in.user_hash = 11111111;
        in.platform_id = 3;
        in.num_tags = 2;
        in.tags[0] = 0x1231314141;
        in.tags[1] = 0x3344556677;
        in.server_events = next_random_uint64();
        in.reported = true;
        in.connection_type = NEXT_CONNECTION_TYPE_WIRED;
        in.direct_rtt = 10.1f;
        in.direct_jitter = 5.2f;
        in.direct_packet_loss = 0.1f;
        in.direct_max_packet_loss_seen = 0.25f;
        in.next = true;
        in.has_near_relay_pings = true;
        in.next_rtt = 5.0f;
        in.next_jitter = 1.5f;
        in.next_packet_loss = 0.0f;
        in.num_near_relays = NEXT_MAX_NEAR_RELAYS;
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            in.near_relay_ids[j] = j;
            in.near_relay_rtt[j] = j + 10.0f;
            in.near_relay_jitter[j] = j + 11.0f;
            in.near_relay_packet_loss[j] = j + 12.0f;
        }
        next_address_parse( &in.client_address, "127.0.0.1:40000" );
        next_address_parse( &in.server_address, "127.0.0.1:12345" );
        next_random_bytes( in.client_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES );
        next_random_bytes( in.server_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES );
        in.direct_kbps_up = 50.0f;
        in.direct_kbps_down = 75.0f;
        in.next_kbps_up = 100.0f;
        in.next_kbps_down = 200.0f;
        in.packets_lost_client_to_server = 100;
        in.packets_lost_server_to_client = 200;
        in.session_data_bytes = NEXT_MAX_SESSION_DATA_BYTES;
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            in.session_data[j] = uint8_t(j);
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            in.session_data_signature[j] = uint8_t(j);
        }

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SESSION_UPDATE_REQUEST_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SESSION_UPDATE_REQUEST_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SESSION_UPDATE_REQUEST_PACKET );

        next_check( in.slice_number == out.slice_number );
        next_check( in.customer_id == out.customer_id );
        next_check( in.datacenter_id == out.datacenter_id );
        next_check( in.session_id == out.session_id );
        next_check( in.user_hash == out.user_hash );
        next_check( in.platform_id == out.platform_id );
        next_check( in.num_tags == out.num_tags );
        for ( int j = 0; j < in.num_tags; ++j )
        {
            next_check( in.tags[j] == out.tags[j] );
        }
        next_check( in.server_events == out.server_events );
        next_check( in.reported == out.reported );
        next_check( in.connection_type == out.connection_type );
        next_check( in.direct_rtt == out.direct_rtt );
        next_check( in.direct_jitter == out.direct_jitter );
        next_check( in.direct_packet_loss == out.direct_packet_loss );
        next_check( in.direct_max_packet_loss_seen == out.direct_max_packet_loss_seen );
        next_check( in.next == out.next );
        next_check( in.next_rtt == out.next_rtt );
        next_check( in.next_jitter == out.next_jitter );
        next_check( in.next_packet_loss == out.next_packet_loss );
        next_check( in.num_near_relays == out.num_near_relays );
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            next_check( in.near_relay_ids[j] == out.near_relay_ids[j] );
            next_check( in.near_relay_rtt[j] == out.near_relay_rtt[j] );
            next_check( in.near_relay_jitter[j] == out.near_relay_jitter[j] );
            next_check( in.near_relay_packet_loss[j] == out.near_relay_packet_loss[j] );
        }
        next_check( next_address_equal( &in.client_address, &out.client_address ) );
        next_check( next_address_equal( &in.server_address, &out.server_address ) );
        next_check( memcmp( in.client_route_public_key, out.client_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES ) == 0 );
        next_check( memcmp( in.server_route_public_key, out.server_route_public_key, NEXT_CRYPTO_BOX_PUBLICKEYBYTES ) == 0 );
        next_check( in.direct_kbps_up == out.direct_kbps_up );
        next_check( in.direct_kbps_down == out.direct_kbps_down );
        next_check( in.next_kbps_up == out.next_kbps_up );
        next_check( in.next_kbps_down == out.next_kbps_down );
        next_check( in.packets_lost_client_to_server == out.packets_lost_client_to_server );
        next_check( in.packets_lost_server_to_client == out.packets_lost_server_to_client );
        next_check( in.session_data_bytes == out.session_data_bytes );
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            next_check( in.session_data[j] == out.session_data[j] );
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            next_check( in.session_data_signature[j] == out.session_data_signature[j] );
        }
    }
}

void test_session_response_packet_direct_has_near_relays()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendSessionUpdateResponsePacket in, out;
        in.slice_number = 10000;
        in.session_id = 1234342431431LL;
        in.has_near_relays = true;
        in.num_near_relays = NEXT_MAX_NEAR_RELAYS;
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            char relay_name[32];
            char relay_address[256];
            snprintf( relay_name, sizeof(relay_name), "relay%d", j );
            snprintf( relay_address, sizeof(relay_address), "127.0.0.1:%d", 40000 + j );
            in.near_relay_ids[j] = next_relay_id( relay_name );
            next_address_parse( &in.near_relay_addresses[j], relay_address );
        }
        in.response_type = NEXT_UPDATE_TYPE_DIRECT;
        in.session_data_bytes = NEXT_MAX_SESSION_DATA_BYTES;
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            in.session_data[j] = uint8_t(j);
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            in.session_data_signature[j] = uint8_t(j);
        }
        in.has_debug = true;
        strcpy( in.debug, "hello session" );

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( in.slice_number == out.slice_number );
        next_check( in.session_id == out.session_id );
        next_check( in.has_near_relays == out.has_near_relays );
        next_check( in.num_near_relays == out.num_near_relays );
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            next_check( in.near_relay_ids[j] == out.near_relay_ids[j] );
            next_check( next_address_equal( &in.near_relay_addresses[j], &out.near_relay_addresses[j] ) );
        }
        next_check( in.response_type == out.response_type );
        next_check( in.has_debug == out.has_debug );
        next_check( strcmp( in.debug, out.debug ) == 0 );
        next_check( in.session_data_bytes == out.session_data_bytes );
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            next_check( out.session_data[j] == uint8_t(j) );
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            next_check( out.session_data_signature[j] == uint8_t(j) );
        }
    }
}

void test_session_response_packet_route_has_near_relays()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendSessionUpdateResponsePacket in, out;
        in.slice_number = 10000;
        in.session_id = 1234342431431LL;
        in.has_near_relays = true;
        in.num_near_relays = NEXT_MAX_NEAR_RELAYS;
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            char relay_name[32];
            char relay_address[256];
            snprintf( relay_name, sizeof(relay_name), "relay%d", j );
            snprintf( relay_address, sizeof(relay_address), "127.0.0.1:%d", 40000 + j );
            in.near_relay_ids[j] = next_relay_id( relay_name );
            next_address_parse( &in.near_relay_addresses[j], relay_address );
        }
        in.response_type = NEXT_UPDATE_TYPE_ROUTE;
        in.multipath = true;
        in.num_tokens = NEXT_MAX_TOKENS;
        next_random_bytes( in.tokens, NEXT_MAX_TOKENS * NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES );
        in.session_data_bytes = NEXT_MAX_SESSION_DATA_BYTES;
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            in.session_data[j] = uint8_t(j);
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            in.session_data_signature[j] = uint8_t(j);
        }

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( in.slice_number == out.slice_number );
        next_check( in.session_id == out.session_id );
        next_check( in.has_near_relays == out.has_near_relays );
        next_check( in.num_near_relays == out.num_near_relays );
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            next_check( in.near_relay_ids[j] == out.near_relay_ids[j] );
            next_check( next_address_equal( &in.near_relay_addresses[j], &out.near_relay_addresses[j] ) );
        }
        next_check( in.response_type == out.response_type );
        next_check( in.multipath == out.multipath );
        next_check( in.num_tokens == out.num_tokens );
        next_check( memcmp( in.tokens, out.tokens, NEXT_MAX_TOKENS * NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES ) == 0 );
        next_check( in.session_data_bytes == out.session_data_bytes );
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            next_check( out.session_data[j] == uint8_t(j) );
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            next_check( out.session_data_signature[j] == uint8_t(j) );
        }
    }
}

void test_session_response_packet_continue_has_near_relays()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendSessionUpdateResponsePacket in, out;
        in.slice_number = 10000;
        in.session_id = 1234342431431LL;
        in.has_near_relays = true;
        in.num_near_relays = NEXT_MAX_NEAR_RELAYS;
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            char relay_name[32];
            char relay_address[256];
            snprintf( relay_name, sizeof(relay_name), "relay%d", j );
            snprintf( relay_address, sizeof(relay_name), "127.0.0.1:%d", 40000 + j );
            in.near_relay_ids[j] = next_relay_id( relay_name );
            next_address_parse( &in.near_relay_addresses[j], relay_address );
        }
        in.response_type = NEXT_UPDATE_TYPE_CONTINUE;
        in.multipath = true;
        in.num_tokens = NEXT_MAX_TOKENS;
        next_random_bytes( in.tokens, NEXT_MAX_TOKENS * NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES );
        in.session_data_bytes = NEXT_MAX_SESSION_DATA_BYTES;
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            in.session_data[j] = uint8_t(j);
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            in.session_data_signature[j] = uint8_t(j);
        }

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];

        next_check( packet_id == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( in.slice_number == out.slice_number );
        next_check( in.session_id == out.session_id );
        next_check( in.multipath == out.multipath );
        next_check( in.has_near_relays == out.has_near_relays );
        next_check( in.num_near_relays == out.num_near_relays );
        for ( int j = 0; j < NEXT_MAX_NEAR_RELAYS; ++j )
        {
            next_check( in.near_relay_ids[j] == out.near_relay_ids[j] );
            next_check( next_address_equal( &in.near_relay_addresses[j], &out.near_relay_addresses[j] ) );
        }
        next_check( in.response_type == out.response_type );
        next_check( in.num_tokens == out.num_tokens );
        next_check( memcmp( in.tokens, out.tokens, NEXT_MAX_TOKENS * NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES ) == 0 );
        next_check( in.session_data_bytes == out.session_data_bytes );
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            next_check( out.session_data[j] == uint8_t(j) );
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            next_check( out.session_data_signature[j] == uint8_t(j) );
        }
    }
}

void test_session_response_packet_direct_near_relays_not_changed()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendSessionUpdateResponsePacket in, out;
        in.slice_number = 10000;
        in.session_id = 1234342431431LL;
        in.has_near_relays = false;
        in.response_type = NEXT_UPDATE_TYPE_DIRECT;
        in.session_data_bytes = NEXT_MAX_SESSION_DATA_BYTES;
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            in.session_data[j] = uint8_t(j);
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            in.session_data_signature[j] = uint8_t(j);
        }
        in.has_debug = true;
        strcpy( in.debug, "hello session" );

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( in.slice_number == out.slice_number );
        next_check( in.session_id == out.session_id );
        next_check( in.has_near_relays == out.has_near_relays );
        next_check( in.response_type == out.response_type );
        next_check( in.has_debug == out.has_debug );
        next_check( strcmp( in.debug, out.debug ) == 0 );
        next_check( in.session_data_bytes == out.session_data_bytes );
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            next_check( out.session_data[j] == uint8_t(j) );
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            next_check( out.session_data_signature[j] == uint8_t(j) );
        }
    }
}

void test_session_response_packet_route_near_relays_not_changed()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendSessionUpdateResponsePacket in, out;
        in.slice_number = 10000;
        in.session_id = 1234342431431LL;
        in.has_near_relays = false;
        in.response_type = NEXT_UPDATE_TYPE_ROUTE;
        in.multipath = true;
        in.num_tokens = NEXT_MAX_TOKENS;
        next_random_bytes( in.tokens, NEXT_MAX_TOKENS * NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES );
        in.session_data_bytes = NEXT_MAX_SESSION_DATA_BYTES;
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            in.session_data[j] = uint8_t(j);
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            in.session_data_signature[j] = uint8_t(j);
        }

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( in.slice_number == out.slice_number );
        next_check( in.session_id == out.session_id );
        next_check( in.has_near_relays == out.has_near_relays );
        next_check( in.response_type == out.response_type );
        next_check( in.multipath == out.multipath );
        next_check( in.num_tokens == out.num_tokens );
        next_check( memcmp( in.tokens, out.tokens, NEXT_MAX_TOKENS * NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES ) == 0 );
        next_check( in.session_data_bytes == out.session_data_bytes );
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            next_check( out.session_data[j] == uint8_t(j) );
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            next_check( out.session_data_signature[j] == uint8_t(j) );
        }
    }
}

void test_session_response_packet_continue_near_relays_not_changed()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendSessionUpdateResponsePacket in, out;
        in.slice_number = 10000;
        in.session_id = 1234342431431LL;
        in.has_near_relays = false;
        in.response_type = NEXT_UPDATE_TYPE_CONTINUE;
        in.multipath = true;
        in.num_tokens = NEXT_MAX_TOKENS;
        next_random_bytes( in.tokens, NEXT_MAX_TOKENS * NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES );
        in.session_data_bytes = NEXT_MAX_SESSION_DATA_BYTES;
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            in.session_data[j] = uint8_t(j);
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            in.session_data_signature[j] = uint8_t(j);
        }

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( in.slice_number == out.slice_number );
        next_check( in.session_id == out.session_id );
        next_check( in.multipath == out.multipath );
        next_check( in.has_near_relays == out.has_near_relays );
        next_check( in.response_type == out.response_type );
        next_check( in.num_tokens == out.num_tokens );
        next_check( memcmp( in.tokens, out.tokens, NEXT_MAX_TOKENS * NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES ) == 0 );
        next_check( in.session_data_bytes == out.session_data_bytes );
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            next_check( out.session_data[j] == uint8_t(j) );
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            next_check( out.session_data_signature[j] == uint8_t(j) );
        }
    }
}

void test_session_response_packet_direct_no_near_relays()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendSessionUpdateResponsePacket in, out;
        in.slice_number = 10000;
        in.session_id = 1234342431431LL;
        in.has_near_relays = false;
        in.response_type = NEXT_UPDATE_TYPE_DIRECT;
        in.multipath = false;
        in.has_near_relays = false;

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( in.slice_number == out.slice_number );
        next_check( in.session_id == out.session_id );
        next_check( in.has_near_relays == out.has_near_relays );
        next_check( in.response_type == out.response_type );
        next_check( in.multipath == out.multipath );
    }
}

void test_session_response_packet_route_no_near_relays()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendSessionUpdateResponsePacket in, out;
        in.slice_number = 10000;
        in.session_id = 1234342431431LL;
        in.has_near_relays = false;
        in.response_type = NEXT_UPDATE_TYPE_ROUTE;
        in.multipath = true;
        in.num_tokens = NEXT_MAX_TOKENS;
        next_random_bytes( in.tokens, NEXT_MAX_TOKENS * NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES );
        in.session_data_bytes = NEXT_MAX_SESSION_DATA_BYTES;
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            in.session_data[j] = uint8_t(j);
        }

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( in.slice_number == out.slice_number );
        next_check( in.session_id == out.session_id );
        next_check( in.multipath == out.multipath );
        next_check( in.has_near_relays == out.has_near_relays );
        next_check( in.response_type == out.response_type );
        next_check( in.num_tokens == out.num_tokens );
        next_check( memcmp( in.tokens, out.tokens, NEXT_MAX_TOKENS * NEXT_ENCRYPTED_ROUTE_TOKEN_BYTES ) == 0 );
    }
}

void test_session_response_packet_continue_no_near_relays()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendSessionUpdateResponsePacket in, out;
        in.slice_number = 10000;
        in.session_id = 1234342431431LL;
        in.has_near_relays = false;
        in.response_type = NEXT_UPDATE_TYPE_CONTINUE;
        in.multipath = true;
        in.num_tokens = NEXT_MAX_TOKENS;
        next_random_bytes( in.tokens, NEXT_MAX_TOKENS * NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES );
        in.session_data_bytes = NEXT_MAX_SESSION_DATA_BYTES;
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            in.session_data[j] = uint8_t(j);
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            in.session_data_signature[j] = uint8_t(j);
        }

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_SESSION_UPDATE_RESPONSE_PACKET );

        next_check( in.slice_number == out.slice_number );
        next_check( in.session_id == out.session_id );
        next_check( in.multipath == out.multipath );
        next_check( in.has_near_relays == out.has_near_relays );
        next_check( in.response_type == out.response_type );
        next_check( in.num_tokens == out.num_tokens );
        next_check( memcmp( in.tokens, out.tokens, NEXT_MAX_TOKENS * NEXT_ENCRYPTED_CONTINUE_TOKEN_BYTES ) == 0 );
        next_check( in.session_data_bytes == out.session_data_bytes );
        for ( int j = 0; j < NEXT_MAX_SESSION_DATA_BYTES; ++j )
        {
            next_check( out.session_data[j] == uint8_t(j) );
        }
        for ( int j = 0; j < NEXT_CRYPTO_SIGN_BYTES; ++j )
        {
            next_check( out.session_data_signature[j] == uint8_t(j) );
        }
    }
}

void test_match_data_request_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendMatchDataRequestPacket in, out;
        in.Reset();
        out.Reset();
        in.version_major = NEXT_VERSION_MAJOR_INT;
        in.version_minor = NEXT_VERSION_MINOR_INT;
        in.version_patch = NEXT_VERSION_PATCH_INT;
        in.customer_id = 1231234127431LL;
        next_address_parse( &in.server_address, "127.0.0.1:12345" );
        in.datacenter_id = next_datacenter_id( "local" );
        in.user_hash = 11111111;
        in.session_id = 1234342431431LL;
        in.match_id = 1234342431431LL;
        in.num_match_values = NEXT_MAX_MATCH_VALUES;
        for ( int j = 0; j < NEXT_MAX_MATCH_VALUES; ++j )
        {
            in.match_values[j] = j + 10.0f;
        }

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_MATCH_DATA_REQUEST_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_MATCH_DATA_REQUEST_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_MATCH_DATA_REQUEST_PACKET );

        next_check( in.version_major == out.version_major );
        next_check( in.version_minor == out.version_minor );
        next_check( in.version_patch == out.version_patch );
        next_check( in.customer_id == out.customer_id );
        next_check( next_address_equal( &in.server_address, &out.server_address ) );
        next_check( in.datacenter_id == out.datacenter_id );
        next_check( in.user_hash == out.user_hash );
        next_check( in.session_id == out.session_id );
        next_check( in.match_id == out.match_id );
        next_check( in.num_match_values == out.num_match_values );
        for ( int j = 0; j < NEXT_MAX_MATCH_VALUES; ++j )
        {
            next_check( in.match_values[j] = out.match_values[j] );
        }
    }
}

void test_match_data_response_packet()
{
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
    uint64_t iterations = 100;
    for ( uint64_t i = 0; i < iterations; ++i )
    {
        unsigned char public_key[NEXT_CRYPTO_SIGN_PUBLICKEYBYTES];
        unsigned char private_key[NEXT_CRYPTO_SIGN_SECRETKEYBYTES];
        next_crypto_sign_keypair( public_key, private_key );

        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );
        uint16_t from_port = uint16_t( i + 1000000 );
        uint16_t to_port = uint16_t( i + 5000 );

        static NextBackendMatchDataRequestPacket in, out;
        in.Reset();
        out.Reset();
        in.version_major = NEXT_VERSION_MAJOR_INT;
        in.version_minor = NEXT_VERSION_MINOR_INT;
        in.version_patch = NEXT_VERSION_PATCH_INT;
        in.customer_id = 1231234127431LL;
        next_address_parse( &in.server_address, "127.0.0.1:12345" );
        in.datacenter_id = next_datacenter_id( "local" );
        in.user_hash = 11111111;
        in.session_id = 1234342431431LL;
        in.match_id = 1234342431431LL;
        in.num_match_values = NEXT_MAX_MATCH_VALUES;
        for ( int j = 0; j < NEXT_MAX_MATCH_VALUES; ++j )
        {
            in.match_values[j] = j + 10.0f;
        }

        int packet_bytes = 0;
        next_check( next_write_backend_packet( NEXT_BACKEND_MATCH_DATA_REQUEST_PACKET, &in, packet_data, &packet_bytes, next_signed_packets, private_key, magic, from_address, 4, from_port, to_address, 4, to_port ) == NEXT_OK );

        const uint8_t packet_id = packet_data[0];
        next_check( packet_id == NEXT_BACKEND_MATCH_DATA_REQUEST_PACKET );

        next_check( next_basic_packet_filter( packet_data, packet_bytes ) );
        next_check( next_advanced_packet_filter( packet_data, magic, from_address, 4, from_port, to_address, 4, to_port, packet_bytes ) );

        const int begin = 16;
        const int end = packet_bytes - 2;

        next_check( next_read_backend_packet( packet_id, packet_data, begin, end, &out, next_signed_packets, public_key ) == NEXT_BACKEND_MATCH_DATA_REQUEST_PACKET );

        next_check( in.version_major == out.version_major );
        next_check( in.version_minor == out.version_minor );
        next_check( in.version_patch == out.version_patch );
        next_check( in.customer_id == out.customer_id );
        next_check( next_address_equal( &in.server_address, &out.server_address ) );
        next_check( in.datacenter_id == out.datacenter_id );
        next_check( in.user_hash == out.user_hash );
        next_check( in.session_id == out.session_id );
        next_check( in.match_id == out.match_id );
        next_check( in.num_match_values == out.num_match_values );
        for ( int j = 0; j < NEXT_MAX_MATCH_VALUES; ++j )
        {
            next_check( in.match_values[j] = out.match_values[j] );
        }
    }
}

void test_pending_session_manager()
{
    const int InitialSize = 32;

    next_pending_session_manager_t * pending_session_manager = next_pending_session_manager_create( NULL, InitialSize );

    next_check( pending_session_manager );

    next_address_t address;
    next_address_parse( &address, "127.0.0.1:12345" );

    double time = 10.0;

    // test private keys

    uint8_t private_keys[InitialSize*3*NEXT_CRYPTO_SECRETBOX_KEYBYTES];
    next_random_bytes( private_keys, sizeof(private_keys) );

    // test upgrade tokens

    uint8_t upgrade_tokens[InitialSize*3*NEXT_UPGRADE_TOKEN_BYTES];
    next_random_bytes( upgrade_tokens, sizeof(upgrade_tokens) );

    // add enough entries to make sure we have to expand

    for ( int i = 0; i < InitialSize*3; ++i )
    {
        next_pending_session_entry_t * entry = next_pending_session_manager_add( pending_session_manager, &address, uint64_t(i)+1000, &private_keys[i*NEXT_CRYPTO_SECRETBOX_KEYBYTES], &upgrade_tokens[i*NEXT_UPGRADE_TOKEN_BYTES], time );
        next_check( entry );
        next_check( entry->session_id == uint64_t(i) + 1000 );
        next_check( entry->upgrade_time == time );
        next_check( entry->last_packet_send_time < 0.0 );
        next_check( next_address_equal( &address, &entry->address ) == 1 );
        next_check( memcmp( entry->private_key, &private_keys[i*NEXT_CRYPTO_SECRETBOX_KEYBYTES], NEXT_CRYPTO_SECRETBOX_KEYBYTES ) == 0 );
        next_check( memcmp( entry->upgrade_token, &upgrade_tokens[i*NEXT_UPGRADE_TOKEN_BYTES], NEXT_UPGRADE_TOKEN_BYTES ) == 0 );
        address.port++;
    }

    // verify that all entries are there

    address.port = 12345;
    for ( int i = 0; i < InitialSize*3; ++i )
    {
        next_pending_session_entry_t * entry = next_pending_session_manager_find( pending_session_manager, &address );
        next_check( entry );
        next_check( entry->session_id == uint64_t(i) + 1000 );
        next_check( entry->upgrade_time == time );
        next_check( entry->last_packet_send_time < 0.0 );
        next_check( next_address_equal( &address, &entry->address ) == 1 );
        address.port++;
    }

    next_check( next_pending_session_manager_num_entries( pending_session_manager ) == InitialSize*3 );

    // remove every second entry

    for ( int i = 0; i < InitialSize*3; ++i )
    {
        if ( (i%2) == 0 )
        {
            next_pending_session_manager_remove_by_address( pending_session_manager, &pending_session_manager->addresses[i] );
        }
    }

    // verify only the entries that remain can be found

    address.port = 12345;
    for ( int i = 0; i < InitialSize*3; ++i )
    {
        next_pending_session_entry_t * entry = next_pending_session_manager_find( pending_session_manager, &address );
        if ( (i%2) != 0 )
        {
            next_check( entry );
            next_check( entry->session_id == uint64_t(i) + 1000 );
            next_check( entry->upgrade_time == time );
            next_check( entry->last_packet_send_time < 0.0 );
            next_check( next_address_equal( &address, &entry->address ) == 1 );
        }
        else
        {
            next_check( entry == NULL );
        }
        address.port++;
    }

    // expand, and verify that all entries get collapsed

    next_pending_session_manager_expand( pending_session_manager );

    address.port = 12346;
    for ( int i = 0; i < pending_session_manager->size; ++i )
    {
        if ( pending_session_manager->addresses[i].type != NEXT_ADDRESS_NONE )
        {
            next_check( next_address_equal( &address, &pending_session_manager->addresses[i] ) == 1 );
            next_pending_session_entry_t * entry = &pending_session_manager->entries[i];
            next_check( entry->session_id == uint64_t(i)*2+1001 );
            next_check( entry->upgrade_time == time );
            next_check( entry->last_packet_send_time < 0.0 );
            next_check( next_address_equal( &address, &entry->address ) == 1 );
        }
        address.port += 2;
    }

    // remove all remaining entries manually

    for ( int i = 0; i < pending_session_manager->size; ++i )
    {
        if ( pending_session_manager->addresses[i].type != NEXT_ADDRESS_NONE )
        {
            next_pending_session_manager_remove_by_address( pending_session_manager, &pending_session_manager->addresses[i] );
        }
    }

    next_check( pending_session_manager->max_entry_index == 0 );

    next_check( next_pending_session_manager_num_entries( pending_session_manager ) == 0 );

    next_pending_session_manager_destroy( pending_session_manager );
}

void test_proxy_session_manager()
{
    const int InitialSize = 32;

    next_proxy_session_manager_t * proxy_session_manager = next_proxy_session_manager_create( NULL, InitialSize );

    next_check( proxy_session_manager );

    next_address_t address;
    next_address_parse( &address, "127.0.0.1:12345" );

    // test private keys

    uint8_t private_keys[InitialSize*3*NEXT_CRYPTO_SECRETBOX_KEYBYTES];
    next_random_bytes( private_keys, sizeof(private_keys) );

    // test upgrade tokens

    uint8_t upgrade_tokens[InitialSize*3*NEXT_UPGRADE_TOKEN_BYTES];
    next_random_bytes( upgrade_tokens, sizeof(upgrade_tokens) );

    // add enough entries to make sure we have to expand

    for ( int i = 0; i < InitialSize*3; ++i )
    {
        next_proxy_session_entry_t * entry = next_proxy_session_manager_add( proxy_session_manager, &address, uint64_t(i)+1000 );
        next_check( entry );
        next_check( entry->session_id == uint64_t(i) + 1000 );
        next_check( next_address_equal( &address, &entry->address ) == 1 );
        address.port++;
    }

    // verify that all entries are there

    address.port = 12345;
    for ( int i = 0; i < InitialSize*3; ++i )
    {
        next_proxy_session_entry_t * entry = next_proxy_session_manager_find( proxy_session_manager, &address );
        next_check( entry );
        next_check( entry->session_id == uint64_t(i) + 1000 );
        next_check( next_address_equal( &address, &entry->address ) == 1 );
        address.port++;
    }

    next_check( next_proxy_session_manager_num_entries( proxy_session_manager ) == InitialSize*3 );

    // remove every second entry

    for ( int i = 0; i < InitialSize*3; ++i )
    {
        if ( (i%2) == 0 )
        {
            next_proxy_session_manager_remove_by_address( proxy_session_manager, &proxy_session_manager->addresses[i] );
        }
    }

    // verify only the entries that remain can be found

    address.port = 12345;
    for ( int i = 0; i < InitialSize*3; ++i )
    {
        next_proxy_session_entry_t * entry = next_proxy_session_manager_find( proxy_session_manager, &address );
        if ( (i%2) != 0 )
        {
            next_check( entry );
            next_check( entry->session_id == uint64_t(i) + 1000 );
            next_check( next_address_equal( &address, &entry->address ) == 1 );
        }
        else
        {
            next_check( entry == NULL );
        }
        address.port++;
    }

    // expand, and verify that all entries get collapsed

    next_proxy_session_manager_expand( proxy_session_manager );

    address.port = 12346;
    for ( int i = 0; i < proxy_session_manager->size; ++i )
    {
        if ( proxy_session_manager->addresses[i].type != NEXT_ADDRESS_NONE )
        {
            next_check( next_address_equal( &address, &proxy_session_manager->addresses[i] ) == 1 );
            next_proxy_session_entry_t * entry = &proxy_session_manager->entries[i];
            next_check( entry->session_id == uint64_t(i)*2+1001 );
            next_check( next_address_equal( &address, &entry->address ) == 1 );
        }
        address.port += 2;
    }

    // remove all remaining entries manually

    for ( int i = 0; i < proxy_session_manager->size; ++i )
    {
        if ( proxy_session_manager->addresses[i].type != NEXT_ADDRESS_NONE )
        {
            next_proxy_session_manager_remove_by_address( proxy_session_manager, &proxy_session_manager->addresses[i] );
        }
    }

    next_check( proxy_session_manager->max_entry_index == 0 );

    next_check( next_proxy_session_manager_num_entries( proxy_session_manager ) == 0 );

    next_proxy_session_manager_destroy( proxy_session_manager );
}

void test_session_manager()
{
    const int InitialSize = 1;

    next_session_manager_t * session_manager = next_session_manager_create( NULL, InitialSize );

    next_check( session_manager );

    next_address_t address;
    next_address_parse( &address, "127.0.0.1:12345" );

    // test private keys

    uint8_t private_keys[InitialSize*3*NEXT_CRYPTO_SECRETBOX_KEYBYTES];
    next_random_bytes( private_keys, sizeof(private_keys) );

    // test upgrade tokens

    uint8_t upgrade_tokens[InitialSize*3*NEXT_UPGRADE_TOKEN_BYTES];
    next_random_bytes( upgrade_tokens, sizeof(upgrade_tokens) );

    // add enough entries to make sure we have to expand

    for ( int i = 0; i < InitialSize*3; ++i )
    {
        next_session_entry_t * entry = next_session_manager_add( session_manager, &address, uint64_t(i)+1000, &private_keys[i*NEXT_CRYPTO_SECRETBOX_KEYBYTES], &upgrade_tokens[i*NEXT_UPGRADE_TOKEN_BYTES], NULL, 0 );
        next_check( entry );
        next_check( entry->session_id == uint64_t(i) + 1000 );
        next_check( next_address_equal( &address, &entry->address ) == 1 );
        next_check( memcmp( entry->ephemeral_private_key, &private_keys[i*NEXT_CRYPTO_SECRETBOX_KEYBYTES], NEXT_CRYPTO_SECRETBOX_KEYBYTES ) == 0 );
        next_check( memcmp( entry->upgrade_token, &upgrade_tokens[i*NEXT_UPGRADE_TOKEN_BYTES], NEXT_UPGRADE_TOKEN_BYTES ) == 0 );
        address.port++;
    }

    // verify that all entries are there

    address.port = 12345;
    for ( int i = 0; i < InitialSize*3; ++i )
    {
        next_session_entry_t * entry = next_session_manager_find_by_address( session_manager, &address );
        next_check( entry );
        next_check( entry->session_id == uint64_t(i)+1000 );
        next_check( next_address_equal( &address, &entry->address ) == 1 );
        address.port++;
    }

    next_check( next_session_manager_num_entries( session_manager ) == InitialSize*3 );

    // remove every second entry

    for ( int i = 0; i < InitialSize*3; ++i )
    {
        if ( (i%2) == 0 )
        {
            next_session_manager_remove_by_address( session_manager, &session_manager->addresses[i] );
        }
    }

    // verify only the entries that remain can be found

    address.port = 12345;
    for ( int i = 0; i < InitialSize*3; ++i )
    {
        next_session_entry_t * entry = next_session_manager_find_by_address( session_manager, &address );
        if ( (i%2) != 0 )
        {
            next_check( entry );
            next_check( entry->session_id == uint64_t(i)+1000 );
            next_check( next_address_equal( &address, &entry->address ) == 1 );
        }
        else
        {
            next_check( entry == NULL );
        }
        address.port++;
    }

    // expand, and verify that all entries get collapsed

    next_session_manager_expand( session_manager );

    address.port = 12346;
    for ( int i = 0; i < session_manager->size; ++i )
    {
        if ( session_manager->addresses[i].type != NEXT_ADDRESS_NONE )
        {
            next_check( next_address_equal( &address, &session_manager->addresses[i] ) == 1 );
            next_session_entry_t * entry = &session_manager->entries[i];
            next_check( entry->session_id == uint64_t(i)*2+1001 );
            next_check( next_address_equal( &address, &entry->address ) == 1 );
        }
        address.port += 2;
    }

    // remove all remaining entries manually

    for ( int i = 0; i < session_manager->size; ++i )
    {
        if ( session_manager->addresses[i].type != NEXT_ADDRESS_NONE )
        {
            next_session_manager_remove_by_address( session_manager, &session_manager->addresses[i] );
        }
    }

    next_check( session_manager->max_entry_index == 0 );

    next_check( next_session_manager_num_entries( session_manager ) == 0 );

    next_session_manager_destroy( session_manager );
}

void test_relay_manager()
{
    uint64_t relay_ids[NEXT_MAX_NEAR_RELAYS];
    next_address_t relay_addresses[NEXT_MAX_NEAR_RELAYS];

    for ( int i = 0; i < NEXT_MAX_NEAR_RELAYS; ++i )
    {
        relay_ids[i] = i;
        char address_string[256];
        snprintf( address_string, sizeof(address_string), "127.0.0.1:%d", 40000 + i );
        next_address_parse( &relay_addresses[i], address_string );
    }

    next_relay_manager_t * manager = next_relay_manager_create( NULL );

    // should be no relays when manager is first created
    {
        next_relay_stats_t stats;
        next_relay_manager_get_stats( manager, &stats );
        next_check( stats.num_relays == 0 );
    }

    // add max relays

    next_relay_manager_update( manager, NEXT_MAX_NEAR_RELAYS, relay_ids, relay_addresses );
    {
        next_relay_stats_t stats;
        next_relay_manager_get_stats( manager, &stats );
        next_check( stats.num_relays == NEXT_MAX_NEAR_RELAYS );
        for ( int i = 0; i < NEXT_MAX_NEAR_RELAYS; ++i )
        {
            next_check( relay_ids[i] == stats.relay_ids[i] );
            next_check( stats.relay_rtt[i] == 0 );
            next_check( stats.relay_jitter[i] == 0 );
            next_check( stats.relay_packet_loss[i] == 0 );
        }
    }

    // remove all relays

    next_relay_manager_update( manager, 0, relay_ids, relay_addresses );
    {
        next_relay_stats_t stats;
        next_relay_manager_get_stats( manager, &stats );
        next_check( stats.num_relays == 0 );
    }

    // add same relay set repeatedly

    for ( int j = 0; j < 2; ++j )
    {
        next_relay_manager_update( manager, NEXT_MAX_NEAR_RELAYS, relay_ids, relay_addresses );
        {
            next_relay_stats_t stats;
            next_relay_manager_get_stats( manager, &stats );
            next_check( stats.num_relays == NEXT_MAX_NEAR_RELAYS );
            for ( int i = 0; i < NEXT_MAX_NEAR_RELAYS; ++i )
            {
                next_check( relay_ids[i] == stats.relay_ids[i] );
            }
        }
    }

    // now add a few new relays, while some relays remain the same

    next_relay_manager_update( manager, NEXT_MAX_NEAR_RELAYS, relay_ids + 4, relay_addresses + 4 );
    {
        next_relay_stats_t stats;
        next_relay_manager_get_stats( manager, &stats );
        next_check( stats.num_relays == NEXT_MAX_NEAR_RELAYS );
        for ( int i = 0; i < NEXT_MAX_NEAR_RELAYS - 4; ++i )
        {
            next_check( relay_ids[i+4] == stats.relay_ids[i] );
        }
    }

    // remove all relays

    next_relay_manager_update( manager, 0, relay_ids, relay_addresses );
    {
        next_relay_stats_t stats;
        next_relay_manager_get_stats( manager, &stats );
        next_check( stats.num_relays == 0 );
    }

    next_relay_manager_destroy( manager );
}

void test_tags()
{
    next_check( next_tag_id( NULL ) == 0 );
    next_check( next_tag_id( "" ) == 0 );
    next_check( next_tag_id( "none" ) == 0 );
    next_check( next_tag_id( "default" ) == 0 );
    next_check( next_tag_id( "pro" ) == 0x77fd571956a1f7f8LL );
}

void test_bandwidth_limiter()
{
    next_bandwidth_limiter_t bandwidth_limiter;

    next_bandwidth_limiter_reset( &bandwidth_limiter );

    next_check( next_bandwidth_limiter_usage_kbps( &bandwidth_limiter, 0.0 ) == 0.0 );

    // come in way under
    {
        const int kbps_allowed = 1000;
        const int packet_bits = 50;

        for ( int i = 0; i < 10; ++i )
        {
            next_check( !next_bandwidth_limiter_add_packet( &bandwidth_limiter, i * ( NEXT_BANDWIDTH_LIMITER_INTERVAL / 10.0 ), kbps_allowed, packet_bits ) );
        }
    }

    // get really close
    {
        next_bandwidth_limiter_reset( &bandwidth_limiter );

        const int kbps_allowed = 1000;
        const int packet_bits = kbps_allowed / 10 * 1000;

        for ( int i = 0; i < 10; ++i )
        {
            next_check( !next_bandwidth_limiter_add_packet( &bandwidth_limiter, i * ( NEXT_BANDWIDTH_LIMITER_INTERVAL / 10.0 ), kbps_allowed, packet_bits ) );
        }
    }

    // really close for several intervals
    {
        next_bandwidth_limiter_reset( &bandwidth_limiter );

        const int kbps_allowed = 1000;
        const int packet_bits = kbps_allowed / 10 * 1000;

        for ( int i = 0; i < 30; ++i )
        {
            next_check( !next_bandwidth_limiter_add_packet( &bandwidth_limiter, i * ( NEXT_BANDWIDTH_LIMITER_INTERVAL / 10.0 ), kbps_allowed, packet_bits ) );
        }
    }

    // go over budget
    {
        next_bandwidth_limiter_reset( &bandwidth_limiter );

        const int kbps_allowed = 1000;
        const int packet_bits = kbps_allowed / 10 * 1000 * 1.01f;

        bool over_budget = false;

        for ( int i = 0; i < 30; ++i )
        {
            over_budget |= next_bandwidth_limiter_add_packet( &bandwidth_limiter, i * ( NEXT_BANDWIDTH_LIMITER_INTERVAL / 10.0 ), kbps_allowed, packet_bits );
        }

        next_check( over_budget );
    }
}

static void context_check_free( void * context, void * p )
{
    (void) p;

    // the context should not be cleared
    next_check( context );
    next_check( *((int *)context) == 23 );
}

void test_free_retains_context()
{
    void * (*current_malloc)( void * context, size_t bytes ) = next_malloc_function;
    void (*current_free)( void * context, void * p ) = next_free_function;

    next_allocator( next_default_malloc_function, context_check_free );

    int canary = 23;
    void * context = (void *)&canary;
    next_queue_t *q = next_queue_create( context, 1 );
    next_queue_destroy( q );

    next_check( context );
    next_check( *((int *)context) == 23 );
    next_check( canary == 23 );

    next_allocator( current_malloc, current_free );
}

void test_packet_loss_tracker()
{
    next_packet_loss_tracker_t tracker;
    next_packet_loss_tracker_reset( &tracker );

    next_check( next_packet_loss_tracker_update( &tracker ) == 0 );

    uint64_t sequence = 0;

    for ( int i = 0; i < NEXT_PACKET_LOSS_TRACKER_SAFETY; ++i )
    {
        next_packet_loss_tracker_packet_received( &tracker, sequence );
        sequence++;
    }

    next_check( next_packet_loss_tracker_update( &tracker ) == 0 );

    for ( int i = 0; i < 200; ++i )
    {
        next_packet_loss_tracker_packet_received( &tracker, sequence );
        sequence++;
    }

    next_check( next_packet_loss_tracker_update( &tracker ) == 0 );

    for ( int i = 0; i < 200; ++i )
    {
        if ( sequence & 1 )
        {
            next_packet_loss_tracker_packet_received( &tracker, sequence );
        }
        sequence++;
    }

    next_check( next_packet_loss_tracker_update( &tracker ) == ( 200 - NEXT_PACKET_LOSS_TRACKER_SAFETY ) / 2 );

    next_check( next_packet_loss_tracker_update( &tracker ) == 0 );

    next_packet_loss_tracker_reset( &tracker );

    sequence = 0;

    next_packet_loss_tracker_packet_received( &tracker, 200 + NEXT_PACKET_LOSS_TRACKER_SAFETY - 1 );

    next_check( next_packet_loss_tracker_update( &tracker ) == 200 );

    next_packet_loss_tracker_packet_received( &tracker, 1000 );

    next_check( next_packet_loss_tracker_update( &tracker ) > 500 );

    next_packet_loss_tracker_packet_received( &tracker, 0xFFFFFFFFFFFFFFFULL );

    next_check( next_packet_loss_tracker_update( &tracker ) == 0 );
}

void test_out_of_order_tracker()
{
    next_out_of_order_tracker_t tracker;
    next_out_of_order_tracker_reset( &tracker );

    next_check( tracker.num_out_of_order_packets == 0 );

    uint64_t sequence = 0;

    for ( int i = 0; i < 1000; ++i )
    {
        next_out_of_order_tracker_packet_received( &tracker, sequence );
        sequence++;
    }

    next_check( tracker.num_out_of_order_packets == 0 );

    sequence = 500;

    for ( int i = 0; i < 500; ++i )
    {
        next_out_of_order_tracker_packet_received( &tracker, sequence );
        sequence++;
    }

    next_check( tracker.num_out_of_order_packets == 499 );

    next_out_of_order_tracker_reset( &tracker );

    next_check( tracker.last_packet_processed == 0 );
    next_check( tracker.num_out_of_order_packets == 0 );

    for ( int i = 0; i < 1000; ++i )
    {
        uint64_t mod_sequence = ( sequence / 2 ) * 2;
        if ( sequence % 2 )
            mod_sequence -= 1;
        next_out_of_order_tracker_packet_received( &tracker, mod_sequence );
        sequence++;
    }

    next_check( tracker.num_out_of_order_packets == 500 );
}

void test_jitter_tracker()
{
    next_jitter_tracker_t tracker;
    next_jitter_tracker_reset( &tracker );

    next_check( tracker.jitter == 0.0 );

    uint64_t sequence = 0;

    double t = 0.0;
    double dt = 1.0 / 60.0;

    for ( int i = 0; i < 1000; ++i )
    {
        next_jitter_tracker_packet_received( &tracker, sequence, t );
        sequence++;
        t += dt;
    }

    next_check( tracker.jitter < 0.000001 );

    for ( int i = 0; i < 1000; ++i )
    {
        t = i * dt;
        if ( (i%3) == 0 )
        {
            t += 2;
        }
        if ( (i%5) == 0 )
        {
            t += 5;
        }
        if ( (i%6) == 0 )
        {
            t -= 10;
        }
        next_jitter_tracker_packet_received( &tracker, sequence, t );
        sequence++;
    }

    next_check( tracker.jitter > 1.0 );

    next_jitter_tracker_reset( &tracker );

    next_check( tracker.jitter == 0.0 );

    for ( int i = 0; i < 1000; ++i )
    {
        t = i * dt;
        if ( (i%3) == 0 )
        {
            t += 0.01f;
        }
        if ( (i%5) == 0 )
        {
            t += 0.05;
        }
        if ( (i%6) == 0 )
        {
            t -= 0.1f;
        }
        next_jitter_tracker_packet_received( &tracker, sequence, t );
        sequence++;
    }

    next_check( tracker.jitter > 0.05 );
    next_check( tracker.jitter < 0.1 );

    for ( int i = 0; i < 10000; ++i )
    {
        t = i * dt;
        next_jitter_tracker_packet_received( &tracker, sequence, t );
        sequence++;
    }

    next_check( tracker.jitter >= 0.0 );
    next_check( tracker.jitter <= 0.000001 );
}

void test_anonymize_address_ipv4()
{
    next_address_t address;
    next_address_parse( &address, "1.2.3.4:5" );

    next_check( address.type == NEXT_ADDRESS_IPV4 );
    next_check( address.data.ipv4[0] == 1 );
    next_check( address.data.ipv4[1] == 2 );
    next_check( address.data.ipv4[2] == 3 );
    next_check( address.data.ipv4[3] == 4 );
    next_check( address.port == 5 );

    next_address_anonymize( &address );

    next_check( address.type == NEXT_ADDRESS_IPV4 );
    next_check( address.data.ipv4[0] == 1 );
    next_check( address.data.ipv4[1] == 2 );
    next_check( address.data.ipv4[2] == 3 );
    next_check( address.data.ipv4[3] == 0 );
    next_check( address.port == 0 );
}

#if defined(NEXT_PLATFORM_HAS_IPV6)

void test_anonymize_address_ipv6()
{
    next_address_t address;
    next_address_parse( &address, "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:40000" );

    next_check( address.type == NEXT_ADDRESS_IPV6 );
    next_check( address.data.ipv6[0] == 0x2001 );
    next_check( address.data.ipv6[1] == 0x0db8 );
    next_check( address.data.ipv6[2] == 0x85a3 );
    next_check( address.data.ipv6[3] == 0x0000 );
    next_check( address.data.ipv6[4] == 0x0000 );
    next_check( address.data.ipv6[5] == 0x8a2e );
    next_check( address.data.ipv6[6] == 0x0370 );
    next_check( address.data.ipv6[7] == 0x7334 );
    next_check( address.port == 40000 );

    next_address_anonymize( &address );

    next_check( address.type == NEXT_ADDRESS_IPV6 );
    next_check( address.data.ipv6[0] == 0x2001 );
    next_check( address.data.ipv6[1] == 0x0db8 );
    next_check( address.data.ipv6[2] == 0x85a3 );
    next_check( address.data.ipv6[3] == 0x0000 );
    next_check( address.data.ipv6[4] == 0x0000 );
    next_check( address.data.ipv6[5] == 0x0000 );
    next_check( address.data.ipv6[6] == 0x0000 );
    next_check( address.data.ipv6[7] == 0x0000 );
    next_check( address.port == 0 );
}

#endif // #if defined(NEXT_PLATFORM_HAS_IPV6)

#if defined(NEXT_PLATFORM_CAN_RUN_SERVER)

static uint64_t test_passthrough_packets_client_packets_received;
static uint64_t test_passthrough_packets_server_packets_received;

void test_passthrough_packets_server_packet_received_callback( next_server_t * server, void * context, const next_address_t * from, const uint8_t * packet_data, int packet_bytes )
{
    (void) context;
    next_server_send_packet( server, from, packet_data, packet_bytes );
    for ( int i = 0; i < packet_bytes; i++ )
    {
        if ( packet_data[i] != uint8_t( packet_bytes + i ) )
            return;
    }
    test_passthrough_packets_server_packets_received++;
}

void test_passthrough_packets_client_packet_received_callback( next_client_t * client, void * context, const next_address_t * from, const uint8_t * packet_data, int packet_bytes )
{
    (void) client;
    (void) context;
    (void) from;
    for ( int i = 0; i < packet_bytes; i++ )
    {
        if ( packet_data[i] != uint8_t( packet_bytes + i ) )
            return;
    }
    test_passthrough_packets_client_packets_received++;
}

void test_passthrough_packets()
{
    next_server_t * server = next_server_create( NULL, "127.0.0.1", "0.0.0.0:12345", "local", test_passthrough_packets_server_packet_received_callback );

    next_check( server );

    next_client_t * client = next_client_create( NULL, "0.0.0.0:0", test_passthrough_packets_client_packet_received_callback );

    next_check( client );

    next_check( next_client_port( client ) != 0 );

    next_client_open_session( client, "127.0.0.1:12345" );

    uint8_t packet_data[NEXT_MTU];
    memset( packet_data, 0, sizeof(packet_data) );

    for ( int i = 0; i < 10000; ++i )
    {
        int packet_bytes = 1 + rand() % NEXT_MTU;
        for ( int j = 0; j < packet_bytes; j++ )
        {
            packet_data[j] = uint8_t( packet_bytes + j );
        }

        next_client_send_packet( client, packet_data, packet_bytes );

        next_client_update( client );

        next_server_update( server );

        if ( test_passthrough_packets_client_packets_received > 10 && test_passthrough_packets_server_packets_received > 10 )
            break;
    }

    next_assert( test_passthrough_packets_client_packets_received > 10 );
    next_assert( test_passthrough_packets_server_packets_received > 10 );

    next_client_close_session( client );

    next_client_destroy( client );

    next_server_flush( server );

    next_server_destroy( server );
}

#endif // #if defined(NEXT_PLATFORM_CAN_RUN_SERVER)

#define RUN_TEST( test_function )                                           \
    do                                                                      \
    {                                                                       \
        next_printf( "    " #test_function );                               \
        fflush( stdout );                                                   \
        test_function();                                                    \
    }                                                                       \
    while (0)

void next_test()
{
    // while ( true )
    {
        RUN_TEST( test_time );
        RUN_TEST( test_endian );
        RUN_TEST( test_base64 );
        RUN_TEST( test_fnv1a );
        RUN_TEST( test_queue );
        RUN_TEST( test_bitpacker );
        RUN_TEST( test_bits_required );
        RUN_TEST( test_stream );
        RUN_TEST( test_address );
        RUN_TEST( test_replay_protection );
        RUN_TEST( test_ping_stats );
        RUN_TEST( test_random_bytes );
        RUN_TEST( test_random_float );
        RUN_TEST( test_crypto_box );
        RUN_TEST( test_crypto_secret_box );
        RUN_TEST( test_crypto_aead );
        RUN_TEST( test_crypto_aead_ietf );
        RUN_TEST( test_crypto_sign_detached );
        RUN_TEST( test_crypto_key_exchange );
        RUN_TEST( test_basic_read_and_write );
        RUN_TEST( test_address_read_and_write );
        RUN_TEST( test_platform_socket );
        RUN_TEST( test_platform_thread );
        RUN_TEST( test_platform_mutex );
        RUN_TEST( test_client_ipv4 );
#if defined(NEXT_PLATFORM_CAN_RUN_SERVER)
        RUN_TEST( test_server_ipv4 );
#endif // #if defined(NEXT_PLATFORM_CAN_RUN_SERVER)
#if defined(NEXT_PLATFORM_HAS_IPV6)
        RUN_TEST( test_client_ipv6 );
#if defined(NEXT_PLATFORM_CAN_RUN_SERVER)
        RUN_TEST( test_server_ipv6 );
#endif // #if defined(NEXT_PLATFORM_CAN_RUN_SERVER)
#endif // #if defined(NEXT_PLATFORM_HAS_IPV6)
        RUN_TEST( test_header );
        RUN_TEST( test_route_token );
        RUN_TEST( test_continue_token );
        RUN_TEST( test_upgrade_token );
        RUN_TEST( test_ping_token );
        RUN_TEST( test_pittle );
        RUN_TEST( test_chonkle );
        RUN_TEST( test_abi );
        RUN_TEST( test_pittle_and_chonkle );
        RUN_TEST( test_basic_packet_filter );
        RUN_TEST( test_advanced_packet_filter );
        RUN_TEST( test_passthrough );
        RUN_TEST( test_address_data_none );
        RUN_TEST( test_address_data_ipv4 );
#if defined(NEXT_PLATFORM_HAS_IPV6)
        RUN_TEST( test_address_data_ipv6 );
#endif // #if defined(NEXT_PLATFORM_HAS_IPV6)
        RUN_TEST( test_direct_packet );
        RUN_TEST( test_direct_ping_packet );
        RUN_TEST( test_direct_pong_packet );
        RUN_TEST( test_upgrade_request_packet );
        RUN_TEST( test_upgrade_response_packet );
        RUN_TEST( test_upgrade_confirm_packet );
        RUN_TEST( test_route_request_packet );
        RUN_TEST( test_route_response_packet );
        RUN_TEST( test_client_to_server_packet );
        RUN_TEST( test_server_to_client_packet );
        RUN_TEST( test_ping_packet );
        RUN_TEST( test_pong_packet );
        RUN_TEST( test_continue_request_packet );
        RUN_TEST( test_continue_response_packet );
        RUN_TEST( test_client_stats_packet_with_near_relays );
        RUN_TEST( test_client_stats_packet_without_near_relays );
        RUN_TEST( test_route_update_packet_direct );
        RUN_TEST( test_route_update_packet_new_route );
        RUN_TEST( test_route_update_packet_continue_route );
        RUN_TEST( test_route_update_ack_packet );
        RUN_TEST( test_relay_ping_packet );
        RUN_TEST( test_relay_pong_packet );
        RUN_TEST( test_server_init_request_packet );
        RUN_TEST( test_server_init_response_packet );
        RUN_TEST( test_server_update_packet );
        RUN_TEST( test_server_response_packet );
        RUN_TEST( test_session_update_packet );
        RUN_TEST( test_session_response_packet_direct_has_near_relays );
        RUN_TEST( test_session_response_packet_route_has_near_relays );
        RUN_TEST( test_session_response_packet_continue_has_near_relays );
        RUN_TEST( test_session_response_packet_direct_no_near_relays );
        RUN_TEST( test_session_response_packet_route_no_near_relays );
        RUN_TEST( test_session_response_packet_continue_no_near_relays );
        RUN_TEST( test_match_data_request_packet );
        RUN_TEST( test_match_data_response_packet );
        RUN_TEST( test_pending_session_manager );
        RUN_TEST( test_proxy_session_manager );
        RUN_TEST( test_session_manager );
        RUN_TEST( test_relay_manager );
        RUN_TEST( test_tags );
        RUN_TEST( test_bandwidth_limiter );
        RUN_TEST( test_free_retains_context );
        RUN_TEST( test_packet_loss_tracker );
        RUN_TEST( test_out_of_order_tracker );
        RUN_TEST( test_jitter_tracker );
        RUN_TEST( test_anonymize_address_ipv4 );
#if defined(NEXT_PLATFORM_HAS_IPV6)
        RUN_TEST( test_anonymize_address_ipv6 );
#endif // #if defined(NEXT_PLATFORM_HAS_IPV6)
#if defined(NEXT_PLATFORM_CAN_RUN_SERVER)
        RUN_TEST( test_passthrough_packets );
#endif // #if defined(NEXT_PLATFORM_CAN_RUN_SERVER)
    }
}

#endif // #if NEXT_COMPILE_WITH_TESTS

#ifdef _MSC_VER
#pragma warning(pop)
#endif
