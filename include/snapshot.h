/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <memory.h>

#define SNAPSHOT_MAX_CLIENTS                                    256

#define SNAPSHOT_MAX_PACKET_BYTES                     ( 10 * 1024 )

#define SNAPSHOT_CLIENT_SOCKET_SNDBUF_SIZE           ( 256 * 1024 )
#define SNAPSHOT_CLIENT_SOCKET_RCVBUF_SIZE           ( 256 * 1024 )

#define SNAPSHOT_SERVER_SOCKET_SNDBUF_SIZE          ( 1024 * 1024 )
#define SNAPSHOT_SERVER_SOCKET_RCVBUF_SIZE          ( 1024 * 1024 )

#define SNAPSHOT_NUM_DISCONNECT_PACKETS                          10

#if !defined(SNAPSHOT_DEVELOPMENT)

    #define SNAPSHOT_VERSION_FULL                            "0.0.1"
    #define SNAPSHOT_VERSION_MAJOR_INT                            0
    #define SNAPSHOT_VERSION_MINOR_INT                            0
    #define SNAPSHOT_VERSION_PATCH_INT                            1

#else // !defined(SNAPSHOT_DEVELOPMENT)

    #define SNAPSHOT_VERSION_FULL                             "dev"
    #define SNAPSHOT_VERSION_MAJOR_INT                          255
    #define SNAPSHOT_VERSION_MINOR_INT                          255
    #define SNAPSHOT_VERSION_PATCH_INT                          255

#endif // !defined(SNAPSHOT_DEVELOPMENT)

#define SNAPSHOT_CONNECT_TOKEN_BYTES                           2048
#define SNAPSHOT_KEY_BYTES                                       32
#define SNAPSHOT_MAC_BYTES                                       16
#define SNAPSHOT_USER_DATA_BYTES                                256
#define SNAPSHOT_MAX_SERVERS_PER_CONNECT                         32

#define SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES                       24
#define SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES                   1024

#define SNAPSHOT_VERSION_INFO ( (uint8_t*) "SNAPSHOT" )
#define SNAPSHOT_VERSION_INFO_BYTES                               9

#define SNAPSHOT_MAX_SERVERS_PER_CONNECT                         32

#define SNAPSHOT_BOOL                                           int
#define SNAPSHOT_TRUE                                             1
#define SNAPSHOT_FALSE                                            0

#define SNAPSHOT_OK                                               0
#define SNAPSHOT_ERROR                                           -1

#define SNAPSHOT_MTU                                           1300

#define SNAPSHOT_LOG_LEVEL_NONE                                   0
#define SNAPSHOT_LOG_LEVEL_ERROR                                  1
#define SNAPSHOT_LOG_LEVEL_INFO                                   2
#define SNAPSHOT_LOG_LEVEL_WARN                                   3
#define SNAPSHOT_LOG_LEVEL_DEBUG                                  4
#define SNAPSHOT_LOG_LEVEL_SPAM                                   5

#define SNAPSHOT_ADDRESS_NONE                                     0
#define SNAPSHOT_ADDRESS_IPV4                                     1
#define SNAPSHOT_ADDRESS_IPV6                                     2

#define SNAPSHOT_MAX_ADDRESS_STRING_LENGTH                      256

#define SNAPSHOT_PLATFORM_UNKNOWN                                 0
#define SNAPSHOT_PLATFORM_WINDOWS                                 1
#define SNAPSHOT_PLATFORM_MAC                                     2
#define SNAPSHOT_PLATFORM_LINUX                                   3
#define SNAPSHOT_PLATFORM_SWITCH                                  4
#define SNAPSHOT_PLATFORM_PS4                                     5
#define SNAPSHOT_PLATFORM_IOS                                     6
#define SNAPSHOT_PLATFORM_XBOX_ONE                                7
#define SNAPSHOT_PLATFORM_XBOX_SERIES_X                           8
#define SNAPSHOT_PLATFORM_PS5                                     9
#define SNAPSHOT_PLATFORM_GDK                                    10
#define SNAPSHOT_PLATFORM_MAX                                    10

#if defined(_WIN32)
#define NOMINMAX
#endif

#if defined(NN_NINTENDO_SDK)
    #define SNAPSHOT_PLATFORM SNAPSHOT_PLATFORM_SWITCH
#elif defined(__ORBIS__)
    #define SNAPSHOT_PLATFORM SNAPSHOT_PLATFORM_PS4
#elif defined(__PROSPERO__)
    #define SNAPSHOT_PLATFORM SNAPSHOT_PLATFORM_PS5
#elif defined(_XBOX_ONE)
    #define SNAPSHOT_PLATFORM SNAPSHOT_PLATFORM_XBOX_ONE
#elif defined(_GAMING_XBOX)
    #define SNAPSHOT_PLATFORM SNAPSHOT_PLATFORM_GDK
#elif defined(_WIN32)
    #define SNAPSHOT_PLATFORM SNAPSHOT_PLATFORM_WINDOWS
#elif defined(__APPLE__)
    #include "TargetConditionals.h"
    #if TARGET_OS_IPHONE
        #define SNAPSHOT_PLATFORM SNAPSHOT_PLATFORM_IOS
    #else
        #define SNAPSHOT_PLATFORM SNAPSHOT_PLATFORM_MAC
    #endif
#else
    #define SNAPSHOT_PLATFORM SNAPSHOT_PLATFORM_LINUX
#endif

#if SNAPSHOT_PLATFORM != SNAPSHOT_PLATFORM_PS4 && SNAPSHOT_PLATFORM != SNAPSHOT_PLATFORM_PS5 && SNAPSHOT_PLATFORM != SNAPSHOT_PLATFORM_SWITCH
#define SNAPSHOT_PLATFORM_HAS_IPV6 1
#endif // #if SNAPSHOT_PLATFORM != SNAPSHOT_PLATFORM_PS4 && SNAPSHOT_PLATFORM != SNAPSHOT_PLATFORM_PS5 && SNAPSHOT_PLATFORM != SNAPSHOT_PLATFORM_SWITCH

#if SNAPSHOT_PLATFORM != SNAPSHOT_PLATFORM_XBOX_ONE && SNAPSHOT_PLATFORM != SNAPSHOT_PLATFORM_GDK
#define SNAPSHOT_PLATFORM_CAN_RUN_SERVER 1
#endif // #if SNAPSHOT_PLATFORM != SNAPSHOT_PLATFORM_XBOX_ONE && SNAPSHOT_PLATFORM != SNAPSHOT_PLATFORM_GDK

#if !defined ( SNAPSHOT_LITTLE_ENDIAN ) && !defined( SNAPSHOT_BIG_ENDIAN )

  #ifdef __BYTE_ORDER__
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
      #define SNAPSHOT_LITTLE_ENDIAN 1
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
      #define SNAPSHOT_BIG_ENDIAN 1
    #else
      #error Unknown machine endianess detected. Please define SNAPSHOT_LITTLE_ENDIAN or SNAPSHOT_BIG_ENDIAN.
    #endif // __BYTE_ORDER__

  // Detect with GLIBC's endian.h
  #elif defined(__GLIBC__)
    #include <endian.h>
    #if (__BYTE_ORDER == __LITTLE_ENDIAN)
      #define SNAPSHOT_LITTLE_ENDIAN 1
    #elif (__BYTE_ORDER == __BIG_ENDIAN)
      #define SNAPSHOT_BIG_ENDIAN 1
    #else
      #error Unknown machine endianess detected. Please define SNAPSHOT_LITTLE_ENDIAN or SNAPSHOT_BIG_ENDIAN.
    #endif // __BYTE_ORDER

  // Detect with _LITTLE_ENDIAN and _BIG_ENDIAN macro
  #elif defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
    #define SNAPSHOT_LITTLE_ENDIAN 1
  #elif defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN)
    #define SNAPSHOT_BIG_ENDIAN 1

  // Detect with architecture macros
  #elif    defined(__sparc)     || defined(__sparc__)                           \
        || defined(_POWER)      || defined(__powerpc__)                         \
        || defined(__ppc__)     || defined(__hpux)      || defined(__hppa)      \
        || defined(_MIPSEB)     || defined(_POWER)      || defined(__s390__)
    #define SNAPSHOT_BIG_ENDIAN 1
  #elif    defined(__i386__)    || defined(__alpha__)   || defined(__ia64)      \
        || defined(__ia64__)    || defined(_M_IX86)     || defined(_M_IA64)     \
        || defined(_M_ALPHA)    || defined(__amd64)     || defined(__amd64__)   \
        || defined(_M_AMD64)    || defined(__x86_64)    || defined(__x86_64__)  \
        || defined(_M_X64)      || defined(__bfin__)
    #define SNAPSHOT_LITTLE_ENDIAN 1
  #elif defined(_MSC_VER) && defined(_M_ARM)
    #define SNAPSHOT_LITTLE_ENDIAN 1
  #else
    #error Unknown machine endianess detected. Please define SNAPSHOT_LITTLE_ENDIAN or SNAPSHOT_BIG_ENDIAN.
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

// -----------------------------------------

int snapshot_init();

void snapshot_term();

// -----------------------------------------

void snapshot_quiet( bool value );

void snapshot_log_level( int level );

const char * snapshot_log_level_string( int level );

void snapshot_log_function( void (*function)( int level, const char * format, ... ) );

void snapshot_printf( const char * format, ... );

void snapshot_printf( int level, const char * format, ... );

// -----------------------------------------

void snapshot_allocator( void * (*malloc_function)( void * context, size_t bytes ), void (*free_function)( void * context, void * p ) );

void * snapshot_malloc( void * context, size_t bytes );

void snapshot_free( void * context, void * p );

// -----------------------------------------

#ifndef NDEBUG
#define SNAPSHOT_ASSERTS 1
#endif

extern void (*snapshot_assert_function_pointer)( const char * condition, const char * function, const char * file, int line );

#ifndef SNAPSHOT_ASSERTS
    #ifdef NDEBUG
        #define SNAPSHOT_ASSERTS 0
    #else
        #define SNAPSHOT_ASSERTS 1
    #endif
#endif

#if SNAPSHOT_ASSERTS
#define snapshot_assert( condition )                                                            \
do                                                                                              \
{                                                                                               \
    if ( !(condition) )                                                                         \
    {                                                                                           \
        snapshot_assert_function_pointer( #condition, __FUNCTION__, __FILE__, __LINE__ );       \
    }                                                                                           \
} while(0)
#else
#define snapshot_assert( ignore ) ((void)0)
#endif

void snapshot_assert_function( void (*function)( const char * condition, const char * function, const char * file, int line ) );

// -----------------------------------------

void snapshot_copy_string( char * dest, const char * source, size_t dest_size );

// -----------------------------------------

#if SNAPSHOT_DEVELOPMENT

#define SNAPSHOT_DEVELOPMENT_FLAG_VALIDATE_PAYLOAD (1<<0)

#endif // #if SNAPSHOT_DEVELOPMENT

// -----------------------------------------

#endif // #ifndef SNAPSHOT_H
