/*
    Snapshot SDK Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licenses under different terms are available. Email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdint.h>
#include <stddef.h>

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

#define SNAPSHOT_BOOL                                           int
#define SNAPSHOT_TRUE                                             1
#define SNAPSHOT_FALSE                                            0

#define SNAPSHOT_OK                                               0
#define SNAPSHOT_ERROR                                           -1

#define SNAPSHOT_MTU                                           1300

#define SNAPSHOT_MAX_PACKET_BYTES                              4096

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

// -----------------------------------------

struct snapshot_config_t
{
    // ...
};

int snapshot_init( void * context, struct snapshot_config_t * config );

void snapshot_term();

// -----------------------------------------

#endif // #ifndef SNAPSHOT_H




// todo: work out where the rest of this belongs

#if 0

NEXT_EXPORT_FUNC double next_time();

NEXT_EXPORT_FUNC void next_sleep( double time_seconds );

NEXT_EXPORT_FUNC void next_printf( int level, const char * format, ... );

extern void (*next_assert_function_pointer)( const char * condition, const char * function, const char * file, int line );

#ifndef NEXT_ASSERTS
    #ifdef NDEBUG
        #define NEXT_ASSERTS 0
    #else
        #define NEXT_ASSERTS 1
    #endif
#endif

#if NEXT_ASSERTS
#define next_assert( condition )                                                            \
do                                                                                          \
{                                                                                           \
    if ( !(condition) )                                                                     \
    {                                                                                       \
        next_assert_function_pointer( #condition, __FUNCTION__, __FILE__, __LINE__ );       \
    }                                                                                       \
} while(0)
#else
#define next_assert( ignore ) ((void)0)
#endif

NEXT_EXPORT_FUNC void next_quiet( NEXT_BOOL flag );

NEXT_EXPORT_FUNC void next_log_level( int level );

NEXT_EXPORT_FUNC void next_log_function( void (*function)( int level, const char * format, ... ) );

NEXT_EXPORT_FUNC void next_assert_function( void (*function)( const char * condition, const char * function, const char * file, int line ) );

NEXT_EXPORT_FUNC void next_allocator( void * (*malloc_function)( void * context, size_t bytes ), void (*free_function)( void * context, void * p ) );

NEXT_EXPORT_FUNC const char * next_user_id_string( uint64_t user_id, char * buffer, size_t buffer_size );

// -----------------------------------------

#if !NEXT_ADDRESS_ALREADY_DEFINED
struct next_address_t
{
    union { uint8_t ipv4[4]; uint16_t ipv6[8]; } data;
    uint16_t port;
    uint8_t type;
};
#define NEXT_ADDRESS_ALREADY_DEFINED
#endif // #if !NEXT_ADDRESS_ALREADY_DEFINED

NEXT_EXPORT_FUNC int next_address_parse( struct next_address_t * address, const char * address_string );

NEXT_EXPORT_FUNC const char * next_address_to_string( const struct next_address_t * address, char * buffer );

NEXT_EXPORT_FUNC NEXT_BOOL next_address_equal( const struct next_address_t * a, const struct next_address_t * b );

NEXT_EXPORT_FUNC void next_address_anonymize( struct next_address_t * address );

// -----------------------------------------

struct next_platform_thread_t;

typedef void (*next_platform_thread_func_t)(void*);

NEXT_EXPORT_FUNC next_platform_thread_t * next_platform_thread_create( void * context, next_platform_thread_func_t func, void * arg );

NEXT_EXPORT_FUNC void next_platform_thread_join( next_platform_thread_t * thread );

NEXT_EXPORT_FUNC void next_platform_thread_destroy( next_platform_thread_t * thread );

// -----------------------------------------

#define NEXT_MUTEX_BYTES 256

struct next_mutex_t { uint8_t dummy[NEXT_MUTEX_BYTES]; };

NEXT_EXPORT_FUNC int next_mutex_create( struct next_mutex_t * mutex );

NEXT_EXPORT_FUNC void next_mutex_destroy( struct next_mutex_t * mutex );

NEXT_EXPORT_FUNC void next_mutex_acquire( struct next_mutex_t * mutex );

NEXT_EXPORT_FUNC void next_mutex_release( struct next_mutex_t * mutex );

#ifdef __cplusplus

struct next_mutex_helper_t
{
    struct next_mutex_t * _mutex;
    next_mutex_helper_t( struct next_mutex_t * mutex ) : _mutex( mutex ) { next_assert( mutex ); next_mutex_acquire( _mutex ); }
    ~next_mutex_helper_t() { next_assert( _mutex ); next_mutex_release( _mutex ); _mutex = NULL; }
};

#define next_mutex_guard( _mutex ) next_mutex_helper_t __mutex_helper( _mutex )

#endif // #ifdef __cplusplus

// -----------------------------------------

NEXT_EXPORT_FUNC void next_copy_string( char * dest, const char * source, size_t dest_size );

// -----------------------------------------

NEXT_EXPORT_FUNC void next_test();      // IMPORTANT: only if compiled with tests. See #if NEXT_COMPILE_WITH_TESTS

#endif // todo
