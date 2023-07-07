/*
    Snapshot SDK Copyright © 2023 Network Next, Inc. This source code is licensed under GPL version 3 or any later version.
    Commercial licenses under different terms are available. Contact licensing@mas-bandwidth.com for details.
*/

#if 0 // todo

#ifndef NEXT_H
#define NEXT_H

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdint.h>
#include <stddef.h>

#ifndef NEXT_PACKET_TAGGING
#define NEXT_PACKET_TAGGING                                       1
#endif // #if NEXT_PACKET_TAGGING

#if !defined(NEXT_DEVELOPMENT)

    #define NEXT_VERSION_FULL                               "5.0.0"
    #define NEXT_VERSION_MAJOR_INT                                5
    #define NEXT_VERSION_MINOR_INT                                0
    #define NEXT_VERSION_PATCH_INT                                0

#else // !defined(NEXT_DEVELOPMENT)

    #define NEXT_VERSION_FULL                                 "dev"
    #define NEXT_VERSION_MAJOR_INT                              255
    #define NEXT_VERSION_MINOR_INT                              255
    #define NEXT_VERSION_PATCH_INT                              255

#endif // !defined(NEXT_DEVELOPMENT)

#define NEXT_BOOL                                               int
#define NEXT_TRUE                                                 1
#define NEXT_FALSE                                                0

#define NEXT_OK                                                   0
#define NEXT_ERROR                                               -1

#define NEXT_MTU                                               1300

#define NEXT_MAX_PACKET_BYTES                                  4096

#define NEXT_LOG_LEVEL_NONE                                       0
#define NEXT_LOG_LEVEL_ERROR                                      1
#define NEXT_LOG_LEVEL_INFO                                       2
#define NEXT_LOG_LEVEL_WARN                                       3
#define NEXT_LOG_LEVEL_DEBUG                                      4
#define NEXT_LOG_LEVEL_SPAM                                       5

#define NEXT_ADDRESS_NONE                                         0
#define NEXT_ADDRESS_IPV4                                         1
#define NEXT_ADDRESS_IPV6                                         2

#define NEXT_MAX_ADDRESS_STRING_LENGTH                          256

#define NEXT_CONNECTION_TYPE_UNKNOWN                              0
#define NEXT_CONNECTION_TYPE_WIRED                                1
#define NEXT_CONNECTION_TYPE_WIFI                                 2
#define NEXT_CONNECTION_TYPE_CELLULAR                             3
#define NEXT_CONNECTION_TYPE_MAX                                  3

#define NEXT_PLATFORM_UNKNOWN                                     0
#define NEXT_PLATFORM_WINDOWS                                     1
#define NEXT_PLATFORM_MAC                                         2
#define NEXT_PLATFORM_LINUX                                       3
#define NEXT_PLATFORM_SWITCH                                      4
#define NEXT_PLATFORM_PS4                                         5
#define NEXT_PLATFORM_IOS                                         6
#define NEXT_PLATFORM_XBOX_ONE                                    7
#define NEXT_PLATFORM_XBOX_SERIES_X                               8
#define NEXT_PLATFORM_PS5                                         9
#define NEXT_PLATFORM_GDK                                        10
#define NEXT_PLATFORM_MAX                                        10

#define NEXT_MAX_TAGS                                             8

#define NEXT_MAX_MATCH_VALUES                                    64

#if defined(_WIN32)
#define NOMINMAX
#endif

#if defined( NEXT_SHARED )
    #if defined( _WIN32 ) || defined( __ORBIS__ ) || defined( __PROSPERO__ )
        #ifdef NEXT_EXPORT
            #if __cplusplus
            #define NEXT_EXPORT_FUNC extern "C" __declspec(dllexport)
            #else
            #define NEXT_EXPORT_FUNC extern __declspec(dllexport)
            #endif
        #else
            #if __cplusplus
            #define NEXT_EXPORT_FUNC extern "C" __declspec(dllimport)
            #else
            #define NEXT_EXPORT_FUNC extern __declspec(dllimport)
            #endif
        #endif
    #else
        #if __cplusplus
        #define NEXT_EXPORT_FUNC extern "C"
        #else
        #define NEXT_EXPORT_FUNC extern
        #endif
    #endif
#else
    #if __cplusplus
    #define NEXT_EXPORT_FUNC extern "C"
    #else
    #define NEXT_EXPORT_FUNC extern
    #endif
#endif

#if defined(NN_NINTENDO_SDK)
    #define NEXT_PLATFORM NEXT_PLATFORM_SWITCH
#elif defined(__ORBIS__)
    #define NEXT_PLATFORM NEXT_PLATFORM_PS4
#elif defined(__PROSPERO__)
    #define NEXT_PLATFORM NEXT_PLATFORM_PS5
#elif defined(_XBOX_ONE)
    #define NEXT_PLATFORM NEXT_PLATFORM_XBOX_ONE
#elif defined(_GAMING_XBOX)
    #define NEXT_PLATFORM NEXT_PLATFORM_GDK
#elif defined(_WIN32)
    #define NEXT_PLATFORM NEXT_PLATFORM_WINDOWS
#elif defined(__APPLE__)
    #include "TargetConditionals.h"
    #if TARGET_OS_IPHONE
        #define NEXT_PLATFORM NEXT_PLATFORM_IOS
    #else
        #define NEXT_PLATFORM NEXT_PLATFORM_MAC
    #endif
#else
    #define NEXT_PLATFORM NEXT_PLATFORM_LINUX
#endif

#if NEXT_PLATFORM != NEXT_PLATFORM_PS4 && NEXT_PLATFORM != NEXT_PLATFORM_PS5 && NEXT_PLATFORM != NEXT_PLATFORM_SWITCH
#define NEXT_PLATFORM_HAS_IPV6 1
#endif // #if NEXT_PLATFORM != NEXT_PLATFORM_PS4 && NEXT_PLATFORM != NEXT_PLATFORM_PS5 && NEXT_PLATFORM != NEXT_PLATFORM_SWITCH

#if NEXT_PLATFORM != NEXT_PLATFORM_XBOX_ONE && NEXT_PLATFORM != NEXT_PLATFORM_GDK
#define NEXT_PLATFORM_CAN_RUN_SERVER 1
#endif // #if NEXT_PLATFORM != NEXT_PLATFORM_XBOX_ONE && NEXT_PLATFORM != NEXT_PLATFORM_GDK

#if NEXT_UNREAL_ENGINE && NEXT_PLATFORM == NEXT_PLATFORM_PS5 && !defined(PLATFORM_PS5)
#error Building unreal engine on PS5, but PLATFORM_PS5 is not defined! Please follow steps in README.md for PS5 platform setup!
#endif // #if NEXT_UNREAL_ENGINE && NEXT_PLATFORM == NEXT_PLATFORM_PS5 && !defined(PLATFORM_PS5)

// -----------------------------------------

struct next_config_t
{
    char server_backend_hostname[256];
    char customer_public_key[256];
    char customer_private_key[256];
    int socket_send_buffer_size;
    int socket_receive_buffer_size;
    NEXT_BOOL disable_network_next;
    NEXT_BOOL disable_autodetect;
};

NEXT_EXPORT_FUNC void next_default_config( struct next_config_t * config );

NEXT_EXPORT_FUNC int next_init( void * context, struct next_config_t * config );

NEXT_EXPORT_FUNC void next_term();

// -----------------------------------------

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

struct next_client_stats_t
{
    int platform_id;
    int connection_type;
    NEXT_BOOL next;
    NEXT_BOOL upgraded;
    NEXT_BOOL committed;
    NEXT_BOOL multipath;
    NEXT_BOOL reported;
    NEXT_BOOL fallback_to_direct;
    float direct_rtt;
    float direct_jitter;
    float direct_packet_loss;
    float direct_max_packet_loss_seen;
    float direct_kbps_up;
    float direct_kbps_down;
    float next_rtt;
    float next_jitter;
    float next_packet_loss;
    float next_kbps_up;
    float next_kbps_down;
    uint64_t packets_sent_client_to_server;
    uint64_t packets_sent_server_to_client;
    uint64_t packets_lost_client_to_server;
    uint64_t packets_lost_server_to_client;
    uint64_t packets_out_of_order_client_to_server;
    uint64_t packets_out_of_order_server_to_client;
    float jitter_client_to_server;
    float jitter_server_to_client;
};

// -----------------------------------------

// todo: these states aren't really helpful
#define NEXT_CLIENT_STATE_CLOSED        0
#define NEXT_CLIENT_STATE_OPEN          1
#define NEXT_CLIENT_STATE_ERROR         2

struct next_client_t;

NEXT_EXPORT_FUNC struct next_client_t * next_client_create( void * context, const char * bind_address, void (*packet_received_callback)( struct next_client_t * client, void * context, const struct next_address_t * from, const uint8_t * packet_data, int packet_bytes ) );

NEXT_EXPORT_FUNC void next_client_destroy( struct next_client_t * client );

NEXT_EXPORT_FUNC uint16_t next_client_port( struct next_client_t * client );

NEXT_EXPORT_FUNC void next_client_open_session( struct next_client_t * client, const char * server_address );

NEXT_EXPORT_FUNC void next_client_close_session( struct next_client_t * client );

// todo: sucks
NEXT_EXPORT_FUNC NEXT_BOOL next_client_is_session_open( struct next_client_t * client );

// todo: sucks
NEXT_EXPORT_FUNC int next_client_state( struct next_client_t * client );

NEXT_EXPORT_FUNC void next_client_update( struct next_client_t * client );

NEXT_EXPORT_FUNC void next_client_send_packet( struct next_client_t * client, const uint8_t * packet_data, int packet_bytes );

NEXT_EXPORT_FUNC void next_client_send_packet_direct( struct next_client_t * client, const uint8_t * packet_data, int packet_bytes );

NEXT_EXPORT_FUNC void next_client_send_packet_raw( struct next_client_t * client, const next_address_t * address, const uint8_t * packet_data, int packet_bytes );

NEXT_EXPORT_FUNC void next_client_report_session( struct next_client_t * client );

NEXT_EXPORT_FUNC uint64_t next_client_session_id( struct next_client_t * client );

NEXT_EXPORT_FUNC const struct next_client_stats_t * next_client_stats( struct next_client_t * client );

NEXT_EXPORT_FUNC const struct next_address_t * next_client_server_address( struct next_client_t * client );

NEXT_EXPORT_FUNC NEXT_BOOL next_client_ready( struct next_client_t * client );

NEXT_EXPORT_FUNC NEXT_BOOL next_client_fallback_to_direct( struct next_client_t * client );

// -----------------------------------------

struct next_server_stats_t
{
    struct next_address_t address;
    uint64_t session_id;
    uint64_t user_hash;
    int platform_id;
    int connection_type;
    NEXT_BOOL next;
    NEXT_BOOL committed;
    NEXT_BOOL multipath;
    NEXT_BOOL reported;
    NEXT_BOOL fallback_to_direct;
    float direct_rtt;
    float direct_jitter;
    float direct_packet_loss;
    float direct_max_packet_loss_seen;
    float direct_kbps_up;
    float direct_kbps_down;
    float next_rtt;
    float next_jitter;
    float next_packet_loss;
    float next_kbps_up;
    float next_kbps_down;
    uint64_t packets_sent_client_to_server;
    uint64_t packets_sent_server_to_client;
    uint64_t packets_lost_client_to_server;
    uint64_t packets_lost_server_to_client;
    uint64_t packets_out_of_order_client_to_server;
    uint64_t packets_out_of_order_server_to_client;
    float jitter_client_to_server;
    float jitter_server_to_client;
    int num_tags;
    uint64_t tags[NEXT_MAX_TAGS];
};

#define NEXT_SERVER_STATE_DIRECT_ONLY               0
#define NEXT_SERVER_STATE_INITIALIZING              1
#define NEXT_SERVER_STATE_INITIALIZED               2

struct next_server_t;

NEXT_EXPORT_FUNC struct next_server_t * next_server_create( void * context, const char * server_address, const char * bind_address, const char * datacenter, void (*packet_received_callback)( struct next_server_t * server, void * context, const struct next_address_t * from, const uint8_t * packet_data, int packet_bytes ) );

NEXT_EXPORT_FUNC void next_server_destroy( struct next_server_t * server );

NEXT_EXPORT_FUNC uint16_t next_server_port( struct next_server_t * server );

NEXT_EXPORT_FUNC struct next_address_t next_server_address( struct next_server_t * server );

NEXT_EXPORT_FUNC int next_server_state( struct next_server_t * server );

NEXT_EXPORT_FUNC void next_server_update( struct next_server_t * server );

NEXT_EXPORT_FUNC uint64_t next_server_upgrade_session( struct next_server_t * server, const struct next_address_t * address, const char * user_id );

NEXT_EXPORT_FUNC void next_server_tag_session( struct next_server_t * server, const struct next_address_t * address, const char * tag );

NEXT_EXPORT_FUNC void next_server_tag_session_multiple( struct next_server_t * server, const struct next_address_t * address, const char ** tags, int num_tags );

NEXT_EXPORT_FUNC NEXT_BOOL next_server_session_upgraded( struct next_server_t * server, const struct next_address_t * address );

NEXT_EXPORT_FUNC void next_server_send_packet( struct next_server_t * server, const struct next_address_t * to_address, const uint8_t * packet_data, int packet_bytes );

NEXT_EXPORT_FUNC void next_server_send_packet_direct( struct next_server_t * server, const struct next_address_t * to_address, const uint8_t * packet_data, int packet_bytes );

NEXT_EXPORT_FUNC void next_server_send_packet_raw( struct next_server_t * server, const struct next_address_t * to_address, const uint8_t * packet_data, int packet_bytes );

NEXT_EXPORT_FUNC NEXT_BOOL next_server_stats( struct next_server_t * server, const struct next_address_t * address, struct next_server_stats_t * stats );

NEXT_EXPORT_FUNC NEXT_BOOL next_server_ready( struct next_server_t * server );

NEXT_EXPORT_FUNC const char * next_server_datacenter( struct next_server_t * server );

NEXT_EXPORT_FUNC void next_server_event( struct next_server_t * server, const struct next_address_t * address, uint64_t server_events );

NEXT_EXPORT_FUNC void next_server_match( struct next_server_t * server, const struct next_address_t * address, const char * match_id, const double * match_values, int num_match_values );

NEXT_EXPORT_FUNC void next_server_flush( struct next_server_t * server );

NEXT_EXPORT_FUNC void next_server_set_packet_receive_callback( struct next_server_t * server, void (*callback) ( void * data, next_address_t * from, uint8_t * packet_data, int * begin, int * end ), void * callback_data );

NEXT_EXPORT_FUNC void next_server_set_send_packet_to_address_callback( struct next_server_t * server, int (*callback) ( void * data, const next_address_t * address, const uint8_t * packet_data, int packet_bytes ), void * callback_data );

NEXT_EXPORT_FUNC void next_server_set_payload_receive_callback( struct next_server_t * server, int (*callback) ( void * data, const next_address_t * address, const uint8_t * payload_data, int payload_bytes ), void * callback_data );

NEXT_EXPORT_FUNC NEXT_BOOL next_server_direct_only( struct next_server_t * server );

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

// -----------------------------------------

#endif // #ifndef NEXT_H

#endif // todo
