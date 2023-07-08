/*
    Snapshot SDK Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_PLATFORM_H
#define SNAPSHOT_PLATFORM_H

#define SNAPSHOT_PLATFORM_SOCKET_NON_BLOCKING       0
#define SNAPSHOT_PLATFORM_SOCKET_BLOCKING           1

#define SNAPSHOT_MUTEX_BYTES                      256

struct snapshot_address_t;
struct snapshot_platform_thread_t;

typedef void (*snapshot_platform_thread_func_t)(void*);

// ----------------------------------------------------------------

int snapshot_platform_init();

void snapshot_platform_term();

// ----------------------------------------------------------------

int snapshot_platform_id();

double snapshot_platform_time();

void snapshot_platform_sleep( double time );

const char * snapshot_platform_getenv( const char * var );

// ----------------------------------------------------------------

uint16_t snapshot_platform_ntohs( uint16_t in );

uint16_t snapshot_platform_htons( uint16_t in );

int snapshot_platform_inet_pton4( const char * address_string, uint32_t * address_out );

int snapshot_platform_inet_pton6( const char * address_string, uint16_t * address_out );

int snapshot_platform_inet_ntop6( const uint16_t * address, char * address_string, size_t address_string_size );

// ----------------------------------------------------------------

int snapshot_platform_hostname_resolve( const char * hostname, const char * port, snapshot_address_t * address );

// ----------------------------------------------------------------

snapshot_platform_thread_t * snapshot_platform_thread_create( void * context, snapshot_platform_thread_func_t func, void * arg );

void snapshot_platform_thread_join( snapshot_platform_thread_t * thread );

void snapshot_platform_thread_destroy( snapshot_platform_thread_t * thread );

// ----------------------------------------------------------------

struct snapshot_mutex_t { uint8_t dummy[SNAPSHOT_MUTEX_BYTES]; };

int snapshot_mutex_create( struct snapshot_mutex_t * mutex );

void snapshot_mutex_destroy( struct snapshot_mutex_t * mutex );

void snapshot_mutex_acquire( struct snapshot_mutex_t * mutex );

void snapshot_mutex_release( struct snapshot_mutex_t * mutex );

#ifdef __cplusplus

struct snapshot_mutex_helper_t
{
    struct snapshot_mutex_t * _mutex;
    snapshot_mutex_helper_t( struct snapshot_mutex_t * mutex ) : _mutex( mutex ) { snapshot_assert( mutex ); snapshot_mutex_acquire( _mutex ); }
    ~snapshot_mutex_helper_t() { snapshot_assert( _mutex ); snapshot_mutex_release( _mutex ); _mutex = NULL; }
};

#define snapshot_mutex_guard( _mutex ) snapshot_mutex_helper_t __mutex_helper( _mutex )

#endif // #ifdef __cplusplus

// ----------------------------------------------------------------

#endif // #ifndef SNAPSHOT_PLATFORM_H
