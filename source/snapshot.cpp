/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"
#include "snapshot_crypto.h"
#include "snapshot_platform.h"

#include <stdarg.h>
#include <stdlib.h>
#include <memory.h>

int snapshot_init()
{
    if ( snapshot_crypto_init() != SNAPSHOT_OK )
    {
        return SNAPSHOT_ERROR;
    }

    if ( snapshot_platform_init() != SNAPSHOT_OK )
    {
        return SNAPSHOT_ERROR;
    }

    return SNAPSHOT_OK;
}

void snapshot_term()
{
    snapshot_platform_term();
}

void snapshot_copy_string( char * dest, const char * source, size_t dest_size )
{
    snapshot_assert( dest );
    snapshot_assert( source );
    snapshot_assert( dest_size >= 1 );
    memset( dest, 0, dest_size );
    for ( size_t i = 0; i < dest_size - 1; i++ )
    {
        if ( source[i] == '\0' )
            break;
        dest[i] = source[i];
    }
}

inline void * snapshot_default_malloc_function( void * context, size_t bytes )
{
    (void) context;
    return malloc( bytes );
}

inline void snapshot_default_free_function( void * context, void * p )
{
    (void) context;
    free( p );
}

static void * (*snapshot_malloc_function)( void * context, size_t bytes ) = snapshot_default_malloc_function;
static void (*snapshot_free_function)( void * context, void * p ) = snapshot_default_free_function;

void snapshot_allocator( void * (*malloc_function)( void * context, size_t bytes ), void (*free_function)( void * context, void * p ) )
{
    snapshot_assert( malloc_function );
    snapshot_assert( free_function );
    snapshot_malloc_function = malloc_function;
    snapshot_free_function = free_function;
}

void * snapshot_malloc( void * context, size_t bytes )
{
    snapshot_assert( snapshot_malloc_function );
    return snapshot_malloc_function( context, bytes );
}

void snapshot_free( void * context, void * p )
{
    snapshot_assert( snapshot_free_function );
    return snapshot_free_function( context, p );
}

const char * snapshot_log_level_string( int level )
{
    if ( level == SNAPSHOT_LOG_LEVEL_SPAM )
        return "spam";
    else if ( level == SNAPSHOT_LOG_LEVEL_DEBUG )
        return "debug";
    else if ( level == SNAPSHOT_LOG_LEVEL_INFO )
        return "info";
    else if ( level == SNAPSHOT_LOG_LEVEL_ERROR )
        return "error";
    else if ( level == SNAPSHOT_LOG_LEVEL_WARN )
        return "warning";
    else
        return "???";
}

static bool log_quiet;

static int log_level = SNAPSHOT_LOG_LEVEL_INFO;

static void default_log_function( int level, const char * format, ... )
{
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof( buffer ), format, args );
    if ( level != SNAPSHOT_LOG_LEVEL_NONE )
    {
        if ( !log_quiet )
        {
            const char * level_string = snapshot_log_level_string( level );
            printf( "%.6f: %s: %s\n", snapshot_platform_time(), level_string, buffer );
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

void snapshot_log_function( void (*function)( int level, const char * format, ... ) )
{
    log_function = function;
}

void snapshot_quiet( bool value )
{
    log_quiet = value;
}

void snapshot_printf( const char * format, ... )
{
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof(buffer), format, args );
    log_function( SNAPSHOT_LOG_LEVEL_NONE, "%s", buffer );
    va_end( args );
}

void snapshot_printf( int level, const char * format, ... )
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

static void default_assert_function( const char * condition, const char * function, const char * file, int line )
{
    snapshot_printf( "assert failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
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

void (*snapshot_assert_function_pointer)( const char * condition, const char * function, const char * file, int line ) = default_assert_function;

void snapshot_assert_function( void (*function)( const char * condition, const char * function, const char * file, int line ) )
{
    snapshot_assert_function_pointer = function;
}
