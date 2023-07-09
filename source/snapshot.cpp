/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"
#include "snapshot_crypto.h"
#include "snapshot_platform.h"

#include <stdarg.h>

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

void * snapshot_malloc( void * context, size_t bytes )
{
    (void) context;
    // todo: custom allocator
    return malloc( bytes );
}

void snapshot_free( void * context, void * p )
{
    (void) context;
    // todo: custom allocator
    free(p);
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

// todo: custom log function
static void log_function( int level, const char * format, ... )
{
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof( buffer ), format, args );
    if ( level != SNAPSHOT_LOG_LEVEL_NONE )
    {
        // todo: quiet flag
//        if ( !log_quiet )
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

// todo
static int log_level = SNAPSHOT_LOG_LEVEL_INFO;

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
