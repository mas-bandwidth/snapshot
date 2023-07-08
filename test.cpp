/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include <stdio.h>
#include <string.h>
#include "snapshot.h"
#include "snapshot_crypto.h"
#include "snapshot_platform.h"

static void snapshot_check_handler( const char * condition,
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

#define snapshot_check( condition )                                                                             \
do                                                                                                              \
{                                                                                                               \
    if ( !(condition) )                                                                                         \
    {                                                                                                           \
        snapshot_check_handler( #condition, (const char*) __FUNCTION__, (const char*) __FILE__, __LINE__ );     \
    }                                                                                                           \
} while(0)

void test_time()
{
    double start = snapshot_platform_time();
    snapshot_platform_sleep( 0.1 );
    double finish = snapshot_platform_time();
    snapshot_check( finish > start );
}

void test_endian()
{
    uint32_t value = 0x11223344;
    char bytes[4];
    memcpy( bytes, &value, 4 );

#if SNAPSHOT_LITTLE_ENDIAN

    snapshot_check( bytes[0] == 0x44 );
    snapshot_check( bytes[1] == 0x33 );
    snapshot_check( bytes[2] == 0x22 );
    snapshot_check( bytes[3] == 0x11 );

#else // #if SNAPSHOT_LITTLE_ENDIAN

    snapshot_check( bytes[3] == 0x44 );
    snapshot_check( bytes[2] == 0x33 );
    snapshot_check( bytes[1] == 0x22 );
    snapshot_check( bytes[0] == 0x11 );

#endif // #if SNAPSHOT_LITTLE_ENDIAN
}

#define RUN_TEST( test_function )                                           \
    do                                                                      \
    {                                                                       \
        snapshot_printf( "    " #test_function );                           \
        fflush( stdout );                                                   \
        test_function();                                                    \
    }                                                                       \
    while (0)

void test()
{
    while ( true )
    {
        RUN_TEST( test_time );
        RUN_TEST( test_endian );

        /*
        RUN_TEST( test_address );
        RUN_TEST( test_read_and_write );
        RUN_TEST( test_bitpacker );
        RUN_TEST( test_bits_required );
        RUN_TEST( test_stream );

        RUN_TEST( test_random_bytes );
        RUN_TEST( test_random_float );
        RUN_TEST( test_crypto_box );
        RUN_TEST( test_crypto_secret_box );
        RUN_TEST( test_crypto_aead );
        RUN_TEST( test_crypto_aead_ietf );
        RUN_TEST( test_crypto_sign_detached );
        RUN_TEST( test_crypto_key_exchange );

        RUN_TEST( test_platform_socket );
        RUN_TEST( test_platform_thread );
        RUN_TEST( test_platform_mutex );
        */
    }
}

int main()
{
    snapshot_init();
    test();
    fflush( stdout );
    snapshot_term();
    return 0;
}
