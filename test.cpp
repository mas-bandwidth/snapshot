/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include <stdio.h>
#include <string.h>
#include "snapshot.h"
#include "snapshot_crypto.h"
#include "snapshot_platform.h"
#include "snapshot_address.h"
#include "snapshot_read_write.h"
#include "snapshot_bitpacker.h"
#include "snapshot_stream.h"
#include "snapshot_serialize.h"

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

void test_address()
{
    {
        struct snapshot_address_t address;
        snapshot_check( snapshot_address_parse( &address, "" ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, "[" ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, "[]" ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, "[]:" ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, ":" ) == SNAPSHOT_ERROR );
#if !defined(WINVER) || WINVER > 0x502 // windows xp sucks
        snapshot_check( snapshot_address_parse( &address, "1" ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, "12" ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, "123" ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, "1234" ) == SNAPSHOT_ERROR );
#endif
        snapshot_check( snapshot_address_parse( &address, "1234.0.12313.0000" ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, "1234.0.12313.0000.0.0.0.0.0" ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, "1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131" ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, "." ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, ".." ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, "..." ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, "...." ) == SNAPSHOT_ERROR );
        snapshot_check( snapshot_address_parse( &address, "....." ) == SNAPSHOT_ERROR );
    }

    {
        struct snapshot_address_t address;
        snapshot_check( snapshot_address_parse( &address, "107.77.207.77" ) == SNAPSHOT_OK );
        snapshot_check( address.type == SNAPSHOT_ADDRESS_IPV4 );
        snapshot_check( address.port == 0 );
        snapshot_check( address.data.ipv4[0] == 107 );
        snapshot_check( address.data.ipv4[1] == 77 );
        snapshot_check( address.data.ipv4[2] == 207 );
        snapshot_check( address.data.ipv4[3] == 77 );
    }

    {
        struct snapshot_address_t address;
        snapshot_check( snapshot_address_parse( &address, "127.0.0.1" ) == SNAPSHOT_OK );
        snapshot_check( address.type == SNAPSHOT_ADDRESS_IPV4 );
        snapshot_check( address.port == 0 );
        snapshot_check( address.data.ipv4[0] == 127 );
        snapshot_check( address.data.ipv4[1] == 0 );
        snapshot_check( address.data.ipv4[2] == 0 );
        snapshot_check( address.data.ipv4[3] == 1 );
    }

    {
        struct snapshot_address_t address;
        snapshot_check( snapshot_address_parse( &address, "107.77.207.77:40000" ) == SNAPSHOT_OK );
        snapshot_check( address.type == SNAPSHOT_ADDRESS_IPV4 );
        snapshot_check( address.port == 40000 );
        snapshot_check( address.data.ipv4[0] == 107 );
        snapshot_check( address.data.ipv4[1] == 77 );
        snapshot_check( address.data.ipv4[2] == 207 );
        snapshot_check( address.data.ipv4[3] == 77 );
    }

    {
        struct snapshot_address_t address;
        snapshot_check( snapshot_address_parse( &address, "127.0.0.1:40000" ) == SNAPSHOT_OK );
        snapshot_check( address.type == SNAPSHOT_ADDRESS_IPV4 );
        snapshot_check( address.port == 40000 );
        snapshot_check( address.data.ipv4[0] == 127 );
        snapshot_check( address.data.ipv4[1] == 0 );
        snapshot_check( address.data.ipv4[2] == 0 );
        snapshot_check( address.data.ipv4[3] == 1 );
    }

#if SNAPSHOT_PLATFORM_HAS_IPV6
    {
        struct snapshot_address_t address;
        snapshot_check( snapshot_address_parse( &address, "fe80::202:b3ff:fe1e:8329" ) == SNAPSHOT_OK );
        snapshot_check( address.type == SNAPSHOT_ADDRESS_IPV6 );
        snapshot_check( address.port == 0 );
        snapshot_check( address.data.ipv6[0] == 0xfe80 );
        snapshot_check( address.data.ipv6[1] == 0x0000 );
        snapshot_check( address.data.ipv6[2] == 0x0000 );
        snapshot_check( address.data.ipv6[3] == 0x0000 );
        snapshot_check( address.data.ipv6[4] == 0x0202 );
        snapshot_check( address.data.ipv6[5] == 0xb3ff );
        snapshot_check( address.data.ipv6[6] == 0xfe1e );
        snapshot_check( address.data.ipv6[7] == 0x8329 );
    }

    {
        struct snapshot_address_t address;
        snapshot_check( snapshot_address_parse( &address, "::" ) == SNAPSHOT_OK );
        snapshot_check( address.type == SNAPSHOT_ADDRESS_IPV6 );
        snapshot_check( address.port == 0 );
        snapshot_check( address.data.ipv6[0] == 0x0000 );
        snapshot_check( address.data.ipv6[1] == 0x0000 );
        snapshot_check( address.data.ipv6[2] == 0x0000 );
        snapshot_check( address.data.ipv6[3] == 0x0000 );
        snapshot_check( address.data.ipv6[4] == 0x0000 );
        snapshot_check( address.data.ipv6[5] == 0x0000 );
        snapshot_check( address.data.ipv6[6] == 0x0000 );
        snapshot_check( address.data.ipv6[7] == 0x0000 );
    }

    {
        struct snapshot_address_t address;
        snapshot_check( snapshot_address_parse( &address, "::1" ) == SNAPSHOT_OK );
        snapshot_check( address.type == SNAPSHOT_ADDRESS_IPV6 );
        snapshot_check( address.port == 0 );
        snapshot_check( address.data.ipv6[0] == 0x0000 );
        snapshot_check( address.data.ipv6[1] == 0x0000 );
        snapshot_check( address.data.ipv6[2] == 0x0000 );
        snapshot_check( address.data.ipv6[3] == 0x0000 );
        snapshot_check( address.data.ipv6[4] == 0x0000 );
        snapshot_check( address.data.ipv6[5] == 0x0000 );
        snapshot_check( address.data.ipv6[6] == 0x0000 );
        snapshot_check( address.data.ipv6[7] == 0x0001 );
    }

    {
        struct snapshot_address_t address;
        snapshot_check( snapshot_address_parse( &address, "[fe80::202:b3ff:fe1e:8329]:40000" ) == SNAPSHOT_OK );
        snapshot_check( address.type == SNAPSHOT_ADDRESS_IPV6 );
        snapshot_check( address.port == 40000 );
        snapshot_check( address.data.ipv6[0] == 0xfe80 );
        snapshot_check( address.data.ipv6[1] == 0x0000 );
        snapshot_check( address.data.ipv6[2] == 0x0000 );
        snapshot_check( address.data.ipv6[3] == 0x0000 );
        snapshot_check( address.data.ipv6[4] == 0x0202 );
        snapshot_check( address.data.ipv6[5] == 0xb3ff );
        snapshot_check( address.data.ipv6[6] == 0xfe1e );
        snapshot_check( address.data.ipv6[7] == 0x8329 );
    }

    {
        struct snapshot_address_t address;
        snapshot_check( snapshot_address_parse( &address, "[::]:40000" ) == SNAPSHOT_OK );
        snapshot_check( address.type == SNAPSHOT_ADDRESS_IPV6 );
        snapshot_check( address.port == 40000 );
        snapshot_check( address.data.ipv6[0] == 0x0000 );
        snapshot_check( address.data.ipv6[1] == 0x0000 );
        snapshot_check( address.data.ipv6[2] == 0x0000 );
        snapshot_check( address.data.ipv6[3] == 0x0000 );
        snapshot_check( address.data.ipv6[4] == 0x0000 );
        snapshot_check( address.data.ipv6[5] == 0x0000 );
        snapshot_check( address.data.ipv6[6] == 0x0000 );
        snapshot_check( address.data.ipv6[7] == 0x0000 );
    }

    {
        struct snapshot_address_t address;
        snapshot_check( snapshot_address_parse( &address, "[::1]:40000" ) == SNAPSHOT_OK );
        snapshot_check( address.type == SNAPSHOT_ADDRESS_IPV6 );
        snapshot_check( address.port == 40000 );
        snapshot_check( address.data.ipv6[0] == 0x0000 );
        snapshot_check( address.data.ipv6[1] == 0x0000 );
        snapshot_check( address.data.ipv6[2] == 0x0000 );
        snapshot_check( address.data.ipv6[3] == 0x0000 );
        snapshot_check( address.data.ipv6[4] == 0x0000 );
        snapshot_check( address.data.ipv6[5] == 0x0000 );
        snapshot_check( address.data.ipv6[6] == 0x0000 );
        snapshot_check( address.data.ipv6[7] == 0x0001 );
    }
#endif // #if SNAPSHOT_PLATFORM_HAS_IPV6
}

void test_read_and_write()
{
    uint8_t buffer[1024];

    struct snapshot_address_t address_a, address_b, address_c;

    memset( &address_a, 0, sizeof(address_a) );
    memset( &address_b, 0, sizeof(address_b) );
    memset( &address_c, 0, sizeof(address_c) );

    snapshot_address_parse( &address_b, "127.0.0.1:50000" );

    snapshot_address_parse( &address_c, "[::1]:50000" );

    uint8_t * p = buffer;
    snapshot_write_uint8( &p, 105 );
    snapshot_write_uint16( &p, 10512 );
    snapshot_write_uint32( &p, 105120000 );
    snapshot_write_uint64( &p, 105120000000000000LL );
    snapshot_write_float32( &p, 100.0f );
    snapshot_write_float64( &p, 100000000000000.0 );
    snapshot_write_bytes( &p, (uint8_t*)"hello", 6 );
    snapshot_write_address( &p, &address_a );
    snapshot_write_address( &p, &address_b );
    snapshot_write_address( &p, &address_c );

    const uint8_t * q = buffer;

    uint8_t a = snapshot_read_uint8( &q );
    uint16_t b = snapshot_read_uint16( &q );
    uint32_t c = snapshot_read_uint32( &q );
    uint64_t d = snapshot_read_uint64( &q );
    float e = snapshot_read_float32( &q );
    double f = snapshot_read_float64( &q );
    uint8_t g[6];
    snapshot_read_bytes( &q, g, 6 );

    struct snapshot_address_t read_address_a, read_address_b, read_address_c;

    snapshot_read_address( &q, &read_address_a );
    snapshot_read_address( &q, &read_address_b );
    snapshot_read_address( &q, &read_address_c );

    snapshot_check( a == 105 );
    snapshot_check( b == 10512 );
    snapshot_check( c == 105120000 );
    snapshot_check( d == 105120000000000000LL );
    snapshot_check( e == 100.0f );
    snapshot_check( f == 100000000000000.0 );
    snapshot_check( memcmp( g, "hello", 6 ) == 0 );
    snapshot_check( snapshot_address_equal( &address_a, &read_address_a ) );
    snapshot_check( snapshot_address_equal( &address_b, &read_address_b ) );
    snapshot_check( snapshot_address_equal( &address_c, &read_address_c ) );
}

using namespace snapshot;

void test_bitpacker()
{
    const int BufferSize = 256;

    uint8_t buffer[BufferSize];

    BitWriter writer( buffer, BufferSize );

    snapshot_check( writer.GetData() == buffer );
    snapshot_check( writer.GetBitsWritten() == 0 );
    snapshot_check( writer.GetBytesWritten() == 0 );
    snapshot_check( writer.GetBitsAvailable() == BufferSize * 8 );

    writer.WriteBits( 0, 1 );
    writer.WriteBits( 1, 1 );
    writer.WriteBits( 10, 8 );
    writer.WriteBits( 255, 8 );
    writer.WriteBits( 1000, 10 );
    writer.WriteBits( 50000, 16 );
    writer.WriteBits( 9999999, 32 );
    writer.FlushBits();

    const int bitsWritten = 1 + 1 + 8 + 8 + 10 + 16 + 32;

    snapshot_check( writer.GetBytesWritten() == 10 );
    snapshot_check( writer.GetBitsWritten() == bitsWritten );
    snapshot_check( writer.GetBitsAvailable() == BufferSize * 8 - bitsWritten );

    const int bytesWritten = writer.GetBytesWritten();

    snapshot_check( bytesWritten == 10 );

    memset( buffer + bytesWritten, 0, size_t(BufferSize) - bytesWritten );

    BitReader reader( buffer, bytesWritten );

    snapshot_check( reader.GetBitsRead() == 0 );
    snapshot_check( reader.GetBitsRemaining() == bytesWritten * 8 );

    uint32_t a = reader.ReadBits( 1 );
    uint32_t b = reader.ReadBits( 1 );
    uint32_t c = reader.ReadBits( 8 );
    uint32_t d = reader.ReadBits( 8 );
    uint32_t e = reader.ReadBits( 10 );
    uint32_t f = reader.ReadBits( 16 );
    uint32_t g = reader.ReadBits( 32 );

    snapshot_check( a == 0 );
    snapshot_check( b == 1 );
    snapshot_check( c == 10 );
    snapshot_check( d == 255 );
    snapshot_check( e == 1000 );
    snapshot_check( f == 50000 );
    snapshot_check( g == 9999999 );

    snapshot_check( reader.GetBitsRead() == bitsWritten );
    snapshot_check( reader.GetBitsRemaining() == bytesWritten * 8 - bitsWritten );
}

void test_bits_required()
{
    snapshot_check( bits_required( 0, 0 ) == 0 );
    snapshot_check( bits_required( 0, 1 ) == 1 );
    snapshot_check( bits_required( 0, 2 ) == 2 );
    snapshot_check( bits_required( 0, 3 ) == 2 );
    snapshot_check( bits_required( 0, 4 ) == 3 );
    snapshot_check( bits_required( 0, 5 ) == 3 );
    snapshot_check( bits_required( 0, 6 ) == 3 );
    snapshot_check( bits_required( 0, 7 ) == 3 );
    snapshot_check( bits_required( 0, 8 ) == 4 );
    snapshot_check( bits_required( 0, 255 ) == 8 );
    snapshot_check( bits_required( 0, 65535 ) == 16 );
    snapshot_check( bits_required( 0, 4294967295U ) == 32 );
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
    snapshot_address_t address_a, address_b, address_c;
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

        memset( &data.address_a, 0, sizeof(snapshot_address_t) );

        snapshot_address_parse( &data.address_b, "127.0.0.1:50000" );

        snapshot_address_parse( &data.address_c, "[::1]:50000" );
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

    snapshot_check( readObject == writeObject );
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
        RUN_TEST( test_address );
        RUN_TEST( test_read_and_write );
        RUN_TEST( test_bitpacker );
        RUN_TEST( test_bits_required );
        RUN_TEST( test_stream );

        /*
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
