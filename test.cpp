/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"
#include "snapshot_crypto.h"
#include "snapshot_platform.h"
#include "snapshot_address.h"
#include "snapshot_read_write.h"
#include "snapshot_bitpacker.h"
#include "snapshot_stream.h"
#include "snapshot_serialize.h"
#include "snapshot_connect_token.h"
#include "snapshot_network_simulator.h"
#include "snapshot_client.h"
#include "snapshot_server.h"
#include "snapshot_connect_token.h"
#include "snapshot_challenge_token.h"
#include "snapshot_packets.h"
#include "snapshot_encryption_manager.h"
#include "snapshot_replay_protection.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

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

void test_crypto_random_bytes()
{
    const int BufferSize = 64;
    uint8_t buffer[BufferSize];
    snapshot_crypto_random_bytes( buffer, BufferSize );
    for ( int i = 0; i < 100; ++i )
    {
        uint8_t buffer2[BufferSize];
        snapshot_crypto_random_bytes( buffer2, BufferSize );
        snapshot_check( memcmp( buffer, buffer2, BufferSize ) != 0 );
        memcpy( buffer, buffer2, BufferSize );
    }
}

void test_crypto_box()
{
    #define CRYPTO_BOX_MESSAGE (const unsigned char *) "test"
    #define CRYPTO_BOX_MESSAGE_LEN 4
    #define CRYPTO_BOX_CIPHERTEXT_LEN ( SNAPSHOT_CRYPTO_BOX_MACBYTES + CRYPTO_BOX_MESSAGE_LEN )

    unsigned char sender_publickey[SNAPSHOT_CRYPTO_BOX_PUBLICKEYBYTES];
    unsigned char sender_secretkey[SNAPSHOT_CRYPTO_BOX_SECRETKEYBYTES];
    snapshot_crypto_box_keypair( sender_publickey, sender_secretkey );

    unsigned char receiver_publickey[SNAPSHOT_CRYPTO_BOX_PUBLICKEYBYTES];
    unsigned char receiver_secretkey[SNAPSHOT_CRYPTO_BOX_SECRETKEYBYTES];
    snapshot_crypto_box_keypair( receiver_publickey, receiver_secretkey );

    unsigned char nonce[SNAPSHOT_CRYPTO_BOX_NONCEBYTES];
    unsigned char ciphertext[CRYPTO_BOX_CIPHERTEXT_LEN];
    snapshot_crypto_random_bytes( nonce, sizeof nonce );
    snapshot_check( snapshot_crypto_box_easy( ciphertext, CRYPTO_BOX_MESSAGE, CRYPTO_BOX_MESSAGE_LEN, nonce, receiver_publickey, sender_secretkey ) == 0 );

    unsigned char decrypted[CRYPTO_BOX_MESSAGE_LEN];
    snapshot_check( snapshot_crypto_box_open_easy( decrypted, ciphertext, CRYPTO_BOX_CIPHERTEXT_LEN, nonce, sender_publickey, receiver_secretkey ) == 0 );

    snapshot_check( memcmp( decrypted, CRYPTO_BOX_MESSAGE, CRYPTO_BOX_MESSAGE_LEN ) == 0 );
}

void test_crypto_secret_box()
{
    #define CRYPTO_SECRET_BOX_MESSAGE ((const unsigned char *) "test")
    #define CRYPTO_SECRET_BOX_MESSAGE_LEN 4
    #define CRYPTO_SECRET_BOX_CIPHERTEXT_LEN (SNAPSHOT_CRYPTO_SECRETBOX_MACBYTES + CRYPTO_SECRET_BOX_MESSAGE_LEN)

    unsigned char key[SNAPSHOT_CRYPTO_SECRETBOX_KEYBYTES];
    unsigned char nonce[SNAPSHOT_CRYPTO_SECRETBOX_NONCEBYTES];
    unsigned char ciphertext[CRYPTO_SECRET_BOX_CIPHERTEXT_LEN];

    snapshot_crypto_secretbox_keygen( key );
    snapshot_crypto_random_bytes( nonce, SNAPSHOT_CRYPTO_SECRETBOX_NONCEBYTES );
    snapshot_crypto_secretbox_easy( ciphertext, CRYPTO_SECRET_BOX_MESSAGE, CRYPTO_SECRET_BOX_MESSAGE_LEN, nonce, key );

    unsigned char decrypted[CRYPTO_SECRET_BOX_MESSAGE_LEN];
    snapshot_check( snapshot_crypto_secretbox_open_easy( decrypted, ciphertext, CRYPTO_SECRET_BOX_CIPHERTEXT_LEN, nonce, key ) == 0 );
}

void test_crypto_aead()
{
    #define CRYPTO_AEAD_MESSAGE (const unsigned char *) "test"
    #define CRYPTO_AEAD_MESSAGE_LEN 4
    #define CRYPTO_AEAD_ADDITIONAL_DATA (const unsigned char *) "123456"
    #define CRYPTO_AEAD_ADDITIONAL_DATA_LEN 6

    unsigned char nonce[SNAPSHOT_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES];
    unsigned char key[SNAPSHOT_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
    unsigned char ciphertext[CRYPTO_AEAD_MESSAGE_LEN + SNAPSHOT_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES];
    unsigned long long ciphertext_len;

    snapshot_crypto_aead_chacha20poly1305_keygen( key );
    snapshot_crypto_random_bytes( nonce, sizeof(nonce) );

    snapshot_crypto_aead_chacha20poly1305_encrypt( ciphertext, &ciphertext_len,
                                                   CRYPTO_AEAD_MESSAGE, CRYPTO_AEAD_MESSAGE_LEN,
                                                   CRYPTO_AEAD_ADDITIONAL_DATA, CRYPTO_AEAD_ADDITIONAL_DATA_LEN,
                                                   NULL, nonce, key );

    unsigned char decrypted[CRYPTO_AEAD_MESSAGE_LEN];
    unsigned long long decrypted_len;
    snapshot_check( snapshot_crypto_aead_chacha20poly1305_decrypt( decrypted, &decrypted_len,
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

    unsigned char nonce[SNAPSHOT_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES];
    unsigned char key[SNAPSHOT_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES];
    unsigned char ciphertext[CRYPTO_AEAD_IETF_MESSAGE_LEN + SNAPSHOT_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];
    unsigned long long ciphertext_len;

    snapshot_crypto_aead_chacha20poly1305_ietf_keygen( key );
    snapshot_crypto_random_bytes( nonce, sizeof(nonce) );

    snapshot_crypto_aead_chacha20poly1305_ietf_encrypt( ciphertext, &ciphertext_len, CRYPTO_AEAD_IETF_MESSAGE, CRYPTO_AEAD_IETF_MESSAGE_LEN, CRYPTO_AEAD_IETF_ADDITIONAL_DATA, CRYPTO_AEAD_IETF_ADDITIONAL_DATA_LEN, NULL, nonce, key);

    unsigned char decrypted[CRYPTO_AEAD_IETF_MESSAGE_LEN];
    unsigned long long decrypted_len;
    snapshot_check( snapshot_crypto_aead_chacha20poly1305_ietf_decrypt( decrypted, &decrypted_len, NULL, ciphertext, ciphertext_len, CRYPTO_AEAD_IETF_ADDITIONAL_DATA, CRYPTO_AEAD_IETF_ADDITIONAL_DATA_LEN, nonce, key ) == 0 );
}

void test_crypto_sign_detached()
{
    #define MESSAGE_PART1 ((const unsigned char *) "Arbitrary data to hash")
    #define MESSAGE_PART1_LEN 22

    #define MESSAGE_PART2 ((const unsigned char *) "is longer than expected")
    #define MESSAGE_PART2_LEN 23

    unsigned char public_key[SNAPSHOT_CRYPTO_SIGN_PUBLICKEYBYTES];
    unsigned char private_key[SNAPSHOT_CRYPTO_SIGN_SECRETKEYBYTES];
    snapshot_crypto_sign_keypair( public_key, private_key );

    snapshot_crypto_sign_state_t state;

    unsigned char signature[SNAPSHOT_CRYPTO_SIGN_BYTES];

    snapshot_crypto_sign_init( &state );
    snapshot_crypto_sign_update( &state, MESSAGE_PART1, MESSAGE_PART1_LEN );
    snapshot_crypto_sign_update( &state, MESSAGE_PART2, MESSAGE_PART2_LEN );
    snapshot_crypto_sign_final_create( &state, signature, NULL, private_key );

    snapshot_crypto_sign_init( &state );
    snapshot_crypto_sign_update( &state, MESSAGE_PART1, MESSAGE_PART1_LEN );
    snapshot_crypto_sign_update( &state, MESSAGE_PART2, MESSAGE_PART2_LEN );
    snapshot_check( snapshot_crypto_sign_final_verify( &state, signature, public_key ) == 0 );
}

void test_crypto_key_exchange()
{
    uint8_t client_public_key[SNAPSHOT_CRYPTO_KX_PUBLICKEYBYTES];
    uint8_t client_private_key[SNAPSHOT_CRYPTO_KX_SECRETKEYBYTES];
    snapshot_crypto_kx_keypair( client_public_key, client_private_key );

    uint8_t server_public_key[SNAPSHOT_CRYPTO_KX_PUBLICKEYBYTES];
    uint8_t server_private_key[SNAPSHOT_CRYPTO_KX_SECRETKEYBYTES];
    snapshot_crypto_kx_keypair( server_public_key, server_private_key );

    uint8_t client_send_key[SNAPSHOT_CRYPTO_KX_SESSIONKEYBYTES];
    uint8_t client_receive_key[SNAPSHOT_CRYPTO_KX_SESSIONKEYBYTES];
    snapshot_check( snapshot_crypto_kx_client_session_keys( client_receive_key, client_send_key, client_public_key, client_private_key, server_public_key ) == 0 );

    uint8_t server_send_key[SNAPSHOT_CRYPTO_KX_SESSIONKEYBYTES];
    uint8_t server_receive_key[SNAPSHOT_CRYPTO_KX_SESSIONKEYBYTES];
    snapshot_check( snapshot_crypto_kx_server_session_keys( server_receive_key, server_send_key, server_public_key, server_private_key, client_public_key ) == 0 );

    snapshot_check( memcmp( client_send_key, server_receive_key, SNAPSHOT_CRYPTO_KX_SESSIONKEYBYTES ) == 0 );
    snapshot_check( memcmp( server_send_key, client_receive_key, SNAPSHOT_CRYPTO_KX_SESSIONKEYBYTES ) == 0 );
}

void test_platform_socket()
{
    // non-blocking socket (ipv4)
    {
        snapshot_address_t bind_address;
        snapshot_address_t local_address;
        snapshot_address_parse( &bind_address, "0.0.0.0" );
        snapshot_address_parse( &local_address, "127.0.0.1" );
        snapshot_platform_socket_t * socket = snapshot_platform_socket_create( NULL, &bind_address, SNAPSHOT_PLATFORM_SOCKET_NON_BLOCKING, 0, 64*1024, 64*1024 );
        local_address.port = bind_address.port;
        snapshot_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        snapshot_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        snapshot_address_t from;
        while ( snapshot_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) ) )
        {
            snapshot_check( snapshot_address_equal( &from, &local_address ) );
        }
        snapshot_platform_socket_destroy( socket );
    }

    // blocking socket with timeout (ipv4)
    {
        snapshot_address_t bind_address;
        snapshot_address_t local_address;
        snapshot_address_parse( &bind_address, "0.0.0.0" );
        snapshot_address_parse( &local_address, "127.0.0.1" );
        snapshot_platform_socket_t * socket = snapshot_platform_socket_create( NULL, &bind_address, SNAPSHOT_PLATFORM_SOCKET_BLOCKING, 0.01f, 64*1024, 64*1024 );
        local_address.port = bind_address.port;
        snapshot_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        snapshot_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        snapshot_address_t from;
        while ( snapshot_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) ) )
        {
            snapshot_check( snapshot_address_equal( &from, &local_address ) );
        }
        snapshot_platform_socket_destroy( socket );
    }

    // blocking socket with no timeout (ipv4)
    {
        snapshot_address_t bind_address;
        snapshot_address_t local_address;
        snapshot_address_parse( &bind_address, "0.0.0.0" );
        snapshot_address_parse( &local_address, "127.0.0.1" );
        snapshot_platform_socket_t * socket = snapshot_platform_socket_create( NULL, &bind_address, SNAPSHOT_PLATFORM_SOCKET_BLOCKING, -1.0f, 64*1024, 64*1024 );
        local_address.port = bind_address.port;
        snapshot_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        snapshot_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        snapshot_address_t from;
        snapshot_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) );
        snapshot_check( snapshot_address_equal( &from, &local_address ) );
        snapshot_platform_socket_destroy( socket );
    }

#if NEXT_PLATFORM_HAS_IPV6

    // non-blocking socket (ipv6)
    {
        snapshot_address_t bind_address;
        snapshot_address_t local_address;
        snapshot_address_parse( &bind_address, "[::]" );
        snapshot_address_parse( &local_address, "[::1]" );
        snapshot_platform_socket_t * socket = snapshot_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0, 64*1024, 64*1024, true );
        local_address.port = bind_address.port;
        snapshot_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        snapshot_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        snapshot_address_t from;
        while ( snapshot_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) ) )
        {
            snapshot_check( snapshot_address_equal( &from, &local_address ) );
        }
        snapshot_platform_socket_destroy( socket );
    }

    // blocking socket with timeout (ipv6)
    {
        snapshot_address_t bind_address;
        snapshot_address_t local_address;
        snapshot_address_parse( &bind_address, "[::]" );
        snapshot_address_parse( &local_address, "[::1]" );
        snapshot_platform_socket_t * socket = snapshot_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_BLOCKING, 0.01f, 64*1024, 64*1024, true );
        local_address.port = bind_address.port;
        snapshot_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        snapshot_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        snapshot_address_t from;
        while ( snapshot_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) ) )
        {
            snapshot_check( snapshot_address_equal( &from, &local_address ) );
        }
        snapshot_platform_socket_destroy( socket );
    }

    // blocking socket with no timeout (ipv6)
    {
        snapshot_address_t bind_address;
        snapshot_address_t local_address;
        snapshot_address_parse( &bind_address, "[::]" );
        snapshot_address_parse( &local_address, "[::1]" );
        snapshot_platform_socket_t * socket = snapshot_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_BLOCKING, -1.0f, 64*1024, 64*1024, true );
        local_address.port = bind_address.port;
        snapshot_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        snapshot_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        snapshot_address_t from;
        snapshot_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) );
        snapshot_check( snapshot_address_equal( &from, &local_address ) );
        snapshot_platform_socket_destroy( socket );
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
    snapshot_platform_thread_t * thread = snapshot_platform_thread_create( NULL, test_thread_function, NULL );
    snapshot_check( thread );
    snapshot_platform_thread_join( thread );
    snapshot_platform_thread_destroy( thread );
    snapshot_check( threads_work );
}

void test_platform_mutex()
{
    snapshot_platform_mutex_t mutex;
    int result = snapshot_platform_mutex_create( &mutex );
    snapshot_check( result == SNAPSHOT_OK );
    snapshot_platform_mutex_acquire( &mutex );
    snapshot_platform_mutex_release( &mutex );
    {
        snapshot_platform_mutex_guard( &mutex );
        // ...
    }
    snapshot_platform_mutex_destroy( &mutex );
}

void test_sequence()
{
    snapshot_check( snapshot_sequence_number_bytes_required( 0 ) == 1 );
    snapshot_check( snapshot_sequence_number_bytes_required( 0x11 ) == 1 );
    snapshot_check( snapshot_sequence_number_bytes_required( 0x1122 ) == 2 );
    snapshot_check( snapshot_sequence_number_bytes_required( 0x112233 ) == 3 );
    snapshot_check( snapshot_sequence_number_bytes_required( 0x11223344 ) == 4 );
    snapshot_check( snapshot_sequence_number_bytes_required( 0x1122334455 ) == 5 );
    snapshot_check( snapshot_sequence_number_bytes_required( 0x112233445566 ) == 6 );
    snapshot_check( snapshot_sequence_number_bytes_required( 0x11223344556677 ) == 7 );
    snapshot_check( snapshot_sequence_number_bytes_required( 0x1122334455667788 ) == 8 );
}

#define TEST_PROTOCOL_ID            0x1122334455667788ULL
#define TEST_CLIENT_ID              0x1ULL
#define TEST_SERVER_PORT            40000
#define TEST_CONNECT_TOKEN_EXPIRY   30
#define TEST_TIMEOUT_SECONDS        15

void test_connect_token_private()
{
    // generate a private connect token

    struct snapshot_address_t server_address;
    server_address.type = SNAPSHOT_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes( user_data, SNAPSHOT_USER_DATA_BYTES );

    struct snapshot_connect_token_private_t input_token;

    snapshot_generate_connect_token_private( &input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, &server_address, user_data );

    snapshot_check( input_token.client_id == TEST_CLIENT_ID );
    snapshot_check( input_token.num_server_addresses == 1 );
    snapshot_check( memcmp( input_token.user_data, user_data, SNAPSHOT_USER_DATA_BYTES ) == 0 );
    snapshot_check( snapshot_address_equal( &input_token.server_addresses[0], &server_address ) );

    // write it to a buffer

    uint8_t buffer[SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES];

    snapshot_write_connect_token_private( &input_token, buffer, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

    // encrypt the buffer

    uint64_t expire_timestamp = time( NULL ) + 30;
    uint8_t nonce[SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES];
    snapshot_crypto_random_bytes( nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );
    
    uint8_t key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( key, SNAPSHOT_KEY_BYTES );    

    snapshot_check( snapshot_encrypt_connect_token_private( buffer, 
                                                            SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES, 
                                                            SNAPSHOT_VERSION_INFO, 
                                                            TEST_PROTOCOL_ID, 
                                                            expire_timestamp, 
                                                            nonce, 
                                                            key ) == SNAPSHOT_OK );

    // decrypt the buffer

    snapshot_check( snapshot_decrypt_connect_token_private( buffer,
                                                            SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES, 
                                                            SNAPSHOT_VERSION_INFO, 
                                                            TEST_PROTOCOL_ID, 
                                                            expire_timestamp, 
                                                            nonce, 
                                                            key ) == SNAPSHOT_OK );

    // read the connect token back in

    struct snapshot_connect_token_private_t output_token;

    snapshot_check( snapshot_read_connect_token_private( buffer, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES, &output_token ) == SNAPSHOT_OK );

    // make sure that everything matches the original connect token

    snapshot_check( output_token.client_id == input_token.client_id );
    snapshot_check( output_token.timeout_seconds == input_token.timeout_seconds );
    snapshot_check( output_token.num_server_addresses == input_token.num_server_addresses );
    snapshot_check( snapshot_address_equal( &output_token.server_addresses[0], &input_token.server_addresses[0] ) );
    snapshot_check( memcmp( output_token.client_to_server_key, input_token.client_to_server_key, SNAPSHOT_KEY_BYTES ) == 0 );
    snapshot_check( memcmp( output_token.server_to_client_key, input_token.server_to_client_key, SNAPSHOT_KEY_BYTES ) == 0 );
    snapshot_check( memcmp( output_token.user_data, input_token.user_data, SNAPSHOT_USER_DATA_BYTES ) == 0 );
}

void test_connect_token_public()
{
    // generate a private connect token

    struct snapshot_address_t server_address;
    server_address.type = SNAPSHOT_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes( user_data, SNAPSHOT_USER_DATA_BYTES );

    struct snapshot_connect_token_private_t connect_token_private;

    snapshot_generate_connect_token_private( &connect_token_private, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, &server_address, user_data );

    snapshot_check( connect_token_private.client_id == TEST_CLIENT_ID );
    snapshot_check( connect_token_private.num_server_addresses == 1 );
    snapshot_check( memcmp( connect_token_private.user_data, user_data, SNAPSHOT_USER_DATA_BYTES ) == 0 );
    snapshot_check( snapshot_address_equal( &connect_token_private.server_addresses[0], &server_address ) );

    // write it to a buffer

    uint8_t connect_token_private_data[SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES];
    snapshot_write_connect_token_private( &connect_token_private, connect_token_private_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

    // encrypt the buffer

    uint64_t create_timestamp = time( NULL );
    uint64_t expire_timestamp = create_timestamp + 30;
    uint8_t connect_token_nonce[SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES];
    snapshot_crypto_random_bytes( connect_token_nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );
    uint8_t key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( key, SNAPSHOT_KEY_BYTES );
    snapshot_check( snapshot_encrypt_connect_token_private( connect_token_private_data, 
                                                            SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES, 
                                                            SNAPSHOT_VERSION_INFO, 
                                                            TEST_PROTOCOL_ID, 
                                                            expire_timestamp, 
                                                            connect_token_nonce, 
                                                            key ) == SNAPSHOT_OK );

    // wrap a public connect token around the private connect token data

    struct snapshot_connect_token_t input_connect_token;
    memset( &input_connect_token, 0, sizeof( struct snapshot_connect_token_t ) );
    memcpy( input_connect_token.version_info, SNAPSHOT_VERSION_INFO, SNAPSHOT_VERSION_INFO_BYTES );
    input_connect_token.protocol_id = TEST_PROTOCOL_ID;
    input_connect_token.create_timestamp = create_timestamp;
    input_connect_token.expire_timestamp = expire_timestamp;
    memcpy( input_connect_token.nonce, connect_token_nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );
    memcpy( input_connect_token.private_data, connect_token_private_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );
    input_connect_token.num_server_addresses = 1;
    input_connect_token.server_addresses[0] = server_address;
    memcpy( input_connect_token.client_to_server_key, connect_token_private.client_to_server_key, SNAPSHOT_KEY_BYTES );
    memcpy( input_connect_token.server_to_client_key, connect_token_private.server_to_client_key, SNAPSHOT_KEY_BYTES );
    input_connect_token.timeout_seconds = (int) TEST_TIMEOUT_SECONDS;

    // write the connect token to a buffer

    uint8_t buffer[SNAPSHOT_CONNECT_TOKEN_BYTES];
    snapshot_write_connect_token( &input_connect_token, buffer, SNAPSHOT_CONNECT_TOKEN_BYTES );

    // read the buffer back in

    struct snapshot_connect_token_t output_connect_token;
    memset( &output_connect_token, 0, sizeof( struct snapshot_connect_token_t ) );
    snapshot_check( snapshot_read_connect_token( buffer, SNAPSHOT_CONNECT_TOKEN_BYTES, &output_connect_token ) == SNAPSHOT_OK );

    // make sure the public connect token matches what was written

    snapshot_check( memcmp( output_connect_token.version_info, input_connect_token.version_info, SNAPSHOT_VERSION_INFO_BYTES ) == 0 );
    snapshot_check( output_connect_token.protocol_id == input_connect_token.protocol_id );
    snapshot_check( output_connect_token.create_timestamp == input_connect_token.create_timestamp );
    snapshot_check( output_connect_token.expire_timestamp == input_connect_token.expire_timestamp );
    snapshot_check( memcmp( output_connect_token.nonce, input_connect_token.nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES ) == 0 );
    snapshot_check( memcmp( output_connect_token.private_data, input_connect_token.private_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES ) == 0 );
    snapshot_check( output_connect_token.num_server_addresses == input_connect_token.num_server_addresses );
    snapshot_check( snapshot_address_equal( &output_connect_token.server_addresses[0], &input_connect_token.server_addresses[0] ) );
    snapshot_check( memcmp( output_connect_token.client_to_server_key, input_connect_token.client_to_server_key, SNAPSHOT_KEY_BYTES ) == 0 );
    snapshot_check( memcmp( output_connect_token.server_to_client_key, input_connect_token.server_to_client_key, SNAPSHOT_KEY_BYTES ) == 0 );
    snapshot_check( output_connect_token.timeout_seconds == input_connect_token.timeout_seconds );
}

void test_challenge_token()
{
    // generate a challenge token

    struct snapshot_challenge_token_t input_token;

    input_token.client_id = TEST_CLIENT_ID;
    snapshot_crypto_random_bytes( input_token.user_data, SNAPSHOT_USER_DATA_BYTES );

    // write it to a buffer

    uint8_t buffer[SNAPSHOT_CHALLENGE_TOKEN_BYTES];

    snapshot_write_challenge_token( &input_token, buffer, SNAPSHOT_CHALLENGE_TOKEN_BYTES );

    // encrypt the buffer

    uint64_t sequence = 1000;
    uint8_t key[SNAPSHOT_KEY_BYTES]; 
    snapshot_crypto_random_bytes( key, SNAPSHOT_KEY_BYTES );

    snapshot_check( snapshot_encrypt_challenge_token( buffer, SNAPSHOT_CHALLENGE_TOKEN_BYTES, sequence, key ) == SNAPSHOT_OK );

    // decrypt the buffer

    snapshot_check( snapshot_decrypt_challenge_token( buffer, SNAPSHOT_CHALLENGE_TOKEN_BYTES, sequence, key ) == SNAPSHOT_OK );

    // read the challenge token back in

    struct snapshot_challenge_token_t output_token;

    snapshot_check( snapshot_read_challenge_token( buffer, SNAPSHOT_CHALLENGE_TOKEN_BYTES, &output_token ) == SNAPSHOT_OK );

    // make sure that everything matches the original challenge token

    snapshot_check( output_token.client_id == input_token.client_id );
    snapshot_check( memcmp( output_token.user_data, input_token.user_data, SNAPSHOT_USER_DATA_BYTES ) == 0 );
}

void test_connection_request_packet()
{
    // generate a connect token

    struct snapshot_address_t server_address;
    server_address.type = SNAPSHOT_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes( user_data, SNAPSHOT_USER_DATA_BYTES );

    struct snapshot_connect_token_private_t input_token;

    snapshot_generate_connect_token_private( &input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, &server_address, user_data );

    snapshot_check( input_token.client_id == TEST_CLIENT_ID );
    snapshot_check( input_token.num_server_addresses == 1 );
    snapshot_check( memcmp( input_token.user_data, user_data, SNAPSHOT_USER_DATA_BYTES ) == 0 );
    snapshot_check( snapshot_address_equal( &input_token.server_addresses[0], &server_address ) );

    // write the conect token to a buffer (non-encrypted)

    uint8_t connect_token_data[SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES];

    snapshot_write_connect_token_private( &input_token, connect_token_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

    // copy to a second buffer then encrypt it in place (we need the unencrypted token for verification later on)

    uint8_t encrypted_connect_token_data[SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES];

    memcpy( encrypted_connect_token_data, connect_token_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

    uint64_t connect_token_expire_timestamp = time( NULL ) + 30;
    uint8_t connect_token_nonce[SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES];
    snapshot_crypto_random_bytes( connect_token_nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );
    uint8_t connect_token_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( connect_token_key, SNAPSHOT_KEY_BYTES );

    snapshot_check( snapshot_encrypt_connect_token_private( encrypted_connect_token_data, 
                                                   SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES, 
                                                   SNAPSHOT_VERSION_INFO, 
                                                   TEST_PROTOCOL_ID, 
                                                   connect_token_expire_timestamp, 
                                                   connect_token_nonce, 
                                                   connect_token_key ) == SNAPSHOT_OK );

    // setup a connection request packet wrapping the encrypted connect token

    struct snapshot_connection_request_packet_t input_packet;

    input_packet.packet_type = SNAPSHOT_CONNECTION_REQUEST_PACKET;
    memcpy( input_packet.version_info, SNAPSHOT_VERSION_INFO, SNAPSHOT_VERSION_INFO_BYTES );
    input_packet.protocol_id = TEST_PROTOCOL_ID;
    input_packet.connect_token_expire_timestamp = connect_token_expire_timestamp;
    memcpy( input_packet.connect_token_nonce, connect_token_nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES );
    memcpy( input_packet.connect_token_data, encrypted_connect_token_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES );

    // write the connection request packet to a buffer

    uint8_t buffer[2048];

    uint8_t packet_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( packet_key, SNAPSHOT_KEY_BYTES );

    int bytes_written = snapshot_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, packet_key, TEST_PROTOCOL_ID );

    snapshot_check( bytes_written > 0 );

    // read the connection request packet back in from the buffer (the connect token data is decrypted as part of the read packet validation)

    uint64_t sequence = 1000;

    uint8_t allowed_packets[SNAPSHOT_CONNECTION_NUM_PACKETS];
    memset( allowed_packets, 1, sizeof( allowed_packets ) );

    uint8_t out_packet_data[1024];

    struct snapshot_connection_request_packet_t * output_packet = (struct snapshot_connection_request_packet_t*) snapshot_read_packet( buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time( NULL ), connect_token_key, allowed_packets, out_packet_data, NULL );

    snapshot_check( output_packet );

    // make sure the read packet matches what was written
    
    snapshot_check( output_packet->packet_type == SNAPSHOT_CONNECTION_REQUEST_PACKET );
    snapshot_check( memcmp( output_packet->version_info, input_packet.version_info, SNAPSHOT_VERSION_INFO_BYTES ) == 0 );
    snapshot_check( output_packet->protocol_id == input_packet.protocol_id );
    snapshot_check( output_packet->connect_token_expire_timestamp == input_packet.connect_token_expire_timestamp );
    snapshot_check( memcmp( output_packet->connect_token_nonce, input_packet.connect_token_nonce, SNAPSHOT_CONNECT_TOKEN_NONCE_BYTES ) == 0 );
    snapshot_check( memcmp( output_packet->connect_token_data, connect_token_data, SNAPSHOT_CONNECT_TOKEN_PRIVATE_BYTES - SNAPSHOT_MAC_BYTES ) == 0 );
}

void test_connection_denied_packet()
{
    // setup a connection denied packet

    struct snapshot_connection_denied_packet_t input_packet;

    input_packet.packet_type = SNAPSHOT_CONNECTION_DENIED_PACKET;

    // write the packet to a buffer

    uint8_t buffer[SNAPSHOT_MAX_PACKET_BYTES];

    uint8_t packet_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( packet_key, SNAPSHOT_KEY_BYTES );

    int bytes_written = snapshot_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, packet_key, TEST_PROTOCOL_ID );

    snapshot_check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[SNAPSHOT_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    uint8_t out_packet_data[1024];

    struct snapshot_connection_denied_packet_t * output_packet = (struct snapshot_connection_denied_packet_t*) snapshot_read_packet( buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time( NULL ), NULL, allowed_packet_types, out_packet_data, NULL );

    snapshot_check( output_packet );

    // make sure the read packet matches what was written
    
    snapshot_check( output_packet->packet_type == SNAPSHOT_CONNECTION_DENIED_PACKET );
}

void test_connection_challenge_packet()
{
    // setup a connection challenge packet

    struct snapshot_connection_challenge_packet_t input_packet;

    input_packet.packet_type = SNAPSHOT_CONNECTION_CHALLENGE_PACKET;
    input_packet.challenge_token_sequence = 0;
    snapshot_crypto_random_bytes( input_packet.challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES );

    // write the packet to a buffer

    uint8_t buffer[SNAPSHOT_MAX_PACKET_BYTES];

    uint8_t packet_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( packet_key, SNAPSHOT_KEY_BYTES );

    int bytes_written = snapshot_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, packet_key, TEST_PROTOCOL_ID );

    snapshot_check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[SNAPSHOT_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    uint8_t out_packet_data[1024];

    struct snapshot_connection_challenge_packet_t * output_packet = (struct snapshot_connection_challenge_packet_t*) snapshot_read_packet( buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time( NULL ), NULL, allowed_packet_types, out_packet_data, NULL );

    snapshot_check( output_packet );

    // make sure the read packet packet matches what was written
    
    snapshot_check( output_packet->packet_type == SNAPSHOT_CONNECTION_CHALLENGE_PACKET );
    snapshot_check( output_packet->challenge_token_sequence == input_packet.challenge_token_sequence );
    snapshot_check( memcmp( output_packet->challenge_token_data, input_packet.challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES ) == 0 );
}

void test_connection_response_packet()
{
    // setup a connection response packet

    struct snapshot_connection_response_packet_t input_packet;

    input_packet.packet_type = SNAPSHOT_CONNECTION_RESPONSE_PACKET;
    input_packet.challenge_token_sequence = 0;
    snapshot_crypto_random_bytes( input_packet.challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES );

    // write the packet to a buffer

    uint8_t buffer[SNAPSHOT_MAX_PACKET_BYTES];

    uint8_t packet_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( packet_key, SNAPSHOT_KEY_BYTES );
    
    int bytes_written = snapshot_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, packet_key, TEST_PROTOCOL_ID );

    snapshot_check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[SNAPSHOT_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    uint8_t out_packet_data[1024];

    struct snapshot_connection_response_packet_t * output_packet = (struct snapshot_connection_response_packet_t*) snapshot_read_packet( buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time( NULL ), NULL, allowed_packet_types, out_packet_data, NULL );

    snapshot_check( output_packet );

    // make sure the read packet matches what was written
    
    snapshot_check( output_packet->packet_type == SNAPSHOT_CONNECTION_RESPONSE_PACKET );
    snapshot_check( output_packet->challenge_token_sequence == input_packet.challenge_token_sequence );
    snapshot_check( memcmp( output_packet->challenge_token_data, input_packet.challenge_token_data, SNAPSHOT_CHALLENGE_TOKEN_BYTES ) == 0 );
}

void test_connection_keep_alive_packet()
{
    // setup a connection keep alive packet

    struct snapshot_connection_keep_alive_packet_t input_packet;

    input_packet.packet_type = SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET;
    input_packet.client_index = 10;
    input_packet.max_clients = 16;

    // write the packet to a buffer

    uint8_t buffer[SNAPSHOT_MAX_PACKET_BYTES];

    uint8_t packet_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( packet_key, SNAPSHOT_KEY_BYTES );

    int bytes_written = snapshot_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, packet_key, TEST_PROTOCOL_ID );

    snapshot_check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[SNAPSHOT_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    uint8_t out_packet_data[1024];
    
    struct snapshot_connection_keep_alive_packet_t * output_packet = (struct snapshot_connection_keep_alive_packet_t*) snapshot_read_packet( buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time( NULL ), NULL, allowed_packet_types, out_packet_data, NULL );

    snapshot_check( output_packet );

    // make sure the read packet matches what was written
    
    snapshot_check( output_packet->packet_type == SNAPSHOT_CONNECTION_KEEP_ALIVE_PACKET );
    snapshot_check( output_packet->client_index == input_packet.client_index );
    snapshot_check( output_packet->max_clients == input_packet.max_clients );
}

void test_connection_payload_packet()
{
    // setup a connection payload packet

    struct snapshot_connection_payload_packet_t * input_packet = snapshot_create_payload_packet( NULL, SNAPSHOT_MAX_PAYLOAD_BYTES );

    snapshot_check( input_packet->packet_type == SNAPSHOT_CONNECTION_PAYLOAD_PACKET );
    snapshot_check( input_packet->payload_bytes == SNAPSHOT_MAX_PAYLOAD_BYTES );

    snapshot_crypto_random_bytes( input_packet->payload_data, SNAPSHOT_MAX_PAYLOAD_BYTES );
    
    // write the packet to a buffer

    uint8_t buffer[SNAPSHOT_MAX_PACKET_BYTES];

    uint8_t packet_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( packet_key, SNAPSHOT_KEY_BYTES );

    int bytes_written = snapshot_write_packet( input_packet, buffer, sizeof( buffer ), 1000, packet_key, TEST_PROTOCOL_ID );

    snapshot_check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[SNAPSHOT_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    uint8_t out_packet_data[1024];

    struct snapshot_connection_payload_packet_t * output_packet = (struct snapshot_connection_payload_packet_t*) snapshot_read_packet( buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time( NULL ), NULL, allowed_packet_types, out_packet_data, NULL );

    snapshot_check( output_packet );

    // make sure the read packet matches what was written
    
    snapshot_check( output_packet->packet_type == SNAPSHOT_CONNECTION_PAYLOAD_PACKET );
    snapshot_check( output_packet->payload_bytes == input_packet->payload_bytes );
    snapshot_check( memcmp( output_packet->payload_data, input_packet->payload_data, SNAPSHOT_MAX_PAYLOAD_BYTES ) == 0 );

    snapshot_destroy_payload_packet( NULL, input_packet );
}

void test_connection_disconnect_packet()
{
    // setup a connection disconnect packet

    struct snapshot_connection_disconnect_packet_t input_packet;

    input_packet.packet_type = SNAPSHOT_CONNECTION_DISCONNECT_PACKET;

    // write the packet to a buffer

    uint8_t buffer[SNAPSHOT_MAX_PACKET_BYTES];

    uint8_t packet_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( packet_key, SNAPSHOT_KEY_BYTES );

    int bytes_written = snapshot_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, packet_key, TEST_PROTOCOL_ID );

    snapshot_check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[SNAPSHOT_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    uint8_t out_packet_data[1024];

    struct snapshot_connection_disconnect_packet_t * output_packet = (struct snapshot_connection_disconnect_packet_t*) snapshot_read_packet( buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time( NULL ), NULL, allowed_packet_types, out_packet_data, NULL );

    snapshot_check( output_packet );

    // make sure the read packet matches what was written
    
    snapshot_check( output_packet->packet_type == SNAPSHOT_CONNECTION_DISCONNECT_PACKET );
}

void test_encryption_manager()
{
    struct snapshot_encryption_manager_t encryption_manager;

    snapshot_encryption_manager_reset( &encryption_manager );

    double time = 100.0;

    // generate some test encryption mappings

    struct encryption_mapping_t
    {
        struct snapshot_address_t address;
        uint8_t send_key[SNAPSHOT_KEY_BYTES];
        uint8_t receive_key[SNAPSHOT_KEY_BYTES];
    };

    #define NUM_ENCRYPTION_MAPPINGS 5

    struct encryption_mapping_t encryption_mapping[NUM_ENCRYPTION_MAPPINGS];
    memset( encryption_mapping, 0, sizeof( encryption_mapping ) );
    int i;
    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i )
    {
        encryption_mapping[i].address.type = SNAPSHOT_ADDRESS_IPV6;
        encryption_mapping[i].address.data.ipv6[7] = 1;
        encryption_mapping[i].address.port = ( uint16_t) ( 20000 + i );
        snapshot_crypto_random_bytes( encryption_mapping[i].send_key, SNAPSHOT_KEY_BYTES );
        snapshot_crypto_random_bytes( encryption_mapping[i].receive_key, SNAPSHOT_KEY_BYTES );
    }

    // add the encryption mappings to the manager and make sure they can be looked up by address

    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i )
    {
        int encryption_index = snapshot_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        snapshot_check( encryption_index == -1 );

        snapshot_check( snapshot_encryption_manager_get_send_key( &encryption_manager, encryption_index ) == NULL );
        snapshot_check( snapshot_encryption_manager_get_receive_key( &encryption_manager, encryption_index ) == NULL );

        snapshot_check( snapshot_encryption_manager_add_encryption_mapping( &encryption_manager, 
                                                                  &encryption_mapping[i].address, 
                                                                  encryption_mapping[i].send_key, 
                                                                  encryption_mapping[i].receive_key, 
                                                                  time, 
                                                                  -1.0,
                                                                  TEST_TIMEOUT_SECONDS ) );

        encryption_index = snapshot_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        uint8_t * send_key = snapshot_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        uint8_t * receive_key = snapshot_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        snapshot_check( send_key );
        snapshot_check( receive_key );

        snapshot_check( memcmp( send_key, encryption_mapping[i].send_key, SNAPSHOT_KEY_BYTES ) == 0 );
        snapshot_check( memcmp( receive_key, encryption_mapping[i].receive_key, SNAPSHOT_KEY_BYTES ) == 0 );
    }

    // removing an encryption mapping that doesn't exist should return 0
    {
        struct snapshot_address_t address;
        address.type = SNAPSHOT_ADDRESS_IPV6;
        address.data.ipv6[7] = 1;
        address.port = 50000;

        snapshot_check( snapshot_encryption_manager_remove_encryption_mapping( &encryption_manager, &address, time ) == 0 );
    }

    // remove the first and last encryption mappings

    snapshot_check( snapshot_encryption_manager_remove_encryption_mapping( &encryption_manager, &encryption_mapping[0].address, time ) == 1 );

    snapshot_check( snapshot_encryption_manager_remove_encryption_mapping( &encryption_manager, &encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].address, time ) == 1 );

    // make sure the encryption mappings that were removed can no longer be looked up by address

    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i )
    {
        int encryption_index = snapshot_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        uint8_t * send_key = snapshot_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        uint8_t * receive_key = snapshot_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        if ( i != 0 && i != NUM_ENCRYPTION_MAPPINGS - 1 )
        {
            snapshot_check( send_key );
            snapshot_check( receive_key );

            snapshot_check( memcmp( send_key, encryption_mapping[i].send_key, SNAPSHOT_KEY_BYTES ) == 0 );
            snapshot_check( memcmp( receive_key, encryption_mapping[i].receive_key, SNAPSHOT_KEY_BYTES ) == 0 );
        }
        else
        {
            snapshot_check( !send_key );
            snapshot_check( !receive_key );
        }
    }

    // add the encryption mappings back in
    
    snapshot_check( snapshot_encryption_manager_add_encryption_mapping( &encryption_manager, 
                                                                        &encryption_mapping[0].address, 
                                                                        encryption_mapping[0].send_key, 
                                                                        encryption_mapping[0].receive_key, 
                                                                        time, 
                                                                        -1.0,
                                                                        TEST_TIMEOUT_SECONDS ) );
    
    snapshot_check( snapshot_encryption_manager_add_encryption_mapping( &encryption_manager, 
                                                                        &encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].address, 
                                                                        encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].send_key, 
                                                                        encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].receive_key, 
                                                                        time, 
                                                                        -1.0,
                                                                        TEST_TIMEOUT_SECONDS ) );

    // all encryption mappings should be able to be looked up by address again

    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i )
    {
        int encryption_index = snapshot_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        uint8_t * send_key = snapshot_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        uint8_t * receive_key = snapshot_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        snapshot_check( send_key );
        snapshot_check( receive_key );

        snapshot_check( memcmp( send_key, encryption_mapping[i].send_key, SNAPSHOT_KEY_BYTES ) == 0 );
        snapshot_check( memcmp( receive_key, encryption_mapping[i].receive_key, SNAPSHOT_KEY_BYTES ) == 0 );
    }

    // check that encryption mappings time out properly

    time += TEST_TIMEOUT_SECONDS * 2;

    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i )
    {
        int encryption_index = snapshot_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        uint8_t * send_key = snapshot_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        uint8_t * receive_key = snapshot_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        snapshot_check( !send_key );
        snapshot_check( !receive_key );
    }

    // add the same encryption mappings after timeout

    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i )
    {
        int encryption_index = snapshot_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        snapshot_check( encryption_index == -1 );

        snapshot_check( snapshot_encryption_manager_get_send_key( &encryption_manager, encryption_index ) == NULL );
        snapshot_check( snapshot_encryption_manager_get_receive_key( &encryption_manager, encryption_index ) == NULL );

        snapshot_check( snapshot_encryption_manager_add_encryption_mapping( &encryption_manager, 
                                                                  &encryption_mapping[i].address, 
                                                                  encryption_mapping[i].send_key, 
                                                                  encryption_mapping[i].receive_key, 
                                                                  time, 
                                                                  -1.0,
                                                                  TEST_TIMEOUT_SECONDS ) );

        encryption_index = snapshot_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        uint8_t * send_key = snapshot_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        uint8_t * receive_key = snapshot_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        snapshot_check( send_key );
        snapshot_check( receive_key );

        snapshot_check( memcmp( send_key, encryption_mapping[i].send_key, SNAPSHOT_KEY_BYTES ) == 0 );
        snapshot_check( memcmp( receive_key, encryption_mapping[i].receive_key, SNAPSHOT_KEY_BYTES ) == 0 );
    }

    // reset the encryption mapping and verify that all encryption mappings have been removed

    snapshot_encryption_manager_reset( &encryption_manager );

    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i )
    {
        int encryption_index = snapshot_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        uint8_t * send_key = snapshot_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        uint8_t * receive_key = snapshot_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        snapshot_check( !send_key );
        snapshot_check( !receive_key );
    }

    // test the expire time for encryption mapping works as expected

    snapshot_check( snapshot_encryption_manager_add_encryption_mapping( &encryption_manager, 
                                                                        &encryption_mapping[0].address, 
                                                                        encryption_mapping[0].send_key, 
                                                                        encryption_mapping[0].receive_key, 
                                                                        time, 
                                                                        time + 1.0,
                                                                        TEST_TIMEOUT_SECONDS ) );

    int encryption_index = snapshot_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[0].address, time );

    snapshot_check( encryption_index != -1 );

    snapshot_check( snapshot_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[0].address, time + 1.1f ) == -1 );

    snapshot_encryption_manager_set_expire_time( &encryption_manager, encryption_index, -1.0 );

    snapshot_check( snapshot_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[0].address, time ) == encryption_index );
}

void test_replay_protection()
{
    struct snapshot_replay_protection_t replay_protection;

    int i;
    for ( i = 0; i < 2; ++i )
    {
        snapshot_replay_protection_reset( &replay_protection );

        snapshot_check( replay_protection.most_recent_sequence == 0 );

        // the first time we receive packets, they should not be already received

        #define MAX_SEQUENCE ( SNAPSHOT_REPLAY_PROTECTION_BUFFER_SIZE * 4 )

        uint64_t sequence;
        for ( sequence = 0; sequence < MAX_SEQUENCE; ++sequence )
        {
            snapshot_check( snapshot_replay_protection_already_received( &replay_protection, sequence ) == 0 );
            snapshot_replay_protection_advance_sequence( &replay_protection, sequence );
        }

        // old packets outside buffer should be considered already received

        snapshot_check( snapshot_replay_protection_already_received( &replay_protection, 0 ) == 1 );

        // packets received a second time should be flagged already received

        for ( sequence = MAX_SEQUENCE - 10; sequence < MAX_SEQUENCE; ++sequence )
        {
            snapshot_check( snapshot_replay_protection_already_received( &replay_protection, sequence ) == 1 );
        }

        // jumping ahead to a much higher sequence should be considered not already received

        snapshot_check( snapshot_replay_protection_already_received( &replay_protection, MAX_SEQUENCE + SNAPSHOT_REPLAY_PROTECTION_BUFFER_SIZE ) == 0 );

        // old packets should be considered already received

        for ( sequence = 0; sequence < MAX_SEQUENCE; ++sequence )
        {
            snapshot_check( snapshot_replay_protection_already_received( &replay_protection, sequence ) == 1 );
        }
    }
}

void test_ipv4_client_create_any_port()
{
    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:0", &client_config, 0.0 );

    snapshot_check( client );
    snapshot_check( snapshot_client_port( client ) != 0 );
    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_DISCONNECTED );

    snapshot_client_destroy( client );
}

void test_ipv4_client_create_specific_port()
{
    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, 0.0 );

    snapshot_check( client );
    snapshot_check( snapshot_client_port( client ) == 30000 );
    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_DISCONNECTED );

    snapshot_client_destroy( client );
}

void test_ipv4_client_server_connect()
{
    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:50000", &client_config, time );

    snapshot_check( client );

    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    const char * server_address = "127.0.0.1:40000";

    struct snapshot_server_t * server = snapshot_server_create( server_address, &server_config, time );

    snapshot_check( server );

    snapshot_server_start( server, 1 );

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );

    snapshot_server_destroy( server );

    snapshot_client_destroy( client );
}

#if SNAPSHOT_PLATFORM_HAS_IPV6

void test_ipv6_client_create_any_port()
{
    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "[::]:0", &client_config, 0.0 );

    snapshot_check( client );
    snapshot_check( snapshot_client_port( client ) != 0 );
    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_DISCONNECTED );

    snapshot_client_destroy( client );
}

void test_ipv6_client_create_specific_port()
{
    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "[::]:30000", &client_config, 0.0 );

    snapshot_check( client );
    snapshot_check( snapshot_client_port( client ) == 30000 );
    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_DISCONNECTED );

    snapshot_client_destroy( client );
}

void test_ipv6_client_server_connect()
{
    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "[::]:50000", &client_config, time );

    snapshot_check( client );

    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    const char * server_address = "[::1]:40000";

    struct snapshot_server_t * server = snapshot_server_create( "[::1]:40000", &server_config, time );

    snapshot_check( server );

    snapshot_server_start( server, 1 );

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );

    snapshot_server_destroy( server );

    snapshot_client_destroy( client );
}

#endif // #if SNAPSHOT_PLATFORM_HAS_IPV6

struct loopback_context_t
{
    struct snapshot_client_t * client;
    struct snapshot_server_t * server;
    int num_loopback_packets_sent_to_client;
    int num_loopback_packets_sent_to_server;
};

void client_send_loopback_packet_callback( void * context, int client_index, const uint8_t * packet_data, int packet_bytes, uint64_t packet_sequence )
{
    (void) context;
    (void) client_index;
    (void) packet_data;
    (void) packet_bytes;
    (void) packet_sequence;
}

void server_send_loopback_packet_callback( void * context, int client_index, const uint8_t * packet_data, int packet_bytes, uint64_t packet_sequence )
{
    (void) context;
    (void) client_index;
    (void) packet_data;
    (void) packet_bytes;
    (void) packet_sequence;
}

void test_client_server_loopback()
{
    double time = 0.0;

    loopback_context_t loopback_context;

    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    // start the server

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.context = &loopback_context;
    server_config.send_loopback_packet_callback = server_send_loopback_packet_callback;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    const char * server_address_string = "127.0.0.1:40000";

    snapshot_address_t server_address;
    snapshot_check( snapshot_address_parse( &server_address, server_address_string ) == SNAPSHOT_OK );

    struct snapshot_server_t * server = snapshot_server_create( server_address_string, &server_config, time );

    snapshot_check( server );

    int max_clients = 2;

    snapshot_server_start( server, max_clients );

    loopback_context.server = server;

    // connect a loopback client in slot 0

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );
    client_config.context = &loopback_context;
    client_config.send_loopback_packet_callback = client_send_loopback_packet_callback;

    struct snapshot_client_t * loopback_client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );
    snapshot_check( loopback_client );

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );
    snapshot_client_connect_loopback( loopback_client, &server_address, 0, max_clients );

    loopback_context.client = loopback_client;

    snapshot_check( snapshot_client_index( loopback_client ) == 0 );
    snapshot_check( snapshot_client_loopback( loopback_client ) == 1 );
    snapshot_check( snapshot_client_max_clients( loopback_client ) == max_clients );
    snapshot_check( snapshot_client_state( loopback_client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_address_equal( snapshot_client_server_address( loopback_client ), &server_address ) );

    snapshot_server_connect_loopback_client( server, 0, client_id, NULL );

    snapshot_check( snapshot_server_client_loopback( server, 0 ) == 1 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    // connect a regular client in the other slot

    struct snapshot_client_t * regular_client = snapshot_client_create( "0.0.0.0:30001", &client_config, time );

    snapshot_check( regular_client );

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes( user_data, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 1, &server_address_string, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( regular_client, connect_token );

    double delta_time = 1.0 / 10.0;

    while ( 1 )
    {
        snapshot_client_update( regular_client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( regular_client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( regular_client ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( regular_client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_client_index( regular_client ) == 1 );

    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_client_connected( server, 1 ) == 1 );
    snapshot_check( snapshot_server_client_loopback( server, 0 ) == 1 );
    snapshot_check( snapshot_server_client_loopback( server, 1 ) == 0 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 2 );

    // verify we can disconnect the loopback client

    snapshot_check( snapshot_server_client_loopback( server, 0 ) == 1 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 2 );

    snapshot_server_disconnect_loopback_client( server, 0 );    

    snapshot_check( snapshot_server_client_loopback( server, 0 ) == 0 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 0 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    snapshot_client_disconnect_loopback( loopback_client );

    snapshot_check( snapshot_client_state( loopback_client ) == SNAPSHOT_CLIENT_STATE_DISCONNECTED );

    // verify we can reconnect the loopback client

    snapshot_server_connect_loopback_client( server, 0, client_id, NULL );

    snapshot_check( snapshot_server_client_loopback( server, 0 ) == 1 );
    snapshot_check( snapshot_server_client_loopback( server, 1 ) == 0 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_client_connected( server, 1 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 2 );

    snapshot_client_connect_loopback( loopback_client, &server_address, 0, max_clients );
    
    snapshot_check( snapshot_client_index( loopback_client ) == 0 );
    snapshot_check( snapshot_client_loopback( loopback_client ) == 1 );
    snapshot_check( snapshot_client_max_clients( loopback_client ) == max_clients );
    snapshot_check( snapshot_client_state( loopback_client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );

    // verify the regular client times out but loopback client doesn't

    time += 100000.0;

    snapshot_server_update( server, time );

    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_client_connected( server, 1 ) == 0 );

    snapshot_client_update( loopback_client, time );

    snapshot_check( snapshot_client_state( loopback_client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );

    // verify that disconnect all clients leaves loopback clients alone

    snapshot_server_disconnect_all_clients( server );

    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_client_connected( server, 1 ) == 0 );
    snapshot_check( snapshot_server_client_loopback( server, 0 ) == 1 );

    // clean up

    snapshot_client_destroy( regular_client );

    snapshot_client_destroy( loopback_client );

    snapshot_server_destroy( server );
}

void test_client_server_network_simulator()
{
    // todo
}

void test_client_server_keep_alive()
{
    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    // connect client to server

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );

    snapshot_check( client );

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( "127.0.0.1:40000", &server_config, time );

    snapshot_check( server );

    snapshot_server_start( server, 1 );

    const char * server_address = "127.0.0.1:40000";

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_client_index( client ) == 0 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    // pump the client and server long enough that they would timeout without keep alive packets

    int num_iterations = (int) ceil( 1.25f * TEST_TIMEOUT_SECONDS / delta_time );

    int i;
    for ( i = 0; i < num_iterations; ++i )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_client_index( client ) == 0 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    snapshot_server_destroy( server );

    snapshot_client_destroy( client );
}

void test_client_server_multiple_clients()
{
    #define NUM_START_STOP_ITERATIONS 3

    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    int max_clients[NUM_START_STOP_ITERATIONS] = { 2, 32, 5 };

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( "127.0.0.1:40000", &server_config, time );

    snapshot_check( server );

    for ( int i = 0; i < NUM_START_STOP_ITERATIONS; ++i )
    {
        // start the server with max # of clients for this iteration

        snapshot_server_start( server, max_clients[i] );

        // create # of client objects for this iteration and connect to server

        struct snapshot_client_t ** client = (struct snapshot_client_t **) malloc( sizeof( struct snapshot_client_t* ) * max_clients[i] );

        snapshot_check( client );

        for ( int j = 0; j < max_clients[i]; ++j )
        {
            char client_bind_address[SNAPSHOT_MAX_ADDRESS_STRING_LENGTH];
            snprintf( client_bind_address, sizeof(client_bind_address), "0.0.0.0:%d", 30000 + j );

            struct snapshot_client_config_t client_config;
            snapshot_default_client_config( &client_config );

            client[j] = snapshot_client_create( client_bind_address, &client_config, time );

            snapshot_check( client[j] );

            uint64_t client_id = j;
            snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

            const char * server_address = "127.0.0.1:40000";

            uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

            uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
            snapshot_crypto_random_bytes( user_data, SNAPSHOT_USER_DATA_BYTES );

            snapshot_check( snapshot_generate_connect_token( 1, 
                                                             &server_address, 
                                                             TEST_CONNECT_TOKEN_EXPIRY, 
                                                             TEST_TIMEOUT_SECONDS,
                                                             client_id, 
                                                             TEST_PROTOCOL_ID, 
                                                             private_key, 
                                                             user_data, 
                                                             connect_token ) == SNAPSHOT_OK );

            snapshot_client_connect( client[j], connect_token );
        }

        // make sure all clients can connect

        while ( 1 )
        {
            for ( int j = 0; j < max_clients[i]; ++j )
            {
                snapshot_client_update( client[j], time );
            }

            snapshot_server_update( server, time );

            int num_connected_clients = 0;

            for ( int j = 0; j < max_clients[i]; ++j )
            {
                if ( snapshot_client_state( client[j] ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
                    break;

                if ( snapshot_client_state( client[j] ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
                    num_connected_clients++;
            }

            if ( num_connected_clients == max_clients[i] )
                break;

            time += delta_time;
        }

        snapshot_check( snapshot_server_num_connected_clients( server ) == max_clients[i] );

        for ( int j = 0; j < max_clients[i]; ++j )
        {
            snapshot_check( snapshot_client_state( client[j] ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
            snapshot_check( snapshot_server_client_connected( server, j ) == 1 );
        }

        for ( int j = 0; j < max_clients[i]; ++j )
        {
            snapshot_client_destroy( client[j] );
        }

        free( client );

        snapshot_server_stop( server );
    }

    snapshot_server_destroy( server );
}

void test_client_server_multiple_servers()
{
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );

    snapshot_check( client );

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( "127.0.0.1:40000", &server_config, time );

    snapshot_check( server );

    snapshot_server_start( server, 1 );

    const char * server_address[] = { "10.10.10.10:1000", "100.100.100.100:50000", "127.0.0.1:40000" };

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 3, server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_client_index( client ) == 0 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    snapshot_server_destroy( server );

    snapshot_client_destroy( client );
}

void test_client_error_connect_token_expired()
{
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    double time = 0.0;

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );
    
    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );

    snapshot_check( client );

    const char * server_address = "127.0.0.1:40000";

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, 0, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    snapshot_client_update( client, time );

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECT_TOKEN_EXPIRED );

    snapshot_client_destroy( client );
}

void test_client_error_invalid_connect_token()
{
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    double time = 0.0;

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );

    snapshot_check( client );

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];
    snapshot_crypto_random_bytes( connect_token, SNAPSHOT_CONNECT_TOKEN_BYTES );

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    snapshot_client_connect( client, connect_token );

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_INVALID_CONNECT_TOKEN );

    snapshot_client_destroy( client );
}

void test_client_error_connection_timed_out()
{
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    // connect a client to the server

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );

    snapshot_check( client );

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( "127.0.0.1:40000", &server_config, time );

    snapshot_check( server );

    snapshot_server_start( server, 1 );

    const char * server_address = "127.0.0.1:40000";

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_client_index( client ) == 0 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    // now disable updating the server and verify that the client times out

    while ( 1 )
    {
        snapshot_client_update( client, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTION_TIMED_OUT );

    snapshot_server_destroy( server );

    snapshot_client_destroy( client );
}

void test_client_error_connection_response_timeout()
{
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );

    snapshot_check( client );

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( "127.0.0.1:40000", &server_config, time );

    snapshot_check( server );

    snapshot_server_set_flags( server, SNAPSHOT_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS );

    snapshot_server_start( server, 1 );

    const char * server_address = "127.0.0.1:40000";

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED  )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT );

    snapshot_server_destroy( server );

    snapshot_client_destroy( client );
}

void test_client_error_connection_request_timeout()
{
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    double time = 0.0;
    double delta_time = 1.0 / 60.0;

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );

    snapshot_check( client );

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( "127.0.0.1:40000", &server_config, time );

    snapshot_check( server );

    snapshot_server_set_flags( server, SNAPSHOT_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS );

    snapshot_server_start( server, 1 );

    const char * server_address = "[::1]:40000";

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED  )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT );

    snapshot_server_destroy( server );

    snapshot_client_destroy( client );
}

void test_client_error_connection_denied()
{
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );

    snapshot_check( client );

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( "127.0.0.1:40000", &server_config, time );

    snapshot_check( server );

    snapshot_server_start( server, 1 );

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    const char * server_address = "127.0.0.1:40000";

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_client_index( client ) == 0 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    // now attempt to connect a second client. the connection should be denied.

    struct snapshot_client_t * client2 = snapshot_client_create( "0.0.0.0:30001", &client_config, time );

    snapshot_check( client2 );

    uint8_t connect_token2[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id2 = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id2, 8 );

    uint8_t user_data2[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data2, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id2, TEST_PROTOCOL_ID, private_key, user_data2, connect_token2 ) == SNAPSHOT_OK );

    snapshot_client_connect( client2, connect_token2 );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_client_update( client2, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client2 ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_client_state( client2 ) == SNAPSHOT_CLIENT_STATE_CONNECTION_DENIED );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    snapshot_server_destroy( server );

    snapshot_client_destroy( client );
    
    snapshot_client_destroy( client2 );
}

void test_client_side_disconnect()
{
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );

    snapshot_check( client );

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( "127.0.0.1:40000", &server_config, time );

    snapshot_check( server );

    snapshot_server_start( server, 1 );

    const char * server_address = "127.0.0.1:40000";

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_client_index( client ) == 0 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    // disconnect client side and verify that the server sees that client disconnect cleanly, rather than timing out.

    snapshot_client_disconnect( client );

    int i;
    for ( i = 0; i < 10; ++i )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_server_client_connected( server, 0 ) == 0 )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_server_client_connected( server, 0 ) == 0 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 0 );

    snapshot_server_destroy( server );

    snapshot_client_destroy( client );
}

void test_server_side_disconnect()
{
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );

    snapshot_check( client );

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( "127.0.0.1:40000", &server_config, time );

    snapshot_check( server );

    snapshot_server_start( server, 1 );

    const char * server_address = "127.0.0.1:40000";

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_client_index( client ) == 0 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    // disconnect server side and verify that the client disconnects cleanly, rather than timing out.

    snapshot_server_disconnect_client( server, 0 );

    int i;
    for ( i = 0; i < 10; ++i )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_DISCONNECTED );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 0 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 0 );

    snapshot_server_destroy( server );

    snapshot_client_destroy( client );
}

void test_client_reconnect()
{
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );

    snapshot_check( client );

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( "127.0.0.1:40000", &server_config, time );

    snapshot_check( server );

    snapshot_server_start( server, 1 );

    const char * server_address = "127.0.0.1:40000";

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_client_index( client ) == 0 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    // disconnect client on the server-side and wait until client sees the disconnect

    snapshot_server_disconnect_client( server, 0 );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_DISCONNECTED );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 0 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 0 );

    // now reconnect the client and verify they connect

    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_client_index( client ) == 0 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    snapshot_server_destroy( server );

    snapshot_client_destroy( client );
}

void test_disable_timeout()
{
    uint8_t private_key[SNAPSHOT_KEY_BYTES];
    snapshot_crypto_random_bytes( private_key, SNAPSHOT_KEY_BYTES );

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct snapshot_client_config_t client_config;
    snapshot_default_client_config( &client_config );

    struct snapshot_client_t * client = snapshot_client_create( "0.0.0.0:30000", &client_config, time );

    snapshot_check( client );

    struct snapshot_server_config_t server_config;
    snapshot_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, SNAPSHOT_KEY_BYTES );

    struct snapshot_server_t * server = snapshot_server_create( "127.0.0.1:40000", &server_config, time );

    snapshot_check( server );

    snapshot_server_start( server, 1 );

    const char * server_address = "127.0.0.1:40000";

    uint8_t connect_token[SNAPSHOT_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    snapshot_crypto_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[SNAPSHOT_USER_DATA_BYTES];
    snapshot_crypto_random_bytes(user_data, SNAPSHOT_USER_DATA_BYTES);

    // IMPORTANT: passing in -1 timeout in connect token disables timeout for that client. This is useful for testing!
    snapshot_check( snapshot_generate_connect_token( 1, &server_address, TEST_CONNECT_TOKEN_EXPIRY, -1, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == SNAPSHOT_OK );

    snapshot_client_connect( client, connect_token );

    while ( 1 )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        if ( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );
    snapshot_check( snapshot_client_index( client ) == 0 );
    snapshot_check( snapshot_server_client_connected( server, 0 ) == 1 );
    snapshot_check( snapshot_server_num_connected_clients( server ) == 1 );

    for ( int i = 0; i < 100; i++ )
    {
        snapshot_client_update( client, time );

        snapshot_server_update( server, time );

        if ( snapshot_client_state( client ) <= SNAPSHOT_CLIENT_STATE_DISCONNECTED )
            break;

        time += 1000.0f;        // normally this would timeout the client
    }

    snapshot_check( snapshot_client_state( client ) == SNAPSHOT_CLIENT_STATE_CONNECTED );

    snapshot_server_destroy( server );

    snapshot_client_destroy( client );
}

#define RUN_TEST( test_function )                                           \
    do                                                                      \
    {                                                                       \
        snapshot_printf( #test_function );                                  \
        fflush( stdout );                                                   \
        test_function();                                                    \
    }                                                                       \
    while (0)

void test()
{
    printf( "\n[test]\n\n" );

    snapshot_quiet( true );

    // while ( true )
    {
        RUN_TEST( test_time );
        RUN_TEST( test_endian );
        RUN_TEST( test_address );
        RUN_TEST( test_read_and_write );
        RUN_TEST( test_bitpacker );
        RUN_TEST( test_bits_required );
        RUN_TEST( test_stream );
        RUN_TEST( test_crypto_random_bytes );
        RUN_TEST( test_crypto_box );
        RUN_TEST( test_crypto_secret_box );
        RUN_TEST( test_crypto_aead );
        RUN_TEST( test_crypto_aead_ietf );
        RUN_TEST( test_crypto_sign_detached );
        RUN_TEST( test_crypto_key_exchange );
        RUN_TEST( test_platform_socket );
        RUN_TEST( test_platform_thread );
        RUN_TEST( test_platform_mutex );
        RUN_TEST( test_sequence );
        RUN_TEST( test_connect_token_private );
        RUN_TEST( test_connect_token_public );
        RUN_TEST( test_challenge_token );
        RUN_TEST( test_connection_request_packet );
        RUN_TEST( test_connection_denied_packet );
        RUN_TEST( test_connection_challenge_packet );
        RUN_TEST( test_connection_response_packet );
        RUN_TEST( test_connection_payload_packet );
        RUN_TEST( test_connection_disconnect_packet );        
        RUN_TEST( test_encryption_manager );
        RUN_TEST( test_replay_protection );
        RUN_TEST( test_ipv4_client_create_any_port );
        RUN_TEST( test_ipv4_client_create_specific_port );
        RUN_TEST( test_ipv4_client_server_connect );
#if SNAPSHOT_PLATFORM_HAS_IPV6
        RUN_TEST( test_ipv6_client_create_any_port );
        RUN_TEST( test_ipv6_client_create_specific_port );
        RUN_TEST( test_ipv6_client_server_connect );
#endif // if SNAPSHOT_PLATFORM_HAS_IPV6
        RUN_TEST( test_client_server_loopback );
        RUN_TEST( test_client_server_network_simulator );
        RUN_TEST( test_client_server_keep_alive );
        RUN_TEST( test_client_server_multiple_clients );
        RUN_TEST( test_client_server_multiple_servers );
        RUN_TEST( test_client_error_connect_token_expired );
        RUN_TEST( test_client_error_invalid_connect_token );
        RUN_TEST( test_client_error_connection_timed_out );
        RUN_TEST( test_client_error_connection_response_timeout );
        RUN_TEST( test_client_error_connection_request_timeout );
        RUN_TEST( test_client_error_connection_denied );
        RUN_TEST( test_client_side_disconnect );
        RUN_TEST( test_server_side_disconnect );
        RUN_TEST( test_client_reconnect );
        RUN_TEST( test_disable_timeout );
    }

    printf( "\nAll tests pass.\n\n" );
}

int main()
{
    snapshot_init();
    test();
    fflush( stdout );
    snapshot_term();
    return 0;
}
