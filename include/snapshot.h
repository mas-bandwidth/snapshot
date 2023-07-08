/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <memory.h>

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

int snapshot_init();

void snapshot_term();

// -----------------------------------------

#define snapshot_assert assert

void snapshot_printf( const char * format, ... );

void snapshot_printf( int level, const char * format, ... );

void * snapshot_malloc( void * context, size_t bytes );

void snapshot_free( void * context, void * p );

void snapshot_copy_string( char * dest, const char * source, size_t dest_size );

// -----------------------------------------

#endif // #ifndef SNAPSHOT_H
