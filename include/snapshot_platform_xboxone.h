/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"

#ifndef SNAPSHOT_PLATFORM_XBOX_ONE_H
#define SNAPSHOT_PLATFORM_XBOX_ONE_H

#if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_XBOX_ONE

#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>

// -------------------------------------

#pragma warning(disable:4996)

#if _WIN64
    typedef uint64_t snapshot_platform_socket_handle_t;
#else
    typedef _W64 unsigned int snapshot_platform_socket_handle_t;
#endif

struct snapshot_platform_socket_t
{
    void * context;
    snapshot_platform_socket_handle_t handle;
};

// -------------------------------------

struct snapshot_platform_thread_t
{
    void * context;
    HANDLE handle;
};

// -------------------------------------

struct snapshot_platform_mutex_t
{
    bool ok;
    CRITICAL_SECTION handle;
};

// -------------------------------------

#endif // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_XBOX_ONE

#endif // #ifndef SNAPSHOT_PLATFORM_XBOX_ONE_H
