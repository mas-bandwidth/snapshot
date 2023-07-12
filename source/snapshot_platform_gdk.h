/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"

#ifndef SNAPSHOT_PLATFORM_GDK_H
#define SNAPSHOT_PLATFORM_GDK_H

#ifdef _GAMING_XBOX

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

typedef DWORD snapshot_platform_thread_return_t;

#define NEXT_PLATFORM_THREAD_RETURN() do { return 0; } while ( 0 )

#define NEXT_PLATFORM_THREAD_FUNC WINAPI

typedef snapshot_platform_thread_return_t (NEXT_PLATFORM_THREAD_FUNC snapshot_platform_thread_func_t)(void*);

// -------------------------------------

struct snapshot_platform_mutex_t
{
    bool ok;
    CRITICAL_SECTION handle;
};

// -------------------------------------

#endif // #ifdef _GAMING_XBOX

#endif // #ifndef SNAPSHOT_PLATFORM_GDK_H
