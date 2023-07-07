/*
    Snapshot SDK Copyright © 2023 Network Next, Inc. This source code is licensed under GPL version 3 or any later version.
    Commercial licenses under different terms are available. Contact licensing@mas-bandwidth.com for details.
*/

#include "common.h"

#ifndef NEXT_GDK_H
#define NEXT_GDK_H

#ifdef _GAMING_XBOX

#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>

#define NEXT_PLATFORM_SOCKET_NON_BLOCKING       0
#define NEXT_PLATFORM_SOCKET_BLOCKING           1

// -------------------------------------

#pragma warning(disable:4996)

#if _WIN64
    typedef uint64_t next_platform_socket_handle_t;
#else
    typedef _W64 unsigned int next_platform_socket_handle_t;
#endif

struct next_platform_socket_t
{
    void * context;
    next_platform_socket_handle_t handle;
};

// -------------------------------------

struct next_platform_thread_t
{
    void * context;
    HANDLE handle;
};

typedef DWORD next_platform_thread_return_t;

#define NEXT_PLATFORM_THREAD_RETURN() do { return 0; } while ( 0 )

#define NEXT_PLATFORM_THREAD_FUNC WINAPI

typedef next_platform_thread_return_t (NEXT_PLATFORM_THREAD_FUNC next_platform_thread_func_t)(void*);

// -------------------------------------

struct next_platform_mutex_t
{
    bool ok;
    CRITICAL_SECTION handle;
};

// -------------------------------------

#endif // #ifdef _GAMING_XBOX

#endif // #ifndef NEXT_GDK_H
