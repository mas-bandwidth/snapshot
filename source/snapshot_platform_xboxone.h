/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"

#if 0 // todo

#ifndef NEXT_XBOXONE_H
#define NEXT_XBOXONE_H

#if NEXT_PLATFORM == NEXT_PLATFORM_XBOX_ONE

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

// -------------------------------------

struct next_platform_mutex_t
{
    bool ok;
    CRITICAL_SECTION handle;
};

// -------------------------------------

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_XBOX_ONE

#endif // #ifndef NEXT_XBOXONE_H

#endif // todo
