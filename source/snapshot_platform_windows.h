/*
    Snapshot SDK Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"

#if 0

#ifndef NEXT_WINDOWS_H
#define NEXT_WINDOWS_H

#if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

#if NEXT_UNREAL_ENGINE
#include "Windows/AllowWindowsPlatformTypes.h"
#include "Windows/PreWindowsApi.h"
#endif // #if NEXT_UNREAL_ENGINE

#ifndef NEXT_UNREAL_ENGINE
#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>
#else // #ifndef NEXT_UNREAL_ENGINE
#include "Windows/MinWindows.h"
#endif // #ifndef NEXT_UNREAL_ENGINE

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

#if NEXT_UNREAL_ENGINE
#include "Windows/PostWindowsApi.h"
#include "Windows/HideWindowsPlatformTypes.h"
#endif // #if NEXT_UNREAL_ENGINE

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_WINDOWS

#endif // #ifndef NEXT_WINDOWS_H

#endif // todo
