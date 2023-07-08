/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"

#ifndef SNAPSHOT_WINDOWS_H
#define SNAPSHOT_WINDOWS_H

#if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_WINDOWS

#if SNAPSHOT_UNREAL_ENGINE
#include "Windows/AllowWindowsPlatformTypes.h"
#include "Windows/PreWindowsApi.h"
#endif // #if SNAPSHOT_UNREAL_ENGINE

#ifndef SNAPSHOT_UNREAL_ENGINE
#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>
#else // #ifndef SNAPSHOT_UNREAL_ENGINE
#include "Windows/MinWindows.h"
#endif // #ifndef SNAPSHOT_UNREAL_ENGINE

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

#if SNAPSHOT_UNREAL_ENGINE
#include "Windows/PostWindowsApi.h"
#include "Windows/HideWindowsPlatformTypes.h"
#endif // #if SNAPSHOT_UNREAL_ENGINE

#endif // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_WINDOWS

#endif // #ifndef SNAPSHOT_WINDOWS_H
