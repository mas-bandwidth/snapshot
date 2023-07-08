/*
    Snapshot SDK Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"

#if 0 // todo

#ifndef NEXT_PS5_H
#define NEXT_PS5_H

#if NEXT_PLATFORM == NEXT_PLATFORM_PS5

#include <kernel.h>
#include <net.h>

#define NEXT_PLATFORM_SOCKET_NON_BLOCKING       0
#define NEXT_PLATFORM_SOCKET_BLOCKING           1

// -------------------------------------

typedef SceNetId next_platform_socket_handle_t;

struct next_platform_socket_t
{
    next_platform_socket_handle_t handle;
    int type;
    float timeout_seconds;
    void * context;
};

// -------------------------------------

struct next_platform_thread_t
{
    ScePthread handle;
    void * context;
};

// -------------------------------------

struct next_platform_mutex_t
{
    bool ok;
    ScePthreadMutex handle;
};

// -------------------------------------

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_PS5

#endif // #ifndef NEXT_PS5_H

#endif // todo