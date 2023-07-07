/*
    Snapshot SDK Copyright © 2023 Network Next, Inc. This source code is licensed under GPL version 3 or any later version.
    Commercial licenses under different terms are available. Contact licensing@mas-bandwidth.com for details.
*/

#include "common.h"

#if 0 // todo

#ifndef NEXT_PS4_H
#define NEXT_PS4_H

#if NEXT_PLATFORM == NEXT_PLATFORM_PS4

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

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_PS4

#endif // #ifndef NEXT_PS4_H

#endif // todo
