/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"

#ifndef SNAPSHOT_PLATFORM_PS4_H
#define SNAPSHOT_PLATFORM_PS4_H

#if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_PS4

#include <kernel.h>
#include <net.h>

// -------------------------------------

typedef SceNetId snapshot_platform_socket_handle_t;

struct snapshot_platform_socket_t
{
    snapshot_platform_socket_handle_t handle;
    int type;
    float timeout_seconds;
    void * context;
};

// -------------------------------------

struct snapshot_platform_thread_t
{
    ScePthread handle;
    void * context;
};

// -------------------------------------

struct snapshot_platform_mutex_t
{
    bool ok;
    ScePthreadMutex handle;
};

// -------------------------------------

#endif // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_PS4

#endif // #ifndef SNAPSHOT_PLATFORM_PS4_H
