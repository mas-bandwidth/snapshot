/*
    Snapshot SDK Copyright © 2023 Network Next, Inc. This source code is licensed under GPL version 3 or any later version.
    Commercial licenses under different terms are available. Contact licensing@mas-bandwidth.com for details.
*/

#include "snapshot_common.h"

#ifndef SNAPSHOT_PLATFORM_MAC_H
#define SNAPSHOT_PLATFORM_MAC_H

#if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_MAC

#include <pthread.h>
#include <unistd.h>

#define SNAPSHOT_PLATFORM_SOCKET_NON_BLOCKING       0
#define SNAPSHOT_PLATFORM_SOCKET_BLOCKING           1

// -------------------------------------

typedef int snapshot_platform_socket_handle_t;

struct snapshot_platform_socket_t
{
    void * context;
    snapshot_platform_socket_handle_t handle;
};

// -------------------------------------

struct snapshot_platform_thread_t
{
    void * context;
    pthread_t handle;
};

// -------------------------------------

struct snapshot_platform_mutex_t
{
    bool ok;
    pthread_mutex_t handle;
};

// -------------------------------------

#endif // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_MAC

#endif // #ifndef SNAPSHOT_PLATFORM_MAC_H
