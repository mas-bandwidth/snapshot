/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"

#ifndef SNAPSHOT_PLATFORM_IOS_H
#define SNAPSHOT_PLATFORM_IOS_H

#if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_IOS

#include <pthread.h>
#include <unistd.h>

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

#endif // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_IOS

#endif // #ifndef SNAPSHOT_PLATFORM_IOS_H
