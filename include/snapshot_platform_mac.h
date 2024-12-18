/*
    Snapshot 

    Copyright © 2024 Más Bandwidth LLC. 

    This source code is licensed under GPL version 3 or any later version.

    Commercial licensing under different terms is available. Email licensing@mas-bandwidth.com for details
*/

#include "snapshot.h"

#ifndef SNAPSHOT_PLATFORM_MAC_H
#define SNAPSHOT_PLATFORM_MAC_H

#if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_MAC

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
    SNAPSHOT_BOOL ok;
    pthread_mutex_t handle;
};

// -------------------------------------

#endif // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_MAC

#endif // #ifndef SNAPSHOT_PLATFORM_MAC_H
