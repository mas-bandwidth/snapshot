/*
    Snapshot SDK Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licenses under different terms are available. Email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"

#ifndef NEXT_IOS_H
#define NEXT_IOS_H

#if NEXT_PLATFORM == NEXT_PLATFORM_IOS

#include <pthread.h>
#include <unistd.h>

#define NEXT_PLATFORM_SOCKET_NON_BLOCKING       0
#define NEXT_PLATFORM_SOCKET_BLOCKING           1

// -------------------------------------

typedef int next_platform_socket_handle_t;

struct next_platform_socket_t
{
    void * context;
    next_platform_socket_handle_t handle;
};

// -------------------------------------

struct next_platform_thread_t
{
    void * context;
    pthread_t handle;
};

// -------------------------------------

struct next_platform_mutex_t
{
    bool ok;
    pthread_mutex_t handle;
};

// -------------------------------------

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_IOS

#endif // #ifndef NEXT_IOS_H