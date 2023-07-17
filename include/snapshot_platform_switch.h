/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"

#ifndef SNAPSHOT_SWITCH_H
#define SNAPSHOT_SWITCH_H

#if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_SWITCH

#include "snapshot_address.h"

#include <nn/os.h>

// -------------------------------------

typedef int snapshot_platform_socket_handle_t;

struct snapshot_platform_socket_t
{
    snapshot_platform_socket_handle_t handle;
    snapshot_address_t address;
    int type;
    float timeout_seconds;
    int send_buffer_size;
    int receive_buffer_size;
    void * context;
};

// -------------------------------------

struct snapshot_platform_thread_t
{
    nn::os::ThreadType handle;
    char * stack;
    void * context;
};

// -------------------------------------

struct snapshot_platform_mutex_t
{
    nn::os::MutexType handle;
};

// -------------------------------------

#endif // #if SNAPSHOT_PLATFORM == SNAPSHOT_PLATFORM_SWITCH

#endif // #ifndef SNAPSHOT_SWITCH_H
