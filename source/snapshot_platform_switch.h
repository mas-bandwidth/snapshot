/*
    Snapshot SDK Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"

#if 0 // todo

#ifndef NEXT_SWITCH_H
#define NEXT_SWITCH_H

#if NEXT_PLATFORM == NEXT_PLATFORM_SWITCH

#include <nn/os.h>

#define NEXT_PLATFORM_SOCKET_NON_BLOCKING       0
#define NEXT_PLATFORM_SOCKET_BLOCKING           1

// -------------------------------------

typedef int next_platform_socket_handle_t;

struct next_platform_socket_t
{
    next_platform_socket_handle_t handle;
    next_address_t address;
    int type;
    float timeout_seconds;
    int send_buffer_size;
    int receive_buffer_size;
    bool enable_packet_tagging;
    void * context;
};

// -------------------------------------

struct next_platform_thread_t
{
    nn::os::ThreadType handle;
    char * stack;
    void * context;
};

// -------------------------------------

struct next_platform_mutex_t
{
    nn::os::MutexType handle;
};

// -------------------------------------

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_SWITCH

#endif // #ifndef NEXT_SWITCH_H

#endif // todo
