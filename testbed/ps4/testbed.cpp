/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"
#include "snapshot_tests.cpp"
#include <stdio.h>

unsigned int sceLibcHeapExtendedAlloc = 1;

size_t sceLibcHeapSize = SCE_LIBC_HEAP_SIZE_EXTENDED_ALLOC_NO_LIMIT;

static volatile int quit = 0;

int32_t main( int argc, const char * const argv[] )
{
    snapshot_init( NULL );

    snapshot_run_tests();

    snapshot_term();

    return 0;
}
