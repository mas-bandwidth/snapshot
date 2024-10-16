/*
    Snapshot 

    Copyright © 2024 Más Bandwidth LLC. 

    This source code is licensed under GPL version 3 or any later version.

    Commercial licensing under different terms is available. Email licensing@mas-bandwidth.com for details
*/

#include "snapshot.h"
#include "snapshot_tests.h"
#include <stdio.h>

int main()
{
    snapshot_init();
    snapshot_run_tests();
    snapshot_term();
    return 0;
}
