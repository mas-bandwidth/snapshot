/*
    Snapshot SDK Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include <stdio.h>
#include <string.h>
#include "snapshot.h"

int main()
{
    snapshot_init();
    printf( "\nhello snapshot world\n\n" );
    fflush( stdout );
    snapshot_term();
    return 0;
}
