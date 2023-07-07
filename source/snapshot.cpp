/*
    Snapshot SDK Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licenses under different terms are available. Email licensing@mas-bandwidth.com for details.
*/

#include "snapshot.h"
#include "snapshot_crypto.h"
#include "snapshot_platform.h"

int snapshot_init()
{
    if ( snapshot_crypto_init() != SNAPSHOT_OK )
    {
        return SNAPSHOT_ERROR;
    }

    if ( snapshot_platform_init() != SNAPSHOT_OK )
    {
        return SNAPSHOT_ERROR;
    }

    return SNAPSHOT_OK;
}

void snapshot_term()
{
    snapshot_platform_term();
}
