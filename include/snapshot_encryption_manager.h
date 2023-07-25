/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_ENCRYPTION_MANAGER_H
#define SNAPSHOT_ENCRYPTION_MANAGER_H

#include "snapshot.h"
#include "snapshot_address.h"

#define SNAPSHOT_MAX_ENCRYPTION_MAPPINGS ( SNAPSHOT_MAX_CLIENTS * 4 )

struct snapshot_encryption_manager_t
{
    int num_encryption_mappings;
    int timeout[SNAPSHOT_MAX_ENCRYPTION_MAPPINGS];
    double expire_time[SNAPSHOT_MAX_ENCRYPTION_MAPPINGS];
    double last_access_time[SNAPSHOT_MAX_ENCRYPTION_MAPPINGS];
    struct snapshot_address_t address[SNAPSHOT_MAX_ENCRYPTION_MAPPINGS];
    int client_index[SNAPSHOT_MAX_ENCRYPTION_MAPPINGS];
    uint8_t send_key[SNAPSHOT_KEY_BYTES*SNAPSHOT_MAX_ENCRYPTION_MAPPINGS];
    uint8_t receive_key[SNAPSHOT_KEY_BYTES*SNAPSHOT_MAX_ENCRYPTION_MAPPINGS];
};

void snapshot_encryption_manager_reset( struct snapshot_encryption_manager_t * encryption_manager );

int snapshot_encryption_manager_entry_expired( struct snapshot_encryption_manager_t * encryption_manager, int index, double time );

int snapshot_encryption_manager_add_encryption_mapping( struct snapshot_encryption_manager_t * encryption_manager, 
                                                        const struct snapshot_address_t * address, 
                                                        uint8_t * send_key, 
                                                        uint8_t * receive_key, 
                                                        double time, 
                                                        double expire_time,
                                                        int timeout );

int snapshot_encryption_manager_remove_encryption_mapping( struct snapshot_encryption_manager_t * encryption_manager, const struct snapshot_address_t * address, double time );

int snapshot_encryption_manager_find_encryption_mapping( struct snapshot_encryption_manager_t * encryption_manager, const struct snapshot_address_t * address, double time );

int snapshot_encryption_manager_touch( struct snapshot_encryption_manager_t * encryption_manager, int index, const struct snapshot_address_t * address, double time );

void snapshot_encryption_manager_set_expire_time( struct snapshot_encryption_manager_t * encryption_manager, int index, double expire_time );

uint8_t * snapshot_encryption_manager_get_send_key( struct snapshot_encryption_manager_t * encryption_manager, int index );

uint8_t * snapshot_encryption_manager_get_receive_key( struct snapshot_encryption_manager_t * encryption_manager, int index );

int snapshot_encryption_manager_get_timeout( struct snapshot_encryption_manager_t * encryption_manager, int index );

#endif // #ifndef SNAPSHOT_ENCRYPTION_MANAGER_H
