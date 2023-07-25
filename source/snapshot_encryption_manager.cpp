/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#include "snapshot_encryption_manager.h"

void snapshot_encryption_manager_reset( struct snapshot_encryption_manager_t * encryption_manager )
{
    snapshot_printf( SNAPSHOT_LOG_LEVEL_DEBUG, "reset encryption manager" );

    snapshot_assert( encryption_manager );

    encryption_manager->num_encryption_mappings = 0;
    
    int i;
    for ( i = 0; i < SNAPSHOT_MAX_ENCRYPTION_MAPPINGS; ++i )
    {
        encryption_manager->client_index[i] = -1;
        encryption_manager->expire_time[i] = -1.0;
        encryption_manager->last_access_time[i] = -1000.0;
        memset( &encryption_manager->address[i], 0, sizeof( struct snapshot_address_t ) );
    }

    memset( encryption_manager->timeout, 0, sizeof( encryption_manager->timeout ) );    
    memset( encryption_manager->send_key, 0, sizeof( encryption_manager->send_key ) );
    memset( encryption_manager->receive_key, 0, sizeof( encryption_manager->receive_key ) );
}

int snapshot_encryption_manager_entry_expired( struct snapshot_encryption_manager_t * encryption_manager, int index, double time )
{
    return ( encryption_manager->timeout[index] > 0 && ( encryption_manager->last_access_time[index] + encryption_manager->timeout[index] ) < time ) ||
           ( encryption_manager->expire_time[index] >= 0.0 && encryption_manager->expire_time[index] < time );
}

int snapshot_encryption_manager_add_encryption_mapping( struct snapshot_encryption_manager_t * encryption_manager, 
                                                        const struct snapshot_address_t * address, 
                                                        uint8_t * send_key, 
                                                        uint8_t * receive_key, 
                                                        double time, 
                                                        double expire_time,
                                                        int timeout )
{
    int i;
    for ( i = 0; i < encryption_manager->num_encryption_mappings; ++i )
    {
        if ( snapshot_address_equal( &encryption_manager->address[i], address ) && !snapshot_encryption_manager_entry_expired( encryption_manager, i, time ) )
        {
            encryption_manager->timeout[i] = timeout;
            encryption_manager->expire_time[i] = expire_time;
            encryption_manager->last_access_time[i] = time;
            memcpy( encryption_manager->send_key + i * SNAPSHOT_KEY_BYTES, send_key, SNAPSHOT_KEY_BYTES );
            memcpy( encryption_manager->receive_key + i * SNAPSHOT_KEY_BYTES, receive_key, SNAPSHOT_KEY_BYTES );
            return 1;
        }
    }

    for ( i = 0; i < SNAPSHOT_MAX_ENCRYPTION_MAPPINGS; ++i )
    {
        if ( encryption_manager->address[i].type == SNAPSHOT_ADDRESS_NONE || 
            ( snapshot_encryption_manager_entry_expired( encryption_manager, i, time ) && encryption_manager->client_index[i] == -1 ) )
        {
            encryption_manager->timeout[i] = timeout;
            encryption_manager->address[i] = *address;
            encryption_manager->expire_time[i] = expire_time;
            encryption_manager->last_access_time[i] = time;
            memcpy( encryption_manager->send_key + i * SNAPSHOT_KEY_BYTES, send_key, SNAPSHOT_KEY_BYTES );
            memcpy( encryption_manager->receive_key + i * SNAPSHOT_KEY_BYTES, receive_key, SNAPSHOT_KEY_BYTES );
            if ( i + 1 > encryption_manager->num_encryption_mappings )
                encryption_manager->num_encryption_mappings = i + 1;
            return 1;
        }
    }

    return 0;
}

int snapshot_encryption_manager_remove_encryption_mapping( struct snapshot_encryption_manager_t * encryption_manager, const struct snapshot_address_t * address, double time )
{
    snapshot_assert( encryption_manager );
    snapshot_assert( address );

    int i;
    for ( i = 0; i < encryption_manager->num_encryption_mappings; ++i )
    {
        if ( snapshot_address_equal( &encryption_manager->address[i], address ) )
        {
            encryption_manager->expire_time[i] = -1.0;
            encryption_manager->last_access_time[i] = -1000.0;
            memset( &encryption_manager->address[i], 0, sizeof( struct snapshot_address_t ) );
            memset( encryption_manager->send_key + i * SNAPSHOT_KEY_BYTES, 0, SNAPSHOT_KEY_BYTES );
            memset( encryption_manager->receive_key + i * SNAPSHOT_KEY_BYTES, 0, SNAPSHOT_KEY_BYTES );

            if ( i + 1 == encryption_manager->num_encryption_mappings )
            {
                int index = i - 1;
                while ( index >= 0 )
                {
                    if ( !snapshot_encryption_manager_entry_expired( encryption_manager, index, time ) || encryption_manager->client_index[index] != -1 )
                    {
                        break;
                    }
                    encryption_manager->address[index].type = SNAPSHOT_ADDRESS_NONE;
                    index--;
                }
                encryption_manager->num_encryption_mappings = index + 1;
            }

            return 1;
        }
    }

    return 0;
}

int snapshot_encryption_manager_find_encryption_mapping( struct snapshot_encryption_manager_t * encryption_manager, const struct snapshot_address_t * address, double time )
{
    int i;
    for ( i = 0; i < encryption_manager->num_encryption_mappings; ++i )
    {
        if ( snapshot_address_equal( &encryption_manager->address[i], address ) && !snapshot_encryption_manager_entry_expired( encryption_manager, i, time ) )
        {
            encryption_manager->last_access_time[i] = time;
            return i;
        }
    }
    return -1;
}

int snapshot_encryption_manager_touch( struct snapshot_encryption_manager_t * encryption_manager, int index, const struct snapshot_address_t * address, double time )
{
    snapshot_assert( index >= 0 );
    snapshot_assert( index < encryption_manager->num_encryption_mappings );
    if ( !snapshot_address_equal( &encryption_manager->address[index], address ) )
        return 0;
    encryption_manager->last_access_time[index] = time;
    return 1;
}

void snapshot_encryption_manager_set_expire_time( struct snapshot_encryption_manager_t * encryption_manager, int index, double expire_time )
{
    snapshot_assert( index >= 0 );
    snapshot_assert( index < encryption_manager->num_encryption_mappings );
    encryption_manager->expire_time[index] = expire_time;
}


uint8_t * snapshot_encryption_manager_get_send_key( struct snapshot_encryption_manager_t * encryption_manager, int index )
{
    snapshot_assert( encryption_manager );
    if ( index == -1 )
        return NULL;
    snapshot_assert( index >= 0 );
    snapshot_assert( index < encryption_manager->num_encryption_mappings );
    return encryption_manager->send_key + index * SNAPSHOT_KEY_BYTES;
}

uint8_t * snapshot_encryption_manager_get_receive_key( struct snapshot_encryption_manager_t * encryption_manager, int index )
{
    snapshot_assert( encryption_manager );
    if ( index == -1 )
        return NULL;
    snapshot_assert( index >= 0 );
    snapshot_assert( index < encryption_manager->num_encryption_mappings );
    return encryption_manager->receive_key + index * SNAPSHOT_KEY_BYTES;
}

int snapshot_encryption_manager_get_timeout( struct snapshot_encryption_manager_t * encryption_manager, int index )
{
    snapshot_assert( encryption_manager );
    if ( index == -1 )
        return 0;
    snapshot_assert( index >= 0 );
    snapshot_assert( index < encryption_manager->num_encryption_mappings );
    return encryption_manager->timeout[index];
}
