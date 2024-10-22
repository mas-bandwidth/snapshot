/*
    Snapshot 

    Copyright © 2023 - 2024 Más Bandwidth LLC. 

    This source code is licensed under GPL version 3 or any later version.

    Commercial licensing under different terms is available. Email licensing@mas-bandwidth.com for details
*/

#include "snapshot_schema.h"

struct snapshot_schema_t
{
    void * context;
};

struct snapshot_schema_t * snapshot_schema_create( void * context )
{
    struct snapshot_schema_t * schema = (struct snapshot_schema_t*) snapshot_malloc( context, sizeof( struct snapshot_schema_t ) );

    if ( !schema )
        return NULL;

    memset( schema, 0, sizeof( struct snapshot_schema_t ) );

    schema->context = context;

    // ...

    return schema;
}

void snapshot_schema_destroy( struct snapshot_schema_t * schema )
{
    snapshot_assert( schema );
    if ( schema )
    {
        snapshot_free( schema->context, schema );
        memset( schema, 0, sizeof( struct snapshot_schema_t ) );
    }
}

void snapshot_schema_add_table( struct snapshot_schema_t * schema, const char * name )
{
    // ...
    (void) schema;
    (void) name;
}

void snapshot_schema_add_message( struct snapshot_schema_t * schema, const char * name )
{
    // ...
    (void) schema;
    (void) name;
}

void snapshot_schema_add_property_boolean( struct snapshot_schema_t * schema, const char * name, SNAPSHOT_BOOL default_value )
{
    // ...
    (void) schema;
    (void) name;
    (void) default_value;
}

void snapshot_schema_add_property_int32( struct snapshot_schema_t * schema, const char * name, int32_t default_value )
{
    // ...
    (void) schema;
    (void) name;
    (void) default_value;
}

void snapshot_schema_add_property_uint32( struct snapshot_schema_t * schema, const char * name, uint32_t default_value )
{
    // ...
    (void) schema;
    (void) name;
    (void) default_value;
}

void snapshot_schema_add_property_int64( struct snapshot_schema_t * schema, const char * name, int64_t default_value )
{
    // ...
    (void) schema;
    (void) name;
    (void) default_value;
}

void snapshot_schema_add_property_uint64( struct snapshot_schema_t * schema, const char * name, uint64_t default_value )
{
    // ...
    (void) schema;
    (void) name;
    (void) default_value;
}

void snapshot_schema_add_property_float32( struct snapshot_schema_t * schema, const char * name, float default_value )
{
    // ...
    (void) schema;
    (void) name;
    (void) default_value;
}

void snapshot_schema_add_property_float64( struct snapshot_schema_t * schema, const char * name, double default_value )
{
    // ...
    (void) schema;
    (void) name;
    (void) default_value;
}

void snapshot_schema_add_property_vector3( struct snapshot_schema_t * schema, const char * name, float default_x, float default_y, float default_z )
{
    // ...
    (void) schema;
    (void) name;
    (void) default_x;
    (void) default_y;
    (void) default_z;
}

void snapshot_schema_add_property_quaternion( struct snapshot_schema_t * schema, const char * name, float default_x, float default_y, float default_z, float default_w )
{
    // ...
    (void) schema;
    (void) name;
    (void) default_x;
    (void) default_y;
    (void) default_z;
    (void) default_w;
}

void snapshot_schema_add_property_network_id( struct snapshot_schema_t * schema, const char * name )
{
    // ...
    (void) schema;
    (void) name;
}

void snapshot_schema_add_property_string( struct snapshot_schema_t * schema, const char * name, const char * default_value, int max_length )
{
    // ...
    (void) schema;
    (void) name;
    (void) default_value;
    (void) max_length;
}

void snapshot_schema_add_property_data_block( struct snapshot_schema_t * schema, const char * name, int max_bytes )
{
    // ...
    (void) schema;
    (void) name;
    (void) max_bytes;
}

void snapshot_schema_set_property_flags( struct snapshot_schema_t * schema, uint64_t flags )
{
    // ...
    (void) schema;
    (void) flags;
}

void snapshot_schema_add_object_type( struct snapshot_schema_t * schema, const char * name )
{
    // ...
    (void) schema;
    (void) name;
}

void snapshot_schema_add_table_to_object( struct snapshot_schema_t * schema, const char * table_name )
{
    // ...
    (void) schema;
    (void) table_name;
}

void snapshot_schema_lock( struct snapshot_schema_t * schema )
{
    // ...
    (void) schema;
}

SNAPSHOT_BOOL snapshot_schema_is_locked( struct snapshot_schema_t * schema )
{
    // ...
    (void) schema;
    return SNAPSHOT_FALSE;
}

int snapshot_schema_get_num_tables( struct snapshot_schema_t * schema )
{
    // ...
    (void) schema;
    return 0;// todo
}

int snapshot_schema_get_num_messages( struct snapshot_schema_t * schema )
{
    // ...
    (void) schema;
    return 0;// todo
}

int snapshot_schema_get_num_object_types( struct snapshot_schema_t * schema )
{
    // ...
    (void) schema;
    return 0;// todo
}

int snapshot_schema_get_message_index( struct snapshot_schema_t * schema, const char * message_name )
{
    // ...
    (void) schema;
    (void) message_name;
    return -1; // todo
}

int snapshot_schema_get_table_index( struct snapshot_schema_t * schema, const char * table_name )
{
    // ...
    (void) schema;
    (void) table_name;
    return -1; // todo
}

int snapshot_schema_get_object_type( struct snapshot_schema_t * schema, const char * object_type_name )
{
    // ...
    (void) schema;
    (void) object_type_name;
    return -1; // todo
}
