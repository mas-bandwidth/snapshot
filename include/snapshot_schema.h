/*
    Snapshot 

    Copyright © 2023 - 2024 Más Bandwidth LLC. 

    This source code is licensed under GPL version 3 or any later version.

    Commercial licensing under different terms is available. Email licensing@mas-bandwidth.com for details
*/

#ifndef SNAPSHOT_SCHEMA_H
#define SNAPSHOT_SCHEMA_H

#include "snapshot.h"

#define PROPERTY_TYPE_BOOLEAN       0
#define PROPERTY_TYPE_INT32         1
#define PROPERTY_TYPE_UINT32        2
#define PROPERTY_TYPE_INT64         3
#define PROPERTY_TYPE_UINT64        4
#define PROPERTY_TYPE_FLOAT32       5
#define PROPERTY_TYPE_FLOAT64       6
#define PROPERTY_TYPE_VECTOR3       7
#define PROPERTY_TYPE_QUATERNION    8
#define PROPERTY_TYPE_STRING        9
#define PROPERTY_TYPE_DATA_BLOCK   10
#define PROPERTY_TYPE_NETWORK_ID   11

#define NUM_PROPERTY_TYPES 12

struct snapshot_schema_t * snapshot_schema_create();

void snapshot_schema_destroy( struct snapshot_schema_t * schema );

void snapshot_schema_add_table( struct snapshot_schema_t * schema, const char * name );

void snapshot_schema_add_message( struct snapshot_schema_t * schema, const char * name );

void snapshot_schema_add_property_boolean( struct snapshot_schema_t * schema, const char * name, bool default_value );

void snapshot_schema_add_property_int32( struct snapshot_schema_t * schema, const char * name, int32_t default_value );

void snapshot_schema_add_property_uint32( struct snapshot_schema_t * schema, const char * name, uint32_t default_value );

void snapshot_schema_add_property_int64( struct snapshot_schema_t * schema, const char * name, int64_t default_value );

void snapshot_schema_add_property_uint64( struct snapshot_schema_t * schema, const char * name, uint64_t default_value );

void snapshot_schema_add_property_float32( struct snapshot_schema_t * schema, const char * name, float default_value );

void snapshot_schema_add_property_float64( struct snapshot_schema_t * schema, const char * name, double default_value );

void snapshot_schema_add_property_vector3( struct snapshot_schema_t * schema, const char * name, float default_x, float default_y, float default_z );

void snapshot_schema_add_property_quaternion( struct snapshot_schema_t * schema, const char * name, float default_x, float default_y, float default_z, float default_w );

void snapshot_schema_add_property_network_id( struct snapshot_schema_t * schema, const char * name );

void snapshot_schema_add_property_string( struct snapshot_schema * schema, const char * name, const char * default_value, int max_length );

void snapshot_schema_add_property_data_block( struct snapshot_schema_t * schema, const char * name, int max_bytes );

void snapshot_schema_set_property_flags( struct snapshot_schema * schema, uint64_t flags );

void snapshot_schema_add_object_type( struct snapshot_schema_t * schema, const char * name );

void snapshot_schema_add_table_to_object( struct snapshot_schema_t * schema, const char * object_type_name, const char * table_name );

void snapshot_schema_lock( struct snapshot_schema_t * schema );

bool snapshot_schema_is_locked( struct snapshot_schema_t * schema );

int snapshot_schema_get_num_tables( struct snapshot_schema_t * schema );

int snapshot_schema_get_num_messages( struct snapshot_schema_t * schema );

int snapshot_schema_get_num_object_types( struct snapshot_schema_t * schema );

int snapshot_schema_get_message_index( struct snapshot_schema_t * schema, const char * message_name );

int snapshot_schema_get_table_index( struct snapshot_schema_t * schema, const char * table_name );

int snapshot_schema_get_object_type( struct snapshot_schema_t * schema, const char * object_type_name );

#endif // #ifndef SNAPSHOT_SCHEMA_H
