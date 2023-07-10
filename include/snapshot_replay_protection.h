/*
    Snapshot Copyright © 2023 Mas Bandwidth LLC. This source code is licensed under GPL version 3 or any later version.
    Commercial licensing under different terms is available. Please email licensing@mas-bandwidth.com for details.
*/

#ifndef SNAPSHOT_REPLAY_PROTECTION_H
#define SNAPSHOT_REPLAY_PROTECTION_H

#include "snapshot.h"

#define SNAPSHOT_REPLAY_PROTECTION_BUFFER_SIZE 256

struct snapshot_replay_protection_t
{
    uint64_t most_recent_sequence;
    uint64_t received_packet[SNAPSHOT_REPLAY_PROTECTION_BUFFER_SIZE];
};

inline void snapshot_replay_protection_reset( struct snapshot_replay_protection_t * replay_protection )
{
    snapshot_assert( replay_protection );
    replay_protection->most_recent_sequence = 0;
    memset( replay_protection->received_packet, 0xFF, sizeof( replay_protection->received_packet ) );
}

inline int snapshot_replay_protection_already_received( struct snapshot_replay_protection_t * replay_protection, uint64_t sequence )
{
    snapshot_assert( replay_protection );

    if ( sequence + SNAPSHOT_REPLAY_PROTECTION_BUFFER_SIZE <= replay_protection->most_recent_sequence )
        return 1;
    
    int index = (int) ( sequence % SNAPSHOT_REPLAY_PROTECTION_BUFFER_SIZE );

    if ( replay_protection->received_packet[index] == UINT64_MAX )
        return 0;

    if ( replay_protection->received_packet[index] >= sequence )
        return 1;

    return 0;
}

inline void snapshot_replay_protection_advance_sequence( struct snapshot_replay_protection_t * replay_protection, uint64_t sequence )
{
    snapshot_assert( replay_protection );

    if ( sequence > replay_protection->most_recent_sequence )
        replay_protection->most_recent_sequence = sequence;

    int index = (int) ( sequence % SNAPSHOT_REPLAY_PROTECTION_BUFFER_SIZE );

    replay_protection->received_packet[index] = sequence;
}

#endif // #ifndef SNAPSHOT_REPLAY_PROTECTION_H
