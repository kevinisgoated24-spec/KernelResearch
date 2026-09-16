#import "metal_trampoline.h"
#import <Foundation/Foundation.h>

id<MTLTexture> _Nullable metal_make_texture_safe(
    id<MTLDevice> _Nonnull device,
    MTLTextureDescriptor * _Nonnull descriptor,
    IOSurfaceRef _Nonnull surface,
    NSUInteger plane,
    char * _Nullable * _Nullable outException
) {
    id<MTLTexture> result = nil;
    @try {
        result = [device newTextureWithDescriptor:descriptor iosurface:surface plane:plane];
    }
    @catch (NSException *e) {
        if (outException) {
            const char *reason = e.reason.UTF8String ?: "unknown";
            size_t len = strlen(reason) + 1;
            char *buf = malloc(len);
            if (buf) memcpy(buf, reason, len);
            *outException = buf;
        }
    }
    return result;
}
