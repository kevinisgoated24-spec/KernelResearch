#pragma once
#import <Metal/Metal.h>
#import <IOSurface/IOSurface.h>

// Wraps makeTexture(descriptor:iosurface:plane:) in an ObjC @try/@catch.
// Returns the texture on success, nil on any exception.
// outException: if non-null and an exception is thrown, filled with the reason string (caller must free).
id<MTLTexture> _Nullable metal_make_texture_safe(
    id<MTLDevice> _Nonnull device,
    MTLTextureDescriptor * _Nonnull descriptor,
    IOSurfaceRef _Nonnull surface,
    NSUInteger plane,
    char * _Nullable * _Nullable outException
);
