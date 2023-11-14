const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const WCHAR = windows.WCHAR;
const PVOID = windows.PVOID;
const SIZE_T = windows.SIZE_T;
const WINAPI = windows.WINAPI;

const in6addr_any = [_]u8{0} ** 16;
const GAI_STRERROR_BUFFER_SIZE = 1024;

comptime {
    if (builtin.os.tag == .windows) {
        @export(in6addr_any, .{ .name = "in6addr_any" });
        @export(gai_strerrorA, .{ .name = "gai_strerrorA" });
        @export(RtlSecureZeroMemory, .{ .name = "RtlSecureZeroMemory" });
    }
}

inline fn MAKELANGID(p: c_ushort, s: c_ushort) windows.LANGID {
    return (s << 10) | p;
}

fn gai_strerrorW(ecode: c_int) callconv(.C) [*c]WCHAR {
    const static = struct {
        var buf: [GAI_STRERROR_BUFFER_SIZE + 1]WCHAR = [_]WCHAR{0} ** (GAI_STRERROR_BUFFER_SIZE + 1);
    };
    var len = windows.kernel32.FormatMessageW(
        windows.FORMAT_MESSAGE_FROM_SYSTEM |
            windows.FORMAT_MESSAGE_IGNORE_INSERTS |
            windows.FORMAT_MESSAGE_MAX_WIDTH_MASK,
        null,
        @enumFromInt(ecode),
        MAKELANGID(windows.LANG.NEUTRAL, windows.SUBLANG.DEFAULT),
        @ptrCast(&static.buf),
        GAI_STRERROR_BUFFER_SIZE,
        null,
    );
    std.debug.assert(len < GAI_STRERROR_BUFFER_SIZE);
    return @ptrCast(&static.buf);
}

fn gai_strerrorA(ecode: c_int) callconv(.C) [*c]u8 {
    const static = struct {
        var buf: [GAI_STRERROR_BUFFER_SIZE + 1]u8 = [_]u8{0} ** (GAI_STRERROR_BUFFER_SIZE + 1);
    };
    var len = std.unicode.utf16leToUtf8(&static.buf, std.mem.span(gai_strerrorW(ecode))) catch
        return null;
    std.debug.assert(len < GAI_STRERROR_BUFFER_SIZE);
    return @ptrCast(&static.buf);
}

fn RtlSecureZeroMemory(ptr: PVOID, cnt: SIZE_T) callconv(WINAPI) PVOID {
    @memset(@as([*]u8, @ptrCast(ptr))[0..cnt], 0);
    return ptr;
}
