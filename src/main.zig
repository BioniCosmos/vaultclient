const std = @import("std");
const fs = std.fs;

pub fn main() !void {
    var in_buf: [1024]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    var reader = fs.File.stdin().reader(&in_buf);
    var writer = (try fs.cwd().createFile("message.log", .{ .truncate = false })).writer(&out_buf);
    defer writer.file.close();

    const in = &reader.interface;
    const out = &writer.interface;

    while (true) {
        try out.print("{s}\n", .{try in.take(try in.takeInt(u32, .little))});
        try out.flush();
    }
}
