const std = @import("std");
const base64 = std.base64;
const crypto = std.crypto;
const debug = std.debug;
const fmt = std.fmt;
const fs = std.fs;
const heap = std.heap;
const Io = std.Io;
const json = std.json;
const log = std.log;
const math = std.math;
const mem = std.mem;

const c = @cImport({
    @cInclude("tomcrypt.h");
});

pub fn main() !void {
    var gpa = heap.DebugAllocator(.{}).init;
    defer debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    var in_buf: [1024]u8 = undefined;
    var reader = fs.File.stdin().reader(&in_buf);
    const in = &reader.interface;

    while (true) {
        const raw = try in.take(try in.takeInt(u32, .little));
        log.info("receive: {s}\n", .{raw});
        const wrapper = try json.parseFromSlice(ReceiveWrapper, allocator, raw, .{});
        if (mem.eql(u8, wrapper.value.message.command, "setupEncryption")) {
            try setupEncryption(allocator, wrapper.value);
        }
        wrapper.deinit();
    }
}

const ReceiveWrapper = struct { message: Receive, appId: []const u8 };

const Receive = struct {
    command: []const u8,
    messageId: i32,
    userId: ?[]const u8,
    timestamp: ?u64,
    publicKey: ?[]const u8,
};

const Send = struct {
    appId: []const u8,
    messageId: ?i32,
    command: ?[]const u8,
    sharedSecret: ?[]const u8,
    // message
};

fn setupEncryption(allocator: mem.Allocator, wrapper: ReceiveWrapper) !void {
    const public_key = try allocator.alloc(
        u8,
        try base64.standard.Decoder.calcSizeForSlice(wrapper.message.publicKey.?),
    );
    defer allocator.free(public_key);
    try base64.standard.Decoder.decode(public_key, wrapper.message.publicKey.?);

    var secret: [64]u8 = undefined;
    crypto.random.bytes(&secret);

    var ciphertext_store: [512]u8 = undefined;
    const ciphertext = try rsaEncrypt(&secret, public_key, &ciphertext_store);

    const encoded = try allocator.alloc(u8, base64.standard.Encoder.calcSize(ciphertext.len));
    defer allocator.free(encoded);
    try sendMessage(allocator, .{
        .appId = wrapper.appId,
        .messageId = -1,
        .command = wrapper.message.command,
        .sharedSecret = base64.standard.Encoder.encode(encoded, ciphertext),
    });
}

var stdout_buf: [1024]u8 = undefined;
var stdout_writer = fs.File.stdout().writer(&stdout_buf);

fn sendMessage(allocator: mem.Allocator, message: Send) !void {
    const encoded = try fmt.allocPrint(allocator, "{f}", .{json.fmt(message, .{})});
    defer allocator.free(encoded);

    if (encoded.len > math.maxInt(u32)) {
        return error.MaxPayloadSizeExceeded;
    }
    try stdout_writer.interface.writeInt(u32, @intCast(encoded.len), .little);

    log.info("send: {s}", .{encoded});
    try stdout_writer.interface.writeAll(encoded);
    try stdout_writer.interface.flush();
}

fn rsaEncrypt(plaintext: []const u8, public_key: []const u8, ciphertext: []u8) ![]const u8 {
    if (c.register_prng(&c.sprng_desc) == -1) {
        return error.RegisterPRNG;
    }

    c.ltc_mp = c.tfm_desc;
    if (c.register_hash(&c.sha1_desc) == -1) {
        return error.RegisterHash;
    }

    var err = c.CRYPT_OK;
    var key: c.rsa_key = undefined;
    err = c.rsa_import(public_key.ptr, public_key.len, &key);
    if (err != c.CRYPT_OK) {
        log.err("rsaEncrypt: {s}", .{c.error_to_string(err)});
        return error.DecodeKey;
    }

    var ciphertext_len = ciphertext.len;
    err = c.rsa_encrypt_key(
        plaintext.ptr,
        plaintext.len,
        ciphertext.ptr,
        &ciphertext_len,
        null,
        0,
        null,
        c.find_prng("sprng"),
        c.find_hash("sha1"),
        &key,
    );
    if (err != c.CRYPT_OK) {
        log.err("rsaEncrypt: {s}", .{c.error_to_string(err)});
        return error.Encrypt;
    }

    return ciphertext[0..ciphertext_len];
}
