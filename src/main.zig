const std = @import("std");
const base64 = std.base64;
const crypto = std.crypto;
const debug = std.debug;
const fmt = std.fmt;
const heap = std.heap;
const Io = std.Io;
const json = std.json;
const log = std.log;
const math = std.math;
const mem = std.mem;
const process = std.process;

const c = @import("c");

var session_key: [64]u8 = undefined;

pub fn main(init: process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    try initCrypto();

    var in_buf: [1024]u8 = undefined;
    var reader = Io.File.stdin().reader(io, &in_buf);
    const in = &reader.interface;
    stdout_writer = Io.File.stdout().writer(io, &stdout_buf);

    while (true) {
        const raw = try in.take(try in.takeInt(u32, .little));
        log.info("receive: {s}", .{raw});

        const wrapper = try json.parseFromSlice(ReceiveWrapper, allocator, raw, .{});
        defer wrapper.deinit();

        if (wrapper.value.message.object.contains("command")) {
            const message = try json.parseFromValue(Receive, allocator, wrapper.value.message, .{});
            defer message.deinit();

            if (mem.eql(u8, message.value.command, "setupEncryption")) {
                try setupEncryption(allocator, io, &message.value, wrapper.value.appId);
            }
        } else {
            const encrypted = try json.parseFromValue(
                EncString.Fields,
                allocator,
                wrapper.value.message,
                .{ .ignore_unknown_fields = true },
            );
            defer encrypted.deinit();

            const message = try decryptMessage(allocator, &encrypted.value, &session_key);
            defer message.deinit();

            if (mem.eql(u8, message.value.command, "getBiometricsStatus")) {
                const encrypted_send = try encryptMessage(allocator, io, .{
                    .command = message.value.command,
                    .messageId = message.value.messageId,
                    .response = .{ .integer = 0 },
                    .timestamp = Io.Clock.real.now(io).toMilliseconds(),
                }, &session_key);
                defer encrypted_send.deinit();

                try sendMessage(allocator, .{
                    .appId = wrapper.value.appId,
                    .messageId = message.value.messageId,
                    .message = encrypted_send.fields,
                });
            }
        }
    }
}

const EncString = struct {
    const Self = @This();
    const Fields = struct {
        encryptedString: []const u8,
        encryptionType: u8 = 2,
        data: []const u8,
        iv: []const u8,
        mac: []const u8,
    };

    fields: Fields,
    arena: ?heap.ArenaAllocator = null,

    fn init(allocator: mem.Allocator, v: Self) !Self {
        const arena = heap.ArenaAllocator.init(allocator);
        const alloc = arena.allocator();
        return .{
            .encryptedString = try alloc.dupe(u8, v.encryptedString),
            .encryptionType = v.encryptionType,
            .data = try alloc.dupe(u8, v.data),
            .iv = try alloc.dupe(u8, v.iv),
            .mac = try alloc.dupe(u8, v.iv),
            .arena = arena,
        };
    }

    fn deinit(self: *const Self) void {
        self.arena.?.deinit();
    }
};

const ReceiveWrapper = struct { message: json.Value, appId: []const u8 };

const Receive = struct {
    command: []const u8,
    messageId: i32,
    userId: []const u8,
    timestamp: i64,
    publicKey: ?[]const u8 = null,
};

const Send = struct {
    appId: []const u8,
    messageId: i32,
    command: ?[]const u8 = null,
    sharedSecret: ?[]const u8 = null,
    message: ?EncString.Fields = null,
};

const SendInner = struct { command: []const u8, messageId: i32, response: json.Value, timestamp: i64 };

fn setupEncryption(allocator: mem.Allocator, io: Io, message: *const Receive, appId: []const u8) !void {
    const public_key = try base64Decode(allocator, message.publicKey.?);
    defer allocator.free(public_key);

    var secret: [64]u8 = undefined;
    io.random(&secret);
    session_key = secret;
    log.debug("key: {s}", .{fmt.bytesToHex(secret, .lower)});

    var ciphertext_store: [512]u8 = undefined;
    const ciphertext = try rsaEncrypt(&secret, public_key, &ciphertext_store);

    const encoded = try base64Encode(allocator, ciphertext);
    defer allocator.free(encoded);

    try sendMessage(allocator, .{
        .appId = appId,
        .messageId = -1,
        .command = message.command,
        .sharedSecret = encoded,
    });
}

fn decryptMessage(
    allocator: mem.Allocator,
    encrypted: *const EncString.Fields,
    key: *const [64]u8,
) !json.Parsed(Receive) {
    const enc_key = key[0..32];

    const iv = try base64Decode(allocator, encrypted.iv);
    defer allocator.free(iv);

    const message = try base64Decode(allocator, encrypted.data);
    defer allocator.free(message);

    var err = c.CRYPT_OK;
    var cbc: c.symmetric_CBC = undefined;
    err = c.cbc_start(c.find_cipher("aes"), iv.ptr, enc_key, enc_key.len, 14, &cbc);
    if (err != c.CRYPT_OK) {
        log.err("decryptMessage: {s}", .{c.error_to_string(err)});
        return error.DecryptMessage;
    }

    err = c.cbc_decrypt(message.ptr, @constCast(message.ptr), message.len, &cbc);
    if (err != c.CRYPT_OK) {
        log.err("decryptMessage: {s}", .{c.error_to_string(err)});
        return error.DecryptMessage;
    }

    err = c.cbc_done(&cbc);
    if (err != c.CRYPT_OK) {
        log.err("decryptMessage: {s}", .{c.error_to_string(err)});
        return error.DecryptMessage;
    }

    const unpadded = try unpadPKCS7(message);
    log.info("decrypted: {s}", .{unpadded});

    return try json.parseFromSlice(Receive, allocator, unpadded, .{ .allocate = .alloc_always });
}

fn encryptMessage(allocator: mem.Allocator, io: Io, message: SendInner, key: *const [64]u8) !EncString {
    const enc_key = key[0..32];
    const auth_key = key[32..];

    var iv: [16]u8 = undefined;
    io.random(&iv);

    const encoded = try fmt.allocPrint(allocator, "{f}", .{json.fmt(message, .{})});
    defer allocator.free(encoded);

    const bytes = try padPKCS7(allocator, encoded);
    defer allocator.free(bytes);

    var err = c.CRYPT_OK;
    var cbc: c.symmetric_CBC = undefined;
    err = c.cbc_start(c.find_cipher("aes"), &iv, enc_key, enc_key.len, 14, &cbc);
    if (err != c.CRYPT_OK) {
        log.err("decryptMessage: {s}", .{c.error_to_string(err)});
        return error.DecryptMessage;
    }

    err = c.cbc_encrypt(bytes.ptr, @constCast(bytes.ptr), bytes.len, &cbc);
    if (err != c.CRYPT_OK) {
        log.err("decryptMessage: {s}", .{c.error_to_string(err)});
        return error.DecryptMessage;
    }

    err = c.cbc_done(&cbc);
    if (err != c.CRYPT_OK) {
        log.err("decryptMessage: {s}", .{c.error_to_string(err)});
        return error.DecryptMessage;
    }

    const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    var hmac = HmacSha256.init(auth_key);
    hmac.update(&iv);
    hmac.update(bytes);
    hmac.final(&mac);

    var arena = heap.ArenaAllocator.init(allocator);
    const alloc = arena.allocator();

    const encoded_iv = try base64Encode(alloc, &iv);
    const encoded_message = try base64Encode(alloc, bytes);
    const encoded_mac = try base64Encode(alloc, &mac);

    return .{
        .fields = .{
            .encryptedString = try fmt.allocPrint(
                alloc,
                "2.{s}|{s}|{s}",
                .{ encoded_iv, encoded_message, encoded_mac },
            ),
            .data = encoded_message,
            .iv = encoded_iv,
            .mac = encoded_mac,
        },
        .arena = arena,
    };
}

var stdout_buf: [1024]u8 = undefined;
var stdout_writer: Io.File.Writer = undefined;

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

fn unpadPKCS7(data: []const u8) ![]const u8 {
    if (data.len == 0) {
        return data;
    }

    const len = data[data.len - 1];
    if (len == 0 or len > data.len) {
        return error.InvalidPadding;
    }

    const start = data.len - len;
    if (!mem.allEqual(u8, data[start..], len)) {
        return error.InvalidPadding;
    }
    return data[0..start];
}

fn padPKCS7(allocator: mem.Allocator, data: []const u8) ![]const u8 {
    const len = 16 - data.len % 16;
    const padded = try allocator.alloc(u8, data.len + len);
    @memcpy(padded[0..data.len], data);
    @memset(padded[data.len..], @intCast(len));
    return padded;
}

fn base64Encode(allocator: mem.Allocator, raw: []const u8) ![]const u8 {
    const encoded = try allocator.alloc(u8, base64.standard.Encoder.calcSize(raw.len));
    return base64.standard.Encoder.encode(encoded, raw);
}

fn base64Decode(allocator: mem.Allocator, encoded: []const u8) ![]const u8 {
    const raw = try allocator.alloc(u8, try base64.standard.Decoder.calcSizeForSlice(encoded));
    try base64.standard.Decoder.decode(raw, encoded);
    return raw;
}

fn initCrypto() !void {
    c.ltc_mp = c.tfm_desc;

    if (c.register_prng(&c.sprng_desc) == -1) {
        return error.RegisterPRNG;
    }

    if (c.register_hash(&c.sha1_desc) == -1) {
        return error.RegisterHash;
    }

    if (c.register_cipher(&c.aes_desc) == -1) {
        return error.RegisterCipher;
    }
}
