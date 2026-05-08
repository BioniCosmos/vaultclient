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
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;

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
            const enc = try json.parseFromValue(
                EncString.Fields,
                allocator,
                wrapper.value.message,
                .{ .ignore_unknown_fields = true },
            );
            defer enc.deinit();

            const message = try decryptMessage(allocator, &enc.value, &session_key);
            defer message.deinit();

            if (mem.eql(u8, message.value.command, "getBiometricsStatus")) {
                try sendInner(allocator, io, .{
                    .command = message.value.command,
                    .messageId = message.value.messageId,
                    .response = .{ .integer = 0 },
                }, wrapper.value.appId);
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
        iv: [24]u8,
        mac: [44]u8,
    };

    fields: Fields,
    arena: ?heap.ArenaAllocator = null,

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

const SendInner = struct { command: []const u8, messageId: i32, response: json.Value, timestamp: i64 = 0 };

fn setupEncryption(allocator: mem.Allocator, io: Io, message: *const Receive, appId: []const u8) !void {
    var public_key: [294]u8 = undefined;
    try base64.standard.Decoder.decode(&public_key, message.publicKey.?);

    var secret: [64]u8 = undefined;
    io.random(&secret);
    session_key = secret;
    log.debug("key: {s}", .{fmt.bytesToHex(secret, .lower)});

    var ciphertext_store: [512]u8 = undefined;
    const ciphertext = try rsaEncrypt(&secret, &public_key, &ciphertext_store);

    const encoded = try base64Encode(allocator, ciphertext);
    defer allocator.free(encoded);

    try send(allocator, .{
        .appId = appId,
        .messageId = -1,
        .command = message.command,
        .sharedSecret = encoded,
    });
}

fn decryptMessage(allocator: mem.Allocator, enc: *const EncString.Fields, key: *const [64]u8) !json.Parsed(Receive) {
    const enc_key = key[0..32];

    var iv: [16]u8 = undefined;
    try base64.standard.Decoder.decode(&iv, &enc.iv);

    const encrypted_bytes = try base64Decode(allocator, enc.data);
    defer allocator.free(encrypted_bytes);

    const json_encoded = try aesDecrypt(@constCast(encrypted_bytes), enc_key, &iv);
    log.info("decrypted: {s}", .{json_encoded});

    return try json.parseFromSlice(Receive, allocator, json_encoded, .{ .allocate = .alloc_always });
}

fn encryptMessage(allocator: mem.Allocator, io: Io, message: SendInner, key: *const [64]u8) !EncString {
    const json_encoded = try json.Stringify.valueAlloc(allocator, message, .{});
    defer allocator.free(json_encoded);

    const enc_key = key[0..32];
    const auth_key = key[32..];

    var iv: [16]u8 = undefined;
    io.random(&iv);

    const encrypted = try aesEncrypt(allocator, json_encoded, enc_key, &iv);
    defer allocator.free(encrypted);

    const mac = hmacGenerate(&.{ &iv, encrypted }, auth_key);

    var arena = heap.ArenaAllocator.init(allocator);
    const alloc = arena.allocator();

    const base64_encoded_encrypted = try base64Encode(alloc, encrypted);

    var encoded_iv: [24]u8 = undefined;
    _ = base64.standard.Encoder.encode(&encoded_iv, &iv);

    var encoded_mac: [44]u8 = undefined;
    _ = base64.standard.Encoder.encode(&encoded_mac, &mac);

    return .{
        .fields = .{
            .encryptedString = try fmt.allocPrint(
                alloc,
                "2.{s}|{s}|{s}",
                .{ encoded_iv, base64_encoded_encrypted, encoded_mac },
            ),
            .data = base64_encoded_encrypted,
            .iv = encoded_iv,
            .mac = encoded_mac,
        },
        .arena = arena,
    };
}

fn sendInner(allocator: mem.Allocator, io: Io, message: SendInner, appId: []const u8) !void {
    var mut = message;
    mut.timestamp = Io.Clock.real.now(io).toMilliseconds();

    const enc = try encryptMessage(allocator, io, mut, &session_key);
    defer enc.deinit();

    try send(allocator, .{ .appId = appId, .messageId = mut.messageId, .message = enc.fields });
}

var stdout_buf: [1024]u8 = undefined;
var stdout_writer: Io.File.Writer = undefined;

fn send(allocator: mem.Allocator, message: Send) !void {
    const encoded = try json.Stringify.valueAlloc(allocator, message, .{});
    defer allocator.free(encoded);

    if (encoded.len > math.maxInt(u32)) {
        return error.MaxPayloadSizeExceeded;
    }
    try stdout_writer.interface.writeInt(u32, @intCast(encoded.len), .little);

    log.info("send: {s}", .{encoded});
    try stdout_writer.interface.writeAll(encoded);
    try stdout_writer.interface.flush();
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

// crypto utilities

const CryptoError = error{ Encryption, Decryption, InvalidPadding, InvalidKey } || mem.Allocator.Error;

fn rsaEncrypt(plaintext: []const u8, public_key: []const u8, ciphertext_buf: []u8) CryptoError![]const u8 {
    var err = c.CRYPT_OK;
    var key: c.rsa_key = undefined;
    err = c.rsa_import(public_key.ptr, public_key.len, &key);
    if (err != c.CRYPT_OK) {
        log.err("rsaEncrypt: {s}", .{c.error_to_string(err)});
        return CryptoError.InvalidKey;
    }

    var ciphertext_len = ciphertext_buf.len;
    err = c.rsa_encrypt_key(
        plaintext.ptr,
        plaintext.len,
        ciphertext_buf.ptr,
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
        return CryptoError.Encryption;
    }

    return ciphertext_buf[0..ciphertext_len];
}

fn aesEncrypt(
    allocator: mem.Allocator,
    plaintext: []const u8,
    key: *const [32]u8,
    iv: *const [16]u8,
) CryptoError![]const u8 {
    const ciphertext = try pkcs7Pad(allocator, plaintext);
    var err = c.CRYPT_OK;

    var cbc: c.symmetric_CBC = undefined;
    err = c.cbc_start(c.find_cipher("aes"), iv, key, key.len, 14, &cbc);
    if (err != c.CRYPT_OK) {
        log.err("aesEncrypt: {s}", .{c.error_to_string(err)});
        return CryptoError.Encryption;
    }

    err = c.cbc_encrypt(ciphertext.ptr, @constCast(ciphertext.ptr), ciphertext.len, &cbc);
    if (err != c.CRYPT_OK) {
        log.err("aesEncrypt: {s}", .{c.error_to_string(err)});
        return CryptoError.Encryption;
    }

    err = c.cbc_done(&cbc);
    if (err != c.CRYPT_OK) {
        log.err("aesEncrypt: {s}", .{c.error_to_string(err)});
        return CryptoError.Encryption;
    }

    return ciphertext;
}

fn aesDecrypt(ciphertext: []u8, key: *const [32]u8, iv: *const [16]u8) CryptoError![]const u8 {
    var err = c.CRYPT_OK;
    var cbc: c.symmetric_CBC = undefined;
    err = c.cbc_start(c.find_cipher("aes"), iv, key, key.len, 14, &cbc);
    if (err != c.CRYPT_OK) {
        log.err("aesDecrypt: {s}", .{c.error_to_string(err)});
        return CryptoError.Decryption;
    }

    err = c.cbc_decrypt(ciphertext.ptr, ciphertext.ptr, ciphertext.len, &cbc);
    if (err != c.CRYPT_OK) {
        log.err("aesDecrypt: {s}", .{c.error_to_string(err)});
        return CryptoError.Decryption;
    }

    err = c.cbc_done(&cbc);
    if (err != c.CRYPT_OK) {
        log.err("aesDecrypt: {s}", .{c.error_to_string(err)});
        return CryptoError.Decryption;
    }

    return pkcs7Unpad(ciphertext);
}

fn hmacGenerate(payload: []const []const u8, key: []const u8) [HmacSha256.mac_length]u8 {
    var mac: [HmacSha256.mac_length]u8 = undefined;
    var hmac = HmacSha256.init(key);
    for (payload) |x| {
        hmac.update(x);
    }
    hmac.final(&mac);
    return mac;
}

fn pkcs7Pad(allocator: mem.Allocator, data: []const u8) CryptoError![]const u8 {
    const len = 16 - data.len % 16;
    const padded = try allocator.alloc(u8, data.len + len);
    @memcpy(padded[0..data.len], data);
    @memset(padded[data.len..], @intCast(len));
    return padded;
}

fn pkcs7Unpad(data: []const u8) CryptoError![]const u8 {
    if (data.len == 0) {
        return data;
    }

    const len = data[data.len - 1];
    if (len == 0 or len > data.len) {
        return CryptoError.InvalidPadding;
    }

    const start = data.len - len;
    if (!mem.allEqual(u8, data[start..], len)) {
        return CryptoError.InvalidPadding;
    }
    return data[0..start];
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
