//! 最小 RESP2 客户端（只覆盖会话存储需要的命令：GET / SET / DEL / EXISTS / TTL）。
//!
//! 设计取舍：
//! - **每次操作新建连接、用完即关**：实现简单、天然线程安全、不持有跨线程 socket；
//!   会话读写的频率远低于业务请求，代价可接受。需要连接复用时由上层缓存整份结果。
//! - 只用 `std.Io.net`，不引第三方依赖。
//! - 不做 RESP3、不做集群、不做 TLS（生产如需 TLS，走前置代理或后续扩展）。

const std = @import("std");

pub const Error = error{
    Connect,
    Io,
    Protocol,
    OutOfMemory,
};

/// 一条 RESP 回复。
pub const Reply = union(enum) {
    /// `+OK`
    status: []u8,
    /// `-ERR ...`
    err: []u8,
    /// `:123`
    int: i64,
    /// `$5\r\nhello` / `$-1`（nil）
    bulk: ?[]u8,
    /// `*N\r\n...`
    array: []Reply,

    pub fn deinit(self: Reply, allocator: std.mem.Allocator) void {
        switch (self) {
            .status => |s| allocator.free(s),
            .err => |s| allocator.free(s),
            .int => {},
            .bulk => |b| if (b) |s| allocator.free(s),
            .array => |items| {
                for (items) |item| item.deinit(allocator);
                allocator.free(items);
            },
        }
    }

    /// `+OK` / `:1` / `$...` 视为成功；`-ERR` 视为失败。
    pub fn isOk(self: Reply) bool {
        return switch (self) {
            .err => false,
            .bulk => |b| b != null,
            else => true,
        };
    }

    pub fn asText(self: Reply) ?[]const u8 {
        return switch (self) {
            .status => |s| s,
            .bulk => |b| b,
            .err => |s| s,
            else => null,
        };
    }
};

/// 命令编码：`*N\r\n$len\r\narg\r\n...`（RESP2 数组形式）。
pub fn encodeCommand(allocator: std.mem.Allocator, args: []const []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var buf: [32]u8 = undefined;
    try out.appendSlice(allocator, try std.fmt.bufPrint(&buf, "*{d}\r\n", .{args.len}));
    for (args) |arg| {
        try out.appendSlice(allocator, try std.fmt.bufPrint(&buf, "${d}\r\n", .{arg.len}));
        try out.appendSlice(allocator, arg);
        try out.appendSlice(allocator, "\r\n");
    }
    return out.toOwnedSlice(allocator);
}

/// 回复解析器：从一段已读入内存的字节流里按 RESP2 语法取一条回复。
pub const Parser = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Parser {
        return .{ .buf = buf };
    }

    /// 消费完一条回复后剩余的字节（用于判断是否还有后续回复）。
    pub fn rest(self: Parser) []const u8 {
        return self.buf[self.pos..];
    }

    /// 解析一条回复；数据不完整时返回 `error.Protocol`（调用方应继续读）。
    pub fn parse(self: *Parser, allocator: std.mem.Allocator) !Reply {
        const tag = try self.takeByte();
        switch (tag) {
            '+' => return .{ .status = try self.takeLine(allocator) },
            '-' => return .{ .err = try self.takeLine(allocator) },
            ':' => {
                const line = try self.takeLineView();
                return .{ .int = std.fmt.parseInt(i64, line, 10) catch return error.Protocol };
            },
            '$' => {
                const line = try self.takeLineView();
                const len = std.fmt.parseInt(i64, line, 10) catch return error.Protocol;
                if (len < 0) return .{ .bulk = null };
                const n: usize = @intCast(len);
                if (self.pos + n + 2 > self.buf.len) return error.Protocol;
                const data = try allocator.dupe(u8, self.buf[self.pos .. self.pos + n]);
                self.pos += n + 2; // 跳过 CRLF
                return .{ .bulk = data };
            },
            '*' => {
                const line = try self.takeLineView();
                const count = std.fmt.parseInt(i64, line, 10) catch return error.Protocol;
                if (count < 0) return .{ .array = try allocator.alloc(Reply, 0) };
                const n: usize = @intCast(count);
                var items = try allocator.alloc(Reply, n);
                var filled: usize = 0;
                errdefer {
                    for (items[0..filled]) |item| item.deinit(allocator);
                    allocator.free(items);
                }
                while (filled < n) : (filled += 1) {
                    items[filled] = try self.parse(allocator);
                }
                return .{ .array = items };
            },
            else => return error.Protocol,
        }
    }

    fn takeByte(self: *Parser) !u8 {
        if (self.pos >= self.buf.len) return error.Protocol;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }

    fn takeLineView(self: *Parser) ![]const u8 {
        const start = self.pos;
        while (self.pos + 1 < self.buf.len) : (self.pos += 1) {
            if (self.buf[self.pos] == '\r' and self.buf[self.pos + 1] == '\n') {
                const line = self.buf[start..self.pos];
                self.pos += 2;
                return line;
            }
        }
        return error.Protocol;
    }

    fn takeLine(self: *Parser, allocator: std.mem.Allocator) ![]u8 {
        const view = try self.takeLineView();
        return allocator.dupe(u8, view) catch return error.OutOfMemory;
    }
};

/// 一个短连接客户端：`connect` → `cmd`（可多次）→ `deinit`。
pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    rbuf: [8192]u8 = undefined,
    rlen: usize = 0,

    /// 连接 Redis。`host` 支持 IPv4 / IPv6 字面量；域名请先自行解析（或用 `connectHost`）。
    pub fn connect(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16) Error!Client {
        const addr = std.Io.net.IpAddress.parse(host, port) catch return error.Connect;
        const stream = addr.connect(io, .{}) catch return error.Connect;
        return .{ .allocator = allocator, .io = io, .stream = stream };
    }

    pub fn deinit(self: *Client) void {
        self.stream.close(self.io);
        self.* = undefined;
    }

    /// 执行一条命令并返回回复；调用方负责 `reply.deinit(allocator)`。
    pub fn cmd(self: *Client, args: []const []const u8) Error!Reply {
        const payload = encodeCommand(self.allocator, args) catch return error.OutOfMemory;
        defer self.allocator.free(payload);

        var wbuf: [4096]u8 = undefined;
        var w = self.stream.writer(self.io, &wbuf);
        w.interface.writeAll(payload) catch return error.Io;
        w.interface.flush() catch return error.Io;

        // 读满一条回复（reserve 足够大；批量命令可能超出一个缓冲区，循环读）
        var acc = std.ArrayList(u8).empty;
        defer acc.deinit(self.allocator);
        try acc.appendSlice(self.allocator, self.rbuf[0..self.rlen]);
        self.rlen = 0;

        while (true) {
            var parser = Parser.init(acc.items);
            if (parser.parse(self.allocator)) |reply| {
                // 把未消费的剩余字节留在缓冲里（随连接关闭丢弃；短连接模型下无跨命令残留）
                return reply;
            } else |_| {
                var tmp: [8192]u8 = undefined;
                const n = self.stream.read(self.io, &.{&tmp}) catch return error.Io;
                if (n == 0) return error.Protocol;
                acc.appendSlice(self.allocator, tmp[0..n]) catch return error.OutOfMemory;
            }
        }
    }

    /// 便捷：`GET key` → 值（调用方 free）。
    pub fn get(self: *Client, key: []const u8) Error!?[]u8 {
        var reply = try self.cmd(&.{ "GET", key });
        defer reply.deinit(self.allocator);
        return switch (reply) {
            .bulk => |b| b,
            .err => error.Protocol,
            else => null,
        };
    }

    /// 便捷：`SET key value [EX ttl]`。
    pub fn set(self: *Client, key: []const u8, value: []const u8, ttl_secs: i64) bool {
        const ok = if (ttl_secs > 0) blk: {
            var ttl_buf: [24]u8 = undefined;
            const ttl_text = std.fmt.bufPrint(&ttl_buf, "{d}", .{ttl_secs}) catch return false;
            var reply = self.cmd(&.{ "SET", key, value, "EX", ttl_text }) catch return false;
            defer reply.deinit(self.allocator);
            break :blk reply.isOk();
        } else blk: {
            var reply = self.cmd(&.{ "SET", key, value }) catch return false;
            defer reply.deinit(self.allocator);
            break :blk reply.isOk();
        };
        return ok;
    }

    /// 便捷：`DEL key`。
    pub fn del(self: *Client, key: []const u8) bool {
        var reply = self.cmd(&.{ "DEL", key }) catch return false;
        defer reply.deinit(self.allocator);
        return switch (reply) {
            .int => |n| n > 0,
            else => false,
        };
    }

    /// 便捷：`EXISTS key`。
    pub fn exists(self: *Client, key: []const u8) bool {
        var reply = self.cmd(&.{ "EXISTS", key }) catch return false;
        defer reply.deinit(self.allocator);
        return switch (reply) {
            .int => |n| n > 0,
            else => false,
        };
    }

    /// 便捷：`PING`（探活）。
    pub fn ping(self: *Client) bool {
        var reply = self.cmd(&.{"PING"}) catch return false;
        defer reply.deinit(self.allocator);
        return reply.isOk();
    }
};

// ---------- 测试 ----------

test "resp: 命令编码" {
    const allocator = std.testing.allocator;
    const encoded = try encodeCommand(allocator, &.{ "SET", "k", "v" });
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n", encoded);
}

test "resp: 回复解析（状态/整数/批量/空/数组/错误）" {
    const allocator = std.testing.allocator;

    {
        var p = Parser.init("+OK\r\n");
        var r = try p.parse(allocator);
        defer r.deinit(allocator);
        try std.testing.expectEqualStrings("OK", r.status);
    }
    {
        var p = Parser.init(":42\r\n");
        var r = try p.parse(allocator);
        defer r.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 42), r.int);
    }
    {
        var p = Parser.init("$5\r\nhello\r\n");
        var r = try p.parse(allocator);
        defer r.deinit(allocator);
        try std.testing.expectEqualStrings("hello", r.bulk.?);
    }
    {
        var p = Parser.init("$-1\r\n");
        var r = try p.parse(allocator);
        defer r.deinit(allocator);
        try std.testing.expect(r.bulk == null);
    }
    {
        var p = Parser.init("*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n");
        var r = try p.parse(allocator);
        defer r.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 2), r.array.len);
        try std.testing.expectEqualStrings("foo", r.array[0].bulk.?);
        try std.testing.expectEqualStrings("bar", r.array[1].bulk.?);
    }
    {
        var p = Parser.init("-WRONGTYPE bad\r\n");
        var r = try p.parse(allocator);
        defer r.deinit(allocator);
        try std.testing.expect(!r.isOk());
    }
}

test "resp: 不完整数据返回 Protocol 错误（调用方继续读）" {
    const allocator = std.testing.allocator;
    var p = Parser.init("$5\r\nhel");
    try std.testing.expectError(error.Protocol, p.parse(allocator));
}
