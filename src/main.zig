const std = @import("std");
const os = std.os;
const net = std.net;

pub const WriteStream = struct {
    ring: *os.linux.IO_Uring,
    user_data: u64,
    fd: os.fd_t,
    out_sqe: *?*os.linux.io_uring_sqe,

    pub inline fn writev(self: *const @This(), iovecs: []os.iovec_const) !usize {
        self.out_sqe.* = try self.ring.writev(self.user_data, self.fd, iovecs, 0);
        var total: usize = 0;
        for (iovecs) |io|
            total += io.iov_len;
        return total;
    }
};

pub const ReadStream = struct {
    data: [][]const u8,

    pub fn readv(self: *const @This(), _iovecs: []os.iovec) !usize {
        var data = self.data;
        var iovecs = _iovecs;
        var total: usize = 0;
        while (data.len > 0 and iovecs.len > 0) {
            if (data[0].len == 0) {
                data = data[1..];
                continue;
            }
            if (iovecs[0].iov_len == 0) {
                iovecs = iovecs[1..];
                continue;
            }
            const M = @min(data[0].len, iovecs[0].iov_len);
            @memcpy(iovecs[0].iov_base[0..M], data[0][0..M]);
            total += M;
            data[0] = data[0][M..];
            iovecs[0].iov_len -= M;
        }
        return total;
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ring = try os.linux.IO_Uring.init(16, 0);
    defer ring.deinit();

    var address_list = try net.getAddressList(allocator, "example.com", 443);
    defer address_list.deinit();

    if (address_list.addrs.len < 1)
        return error.DnsLookupFailure;

    const address = address_list.addrs[0];
    std.debug.print("{}\n", .{address});

    var tls_client = try allocator.create(std.crypto.tls.Client);
    defer allocator.destroy(tls_client);

    var bundle: std.crypto.Certificate.Bundle = .{};
    try bundle.rescan(allocator);
    defer bundle.deinit(allocator);

    const client = try os.socket(address.any.family, os.SOCK.STREAM | os.SOCK.CLOEXEC, 0);
    defer os.closeSocket(client);

    // If you're actually using the ring buffer to connect and aren't
    // explicitly chaining together sqes then you need some mechanism
    // to route the cqes to the right place and block at the right time
    // (an event loop). I'm ignoring any notion of that till async is
    // back in the compiler.
    _ = try ring.connect(0xcccccccc, client, &address.any, address.getOsSockLen());
    _ = try ring.submit();

    var cqe_connect = try ring.copy_cqe();
    switch (cqe_connect.err()) {
        .SUCCESS => {},
        else => |err| {
            std.debug.print("copy_cqe result enum: {}\n", .{err});
            return error.UnexpectedReturnCode;
        },
    }

    // The tls Client expects a synchronous read/write interface for basically
    // everything it does. For a stream of data we can hack around that pretty
    // trivially, but the handshake at the start of a connection is more annoying
    // to work with without actual async frame support. You can handle this however
    // you'd like, but under the assumption that connections aren't too short-lived
    // I'm just going to use a synchronous interface to create the thing.
    var stream = net.Stream{ .handle = client };
    tls_client.* = try std.crypto.tls.Client.init(stream, bundle, "example.com");

    // Safe for HTTP because of the length prefix, but you need a little love
    // and care to find the "right" length (e.g., with Transfer-Encoding chunked)
    // tls_client.allow_truncation_attacks = true;

    const buffer_send = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    // The tls_client calls back into our code, so to actually get the sqe out of the
    // ring buffer we need to put it somewhere.
    //
    // The user_data (as in other io_uring calls) should be unique enough that you can
    // route the eventual cqes back to the right sqe.
    var out: ?*os.linux.io_uring_sqe = null;
    var write_stream = WriteStream{ .ring = &ring, .user_data = 42, .fd = client, .out_sqe = &out };
    _ = try tls_client.write(write_stream, buffer_send[0..]);

    // As a reminder, ring.submit() is a syscall, and one point of io_uring is to
    // reduce those. The best way to handle that is application-specific (and might
    // include setting up kernel polling instead), but you probably want to think
    // about a batching strategy up-front.
    _ = try ring.submit();

    var cqe_writev = try ring.copy_cqe();
    switch (cqe_writev.err()) {
        .SUCCESS => {},
        else => |err| {
            std.debug.print("copy_cqe result enum: {}\n", .{err});
            return error.UnexpectedReturnCode;
        },
    }

    // This example is already too long, so rather properly track length
    // headers or anything else we'll just wait 1e9 nanoseconds to hope
    // https://example.com/ has finished sending us data so that the
    // recv will be complete.
    //
    // Instead, you might want to keep track of the expected/actual lengths
    // and fire off additional recvs (with timeouts or other error handling)
    // till you have all the data. The ReadStream interface we created
    // accepts a rope of such data.
    std.time.sleep(1000000000);

    var buffer_recv: [1024 * 64]u8 = undefined;
    _ = try ring.recv(0x45, client, .{ .buffer = buffer_recv[0..] }, 0);
    _ = try ring.submit();

    // Recall that copy_cqe() waits for some cqe (or a timeout), but not
    // necessarily the last one. The only reason this code works is because
    // we've been submitting and waiting for every syscall. That's bad.
    // Don't do it.
    const cqe_recv = try ring.copy_cqe();
    switch (cqe_recv.err()) {
        .SUCCESS => {},
        else => |err| {
            std.debug.print("copy_cqe result enum: {}\n", .{err});
            return error.UnexpectedReturnCode;
        },
    }

    // The @intCast() is safe because we just checked for errors, ignoring
    // any eBPF fuckery or whatnot messing with userspace structs
    var rope: [1][]const u8 = .{buffer_recv[0..@intCast(cqe_recv.res)]};
    var read_stream = ReadStream{ .data = &rope };

    // Implicitly we're forcing a copy here, but at surface-level it looks
    // like the TLS implementation might handle aliased in/out gracefully
    // and write in-place without mucking anything up. We would need to
    // update our ReadStream if we tried that because `@memcpy` explicitly
    // requires noalias inputs.
    var tls_recv: [1024 * 64]u8 = undefined;
    const webpage_len = try tls_client.read(read_stream, tls_recv[0..]);
    std.debug.print("{s}\n", .{tls_recv[0..webpage_len]});
}
