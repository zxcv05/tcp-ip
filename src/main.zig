const std = @import("std");

const Tap = @import("tap.zig");
const TCP = @import("tcp.zig");
const ARP = @import("arp.zig");
const IPv4 = @import("ipv4.zig");
const ICMP4 = @import("icmp4.zig");
const Socket = @import("socket.zig");
const Ethernet = @import("ethernet.zig");

pub fn serverLoop(allocator: std.mem.Allocator, tcp: *TCP) void {
    var server = Socket.init(allocator, tcp);
    defer server.deinit();

    server.listen("10.0.10.1", 5501, 1) catch return;
    std.debug.print("Listenning...\n", .{});

    var client = server.accept() catch return;
    defer client.deinit();

    std.debug.print("Accepted connection!\n", .{});

    var buffer: [1024]u8 = undefined;
    while (client.state() == .ESTABLISHED) {
        const size = client.read(buffer[0..]) catch {
            continue;
        };
        if (size == 0) break;
        std.debug.print("[Server] Received: {s}\n", .{buffer[0..size]});
        _ = client.write(buffer[0..size]) catch {};
    }

    std.debug.print("Client disconnected. Finishing...\n", .{});
}

fn clientLoop(allocator: std.mem.Allocator, tcp: *TCP, endpoint: []const u8) void {
    var buffer: [1024]u8 = undefined;

    var client = Socket.init(allocator, tcp);
    defer client.deinit();

    std.debug.print("Connecting...\n", .{});
    client.connect(endpoint, 5501) catch |err| {
        std.debug.print("Failed to connect: {s}\n", .{@errorName(err)});
        return;
    };

    std.debug.print("Connected!\n", .{});
    while (client.state() == .ESTABLISHED) {
        const size = client.read(buffer[0..]) catch return;
        if (size == 0) break;
        std.debug.print("[Client] Received: {s}\n", .{buffer[0..size]});
        _ = client.write(buffer[0..size]) catch return;
    }

    std.debug.print("Disconnected!\n", .{});
}

fn ethernetLoop(running: *std.atomic.Value(bool), eth: *Ethernet) void {
    while (running.load(.acquire)) {
        std.debug.print("reading frame\n", .{});
        eth.readAndDispatch() catch |err| {
            std.debug.print("[ETHERNET] Failed to read frame: {s}\n", .{
                @errorName(err),
            });
            break;
        };
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var mode: enum{server,client} = .server;
    var addr: []const u8 = "";
    var hw_addr: []const u8 = "";
    var r_addr: []const u8 = "";
    var ep_addr: []const u8 = "";

    {
        var iter = std.process.args();
        _ = iter.skip();
        const mode_arg = iter.next() orelse return error.MissingArgument;

        if (std.ascii.eqlIgnoreCase(mode_arg, "server")) {mode = .server;}
        else if (std.ascii.eqlIgnoreCase(mode_arg, "client")) {mode = .client;}
        else return error.BadMode;

        addr = iter.next() orelse return error.MissingArgument;
        if (mode == .client) {
            ep_addr = iter.next() orelse return error.MissingArgument;
        }
        hw_addr = iter.next() orelse return error.MissingArgument;
        r_addr = iter.next() orelse return error.MissingArgument;
        if (iter.next() != null) return error.ExtraArgument;
    }

    var dev = Tap.Device.init(allocator, null) catch |err| switch (err) {
        error.IoCtl => {
            std.debug.print("[ERROR] Cannot IOCTL on the Tap device.\n", .{});
            std.debug.print("Try running this program as root or set cap_net_admin capability on the file\n", .{});
            return err;
        },
        else => return err,
    };
    defer dev.deinit();
    try dev.ifup(hw_addr, addr, r_addr, "255.255.255.0");

    var eth = Ethernet.init(allocator, &dev);
    defer eth.deinit();

    var arp = ARP.init(allocator, &eth);
    defer arp.deinit();

    var ip = IPv4.init(allocator, &arp, &eth);
    defer ip.deinit();

    var tcp = try TCP.init(allocator, &ip, 500);
    defer tcp.deinit();

    var icmp = ICMP4.init(allocator, &ip);
    defer icmp.deinit();

    try eth.addProtocolHandler(.ip4, ip.handler());
    try eth.addProtocolHandler(.arp, arp.handler());

    try ip.addProtocolHandler(.ICMP, icmp.handler());
    try ip.addProtocolHandler(.TCP, tcp.handler());

    var running = std.atomic.Value(bool).init(true);

    var thread = try std.Thread.spawn(.{}, ethernetLoop, .{ &running, &eth });
    defer {
        running.store(false, .release);
        thread.join();
    }

    switch (mode) {
        .server => serverLoop(allocator, tcp),
        .client => clientLoop(allocator, tcp, ep_addr),
    }
}
