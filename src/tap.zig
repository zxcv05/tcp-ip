const std = @import("std");
const linux = std.os.linux;
const native_endian = @import("builtin").target.cpu.arch.endian();

const Utils = @import("utils.zig");

const IFF_UP: u16 = 0x0001;
const IFF_TAP: u16 = 0x0002;
const IFF_NO_PI: u16 = 0x1000;
const IFF_RUNNING: u16 = 0x0040;

const TUNSETIFF: u32 = 0x400454ca;
const SIOCSIFADDR: u32 = 0x8916;
const SIOCSIFFLAGS: u32 = 0x8914;
const SIOCGIFFLAGS: u32 = 0x8913;
const SIOCSIFHWADDR: u32 = 0x8924;
const SIOCSIFNETMASK: u32 = 0x891c;

pub const Device = struct {
    file: std.fs.File,
    name: [linux.IFNAMESIZE]u8,
    hwaddr: [6]u8,
    ipaddr: u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, ifname: ?[]u8) !Device {
        const fd = try std.posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0);
        errdefer std.posix.close(fd);

        var ifr = std.mem.zeroes(linux.ifreq);
        var dev = Device{
            .file = .{ .handle = @intCast(fd) },
            .name = undefined,
            .ipaddr = 0,
            .hwaddr = undefined,
            .allocator = allocator,
        };

        if (ifname) |name| std.mem.copyForwards(u8, ifr.ifrn.name[0..], name);
        @as(*u16, @ptrCast(&ifr.ifru.flags)).* = IFF_TAP | IFF_NO_PI;

        if (linux.ioctl(dev.file.handle, TUNSETIFF, @intFromPtr(&ifr)) != 0) return error.IoCtl;
        std.mem.copyForwards(u8, dev.name[0..], &ifr.ifrn.name);

        return dev;
    }

    fn setHWAddr(self: *Device, mac: []const u8) !void {
        var i: usize = 0;
        var split = std.mem.splitScalar(u8, mac, ':');
        while (split.next()) |hex| {
            if (i >= 6) break;
            self.hwaddr[i] = try std.fmt.parseInt(u8, hex, 16);
            i += 1;
        }
    }

    pub fn ifup(self: *Device, mac: []const u8, ip: []const u8, host: []const u8, netmask: []const u8) !void {
        try self.setHWAddr(mac);

        self.ipaddr = try Utils.pton(ip);

        var sin = std.mem.zeroInit(linux.sockaddr.in, .{
            .addr = try Utils.pton(host),
        });

        // we need a socket to use SIOCSIFADDR and other netdev IOCTLs
        const sock: linux.fd_t = @bitCast(
            @as(u32, @truncate(linux.socket(sin.family, linux.SOCK.DGRAM, 0))),
        );

        if (sock < 0) return error.SOCKET;

        defer _ = linux.close(sock);

        var ifr = linux.ifreq{
            // our tap interface is identified its name
            .ifrn = .{ .name = self.name },
            .ifru = .{
                .addr = .{
                    .family = linux.AF.INET,
                    .data = std.mem.asBytes(&sin)[2..].*,
                },
            },
        };

        if (linux.ioctl(sock, SIOCSIFADDR, @intFromPtr(&ifr)) != 0) {
            return error.IFADDR;
        }

        sin.addr = try Utils.pton(netmask);

        ifr.ifru.netmask = .{
            .family = linux.AF.INET,
            .data = std.mem.asBytes(&sin)[2..].*,
        };

        if (linux.ioctl(sock, SIOCSIFNETMASK, @intFromPtr(&ifr)) != 0) {
            return error.IFNETMASK;
        }

        ifr.ifru.flags = @as(*const linux.IFF, @ptrCast(&IFF_UP)).*;

        if (linux.ioctl(sock, SIOCSIFFLAGS, @intFromPtr(&ifr)) != 0) {
            return error.IFUP;
        }
    }

    pub fn ifdown(self: Device) !void {
        const sock: linux.fd_t = @bitCast(
            @as(u32, @truncate(linux.socket(2, linux.SOCK.DGRAM, 0))),
        );

        if (sock < 0) return error.SOCKET;

        defer _ = linux.close(sock);

        const ifr = linux.ifreq{
            .ifrn = .{ .name = self.name },
            .ifru = .{ .flags = @bitCast(~IFF_UP) },
        };

        if (linux.ioctl(sock, SIOCSIFFLAGS, @intFromPtr(&ifr)) != 0) {
            return error.IFDOWN;
        }
    }

    pub fn deinit(self: Device) void {
        self.ifdown() catch {};
        self.file.close();
    }

    pub fn reader(self: *Device, buffer: []u8) std.fs.File.Reader {
        return self.file.reader(buffer);
    }

    pub fn writer(self: *Device, buffer: []u8) std.fs.File.Writer {
        return self.file.writer(buffer);
    }
};
