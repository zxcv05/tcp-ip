const std = @import("std");
const Tap = @import("tap.zig");
const native_endian = @import("builtin").target.cpu.arch.endian();

const Self = @This();

pub const BroadcastAddress: [6]u8 = @splat(0xff);

pub const EtherType = enum(u16) {
    ip4 = 0x0800,
    arp = 0x0806,
    ip6 = 0x86DD,
    pub fn fromInt(val: u16) !EtherType {
        return try std.meta.intToEnum(EtherType, val);
    }
};

pub const Header = extern struct {
    dmac: [6]u8 align(1),
    smac: [6]u8 align(1),
    type: u16 align(1),
};

pub const Frame = extern struct {
    pub const MAX_DATA_BYTES = 1500;
    header: Header,
    // tags: u32,
    data: [MAX_DATA_BYTES]u8 align(1),
};

pub const Handler = struct {
    pub const VTable = struct {
        handle: *const fn (ctx: *anyopaque, frame: *const Frame) void,
    };
    ptr: *anyopaque,
    vtable: *const VTable,
    pub fn handle(self: Handler, frame: *const Frame) void {
        self.vtable.handle(self.ptr, frame);
    }
};

dev: *Tap.Device,
handlers: std.AutoHashMap(EtherType, Handler),
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, dev: *Tap.Device) Self {
    return .{
        .dev = dev,
        .handlers = std.AutoHashMap(EtherType, Handler).init(allocator),
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    self.handlers.deinit();
}

pub fn addProtocolHandler(self: *Self, protocol: EtherType, handler: Handler) !void {
    try self.handlers.put(protocol, handler);
}

pub fn readFrame(self: *Self) !Frame {
    var buff: [@sizeOf(Frame)]u8 = undefined;
    var dev_reader = self.dev.reader(&buff);

    const reader = &dev_reader.interface;
    const data = (try reader.peekGreedy(@sizeOf(Header)))[@sizeOf(Header)..];

    var frame: Frame = .{
        .header = try reader.takeStruct(Header, .big),
        .data = undefined,
    };

    std.mem.copyForwards(u8, &frame.data, data);
    return frame;
}

pub fn dispatch(self: Self, frame: *const Frame) !void {
    const protocol = try EtherType.fromInt(frame.header.type);
    if (self.handlers.get(protocol)) |*handler| {
        // std.debug.print("Dispatching to handler\n", .{});
        handler.handle(frame);
    } else {
        // std.debug.print("Unsupported protocol: {}\n", .{protocol});
    }
}

pub fn readAndDispatch(self: *Self) !void {
    const frame = try self.readFrame();
    try self.dispatch(&frame);
}

pub fn transmit(self: *Self, data: []const u8, dmac: [6]u8, _type: EtherType) !void {
    if (data.len >= Frame.MAX_DATA_BYTES) return error.TooMuchData;

    var buff: [@sizeOf(Frame)]u8 = undefined;
    var dev_writer = self.dev.writer(&buff);
    const writer = &dev_writer.interface;

    const header: Header = .{
        .dmac = dmac,
        .smac = self.dev.hwaddr,
        .type = @intFromEnum(_type),
    };

    try writer.writeStruct(header, .big);
    try writer.writeAll(data);
    try writer.flush();
}
