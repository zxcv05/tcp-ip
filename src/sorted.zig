const std = @import("std");

const Self = @This();

pub const Item = struct {
    seq: usize, // start of data
    end: usize, // seq + data.len
    psh: bool,
    con: bool,
    data: []const u8,
    node: std.DoublyLinkedList.Node,
};

psh: usize,
items: std.DoublyLinkedList,
mutex: std.Thread.Mutex,
data_len: usize,
condition: std.Thread.Condition,
allocator: std.mem.Allocator,
last_cont: ?usize,
contiguous_len: usize,

pub fn init(allocator: std.mem.Allocator) Self {
    return .{
        .psh = 0,
        .items = .{},
        .mutex = .{},
        .data_len = 0,
        .allocator = allocator,
        .last_cont = null,
        .condition = .{},
        .contiguous_len = 0,
    };
}

pub fn deinit(self: *Self) void {
    self.psh += 1;
    self.condition.signal();
    self.clear();
}

pub fn clear(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    while (self.items.pop()) |last| {
        const item: *Item = @fieldParentPtr("node", last);

        self.allocator.free(item.data);
        self.allocator.destroy(last);
    }
}

pub fn getData(self: *Self, buffer: []u8) !usize {
    self.mutex.lock();
    defer self.mutex.unlock();

    while (self.contiguous_len < buffer.len and self.psh == 0) {
        self.condition.wait(&self.mutex);
    }

    var maybe_node = self.items.first;
    var last: usize = if (maybe_node) |node| seq: {
        const item: *Item = @fieldParentPtr("node", node);
        break :seq item.seq;
    } else return error.NoData;

    var index: usize = 0;
    const wanted_node = get_node: while (maybe_node) |node| : (maybe_node = node.next) {
        const item: *Item = @fieldParentPtr("node", node);
        const avail = buffer.len - index;
        if (item.seq >= last) {
            const diff = item.end - last;
            const data = item.data[item.data.len - diff ..];
            const size = if (avail > data.len) data.len else avail;
            std.mem.copyForwards(u8, buffer[index..], data[0..size]);
            index += size;
            last += size;
            item.seq += size;
        } else if (item.seq > last) {
            return error.NonContiguousData;
        }
        if (item.psh and last >= item.end) {
            self.psh -= if (self.psh > 0) 1 else 0;
            break;
        }
        if (index == buffer.len) break :get_node node;
    } else unreachable;

    maybe_node = self.items.first;
    while (maybe_node) |node| {
        if (node == wanted_node) break;
        const next = node.next;

        const item: *Item = @fieldParentPtr("node", node);
        self.allocator.free(item.data);
        self.allocator.destroy(item);
        maybe_node = next;
    }

    if (maybe_node) |node| {
        const item: *Item = @fieldParentPtr("node", node);

        if (last >= item.end) {
            self.items.remove(node);
            self.allocator.free(item.data);
            self.allocator.destroy(node);
        }
    }

    self.data_len -= index;
    self.contiguous_len -= index;

    return index;
}

pub fn getAllData(self: *Self) ![]u8 {
    const buffer = try self.allocator.alloc(u8, self.contiguous_len);

    const size = try self.getData(buffer);

    return if (size < buffer.len)
        self.allocator.realloc(buffer, size)
    else
        buffer;
}

fn checkContiguous(self: *Self, node: *std.DoublyLinkedList.Node) void {
    var item: *Item = @fieldParentPtr("node", node);

    if (node.prev) |prev_node| {
        const prev_item: *Item = @fieldParentPtr("node", prev_node);

        item.con = prev_item.con and prev_item.end >= item.seq;
        if (item.con) {
            self.contiguous_len += item.end - prev_item.end;
        } else return;
    } else {
        item.con = if (self.last_cont) |last|
            last >= item.seq
        else
            true;
        if (!item.con) return;
        self.contiguous_len += item.data.len;
    }

    self.last_cont = item.end;

    if (item.psh) self.psh += 1;

    var prev_node = node;
    var maybe_node = node.next;
    while (maybe_node) |next_node| {
        const next_item: *Item = @fieldParentPtr("node", next_node);
        const prev_item: *Item = @fieldParentPtr("node", prev_node);

        next_item.con = prev_item.end >= next_item.seq;
        if (next_item.con) break;

        self.contiguous_len += next_item.end - prev_item.end;
        self.last_cont = next_item.end;
        if (item.psh) self.psh += 1;

        prev_node = next_node;
        maybe_node = next_node.next;
    }
}

pub fn ackable(self: *Self) ?usize {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.last_cont;
}

pub fn insert(self: *Self, seq: usize, data: []const u8, psh: bool) !void {
    // check data boundaries when inserting to skip previously received data
    const end = seq + data.len;
    if (data.len > 0 and self.last_cont != null and end <= self.last_cont.?) return;

    self.mutex.lock();

    defer {
        self.condition.signal();
        self.mutex.unlock();
    }

    const new_item = try self.allocator.create(std.DoublyLinkedList.Node);
    errdefer self.allocator.destroy(new_item);

    new_item.* = .{
        .seq = seq,
        .end = end,
        .psh = psh,
        .con = false,
        .data = try self.allocator.dupe(u8, data),
        .node = .{},
    };

    var maybe_node = self.items.first;
    while (maybe_node) |node| : (maybe_node = node.next) {
        const item: *Item = @fieldParentPtr("node", node);

        if (item.seq <= seq and item.end >= new_item.end)
            return;

        if (item.seq > seq) {
            if (node.prev) |prev_node| {
                const prev_item: *Item = @fieldParentPtr("node", prev_node);
                if (prev_item.end >= new_item.end) {
                    self.allocator.free(new_item.data);
                    self.allocator.destroy(new_item);
                    return; // note(zxcv05): this is missing originally, is that intended?
                }
            }
            self.items.insertBefore(node, &new_item.node);
            self.data_len += data.len;
            self.checkContiguous(&new_item.node);
            return;
        }
    }

    self.items.append(&new_item.node);
    self.data_len += data.len;
    self.checkContiguous(&new_item.node);
}
