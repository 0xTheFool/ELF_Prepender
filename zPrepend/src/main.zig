const std = @import("std");
const fs = std.fs;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const stdout_file = std.io.getStdOut().writer();

const Infector = struct {
    alloc: std.mem.Allocator = gpa.allocator(),
    writer: std.fs.File.Writer = stdout_file,

    pub fn init() Infector {
        const alloc = gpa.allocator();
        return Infector{
            .alloc = alloc,
        };
    }

    pub fn run(self: Infector) !void {
        const current_bin_path = try fs.selfExePathAlloc(self.alloc);
        defer self.alloc.free(current_bin_path);

        const current_dir_path = try fs.selfExeDirPathAlloc(self.alloc);
        defer self.alloc.free(current_dir_path);

        var current_dir = try fs.openDirAbsolute(current_dir_path, .{
            .access_sub_paths = false,
            .iterate = true,
        });
        defer current_dir.close();

        var directory_iter = try current_dir.walk(self.alloc);
        defer directory_iter.deinit();

        while (directory_iter.next()) |entry| {
            if (entry) |e| {
                if (e.kind == fs.File.Kind.file) {
                    const file_complete_path = try std.fmt.allocPrint(self.alloc, "{s}/{s}", .{ current_dir_path, e.path });
                    defer self.alloc.free(file_complete_path);

                    if (std.mem.eql(u8, file_complete_path, current_bin_path)) {
                        continue;
                    }
                    const meta = try e.dir.statFile(e.basename);
                    try self.writer.print("{s}\n", .{file_complete_path});
                    _ = meta;
                }
            } else {
                break;
            }
        } else |err| {
            return err;
        }
    }
};

pub fn main() !void {
    const infector = Infector.init();
    try infector.run();
    defer _ = gpa.deinit();
}
