#!/usr/bin/env ruby

PROGRAM_HDR = "vm_bytecode.h"
PROGRAM_BIN = "vm_bytecode.bin"
PROGRAM_SIZE = 8192 * 64
@bytecode = "\x00" * PROGRAM_SIZE

@bytecode[0x38,8] = [ 0x40 ].pack 'Q'

File.binwrite(PROGRAM_BIN, @bytecode)
system "./chacha_crypt #{PROGRAM_BIN}"

@bytecode = File.binread PROGRAM_BIN

File.open(PROGRAM_HDR, 'w') do |fd|
    fd.puts "#ifndef __H_BYTECODE"
    fd.puts "#define __H_BYTECODE"
    fd.puts
    fd.puts "unsigned char vm_bytecode[] = {"
    fd.write " " * 4

    i = 0
    @bytecode.each_byte { |byte|
        fd.write("0x%02x, " % byte)
        fd.write("\n    ") if i % 16 == 15
        i += 1
    }

    fd.puts "};"
    fd.puts
    fd.puts "#endif"
end
