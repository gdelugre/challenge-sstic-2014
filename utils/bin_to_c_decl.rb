#!/usr/bin/env ruby

exit if ARGV.length < 2

bytecode = File.binread ARGV[0]
struct_name = ARGV[1]

File.open(File.join(File.dirname(ARGV[0]), "#{ARGV[1]}.h"), 'w') do |fd|
    fd.puts "#ifndef __H_#{struct_name.upcase}"
    fd.puts "#define __H_#{struct_name.upcase}"
    fd.puts
    fd.puts "unsigned char #{struct_name}[] = {"
    fd.write " " * 4 

    i = 0 
    bytecode.each_byte { |byte|
        fd.write("0x%02x, " % byte)
        fd.write("\n    ") if i % 16 == 15
        i += 1
    }   

    fd.puts "};"
    fd.puts
    fd.puts "#endif"
end

