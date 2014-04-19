#!/usr/bin/env ruby

require 'tempfile'

exit(1) if ARGV.size < 2

elf = File.binread ARGV[0]

if elf[4].ord == 1 # ELF32
    ELFCLASS = 32
elsif elf[4].ord == 2 # ELF64
    ELFCLASS = 64
else
    fail "Unknown ELF class."
end

case ELFCLASS
    when 64
    entry = elf[0x18,8].unpack('Q')[0]
    phoff = elf[0x20,8].unpack('Q')[0]
    ehsize = elf[0x34, 2].unpack('v')[0]
    phnum = elf[0x38,2].unpack('v')[0]
    phentsize = 56
    
    when 32
    entry = elf[0x18,4].unpack('V')[0]
    phoff = elf[0x1c,4].unpack('V')[0]
    ehsize = elf[0x28,2].unpack('v')[0]
    phnum = elf[0x2c,2].unpack('v')[0]
    phentsize = 32
end

source = <<HEADER
#ifndef _H_ELF_MAP
#define _H_ELF_MAP

#include <stddef.h>

struct elf_segment
{
    unsigned long address;
    size_t size;
    unsigned char *data;
    size_t data_size;
    int prot;
    int compressed;
};

#define MAX_NR_SEGMENTS 4
struct elf_memory_map
{
    unsigned int nr_segments; 
    unsigned long entry;
    struct elf_segment entries[MAX_NR_SEGMENTS];
} memory_map =
{
    .entry = 0x#{"%016X" % entry},
    .entries = {
HEADER

def mmap_prot(elf_prot)
    prot = 0

    prot |= 1 if elf_prot & 4 != 0
    prot |= 2 if elf_prot & 2 != 0
    prot |= 4 if elf_prot & 1 != 0

    prot
end

def define_segment(addr, size, data, prot, compressed)
    segdef = <<-DEF
    {
        .address = 0x#{"%016X" % addr},
        .size = #{size},
        .data = (unsigned char []){#{data.bytes.join(",")}},
        .data_size = #{data.size},
        .prot = #{mmap_prot(prot)},
        .compressed = #{compressed ? 1 : 0}
    },
    DEF
end

phdrs = elf[phoff, phentsize * phnum]
elf[0, ehsize] = "\x00" * ehsize
elf[phoff, phdrs.size] = "\x00" * phdrs.size

segdefs = []
for i in (0 ... phnum)
    phdr = phdrs[phentsize * i, phentsize]
    if ELFCLASS == 64
        type, flags, offset, vaddr, paddr, filesz, memsz, align = phdr.unpack('V2Q6')
    elsif ELFCLASS == 32
        type, offset, vaddr, paddr, filesz, memsz, flags, align = phdr.unpack('V8')
    end

    next if type != 1 # only treats LOAD segments

    segdata, compressed = '', false

    segfile = Tempfile.new('elf')
    begin
        segfile.write(elf[offset, filesz]); segfile.close
        system "utils/lz4hc_util_compress #{segfile.path} #{segfile.path}.compressed"
        
        if File.size?("#{segfile.path}.compressed").to_i >= filesz
            segdata = elf[offset, filesz]
            compressed = false
        else
            segdata = File.binread("#{segfile.path}.compressed")
            compressed = true
        end
    ensure
        segfile.unlink
        File.delete("#{segfile.path}.compressed") rescue nil
    end

    segdefs.push define_segment(vaddr, memsz, segdata, flags, compressed)
end

source += segdefs.join($/)
source += "    },\n    .nr_segments = #{segdefs.size},\n"
source += <<FOOTER
};

#endif

FOOTER

File.write(ARGV[1], source)
