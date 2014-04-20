ARCH=aarch64
VENDOR=
OS=linux
ABI=gnu
PREFIX:=$(ARCH)-
ifneq ($(VENDOR),)
PREFIX:=$(PREFIX)$(VENDOR)-
endif
PREFIX:=$(PREFIX)$(OS)-$(ABI)

LZ4_DIR=lz4
TMP_DIR=tmp
STUB_DIR=stub
UTILS_DIR=utils
INCLUDE_DIR=include

CC=$(PREFIX)-gcc
AS=$(PREFIX)-as
LD=$(PREFIX)-ld
STRIP=$(PREFIX)-strip
OBJDUMP=$(PREFIX)-objdump
OBJCOPY=$(PREFIX)-objcopy
ARMOR=ruby armor/armor.rb -a $(ARCH)
QEMU=~/tmp/qemu/aarch64-linux-user/qemu-aarch64
CFLAGS_COMMON=-Wall -std=gnu11 -O2 -static -I$(INCLUDE_DIR) -I$(INCLUDE_DIR)/chacha
ifeq ($(ARCH),aarch64)
    CFLAGS_MACHDEP=-mcpu=generic+nosimd+nofp -ffixed-x28
else
ifeq ($(ARCH),arm)
    CFLAGS_MACHDEP=-mcpu=generic-armv7-a
endif
endif
CFLAGS_RELEASE=$(CFLAGS_MACHDEP) $(CFLAGS_COMMON) -nostdlib -nodefaultlibs
CFLAGS_DEBUG=$(CFLAGS_MACHDEP) $(CFLAGS_COMMON) -DDEBUG
LDFLAGS=
COMPILE_RELEASE=$(CC) $(CFLAGS_RELEASE) -S
COMPILE_DEBUG=$(CC) $(CFLAGS_DEBUG)
ASSEMBLE=$(AS)
LINK=$(LD) $(LDFLAGS)
SRC=main.c chacha.c vm.c vm_handlers.c
TARGET=sstic14-armageddon.elf

TEXT_ADDR=0x400000
DATA_ADDR=0x500000

all: check_toolchain debug 

debug: dirs compile_debug
release: dirs compile_release compress

check_toolchain:
	@which $(CC) > /dev/null
	@which $(AS) > /dev/null
	@which $(LD) > /dev/null
	@which $(STRIP) > /dev/null
	@which $(OBJDUMP) > /dev/null
	@which $(OBJCOPY) > /dev/null

dirs:
	mkdir -p $(TMP_DIR)

compress:
	$(UTILS_DIR)/compress_elf.rb $(TARGET) $(TMP_DIR)/elf_map.h
	$(CC) $(CFLAGS_RELEASE) $(STUB_DIR)/$(ARCH)/start.S $(STUB_DIR)/stub.c $(LZ4_DIR)/lz4_reduced.c -I. -I$(TMP_DIR) -o $(TARGET).packed -Wl,-Ttext-segment=0x10000
	$(STRIP) $(TARGET).packed
	$(OBJCOPY) -w -R '.note.gnu.build-id' -R .comment $(TARGET).packed
	#rm -f *.o
	echo "Done."

compile_release: util bytecode
	$(COMPILE_RELEASE) $(SRC)
	$(ARMOR) vm_handlers.s
	cp $(STUB_DIR)/$(ARCH)/start.S start.s
	cp $(STUB_DIR)/$(ARCH)/div.S div.s
	for obj in *.s; do \
		cp $$obj $(TMP_DIR)/$$obj.orig ; \
		$(ASSEMBLE) $$obj -o $$obj.o ; \
	done
	$(LINK) -Ttext-segment=$(TEXT_ADDR) -Tdata=$(DATA_ADDR) *.o -o $(TARGET)
	rm -f *.o
	$(STRIP) $(TARGET)

compile_debug: util bytecode
	$(COMPILE_DEBUG) $(SRC) -o $(TARGET)
	rm -f *.o

bytecode:
	ruby make_bytecode.rb vm_bytecode.bin
	cp vm_bytecode.bin vm_bytecode.clear.bin
	$(UTILS_DIR)/chacha_crypt vm_bytecode.bin
	$(UTILS_DIR)/bin_to_c_decl.rb vm_bytecode.bin vm_bytecode
	#rm -f vm_bytecode.bin

dis:
	$(OBJDUMP) -d $(TARGET) | most

run:
	$(QEMU) $(TARGET)

test:
	$(QEMU) -strace $(TARGET)

gdb:
	$(QEMU) -g 1234 $(TARGET)

util:
	gcc -I$(INCLUDE_DIR)/chacha chacha.c chacha_util_crypt.c -o $(UTILS_DIR)/chacha_crypt
	gcc lz4_util_compress.c $(LZ4_DIR)/lz4.c $(LZ4_DIR)/lz4hc.c -o $(UTILS_DIR)/lz4_util_compress
	ln -sf lz4_util_compress $(UTILS_DIR)/lz4hc_util_compress

bundle:
	@cd mcu; ruby assembler.rb > /dev/null
	zip mcu_programmer.zip mcu/upload.py mcu/fw.hex

clean:
	rm -f $(TARGET) $(TMP_DIR)/* *.o *.s vm_bytecode.* a.out *.elf *.packed *.txz
