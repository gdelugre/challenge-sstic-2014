CC=aarch64-linux-gnu-gcc
AS=aarch64-linux-gnu-as
LD=aarch64-linux-gnu-ld
STRIP=aarch64-linux-gnu-strip
OBJDUMP=aarch64-linux-gnu-objdump
OBJCOPY=aarch64-linux-gnu-objcopy
QEMU=~/tmp/qemu/aarch64-linux-user/qemu-aarch64
CFLAGS_RELEASE=-Wall -std=gnu11 -mcpu=generic+nosimd+nofp -O2 -static -nostdlib -nodefaultlibs -ffixed-x28
CFLAGS_DEBUG=-Wall -std=gnu11 -mcpu=generic+nosimd+nofp -O2 -static -ffixed-x28 -DDEBUG
LDFLAGS=-estart
COMPILE_RELEASE=$(CC) $(CFLAGS_RELEASE) -S
COMPILE_DEBUG=$(CC) $(CFLAGS_DEBUG)
ASSEMBLE=$(AS)
LINK=$(LD) $(LDFLAGS)
LZ4_DIR=lz4
TMP_DIR=tmp
STUB_DIR=stub
UTILS_DIR=utils
SRC=main.c chacha.c vm.c
TARGET=sstic14-armageddon.elf

TEXT_ADDR=0x400000
DATA_ADDR=0x500000

all: debug 

debug: dirs compile_debug
release: dirs compile_release compress

dirs:
	mkdir -p $(TMP_DIR)

compress:
	$(UTILS_DIR)/compress_elf.rb $(TARGET) $(TMP_DIR)/elf_map.h
	$(CC) $(CFLAGS_RELEASE) $(STUB_DIR)/start.S $(STUB_DIR)/stub.c $(LZ4_DIR)/lz4_reduced.c -I. -I$(TMP_DIR) -o $(TARGET).packed -Wl,-Ttext-segment=0x10000
	$(STRIP) $(TARGET).packed
	$(OBJCOPY) -w -R '.note.gnu.build-id' -R .comment $(TARGET).packed
	#rm -f *.o
	echo "Done."

compile_release: util bytecode
	$(COMPILE_RELEASE) $(SRC)
	cp start.ASM start.s
	for obj in *.s; do \
		cp $$obj $(TMP_DIR)/$$obj.orig ; \
		ruby armor.rb -c aarch64/armor.conf $$obj ; \
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
	gcc chacha.c chacha_util_crypt.c -o $(UTILS_DIR)/chacha_crypt
	gcc lz4_util_compress.c $(LZ4_DIR)/lz4.c $(LZ4_DIR)/lz4hc.c -o $(UTILS_DIR)/lz4_util_compress
	ln -sf lz4_util_compress $(UTILS_DIR)/lz4hc_util_compress

bundle:
	@cd mcu; ruby assembler.rb > /dev/null
	zip mcu_programmer.zip mcu/upload.py mcu/fw.hex

clean:
	rm -f $(TARGET) $(TMP_DIR)/* *.o *.s vm_bytecode.* a.out *.elf *.packed *.txz
