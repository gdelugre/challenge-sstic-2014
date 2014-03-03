CC=aarch64-linux-gnu-gcc
AS=aarch64-linux-gnu-as
LD=aarch64-linux-gnu-ld
STRIP=aarch64-linux-gnu-strip
OBJDUMP=aarch64-linux-gnu-objdump
QEMU=~/tmp/qemu/aarch64-linux-user/qemu-aarch64
CFLAGS_RELEASE=-Wall -std=gnu11 -mcpu=generic+nosimd+nofp -O2 -static -nostdlib -nodefaultlibs -ffixed-x28
CFLAGS_DEBUG=-Wall -std=gnu11 -mcpu=generic+nosimd+nofp -O2 -static -ffixed-x28 -DDEBUG
LDFLAGS=-estart
COMPILE_RELEASE=$(CC) $(CFLAGS_RELEASE) -S
COMPILE_DEBUG=$(CC) $(CFLAGS_DEBUG)
ASSEMBLE=$(AS)
LINK=$(LD) $(LDFLAGS)
LZ4_DIR=lz4
UTILS_DIR=utils
SRC=main.c chacha.c vm.c
TARGET=sstic14-armecage.elf

all: debug

release: util bytecode
	$(COMPILE_RELEASE) $(SRC)
	for obj in *.s; do \
		ruby armor.rb --enable "shuffle_blocks,shuffle_insns,junk,expand_insns" $$obj ; \
		$(ASSEMBLE) $$obj -o $$obj.o ; \
	done
	$(LINK) *.o -o $(TARGET)
	rm -f *.o
	$(STRIP) $(TARGET)

debug: util bytecode
	$(COMPILE_DEBUG) $(SRC) -o $(TARGET)
	rm -f *.o

bytecode:
	ruby make_bytecode.rb vm_bytecode.bin
	$(UTILS_DIR)/chacha_crypt vm_bytecode.bin
	ruby $(UTILS_DIR)/bin_to_c_decl.rb vm_bytecode.bin vm_bytecode
	rm -f vm_bytecode.bin

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
	make -C $(LZ4_DIR)/programs lz4
	mv -u $(LZ4_DIR)/programs/lz4 $(UTILS_DIR)

clean:
	rm -f $(TARGET) *.o *.s vm_bytecode.* a.out
