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
SRC=main.c chacha.c vm.c
TARGET=sstic14-armecage

all: debug

release: util
	ruby make_bytecode.rb
	$(COMPILE_RELEASE) $(SRC)
	for obj in *.s; do \
		ruby armor.rb --enable "shuffle_blocks,shuffle_insns,junk,expand_insns" $$obj ; \
		$(ASSEMBLE) $$obj -o $$obj.o ; \
	done
	$(LINK) *.o -o $(TARGET)
	rm -f *.o
	$(STRIP) $(TARGET)

debug: util
	ruby make_bytecode.rb
	$(COMPILE_DEBUG) $(SRC) -o $(TARGET)
	rm -f *.o

dis:
	$(OBJDUMP) -d $(TARGET) | most

run:
	$(QEMU) -strace $(TARGET)

gdb:
	$(QEMU) -g 1234 $(TARGET)

util:
	gcc chacha.c chacha_util_crypt.c -o chacha_crypt

clean:
	rm -f $(TARGET) *.o *.s vm_bytecode.* a.out
