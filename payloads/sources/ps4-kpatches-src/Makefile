TARGET_VERSIONS = 900 903 950 1000 1050 1100 1102 1150 1200

CC = gcc
OBJCOPY = objcopy
CFLAGS = -O3 -std=gnu11 -Wno-int-conversion -masm=intel -nostartfiles -fcf-protection=none -Tscript.ld

.PHONY: all
ALL_SOURCES = $(TARGET_VERSIONS:%=%.c)
ALL_OBJECTS = $(TARGET_VERSIONS:%=%.o)
ALL_BINS = $(TARGET_VERSIONS:%=%.bin)

all: $(ALL_BINS)

%.bin: %.o
	$(CC) $< -o $*.elf $(CFLAGS)
	$(OBJCOPY) -O binary --only-section=.text $*.elf $@
	-rm -f $*.elf

.PHONY: clean
clean:
	-rm -f $(ALL_OBJECTS) $(ALL_BINS)
