CC := gcc

CFLAGS := $(FLAG)
CFLAGS += -g -Wall -c -D _FILE_OFFSET_BITS=64 -D LZO_DEBUG

#CXX = g++
#CLFLAGS = -O2 -Wall -D_7ZIP_ST

ASCC := as
ASFLAGS := -g
.LINK := -l

SRCS := main.c common.c bsdiffpatch.c compress.c minilzo.c network.c
OBJS := $(SRCS:.c=.o)

LIBNAMES := zstd bz2 pthread
LINKFLAGS := $(addprefix $(.LINK),$(LIBNAMES))

TARGET := main

.PHONY:all clean dep
all: $(TARGET)

main: $(OBJS) 
	$(CC) $^ -o $@ $(LINKFLAGS)
	
#below is the interface part
main.o: main.c
	$(CC) $(CFLAGS) $^ -o $@
common.o: common.c
	$(CC) $(CFLAGS) $^ -o $@
bsdiffpatch.o: bsdiffpatch.c
	$(CC) $(CFLAGS) $^ -o $@
compress.o: compress.c
	$(CC) $(CFLAGS) $^ -o $@
minilzo.o: minilzo.c
	$(CC) $(CFLAGS) $^ -o $@
network.o: network.c
	$(CC) $(CFLAGS) $^ -o $@
clean:
	-rm -f  $(OBJS) $(TARGET)
	
dep:
	@for i in $(SRCS); do echo `$(CC) -MM $$i`; done
