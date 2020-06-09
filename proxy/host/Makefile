CC ?= $(CROSS_COMPILE)gcc
LD ?= $(CROSS_COMPILE)ld
AR ?= $(CROSS_COMPILE)ar
NM ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

OBJS=proxy_client.o

CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include -I./include -I$(HOME)/qemu-optee/mbedtls/include
LDADD += -lteec -L$(TEEC_EXPORT)/lib -lmbedtls -lmbedx509 -lmbedcrypto -L$(HOME)/qemu-optee/mbedtls/build/library

BINARY=proxy_client

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) -o $@ $< $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
