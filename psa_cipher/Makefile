export V ?= 0

# If _HOST or _TA specific compilers are not specified, then use CROSS_COMPILE
HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)
TA_CROSS_COMPILE ?= $(CROSS_COMPILE)

TA_NO_STACK_PROTECT ?= 1
CFLAGS  := $(filter-out -fstack-protector -fstack-protector-strong -fstack-protector-all,$(CFLAGS))
CFLAGS  += -fno-stack-protector
CPPFLAGS := $(filter-out -D_FORTIFY_SOURCE=%,$(CPPFLAGS))
CPPFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0


.PHONY: all
all:
	$(MAKE) -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables
	$(MAKE) -C ta CROSS_COMPILE="$(TA_CROSS_COMPILE)" TA_DEV_KIT_DIR="$(TA_DEV_KIT_DIR)"             \
                                                      		CFLAGS+="$(TA_EXTRA_CFLAGS)"                    \
                                                      		CPPFLAGS+="$(TA_EXTRA_CPPFLAGS)"               \
                                                      		LDFLAGS=""

.PHONY: clean
clean:
	$(MAKE) -C host clean
	$(MAKE) -C ta clean
