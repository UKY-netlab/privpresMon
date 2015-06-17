OPENWRT = ${HOME}/openwrt/attitude_adjustment
KERNEL = ${OPENWRT}/build_dir/linux-ar71xx_generic/linux-3.3.8

obj-m += nfl_mod.o
nfl_mod-objs := nfl.o nfl_functions.o
MY_CFLAGS += -Wall

all:
	make -C ${KERNEL} ARCH="mips" CC=mips-openwrt-linux-uclibc-gcc LD=mips-openwrt-linux-uclibc-ld M=$(PWD) EXTRA_CFLAGS="$(MY_CFLAGS)" modules

clean:
	make -C ${KERNEL} CC=mips-openwrt-linux-uclibc-gcc LD=mips-openwrt-linux-uclibc-ld M=$(PWD) clean

debug:	MY_CFLAGS += -DNFL_DEBUG
debug:
	make -C ${KERNEL} ARCH="mips" CC=mips-openwrt-linux-uclibc-gcc LD=mips-openwrt-linux-uclibc-ld M=$(PWD) EXTRA_CFLAGS="$(MY_CFLAGS)" modules

dwbr:	MY_CFLAGS += -DBR_FORWARD -DNFL_DEBUG
dwbr:
	make -C ${KERNEL} ARCH="mips" CC=mips-openwrt-linux-uclibc-gcc LD=mips-openwrt-linux-uclibc-ld M=$(PWD) EXTRA_CFLAGS="$(MY_CFLAGS)" modules

dpre:	MY_CFLAGS += -DNO_LOCAL_OUT -DNFL_DEBUG
dpre:
	make -C ${KERNEL} ARCH="mips" CC=mips-openwrt-linux-uclibc-gcc LD=mips-openwrt-linux-uclibc-ld M=$(PWD) EXTRA_CFLAGS="$(MY_CFLAGS)" modules

dlo:	MY_CFLAGS += -DNO_PRE_ROUTING -DNFL_DEBUG
dlo:
	make -C ${KERNEL} ARCH="mips" CC=mips-openwrt-linux-uclibc-gcc LD=mips-openwrt-linux-uclibc-ld M=$(PWD) EXTRA_CFLAGS="$(MY_CFLAGS)" modules

dbr:	MY_CFLAGS += -DNO_PRE_ROUTING -DNO_LOCAL_OUT -DBR_FORWARD -DNFL_DEBUG
dbr:
	make -C ${KERNEL} ARCH="mips" CC=mips-openwrt-linux-uclibc-gcc LD=mips-openwrt-linux-uclibc-ld M=$(PWD) EXTRA_CFLAGS="$(MY_CFLAGS)" modules
