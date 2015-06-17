OPENWRT = ${HOME}/openwrt/attitude_adjustment
KERNEL = ${OPENWRT}/build_dir/linux-ar71xx_generic/linux-3.3.8

obj-m += dnsres.o
dnsres_mod-objs := dnsres.o
MY_CFLAGS += -Wall

all:
	make -C ${KERNEL} ARCH="mips" CC=mips-openwrt-linux-uclibc-gcc LD=mips-openwrt-linux-uclibc-ld M=$(PWD) EXTRA_CFLAGS="$(MY_CFLAGS)" modules

clean:
	make -C ${KERNEL} CC=mips-openwrt-linux-uclibc-gcc LD=mips-openwrt-linux-uclibc-ld M=$(PWD) clean

debug:	MY_CFLAGS += -DDNSRES_DEBUG
debug:
	make -C ${KERNEL} ARCH="mips" CC=mips-openwrt-linux-uclibc-gcc LD=mips-openwrt-linux-uclibc-ld M=$(PWD) EXTRA_CFLAGS="$(MY_CFLAGS)" modules