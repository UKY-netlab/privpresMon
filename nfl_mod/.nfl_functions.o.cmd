cmd_/home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/nfl_functions.o := mips-openwrt-linux-uclibc-gcc -Wp,-MD,/home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/.nfl_functions.o.d  -nostdinc -isystem /home/xuzizhou/openwrt/attitude_adjustment/staging_dir/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2/lib/gcc/mips-openwrt-linux-uclibc/4.6.3/include -I/home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include -Iarch/mips/include/generated -Iinclude  -include /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/include/linux/kconfig.h -D__KERNEL__ -D"VMLINUX_LOAD_ADDRESS=0xffffffff80060000" -D"DATAOFFSET=0" -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Wno-format-security -fno-delete-null-pointer-checks -Os -fno-caller-saves -mno-check-zero-division -mabi=32 -G 0 -mno-abicalls -fno-pic -pipe -msoft-float -ffreestanding -march=mips32r2 -Wa,-mips32r2 -Wa,--trap -I/home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/mach-ath79 -I/home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/mach-generic -Wframe-larger-than=1024 -fno-stack-protector -Wno-unused-but-set-variable -fomit-frame-pointer -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fconserve-stack -DCC_HAVE_ASM_GOTO -Wall  -DMODULE -mno-long-calls  -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(nfl_functions)"  -D"KBUILD_MODNAME=KBUILD_STR(nfl_mod)" -c -o /home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/nfl_functions.o /home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/nfl_functions.c

source_/home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/nfl_functions.o := /home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/nfl_functions.c

deps_/home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/nfl_functions.o := \
  include/linux/file.h \
  include/linux/compiler.h \
    $(wildcard include/config/sparse/rcu/pointer.h) \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
  include/linux/compiler-gcc4.h \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbdaf.h) \
    $(wildcard include/config/arch/dma/addr/t/64bit.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/64bit.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/types.h \
    $(wildcard include/config/64bit/phys/addr.h) \
  include/asm-generic/int-ll64.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/bitsperlong.h \
  include/asm-generic/bitsperlong.h \
  include/linux/posix_types.h \
  include/linux/stddef.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/posix_types.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/sgidefs.h \
  include/linux/fs.h \
    $(wildcard include/config/sysfs.h) \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/fs/posix/acl.h) \
    $(wildcard include/config/security.h) \
    $(wildcard include/config/quota.h) \
    $(wildcard include/config/fsnotify.h) \
    $(wildcard include/config/ima.h) \
    $(wildcard include/config/preempt.h) \
    $(wildcard include/config/epoll.h) \
    $(wildcard include/config/debug/writecount.h) \
    $(wildcard include/config/file/locking.h) \
    $(wildcard include/config/auditsyscall.h) \
    $(wildcard include/config/block.h) \
    $(wildcard include/config/debug/lock/alloc.h) \
    $(wildcard include/config/fs/xip.h) \
    $(wildcard include/config/migration.h) \
  include/linux/limits.h \
  include/linux/ioctl.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/ioctl.h \
  include/asm-generic/ioctl.h \
  include/linux/blk_types.h \
    $(wildcard include/config/blk/dev/integrity.h) \
  include/linux/linkage.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/linkage.h \
  include/linux/wait.h \
    $(wildcard include/config/lockdep.h) \
  include/linux/list.h \
    $(wildcard include/config/debug/list.h) \
  include/linux/poison.h \
    $(wildcard include/config/illegal/pointer/value.h) \
  include/linux/const.h \
  include/linux/spinlock.h \
    $(wildcard include/config/debug/spinlock.h) \
    $(wildcard include/config/generic/lockbreak.h) \
  include/linux/typecheck.h \
  include/linux/preempt.h \
    $(wildcard include/config/debug/preempt.h) \
    $(wildcard include/config/preempt/tracer.h) \
    $(wildcard include/config/preempt/count.h) \
    $(wildcard include/config/preempt/notifiers.h) \
  include/linux/thread_info.h \
    $(wildcard include/config/compat.h) \
  include/linux/bitops.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/bitops.h \
    $(wildcard include/config/cpu/mipsr2.h) \
  include/linux/irqflags.h \
    $(wildcard include/config/trace/irqflags.h) \
    $(wildcard include/config/irqsoff/tracer.h) \
    $(wildcard include/config/trace/irqflags/support.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/irqflags.h \
    $(wildcard include/config/mips/mt/smtc.h) \
    $(wildcard include/config/irq/cpu.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/hazards.h \
    $(wildcard include/config/cpu/cavium/octeon.h) \
    $(wildcard include/config/cpu/mipsr1.h) \
    $(wildcard include/config/mips/alchemy.h) \
    $(wildcard include/config/cpu/bmips.h) \
    $(wildcard include/config/cpu/loongson2.h) \
    $(wildcard include/config/cpu/r10000.h) \
    $(wildcard include/config/cpu/r5500.h) \
    $(wildcard include/config/cpu/rm9000.h) \
    $(wildcard include/config/cpu/sb1.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/cpu-features.h \
    $(wildcard include/config/32bit.h) \
    $(wildcard include/config/cpu/mipsr2/irq/vi.h) \
    $(wildcard include/config/cpu/mipsr2/irq/ei.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/cpu.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/cpu-info.h \
    $(wildcard include/config/mips/mt/smp.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/cache.h \
    $(wildcard include/config/mips/l1/cache/shift.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/mach-generic/kmalloc.h \
    $(wildcard include/config/dma/coherent.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/mach-ath79/cpu-feature-overrides.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/barrier.h \
    $(wildcard include/config/cpu/has/sync.h) \
    $(wildcard include/config/sgi/ip28.h) \
    $(wildcard include/config/cpu/has/wb.h) \
    $(wildcard include/config/weak/ordering.h) \
    $(wildcard include/config/weak/reordering/beyond/llsc.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/bug.h \
    $(wildcard include/config/bug.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/break.h \
  include/asm-generic/bug.h \
    $(wildcard include/config/generic/bug.h) \
    $(wildcard include/config/generic/bug/relative/pointers.h) \
    $(wildcard include/config/debug/bugverbose.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/byteorder.h \
  include/linux/byteorder/big_endian.h \
  include/linux/swab.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/swab.h \
  include/linux/byteorder/generic.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/war.h \
    $(wildcard include/config/cpu/r4000/workarounds.h) \
    $(wildcard include/config/cpu/r4400/workarounds.h) \
    $(wildcard include/config/cpu/daddi/workarounds.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/mach-ath79/war.h \
  include/asm-generic/bitops/non-atomic.h \
  include/asm-generic/bitops/fls64.h \
  include/asm-generic/bitops/ffz.h \
  include/asm-generic/bitops/find.h \
    $(wildcard include/config/generic/find/first/bit.h) \
  include/asm-generic/bitops/sched.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/arch_hweight.h \
  include/asm-generic/bitops/arch_hweight.h \
  include/asm-generic/bitops/const_hweight.h \
  include/asm-generic/bitops/le.h \
  include/asm-generic/bitops/ext2-atomic.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/thread_info.h \
    $(wildcard include/config/page/size/4kb.h) \
    $(wildcard include/config/page/size/8kb.h) \
    $(wildcard include/config/page/size/16kb.h) \
    $(wildcard include/config/page/size/32kb.h) \
    $(wildcard include/config/page/size/64kb.h) \
    $(wildcard include/config/debug/stack/usage.h) \
    $(wildcard include/config/mips32/o32.h) \
    $(wildcard include/config/mips32/n32.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/processor.h \
    $(wildcard include/config/cavium/octeon/cvmseg/size.h) \
    $(wildcard include/config/mips/mt/fpaff.h) \
    $(wildcard include/config/cpu/has/prefetch.h) \
  include/linux/cpumask.h \
    $(wildcard include/config/cpumask/offstack.h) \
    $(wildcard include/config/hotplug/cpu.h) \
    $(wildcard include/config/debug/per/cpu/maps.h) \
    $(wildcard include/config/disable/obsolete/cpumask/functions.h) \
  include/linux/kernel.h \
    $(wildcard include/config/preempt/voluntary.h) \
    $(wildcard include/config/debug/atomic/sleep.h) \
    $(wildcard include/config/prove/locking.h) \
    $(wildcard include/config/ring/buffer.h) \
    $(wildcard include/config/tracing.h) \
    $(wildcard include/config/numa.h) \
    $(wildcard include/config/compaction.h) \
    $(wildcard include/config/ftrace/mcount/record.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/staging_dir/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2/lib/gcc/mips-openwrt-linux-uclibc/4.6.3/include/stdarg.h \
  include/linux/log2.h \
    $(wildcard include/config/arch/has/ilog2/u32.h) \
    $(wildcard include/config/arch/has/ilog2/u64.h) \
  include/linux/printk.h \
    $(wildcard include/config/printk.h) \
    $(wildcard include/config/dynamic/debug.h) \
  include/linux/init.h \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/hotplug.h) \
  include/linux/dynamic_debug.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/div64.h \
  include/asm-generic/div64.h \
  include/linux/threads.h \
    $(wildcard include/config/nr/cpus.h) \
    $(wildcard include/config/base/small.h) \
  include/linux/bitmap.h \
  include/linux/string.h \
    $(wildcard include/config/binary/printf.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/string.h \
    $(wildcard include/config/cpu/r3000.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/cachectl.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/mipsregs.h \
    $(wildcard include/config/cpu/vr41xx.h) \
    $(wildcard include/config/hugetlb/page.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/prefetch.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/system.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/addrspace.h \
    $(wildcard include/config/cpu/r8000.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/mach-generic/spaces.h \
    $(wildcard include/config/dma/noncoherent.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/cmpxchg.h \
  include/asm-generic/cmpxchg-local.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/dsp.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/watch.h \
    $(wildcard include/config/hardware/watchpoints.h) \
  include/linux/stringify.h \
  include/linux/bottom_half.h \
  include/linux/spinlock_types.h \
  include/linux/spinlock_types_up.h \
  include/linux/lockdep.h \
    $(wildcard include/config/lock/stat.h) \
    $(wildcard include/config/prove/rcu.h) \
  include/linux/rwlock_types.h \
  include/linux/spinlock_up.h \
  include/linux/rwlock.h \
  include/linux/spinlock_api_up.h \
  include/linux/atomic.h \
    $(wildcard include/config/arch/has/atomic/or.h) \
    $(wildcard include/config/generic/atomic64.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/atomic.h \
  include/asm-generic/atomic-long.h \
  include/asm-generic/atomic64.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/current.h \
  include/asm-generic/current.h \
  include/linux/kdev_t.h \
  include/linux/dcache.h \
  include/linux/rculist.h \
  include/linux/rcupdate.h \
    $(wildcard include/config/rcu/torture/test.h) \
    $(wildcard include/config/tree/rcu.h) \
    $(wildcard include/config/tree/preempt/rcu.h) \
    $(wildcard include/config/rcu/trace.h) \
    $(wildcard include/config/preempt/rcu.h) \
    $(wildcard include/config/tiny/rcu.h) \
    $(wildcard include/config/tiny/preempt/rcu.h) \
    $(wildcard include/config/debug/objects/rcu/head.h) \
    $(wildcard include/config/preempt/rt.h) \
  include/linux/cache.h \
    $(wildcard include/config/arch/has/cache/line/size.h) \
  include/linux/seqlock.h \
  include/linux/completion.h \
  include/linux/debugobjects.h \
    $(wildcard include/config/debug/objects.h) \
    $(wildcard include/config/debug/objects/free.h) \
  include/linux/rcutiny.h \
    $(wildcard include/config/rcu/boost.h) \
  include/linux/rculist_bl.h \
  include/linux/list_bl.h \
  include/linux/bit_spinlock.h \
  include/linux/path.h \
  include/linux/stat.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/stat.h \
  include/linux/time.h \
    $(wildcard include/config/arch/uses/gettimeoffset.h) \
  include/linux/math64.h \
  include/linux/radix-tree.h \
  include/linux/prio_tree.h \
  include/linux/pid.h \
  include/linux/mutex.h \
    $(wildcard include/config/debug/mutexes.h) \
    $(wildcard include/config/have/arch/mutex/cpu/relax.h) \
  include/linux/capability.h \
  include/linux/semaphore.h \
  include/linux/fiemap.h \
  include/linux/shrinker.h \
  include/linux/migrate_mode.h \
  include/linux/quota.h \
    $(wildcard include/config/quota/netlink/interface.h) \
  include/linux/errno.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/errno.h \
  include/asm-generic/errno-base.h \
  include/linux/rwsem.h \
    $(wildcard include/config/rwsem/generic/spinlock.h) \
  include/linux/rwsem-spinlock.h \
  include/linux/percpu_counter.h \
  include/linux/smp.h \
    $(wildcard include/config/use/generic/smp/helpers.h) \
  include/linux/percpu.h \
    $(wildcard include/config/need/per/cpu/embed/first/chunk.h) \
    $(wildcard include/config/need/per/cpu/page/first/chunk.h) \
    $(wildcard include/config/have/setup/per/cpu/area.h) \
  include/linux/pfn.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/percpu.h \
  include/asm-generic/percpu.h \
  include/linux/percpu-defs.h \
    $(wildcard include/config/debug/force/weak/per/cpu.h) \
  include/linux/dqblk_xfs.h \
  include/linux/dqblk_v1.h \
  include/linux/dqblk_v2.h \
  include/linux/dqblk_qtree.h \
  include/linux/nfs_fs_i.h \
  include/linux/nfs.h \
  include/linux/sunrpc/msg_prot.h \
  include/linux/inet.h \
  include/linux/fcntl.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/fcntl.h \
  include/asm-generic/fcntl.h \
  include/linux/err.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/uaccess.h \
  include/linux/timer.h \
    $(wildcard include/config/timer/stats.h) \
    $(wildcard include/config/debug/objects/timers.h) \
  include/linux/ktime.h \
    $(wildcard include/config/ktime/scalar.h) \
  include/linux/jiffies.h \
  include/linux/timex.h \
  include/linux/param.h \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/param.h \
  include/asm-generic/param.h \
    $(wildcard include/config/hz.h) \
  /home/xuzizhou/openwrt/attitude_adjustment/build_dir/linux-ar71xx_generic/linux-3.3.8/arch/mips/include/asm/timex.h \
  /home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/crc.h \
  /home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/nfl.h \
  /home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/uthash.h \
  /home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/nfl_functions.h \

/home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/nfl_functions.o: $(deps_/home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/nfl_functions.o)

$(deps_/home/xuzizhou/Dropbox/00Project/Experiments/nfl_mod/kernel_mod/src/nfl_functions.o):
