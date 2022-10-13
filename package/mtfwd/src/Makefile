ifneq ($(KERNELRELEASE),)

obj-$(CONFIG_MTFWD_SUPPORT) := mtfwd.o

else

KERNEL_DIR = $(PWD)/../../$(LINUXDIR)
CROSS_COMPILE :=
ARCH := arm64
CONFIG_MTFWD_SUPPORT = m
export CROSS_COMPILE ARCH CONFIG_MTFWD_SUPPORT

default:
	make -C $(KERNEL_DIR) M=$(shell pwd) modules
clean:
	rm -f *.ko
	rm -f *.o
	rm -f *.order
	rm -f *.symvers
	rm -f *.mod.*
	rm -f .*.cmd
	rm -rf .tmp_versions
	rm -f *.builtin
endif #KERNELRELEASE

