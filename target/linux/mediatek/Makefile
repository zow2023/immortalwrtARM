# Copyright (c) 2015 OpenWrt.org
#
include $(TOPDIR)/rules.mk

ARCH:=arm
BOARD:=mediatek
BOARDNAME:=MediaTek Ralink ARM
SUBTARGETS:=mt7622 mt7623 mt7629 mt7986 mt7981
FEATURES:=squashfs nand ramdisk fpu

KERNEL_PATCHVER:=5.4
KERNEL_TESTING_PATCHVER:=5.4

include $(INCLUDE_DIR)/target.mk
DEFAULT_PACKAGES += \
	kmod-leds-gpio kmod-gpio-button-hotplug \
	autocore-arm mtkiappd uboot-envtools iptables-mod-ipopt luci-app-mtk l1profile wireless-tools \
	kmod-conninfra kmod-warp kmod-mt_wifi ipv6helper kmod-mediatek_hnat bash autocore-arm \
	mtkhnat_util  wifi-profile swconfig luci-app-turboacc-mtk

$(eval $(call BuildTarget))
