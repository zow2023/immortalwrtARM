KERNEL_LOADADDR := 0x44080000

define Device/bpi_bananapi-r64
  DEVICE_VENDOR := Bpi
  DEVICE_MODEL := Banana Pi R64
  DEVICE_DTS := mt7622-bananapi-bpi-r64
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  SUPPORTED_DEVICES := bananapi,bpi-r64
  DEVICE_PACKAGES := kmod-usb-ohci kmod-usb2 kmod-usb3 kmod-ata-ahci-mtk
endef
TARGET_DEVICES += bpi_bananapi-r64

define Device/bpi_bananapi-r64-rootdisk
  DEVICE_VENDOR := Bpi
  DEVICE_MODEL := Banana Pi R64 (rootdisk)
  DEVICE_DTS := mt7622-bananapi-bpi-r64-rootdisk
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  SUPPORTED_DEVICES := bananapi,bpi-r64
  DEVICE_PACKAGES := kmod-usb-ohci kmod-usb2 kmod-usb3 kmod-ata-ahci-mtk
  IMAGES := sysupgrade-emmc.bin.gz
  IMAGE/sysupgrade-emmc.bin.gz := sysupgrade-emmc | gzip | append-metadata
endef
TARGET_DEVICES += bpi_bananapi-r64-rootdisk

define Device/elecom_wrc-2533gent
  DEVICE_VENDOR := Elecom
  DEVICE_MODEL := WRC-2533GENT
  DEVICE_DTS := mt7622-elecom-wrc-2533gent
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  DEVICE_PACKAGES := kmod-usb-ohci kmod-usb2 kmod-usb3 kmod-mt7615e \
	kmod-mt7615-firmware kmod-btmtkuart swconfig
endef
TARGET_DEVICES += elecom_wrc-2533gent

define Device/mediatek_mt7622-rfb1
  DEVICE_VENDOR := MediaTek
  DEVICE_MODEL := MTK7622 rfb1 AP
  DEVICE_DTS := mt7622-rfb1
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  DEVICE_PACKAGES := kmod-usb-ohci kmod-usb2 kmod-usb3 kmod-ata-ahci-mtk
endef
TARGET_DEVICES += mediatek_mt7622-rfb1

define Device/mediatek_mt7622-ubi
  DEVICE_VENDOR := MediaTek
  DEVICE_MODEL := MTK7622 AP (UBI)
  DEVICE_DTS := mt7622-rfb1-ubi
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  UBINIZE_OPTS := -E 5
  BLOCKSIZE := 128k
  PAGESIZE := 2048
  KERNEL_SIZE := 4194304
  IMAGE_SIZE := 32768k
  IMAGES += factory.bin
  IMAGE/factory.bin := append-kernel | pad-to $$(KERNEL_SIZE) | append-ubi | \
                check-size $$$$(IMAGE_SIZE)
  IMAGE/sysupgrade.bin := sysupgrade-tar
  DEVICE_PACKAGES := kmod-usb-ohci kmod-usb2 kmod-usb3 kmod-ata-ahci-mtk
endef
TARGET_DEVICES += mediatek_mt7622-ubi

define Device/ubnt_unifi-6-lr
  DEVICE_VENDOR := Ubiquiti
  DEVICE_MODEL := UniFi 6 LR
  DEVICE_DTS := mt7622-ubnt-unifi-6-lr
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  DEVICE_PACKAGES := kmod-mt7915e
endef
TARGET_DEVICES += ubnt_unifi-6-lr

define Device/xiaomi_redmi-router-ax6s
   DEVICE_VENDOR := Xiaomi
   DEVICE_MODEL := Redmi Router AX6S
   DEVICE_ALT0_VENDOR := Xiaomi
   DEVICE_ALT0_MODEL := Router AX3200
   DEVICE_DTS := mt7622-xiaomi-redmi-router-ax6s
   DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
   BOARD_NAME := xiaomi,redmi-router-ax6s
   DEVICE_PACKAGES :=luci-app-mtwifi l1profile wireless-tools  kmod-mt7622 kmod-mt_wifi ipv6helper kmod-mediatek_hnat bash autocore-arm luci-app-turboacc-mtk
   UBINIZE_OPTS := -E 5
   IMAGES += factory.bin
   BLOCKSIZE := 128k
   PAGESIZE := 2048
   KERNEL_SIZE :=10240k
   IMAGE/factory.bin := append-kernel | pad-to $$(KERNEL_SIZE) | append-ubi
   IMAGE/sysupgrade.bin := sysupgrade-tar | append-metadata
endef
TARGET_DEVICES += xiaomi_redmi-router-ax6s

define Device/netgear_wax206
   DEVICE_VENDOR := NETGEAR
   DEVICE_MODEL := WAX206
   DEVICE_DTS := mt7622-netgear-wax206
   DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
   NETGEAR_ENC_MODEL := WAX206
   NETGEAR_ENC_REGION := US
   DEVICE_PACKAGES :=luci-app-mtwifi l1profile wireless-tools  kmod-mt7622 kmod-mt_wifi ipv6helper kmod-mediatek_hnat bash autocore-arm luci-app-turboacc-mtk
   UBINIZE_OPTS := -E 5
   IMAGES += factory.bin
   BLOCKSIZE := 128k
   PAGESIZE := 2048
   KERNEL_SIZE :=6144k
   IMAGE_SIZE := 32768k 
   IMAGE/sysupgrade.bin := sysupgrade-tar | append-metadata
endef
TARGET_DEVICES += netgear_wax206

define Device/linksys_e8450-ubi
  DEVICE_VENDOR := Linksys
  DEVICE_MODEL := E8450
  DEVICE_VARIANT := UBI
  DEVICE_ALT0_VENDOR := Belkin
  DEVICE_ALT0_MODEL := RT3200
  DEVICE_ALT0_VARIANT := UBI
  DEVICE_DTS := mt7622-linksys-e8450-ubi
  DEVICE_DTS_DIR := ../dts
  DEVICE_PACKAGES := kmod-mt7915e kmod-usb3
  UBINIZE_OPTS := -E 5
  BLOCKSIZE := 128k
  PAGESIZE := 2048
  UBOOTENV_IN_UBI := 1
  KERNEL_IN_UBI := 1
  KERNEL := kernel-bin | gzip
# recovery can also be used with stock firmware web-ui, hence the padding...
  KERNEL_INITRAMFS := kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd | pad-to 128k
  KERNEL_INITRAMFS_SUFFIX := -recovery.itb
  IMAGES := sysupgrade.itb
  IMAGE/sysupgrade.itb := append-kernel | fit gzip $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb external-static-with-rootfs | append-metadata
  ARTIFACTS := preloader.bin bl31-uboot.fip
  ARTIFACT/preloader.bin := bl2 snand-1ddr
  ARTIFACT/bl31-uboot.fip := bl31-uboot linksys_e8450
endef
TARGET_DEVICES += linksys_e8450-ubi
