#
# Copyright (C) 2016 MediaTek
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/version.mk

PKG_NAME:=wifi-profile
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/wifi-profile
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  DEPENDS:=
  TITLE:=WiFi l1 & l2 profile
  VERSION:=$(PKG_RELEASE)
  MENU:=1
endef

define Package/wifi-profile/description
  This package install wifi l1 and l2 profile.
endef

define Package/wifi-profile/config
	if PACKAGE_wifi-profile
	source "$(SOURCE)/Config.in"
	endif
endef

define Build/Compile
endef

define Package/wifi-profile/conffiles
/etc/wireless/
endef

define Package/wifi-profile/install
	$(INSTALL_DIR) $(1)/etc/wireless/
	$(INSTALL_DIR) $(1)/lib/wifi/
	$(INSTALL_DIR) $(1)/etc/wireless/mediatek/
	$(INSTALL_DIR) $(1)/sbin/
	$(INSTALL_BIN) ./files/common/wifi_jedi $(1)/sbin/wifi
	$(INSTALL_BIN) ./files/common/mtwifi.lua $(1)/lib/wifi/
	$(INSTALL_BIN) ./files/common/quick_setting.lua $(1)/lib/wifi/
	$(INSTALL_DATA) ./files/mt7981/* $(1)/etc/wireless/mediatek/
	mv $(1)/etc/wireless/mediatek/l1profile.dat $(1)/etc/wireless/l1profile.dat 
	
endef

$(eval $(call BuildPackage,wifi-profile))
