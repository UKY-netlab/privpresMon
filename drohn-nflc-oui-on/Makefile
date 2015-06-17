##############################################
# OpenWrt Makefile for DR.OHN nflc OUI feature 
# 
##############################################

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=drohn-nflc-oui-on
PKG_VERSION:=1.0
PKG_RELEASE:=a

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/drohn-nflc-oui-on
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=DR.OHN Update
	DEPENDS:=+drohn-nflc
endef

define Package/drohn-nflc-oui-on/description
	define Package/drohn-nflc-oui-on/description
	Package drohn-nflc-oui-on is to turn on OUI logging feature in
	drohn-nflc.
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/drohn-nflc-oui-on/install
	$(INSTALL_DIR) $(1)/etc/nflc
	$(INSTALL_DATA) ./files/nflc-oui.conf $(1)/etc/nflc/
endef

define Package/drohn-nflc-oui-on/postinst
#!/bin/sh
if [ ! -e /etc/drohn/installed_pkgs ]; then
	echo 'drohn-nflc-oui-on,1.0' > /etc/drohn/installed_pkgs
else
	cat /etc/drohn/installed_pkgs | grep -v drohn-update > /tmp/drohn_step_dir/installed_pkgs
	echo 'drohn-nflc-oui-on,1.0' >> /tmp/drohn_step_dir/installed_pkgs
	mv /tmp/drohn_step_dir/installed_pkgs /etc/drohn/installed_pkgs
fi
cat /etc/nflc/nflc.conf /etc/nflc/nflc-oui.conf | grep -v use_oui=0 | sort -u > /tmp/drohn_step_dir/nflc.conf
mv /tmp/drohn_step_dir/nflc.conf /etc/nflc/nflc.conf
rm /usr/lib/opkg/info/drohn-nflc-oui-on.postinst
endef

$(eval $(call BuildPackage,drohn-nflc-oui-on))
