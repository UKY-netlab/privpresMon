##############################################
# OpenWrt Makefile for DR.OHN upload package  
# 
##############################################

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=drohn-upload
PKG_VERSION:=1.01
PKG_RELEASE:=a

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/drohn-upload
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=DR.OHN Upload
	DEPENDS:=+libcurl +drohn-nflc
endef

define Package/drohn-upload/description
	define Package/drohn-upload/description
	Package drohn-upload is the upload package of DR.OHN 
	(Desirable Router for Optimal Home Network).
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/drohn-upload/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/curlput $(1)/usr/bin/
	$(INSTALL_BIN) ./files/scripts/drohn-upload $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/drohn/cron
	$(INSTALL_DATA) ./files/cron/crontab-drohn-upload $(1)/etc/drohn/cron/
endef

define Package/drohn-upload/postinst
#!/bin/sh
if [ ! -e /etc/drohn/installed_pkgs ]; then
	echo 'drohn-upload,1.0' > /etc/drohn/installed_pkgs
else
	cat /etc/drohn/installed_pkgs | grep -v drohn-upload > /tmp/drohn_step_dir/installed_pkgs
	echo '$(PKG_NAME),$(PKG_VERSION)' >> /tmp/drohn_step_dir/installed_pkgs
	mv /tmp/drohn_step_dir/installed_pkgs /etc/drohn/installed_pkgs
fi
cat /etc/crontabs/root /etc/drohn/cron/crontab-drohn-upload | sort -u > /tmp/drohn_step_dir/root
mv /tmp/drohn_step_dir/root /etc/crontabs/root
/etc/init.d/cron stop
/etc/init.d/cron start
rm /usr/lib/opkg/info/drohn-upload.postinst
endef

define Package/drohn-upload/prerm
#!/bin/sh
/etc/init.d/cron stop
crontab -l | grep -sFv -f /etc/drohn/cron/crontab-drohn-upload | sort -u | crontab -
/etc/init.d/cron start
killall drohn-upload
killall curlput
endef

$(eval $(call BuildPackage,drohn-upload))
