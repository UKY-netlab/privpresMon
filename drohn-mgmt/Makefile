#################################################
# OpenWrt Makefile for DR.OHN Management Package
# 
#################################################

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=drohn-mgmt
PKG_VERSION:=1.0
PKG_RELEASE:=a

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/drohn-mgmt
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=DR.OHN Management
endef

define Package/drohn-mgmt/description
	define Package/drohn-mgmt/description
	Package drohn-mgmt is the management package of DR.OHN 
	(Desirable Router for Optimal Home Network).
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/drohn-mgmt/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/scripts/drohn-start $(1)/usr/bin/
	$(INSTALL_BIN) ./files/scripts/drohn-maintain $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/scripts/drohn $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/drohn
	$(INSTALL_DATA) ./files/drohn.conf $(1)/etc/drohn/
	$(INSTALL_DIR) $(1)/etc/drohn/cron
	$(INSTALL_DATA) ./files/cron/crontab-drohn $(1)/etc/drohn/cron/
	$(INSTALL_DIR) $(1)/etc/drohn/certs
	$(INSTALL_DATA) ./files/certs/cacert.pem $(1)/etc/drohn/certs/
	$(INSTALL_DIR) $(1)/etc/drohn/private
endef

define Package/drohn-mgmt/postinst
#!/bin/sh
/etc/init.d/drohn enable
/etc/init.d/drohn boot
if [ ! -e /etc/drohn/installed_pkgs ]; then
	echo 'drohn-mgmt,1.0' > /etc/drohn/installed_pkgs
else
	cat /etc/drohn/installed_pkgs | grep -v drohn-mgmt > /tmp/drohn_step_dir/installed_pkgs
	echo 'drohn-mgmt,1.0' >> /tmp/drohn_step_dir/installed_pkgs
	mv /tmp/drohn_step_dir/installed_pkgs /etc/drohn/installed_pkgs
fi
rm /usr/lib/opkg/info/drohn-mgmt.postinst
endef

define Package/drohn-mgmt/prerm
#!/bin/sh
/etc/init.d/drohn disable
/etc/init.d/cron stop
crontab -l | grep -sFv -f /etc/drohn/cron/crontab-drohn | sort -u | crontab -
/etc/init.d/cron start
endef

$(eval $(call BuildPackage,drohn-mgmt))