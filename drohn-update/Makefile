##############################################
# OpenWrt Makefile for DR.OHN update package  
# 
##############################################

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=drohn-update
PKG_VERSION:=1.01
PKG_RELEASE:=a

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/drohn-update
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=DR.OHN Update
	DEPENDS:=+curl +drohn-nflc
endef

define Package/drohn-update/description
	define Package/drohn-update/description
	Package drohn-update is the update package of DR.OHN 
	(Desirable Router for Optimal Home Network).
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/drohn-update/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/scripts/drohn-update-check $(1)/usr/bin/
	$(INSTALL_BIN) ./files/scripts/drohn-update-install $(1)/usr/bin/
	$(INSTALL_BIN) ./files/scripts/drohn-update-server $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/drohn/cron
	$(INSTALL_DATA) ./files/cron/crontab-drohn-update $(1)/etc/drohn/cron/
endef

define Package/drohn-update/postinst
#!/bin/sh
if [ ! -e /etc/drohn/installed_pkgs ]; then
	echo 'drohn-update,1.0' > /etc/drohn/installed_pkgs
else
	cat /etc/drohn/installed_pkgs | grep -v drohn-update > /tmp/drohn_step_dir/installed_pkgs
	echo 'drohn-update,1.01' >> /tmp/drohn_step_dir/installed_pkgs
	mv /tmp/drohn_step_dir/installed_pkgs /etc/drohn/installed_pkgs
fi
if [ ! -e /tmp/drohn_vault_dir/updates ]; then
	mkdir -p /tmp/drohn_vault_dir/updates
fi
if [ ! -e /tmp/drohn_vault_dir/update_ack ]; then
	mkdir -p /tmp/drohn_vault_dir/update_ack
fi
cat /etc/crontabs/root /etc/drohn/cron/crontab-drohn-update | sort -u > /tmp/drohn_step_dir/root
mv /tmp/drohn_step_dir/root /etc/crontabs/root
rm /tmp/drohn_step_dir/root_tmp
/etc/init.d/cron stop
/etc/init.d/cron start
rm /usr/lib/opkg/info/drohn-update.postinst
endef

define Package/drohn-update/prerm
#!/bin/sh
/etc/init.d/cron stop
crontab -l | grep -sFv -f /etc/drohn/cron/crontab-drohn-update | sort -u | crontab -
/etc/init.d/cron start
killall drohn-update-check
killall drohn-update-install
killall drohn-update-server
endef

$(eval $(call BuildPackage,drohn-update))
