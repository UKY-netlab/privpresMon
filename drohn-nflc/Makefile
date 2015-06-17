##############################################
# OpenWrt Makefile for NetFlowLogger Client
# 
##############################################

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=drohn-nflc
PKG_VERSION:=1.0
PKG_RELEASE:=a

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/drohn-nflc
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=DR.OHN Network Flow Logger
	DEPENDS:=+libcurl +luci
endef

define Package/drohn-nflc/description
	define Package/drohn-nflc/description
	Package drohn-nflc is the NFL utilitie of DR.OHN 
	(Desirable Router for Optimal Home Network).
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/drohn-nflc/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nflc $(1)/usr/bin/
	$(INSTALL_BIN) ./files/scripts/nflc-guard $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/nflc
	$(INSTALL_DATA) ./files/nfl_mod.ko $(1)/etc/nflc/
	$(INSTALL_DATA) ./files/dnsres.ko $(1)/etc/nflc/
	$(INSTALL_DATA) ./files/nflc.conf $(1)/etc/nflc/
	$(INSTALL_DATA) ./files/tmp_httpd.conf $(1)/etc/nflc/
	$(INSTALL_DIR) $(1)/etc/drohn/cron
	$(INSTALL_DATA) ./files/cron/crontab-nflc $(1)/etc/drohn/cron/
	$(INSTALL_DIR) $(1)/etc/nflc/www
	$(INSTALL_DATA) ./files/www/index.html $(1)/etc/nflc/www/
	$(INSTALL_DATA) ./files/www/wildcat-router-dashboard.html $(1)/etc/nflc/www/
	$(INSTALL_DIR) $(1)/etc/nflc/www/cgi-bin
	$(INSTALL_BIN) ./files/www/cgi-bin/dashboard-hit.sh $(1)/etc/nflc/www/cgi-bin/
	$(INSTALL_DIR) $(1)/etc/nflc/www/images
	$(INSTALL_DATA) ./files/www/images/* $(1)/etc/nflc/www/images/
	$(INSTALL_DIR) $(1)/etc/nflc/www/scripts
	$(INSTALL_DATA) ./files/www/scripts/* $(1)/etc/nflc/www/scripts/
endef

define Package/drohn-nflc/postinst
#!/bin/sh
if [ ! -e /etc/drohn/installed_pkgs ]; then
	echo 'drohn-nflc,1.0' > /etc/drohn/installed_pkgs
else
	cat /etc/drohn/installed_pkgs | grep -v drohn-nflc > /tmp/drohn_step_dir/installed_pkgs
	echo 'drohn-nflc,1.0' >> /tmp/drohn_step_dir/installed_pkgs
	mv /tmp/drohn_step_dir/installed_pkgs /etc/drohn/installed_pkgs
fi
if [ ! -e /tmp/drohn_vault_dir/upload ]; then
	mkdir -p /tmp/drohn_vault_dir/upload
fi
if [ ! -e /tmp/drohn_vault_dir/upload_tmp ]; then
	mkdir -p /tmp/drohn_vault_dir/upload_tmp
fi
if [ -e /etc/nflc/www ]; then
	cp -rf /etc/nflc/www /
fi
cat /etc/crontabs/root /etc/drohn/cron/crontab-nflc | sort -u > /tmp/drohn_step_dir/root
mv /tmp/drohn_step_dir/root /etc/crontabs/root
/etc/init.d/cron stop
/etc/init.d/cron start
cat /etc/httpd.conf /etc/nflc/tmp_httpd.conf | sort -u > /tmp/drohn_step_dir/httpd.conf
echo "" >> /tmp/drohn_step_dir/httpd.conf
mv /tmp/drohn_step_dir/httpd.conf /etc/httpd.conf
/etc/init.d/uhttpd restart
rm /usr/lib/opkg/info/drohn-nflc.postinst
endef

define Package/drohn-nflc/prerm
#!/bin/sh
/etc/init.d/cron stop
crontab -l | grep -sFv -f /etc/drohn/cron/crontab-nflc | sort -u | crontab -
/etc/init.d/cron start
killall nflc-guard
killall nflc
rmmod nfl_mod
rmmod dnsres
endef

$(eval $(call BuildPackage,drohn-nflc))
