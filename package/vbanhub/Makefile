include $(TOPDIR)/rules.mk

PKG_NAME:=vbanhub
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/vbanhub
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Tiny VBAN UDP fan-out hub
  DEPENDS:=+libc
endef

define Package/vbanhub/description
  Routes VBAN audio streams between any transmitters and receivers,
  rewriting stream names. No audio decoding; a few hundred KB of RAM.
endef

define Package/vbanhub/conffiles
/etc/config/vbanhub
endef

define Package/vbanhub/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || /etc/init.d/vbanhub enable
exit 0
endef

define Package/vbanhub/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || /etc/init.d/vbanhub disable
exit 0
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS)" LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/vbanhub/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vbanhub $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/vbanhub.init $(1)/etc/init.d/vbanhub
	$(INSTALL_CONF) ./files/vbanhub.config $(1)/etc/config/vbanhub
endef

$(eval $(call BuildPackage,vbanhub))
