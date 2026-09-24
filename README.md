# OpenWrt Packages Extended

This repository contains extended and custom OpenWrt packages.

## Adding to OpenWrt

### 1. Download & Add Public Key

Download the signing key (`openwrt-packages-extended.pub`) to trust packages from this repository:

```bash
wget -O /etc/apk/keys/openwrt-packages-extended.pub https://francynox.github.io/openwrt-packages-extended/openwrt-packages-extended.pub
```

### 2. Configure Repository Source

Add the repository URL corresponding to your OpenWrt architecture:

```text
https://francynox.github.io/openwrt-packages-extended/packages/<architecture>/packages.adb
```

Update package lists:

```bash
apk update
```

---

## Included Packages

| Package | Description |
| ------- | ----------- |
| `luci-app-firewall-hybrid` | Advanced Hybrid Firewall Status and Rules View for LuCI |

### Package Details

#### `luci-app-firewall-hybrid`
- **Description:** LuCI interface for managing OpenWrt firewall hybrid views (Port Forwards, Traffic Rules, SNATs, IP Sets).
- **Dependencies:** `luci-app-firewall`, `luci-base`
