# privpresMon
Privacy-preserving passive traffic monitoring for OpenWRT

## Kernel Modules
#### dnsres_mod
Linux kernel module to perform reverser DNS resolution by inspecting DNS packets. The resolution table could be obtained from user space by reading specific proc file.

#### nfl_mod
Linux kernel module to capture cross-boundary network packets and aggregate them in to unidirectional flows. The store flow data could be obtained from user space by reading specific proc file.

## OpenWrt Packages
#### drohn-mgmt
Maintain router ID, required directories, cron jobs, certificates, and keys. 

#### drohn-nflc
The main tool to perform passive measurement on OpenWrt routers with a set of kernel modules and user space daemon.

#### drohn-update
Update the router with latest packages from remote server.

#### drohn-upload
Upload passive measurement data to remote server.

#### drohn-nflc-oui-on
Turn on OUI capturing feature in drohn-nflc
