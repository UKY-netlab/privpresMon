# privpresMon
Privacy-preserving passive traffic monitoring for OpenWRT.  Takes
5-minute snapshots of flows between inside nodes and outside nodes,
including inside device, outside IP address, ports, bytes
upstream/downstream, and packets upstream/downstream.  Outside IP
addresses are encrypted, inside addresses are replaced with ordinal
numbers; mappings are consistent across the life of the router.

This project was supported by the US National Science Foundation under
grants number IIS-0904350 and CNS-1058977.

## Kernel Modules
#### dnsres_mod
Linux kernel module to perform reverse DNS resolution by inspecting DNS packets. The resolution table could be obtained from user space by reading specific proc file.

#### nfl_mod
Linux kernel module to capture cross-boundary network packets and aggregate them in to unidirectional flows. The stored flow data can be obtained from user space by reading specific proc file.

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
