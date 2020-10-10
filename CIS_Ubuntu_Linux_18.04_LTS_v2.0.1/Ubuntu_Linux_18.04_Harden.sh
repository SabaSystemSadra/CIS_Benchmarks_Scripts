#!/bin/bash

apt update && apt upgrade -y

echo ">>>>>>>>>> 1.1.1 <<<<<<<<<<"
echo ">>>>>>>>>> cramfs <<<<<<<<<<"
if ls /etc/modprobe.d/cramfs.conf 1>/dev/null 2>&1 ; then
  echo "filesh hast"
  if grep "install cramfs" /etc/modprobe.d/cramfs.conf 1>/dev/null 2>&1 ; then
    echo "ebarat toosh hast"
    sed -i '/install cramfs*/d' /etc/modprobe.d/cramfs.conf 1>/dev/null 2>&1
    echo "ghabli pak shod"
  else
    echo "ebarat toosh nist"
  fi
else
  echo "filesh nist"
fi

echo "install cramfs /bin/true" >> /etc/modprobe.d/cramfs.conf
echo "jadide vared shod"
rmmod cramfs 1>/dev/null 2>&1

echo ">>>>>>>>>> vxfs <<<<<<<<<<"
if ls /etc/modprobe.d/freevxfs.conf 1>/dev/null 2>&1 ; then
  echo "filesh hast"
  if grep "install freevxfs" /etc/modprobe.d/freevxfs.conf 1>/dev/null 2>&1 ; then
    echo "ebarat toosh hast"
    sed -i '/install freevxfs*/d' /etc/modprobe.d/freevxfs.conf 1>/dev/null 2>&1
    echo "ghabli pak shod"
  else
    echo "ebarat toosh nist"
  fi
else
  echo "filesh nist"
fi

echo "install freevxfs /bin/true" >> /etc/modprobe.d/freevxfs.conf
echo "jadide vared shod"
rmmod freevxfs 1>/dev/null 2>&1

echo ">>>>>>>>>> jffs2 <<<<<<<<<<"
if ls /etc/modprobe.d/jffs2.conf 1>/dev/null 2>&1 ; then
  echo "filesh hast"
  if grep "install jffs2" /etc/modprobe.d/jffs2.conf 1>/dev/null 2>&1 ; then
    echo "ebarat toosh hast"
    sed -i '/install jffs2*/d' /etc/modprobe.d/jffs2.conf 1>/dev/null 2>&1
    echo "ghabli pak shod"
  else
    echo "ebarat toosh nist"
  fi
else
  echo "filesh nist"
fi
echo "install jffs2 /bin/true" >> /etc/modprobe.d/jffs2.conf
echo "jadide vared shod"
rmmod jffs2 1>/dev/null 2>&1

echo ">>>>>>>>>> hfs <<<<<<<<<<"
if ls /etc/modprobe.d/hfs.conf 1>/dev/null 2>&1 ; then
  echo "filesh hast"
  if grep "install hfs" /etc/modprobe.d/hfs.conf 1>/dev/null 2>&1 ; then
    echo "ebarat toosh hast"
    sed -i '/install hfs*/d' /etc/modprobe.d/hfs.conf 1>/dev/null 2>&1
    echo "ghabli pak shod"
  else
    echo "ebarat toosh nist"
  fi
else
  echo "filesh nist"
fi
echo "install hfs /bin/true" >> /etc/modprobe.d/hfs.conf
echo "jadide vared shod"
rmmod hfs 1>/dev/null 2>&1

echo ">>>>>>>>>> hfsplus <<<<<<<<<<"
if ls /etc/modprobe.d/hfsplus.conf 1>/dev/null 2>&1 ; then
  echo "filesh hast"
  if grep "install hfsplus" /etc/modprobe.d/hfsplus.conf 1>/dev/null 2>&1 ; then
    echo "ebarat toosh hast"
    sed -i '/install hfsplus*/d' /etc/modprobe.d/hfsplus.conf 1>/dev/null 2>&1
    echo "ghabli pak shod"
  else
    echo "ebarat toosh nist"
  fi
else
  echo "filesh nist"
fi
echo "install hfsplus /bin/true" >> /etc/modprobe.d/hfsplus.conf
echo "jadide vared shod"
rmmod hfsplus 1>/dev/null 2>&1

echo ">>>>>>>>>> squashfs <<<<<<<<<<"
if ls /etc/modprobe.d/squashfs.conf 1>/dev/null 2>&1 ; then
  echo "filesh hast"
  if grep "install squashfs" /etc/modprobe.d/squashfs.conf 1>/dev/null 2>&1 ; then
    echo "ebarat toosh hast"
    sed -i '/install squashfs*/d' /etc/modprobe.d/squashfs.conf 1>/dev/null 2>&1
    echo "ghabli pak shod"
  else
    echo "ebarat toosh nist"
  fi
else
  echo "filesh nist"
fi
echo "install squashfs /bin/true" >> /etc/modprobe.d/squashfs.conf
echo "jadide vared shod"
rmmod squashfs 1>/dev/null 2>&1

echo ">>>>>>>>>> udf <<<<<<<<<<"
if ls /etc/modprobe.d/udf.conf 1>/dev/null 2>&1 ; then
  echo "filesh hast"
  if grep "install udf" /etc/modprobe.d/udf.conf 1>/dev/null 2>&1 ; then
    echo "ebarat toosh hast"
    sed -i '/install udf*/d' /etc/modprobe.d/udf.conf 1>/dev/null 2>&1
    echo "ghabli pak shod"
  else
    echo "ebarat toosh nist"
  fi
else
  echo "filesh nist"
fi
echo "install udf /bin/true" >> /etc/modprobe.d/udf.conf
echo "jadide vared shod"
rmmod udf 1>/dev/null 2>&1

echo ">>>>>>>>>> vfat <<<<<<<<<<"
if ls /etc/modprobe.d/vfat.conf 1>/dev/null 2>&1 ; then
  echo "filesh hast"
  if grep "install vfat" /etc/modprobe.d/vfat.conf 1>/dev/null 2>&1 ; then
    echo "ebarat toosh hast"
    sed -i '/install vfat*/d' /etc/modprobe.d/vfat.conf 1>/dev/null 2>&1
    echo "ghabli pak shod"
  else
    echo "ebarat toosh nist"
  fi
else
  echo "filesh nist"
fi
echo "install vfat /bin/true" >> /etc/modprobe.d/vfat.conf
echo "jadide vared shod"
rmmod vfat 1>/dev/null 2>&1


echo ">>>>>>>>>> 1.1.2 & 1.1.3 & 1.1.4 & 1.1.5 <<<<<<<<<<"
if grep "*/tmp*" /etc/fstab ; then
  :
else
  sed -i '/\/tmp/d' /etc/fstab 1>/dev/null
  echo "tmpfs   /tmp   tmpfs   defaults,rw,nosuid,nodev,noexec,relatime  0 0" >> /etc/fstab
  echo "dashtesh"
fi
echo "fstab update shod"

echo ">>>>>>>>>> 1.1.6 ~ 1.1.20 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 1.1.21 <<<<<<<<<<"
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'

echo ">>>>>>>>>> 1.1.22 <<<<<<<<<<"
apt purge autofs

echo ">>>>>>>>>> 1.1.23  (usb_storage) <<<<<<<<<<"
if ls /etc/modprobe.d/usb_storage.conf 1>/dev/null ; then
  echo "filesh hast"
  if grep "install usb_storage" /etc/modprobe.d/usb_storage.conf 1>/dev/null 2>&1 ; then
    echo "ebarat toosh hast"
    sed -i '/install usb_storage*/d' /etc/modprobe.d/usb_storage.conf 1>/dev/null 2>&1
    echo "ghabli pak shod"
  else
    echo "ebarat toosh nist"
  fi
else
  echo "filesh nist"
fi
echo "install usb_storage /bin/true" >> /etc/modprobe.d/usb_storage.conf
echo "jadide vared shod"
rmmod usb_storage 1>/dev/null 2>&1

echo ">>>>>>>>>> 1.2 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 1.3.1 <<<<<<<<<<"
apt install sudo

echo ">>>>>>>>>> 1.3.2 <<<<<<<<<<"
sed -i '/Defaults use_pty*/d' /etc/sudoers 1>/dev/null 2>&1
echo "Defaults use_pty" >> /etc/sudoers

echo ">>>>>>>>>> 1.3.3 <<<<<<<<<<"
if grep -Ei '^\s*Defaults\s+logfile=\S+' /etc/sudoers /etc/sudoers.d/* ; then
  :
else
  echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers
fi

echo ">>>>>>>>>> 1.4.1 <<<<<<<<<<"
apt install -y aide aide-common

echo ">>>>>>>>>> 1.4.2 <<<<<<<<<<"
if grep -r aide /etc/cron.* /etc/crontab ; then
  :
else
  echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" >> /etc/crontab
fi

echo ">>>>>>>>>> 1.5.1 <<<<<<<<<<"
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

echo ">>>>>>>>>> 1.5.2 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 1.5.3 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 1.5.4 <<<<<<<<<<"
if ls /etc/sysconfig/boot 1>/dev/null 2>&1 ; then
  if grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot ; then
    sed -i '/PROMPT_FOR_CONFIRM*/d' /etc/sysconfig/boot 1>/dev/null 2>&1
  else
    :
  fi
  echo 'PROMPT_FOR_CONFIRM="no"' >> /etc/sysconfig/boot
else
  :
fi

echo ">>>>>>>>>> 1.6.1 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 1.6.2 <<<<<<<<<<"
sed -i '/kernel.randomize_va_space*/d' /etc/sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
sysctl -w kernel.randomize_va_space=2

echo ">>>>>>>>>> 1.6.3 <<<<<<<<<<"
prelink -ua 2>/dev/null
apt purge prelink 2>/dev/null

echo ">>>>>>>>>> 1.6.4 <<<<<<<<<<"
sed -i '/hard core*/d' /etc/security/limits.conf
echo "* hard core 0" >> /etc/security/limits.conf
sed -i '/fs.suid_dumpable =*/d' /etc/sysctl.conf
sed -i '/fs.suid_dumpable =*/d' /etc/sysctl.d/*
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0
sed -i '/Storage=*/d' /etc/systemd/coremap.conf
sed -i '/ProcessSizeMax=*/d' /etc/systemd/coremap.conf
echo "Storage=none" >> /etc/systemd/coredump.conf
echo "ProcessSizeMax=0" >> /etc/systemd/coredump.conf
systemctl daemon-reload

echo ">>>>>>>>>> 1.7.1.1 <<<<<<<<<<"
apt install -y apparmor apparmor-utils

echo ">>>>>>>>>> 1.7.1.2 <<<<<<<<<<"
sed -i '/GRUB_CMDLINE_LINUX=*/d' /etc/default/grub
echo 'GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"' >> /etc/default/grub
update-grub

echo ">>>>>>>>>> 1.7.1.3 & 1.7.1.4 <<<<<<<<<<"
aa-enforce /etc/apparmor.d/*

echo ">>>>>>>>>> 1.8.1.1 <<<<<<<<<<"
rm -rf /etc/motd

echo ">>>>>>>>>> 1.8.1.2 <<<<<<<<<<"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

echo ">>>>>>>>>> 1.8.1.3 <<<<<<<<<<"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

echo ">>>>>>>>>> 1.8.1.4 (skipped)  <<<<<<<<<<"
echo ">>>>>>>>>> 1.8.1.5 <<<<<<<<<<"
chown root:root /etc/issue
chmod u-x,go-wx /etc/issue

echo ">>>>>>>>>> 1.8.1.6 <<<<<<<<<<"
chown root:root /etc/issue.net
chmod u-x,go-wx /etc/issue.net

echo ">>>>>>>>>> 1.8.2  <<<<<<<<<<"
sed -i '/banner-message-enable=*/d' /etc/gdm3/greeter.dconf-defaults
sed -i '/banner-message-text=*/d' /etc/gdm3/greeter.dconf-defaults
echo "banner-message-enable=true" >> /etc/gdm3/greeter.dconf-defaults
echo "banner-message-text='Authorized uses only. All activity may be monitored and reported.'" >> /etc/gdm3/greeter.dconf-defaults

echo ">>>>>>>>>> 1.9  <<<<<<<<<<"
echo "already done"

echo ">>>>>>>>>> 2.1.1  <<<<<<<<<<"
apt purge xinetd

echo ">>>>>>>>>> 2.1.2  <<<<<<<<<<"
apt remove openbsd-inetd

echo ">>>>>>>>>> 2.2.1.1  <<<<<<<<<<"
atp install -y chrony
apt install -y ntp

echo ">>>>>>>>>> 2.2.1.2  <<<<<<<<<<"
systemctl enable systemd-timesyncd.service
sed -i '/NTP=*/d' /etc/systemd/timesyncd.conf
sed -i '/FallbackNTP=*/d' /etc/systemd/timesyncd.conf
sed -i '/RootDistanceMaxSec=*/d' /etc/systemd/timesyncd.conf
echo "NTP=0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org" >> /etc/systemd/timesyncd.conf
echo "FallbackNTP=ntp.ubuntu.com 3.ubuntu.pool.ntp.org" >> /etc/systemd/timesyncd.conf
echo "RootDistanceMaxSec=1" >> /etc/systemd/timesyncd.conf
systemctl start systemd-timesyncd.service
timedatectl set-ntp true

echo ">>>>>>>>>> 2.2.1.3 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 2.2.1.4 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 2.2.2 <<<<<<<<<<"
apt purge -y xserver-xorg*

echo ">>>>>>>>>> 2.2.3 <<<<<<<<<<"
systemctl --now disable avahi-daemon

echo ">>>>>>>>>> 2.2.4 <<<<<<<<<<"
systemctl --now disable cups

echo ">>>>>>>>>> 2.2.5 <<<<<<<<<<"
systemctl --now disable isc-dhcp-server
systemctl --now disable isc-dhcp-server6

echo ">>>>>>>>>> 2.2.6 <<<<<<<<<<"
systemctl --now disable slapd

echo ">>>>>>>>>> 2.2.7 <<<<<<<<<<"
systemctl --now disable nfs-server
systemctl --now disable rpcbind

echo ">>>>>>>>>> 2.2.8 <<<<<<<<<<"
systemctl --now disable bind9

echo ">>>>>>>>>> 2.2.9 <<<<<<<<<<"
systemctl --now disable vsftpd

echo ">>>>>>>>>> 2.2.10 <<<<<<<<<<"
systemctl --now disable apache2

echo ">>>>>>>>>> 2.2.11 <<<<<<<<<<"
systemctl --now disable dovecot

echo ">>>>>>>>>> 2.2.12 <<<<<<<<<<"
systemctl --now disable smbd

echo ">>>>>>>>>> 2.2.13 <<<<<<<<<<"
systemctl --now disable squid

echo ">>>>>>>>>> 2.2.14 <<<<<<<<<<"
systemctl --now disable snmpd

echo ">>>>>>>>>> 2.2.15 <<<<<<<<<<"
sed -i '/inet_interfaces=*/d' /etc/postfix/main.cf*
echo "inet_interfaces = loopback-only" >> /etc/postfix/main.cf*
systemctl restart postfix

echo ">>>>>>>>>> 2.2.16 <<<<<<<<<<"
systemctl --now disable rsync

echo ">>>>>>>>>> 2.2.17 <<<<<<<<<<"
systemctl --now disable nis

echo ">>>>>>>>>> 2.3.1 <<<<<<<<<<"
apt purge nis

echo ">>>>>>>>>> 2.3.2 <<<<<<<<<<"
apt remove rsh-client

echo ">>>>>>>>>> 2.3.3 <<<<<<<<<<"
apt remove talk

echo ">>>>>>>>>> 2.3.4 <<<<<<<<<<"
apt purge -y telnet

echo ">>>>>>>>>> 2.3.5 <<<<<<<<<<"
apt purge ldap-utils

echo ">>>>>>>>>> 3.1.1 <<<<<<<<<<"
sed -i '/net.ipv4.conf.all.send_redirects*/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.all.send_redirects*/d' /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.send_redirects*/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.default.send_redirects*/d' /etc/sysctl.d/*
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1

echo ">>>>>>>>>> 3.1.2 <<<<<<<<<<"
grep -Els "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv4\.ip_forward\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; sysctl -w net.ipv4.ip_forward=0; sysctl -w net.ipv4.route.flush=1
grep -Els "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv6\.conf\.all\.forwarding\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; sysctl -w net.ipv6.conf.all.forwarding=0; sysctl -w net.ipv6.route.flush=1

echo ">>>>>>>>>> 3.2.1 <<<<<<<<<<"
sed -i '/net.ipv4.conf.all.accept_source_route*/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.all.accept_source_route*/d' /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.accept_source_route*/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.default.accept_source_route*/d' /etc/sysctl.d/*
sed -i '/net.ipv6.conf.all.accept_source_route*/d' /etc/sysctl.conf
sed -i '/net.ipv6.conf.all.accept_source_route*/d' /etc/sysctl.d/*
sed -i '/net.ipv6.conf.default.accept_source_route*/d' /etc/sysctl.conf
sed -i '/net.ipv6.conf.default.accept_source_route*/d' /etc/sysctl.d/*
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1

echo ">>>>>>>>>> 3.2.2 <<<<<<<<<<"
sed -i '/net.ipv4.conf.all.accept_redirects*/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.all.accept_redirects*/d' /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.accept_redirects*/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.default.accept_redirects*/d' /etc/sysctl.d/*
sed -i '/net.ipv6.conf.all.accept_redirects*/d' /etc/sysctl.conf
sed -i '/net.ipv6.conf.all.accept_redirects*/d' /etc/sysctl.d/*
sed -i '/net.ipv6.conf.default.accept_redirects*/d' /etc/sysctl.conf
sed -i '/net.ipv6.conf.default.accept_redirects*/d' /etc/sysctl.d/*
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1

echo ">>>>>>>>>> 3.2.3 <<<<<<<<<<"
sed -i '/net.ipv4.conf.all.secure_redirects*/d' /etc/sysctl*
sed -i '/net.ipv4.conf.default.secure_redirects*/d' /etc/sysctl*
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1

echo ">>>>>>>>>> 3.2.4 <<<<<<<<<<"
sed -i '/net.ipv4.conf.all.log_martians*/d' /etc/sysctl*
sed -i '/net.ipv4.conf.default.log_martians*/d' /etc/sysctl*
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

echo ">>>>>>>>>> 3.2.5 <<<<<<<<<<"
sed -i '/net.ipv4.icmp_echo_ignore_broadcasts*/d' /etc/sysctl*
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1

echo ">>>>>>>>>> 3.2.6 <<<<<<<<<<"
sed -i '/net.ipv4.icmp_ignore_bogus_error_responses*/d' /etc/sysctl*
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1

echo ">>>>>>>>>> 3.2.7 <<<<<<<<<<"
sed -i '/net.ipv4.conf.all.rp_filter*/d' /etc/sysctl*
sed -i '/net.ipv4.conf.default.rp_filter*/d' /etc/sysctl*
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

echo ">>>>>>>>>> 3.2.8 <<<<<<<<<<"
sed -i '/net.ipv4.tcp_syncookies*/d' /etc/sysctl*
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

echo ">>>>>>>>>> 3.2.9 <<<<<<<<<<"
sed -i '/net.ipv6.conf.all.accept_ra*/d' /etc/sysctl*
sed -i '/net.ipv6.conf.default.accept_ra*/d' /etc/sysctl*
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1

echo ">>>>>>>>>> 3.3.1 <<<<<<<<<<"
apt install tcpd

echo ">>>>>>>>>> 3.3.2 & 3.3.3 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 3.3.4 <<<<<<<<<<"
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow

echo ">>>>>>>>>> 3.3.5 <<<<<<<<<<"
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

echo ">>>>>>>>>> 3.4.1 <<<<<<<<<<"
sed -i '/install dccp*/d' /etc/modprobe.d/*
echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf

echo ">>>>>>>>>> 3.4.2 <<<<<<<<<<"
sed -i '/install sctp*/d' /etc/modprobe.d/*
echo "install sctp /bin/true" >> /etc/modprobe.d/sctp.conf

echo ">>>>>>>>>> 3.4.3 <<<<<<<<<<"
sed -i '/install rds*/d' /etc/modprobe.d/*
echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf

echo ">>>>>>>>>> 3.4.4 <<<<<<<<<<"
sed -i '/install tipc*/d' /etc/modprobe.d/*
echo "install tipc /bin/true" >> /etc/modprobe.d/tipc.conf

echo ">>>>>>>>>> 3.5.1.1 <<<<<<<<<<"
apt install -y ufw
apt install -y nftables
apt install -y iptables

echo ">>>>>>>>>> 3.5.2.1 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 3.5.2.2 <<<<<<<<<<"
ufw enable

echo ">>>>>>>>>> 3.5.2.3 <<<<<<<<<<"
ufw allow in on lo
ufw deny in from 127.0.0.0/8
ufw deny in from ::1

echo ">>>>>>>>>> 3.5.2.4 <<<<<<<<<<"
ufw allow out on all

echo ">>>>>>>>>> 3.5.2.5 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 3.5.3 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 3.5.4 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 3.6 <<<<<<<<<<"
nmcli radio all off

echo ">>>>>>>>>> 3.7 <<<<<<<<<<"
sed -i '/GRUB_CMDLINE_LINUX="ipv6.disable=*/d' /etc/default/grub
echo 'GRUB_CMDLINE_LINUX="ipv6.disable=1"' >> /etc/modprobe.d/tipc.conf
update-grub

echo ">>>>>>>>>> 4.1.1.1 <<<<<<<<<<"
apt install -y auditd audispd-plugins

echo ">>>>>>>>>> 4.1.1.2 <<<<<<<<<<"
systemctl --now enable auditd
echo -n > /etc/audit/rules.d/*

echo ">>>>>>>>>> 4.1.1.3 <<<<<<<<<<"
sed -i '/GRUB_CMDLINE_LINUX="audit=*/d' /etc/default/grub
echo 'GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
update-grub

echo ">>>>>>>>>> 4.1.1.4 <<<<<<<<<<"
sed -i '/GRUB_CMDLINE_LINUX="audit_backlog_limit=*/d' /etc/default/grub
echo 'GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"' >> /etc/default/grub
update-grub

echo ">>>>>>>>>> 4.1.2.1 <<<<<<<<<<"
sed -i '/max_log_file*/d' /etc/audit/auditd.conf
echo 'max_log_file = 50' >> /etc/audit/auditd.conf

echo ">>>>>>>>>> 4.1.2.2 <<<<<<<<<<"
sed -i '/max_log_file_action*/d' /etc/audit/auditd.conf
echo 'max_log_file_action = keep_logs' >> /etc/audit/auditd.conf

echo ">>>>>>>>>> 4.1.2.3 <<<<<<<<<<"
sed -i '/space_left_action*/d' /etc/audit/auditd.conf
sed -i '/action_mail_acct*/d' /etc/audit/auditd.conf
sed -i '/admin_space_left_action*/d' /etc/audit/auditd.conf
echo 'space_left_action = email' >> /etc/audit/auditd.conf
echo 'action_mail_acct = root' >> /etc/audit/auditd.conf
echo 'admin_space_left_action = halt' >> /etc/audit/auditd.conf

echo ">>>>>>>>>> 4.1.3 <<<<<<<<<<"
cmd_4_1_3=$(uname -m)
if [[ "${cmd_4_1_3}" == "x86_64" ]] ; then
  echo "64 bit OS"
  echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/time-change.rules
  echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/time-change.rules
  echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/time-change.rules
  echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/time-change.rules
  echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/time-change.rules

else
  echo "32 bit OS"
  echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/time-change.rules
  echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/time-change.rules
  echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/time-change.rules
fi

echo ">>>>>>>>>> 4.1.4 <<<<<<<<<<"
echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/identity.rules

echo ">>>>>>>>>> 4.1.5 <<<<<<<<<<"
cmd_4_1_5=$(uname -m)
if [[ "${cmd_4_1_5}" == "x86_64" ]] ; then
  echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/system-locale.rules
  echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/system-locale.rules
  echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
  echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
  echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
  echo "-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
else
  echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/system-locale.rules
  echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
  echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
  echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
  echo "-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
fi

echo ">>>>>>>>>> 4.1.6 <<<<<<<<<<"
echo "-w /etc/apparmor/ -p wa -k MAC-policy" >> /etc/audit/rules.d/MAC-policy.rules
echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/rules.d/MAC-policy.rules

echo ">>>>>>>>>> 4.1.7 <<<<<<<<<<"
echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/rules.d/logins.rules
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/logins.rules
echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/logins.rules

echo ">>>>>>>>>> 4.1.8 <<<<<<<<<<"
echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/session.rules
echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/session.rules
echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/session.rules

echo ">>>>>>>>>> 4.1.9 <<<<<<<<<<"
cmd_4_1_9=$(uname -m)
if [[ "${cmd_4_1_9}" == "x86_64" ]] ; then
  echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules
  echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules
  echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules
  echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules
  echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules
  echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules
else
  echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules
  echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules
  echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules
fi

echo ">>>>>>>>>> 4.1.10 <<<<<<<<<<"
cmd_4_1_10=$(uname -m)
if [[ "${cmd_4_1_10}" == "x86_64" ]] ; then
  echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/access.rules
  echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/access.rules
  echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/access.rules
  echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/access.rules
else
  echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/access.rules
  echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/access.rules
fi

echo ">>>>>>>>>> 4.1.11 (skipped) <<<<<<<<<<"
find <partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \ "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \ -k privileged" }'

echo ">>>>>>>>>> 4.1.12 <<<<<<<<<<"
cmd_4_1_12=$(uname -m)
if [[ "${cmd_4_1_12}" == "x86_64" ]] ; then
  echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/mounts.rules
  echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/mounts.rules
else
  echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/mounts.rules
fi

echo ">>>>>>>>>> 4.1.13 <<<<<<<<<<"
cmd_4_1_13=$(uname -m)
if [[ "${cmd_4_1_13}" == "x86_64" ]] ; then
  echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/delete.rules
  echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/delete.rules
else
  echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/delete.rules
fi

echo ">>>>>>>>>> 4.1.14 <<<<<<<<<<"
echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/scope.rules
echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/scope.rules

echo ">>>>>>>>>> 4.1.15 <<<<<<<<<<"
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/actions.rules

echo ">>>>>>>>>> 4.1.16 <<<<<<<<<<"
cmd_4_1_16=$(uname -m)
if [[ "${cmd_4_1_16}" == "x86_64" ]] ; then
  echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/modules.rules
  echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/modules.rules
  echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/modules.rules
  echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/modules.rules
else
  echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/modules.rules
  echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/modules.rules
  echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/modules.rules
  echo "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/modules.rules
fi

echo ">>>>>>>>>> 4.1.17 <<<<<<<<<<"
echo "-e 2" >> /etc/audit/rules.d/99-finalize.rules

echo ">>>>>>>>>> 4.2.1.1 <<<<<<<<<<"
apt install -y rsyslog

echo ">>>>>>>>>> 4.2.1.2 <<<<<<<<<<"
systemctl --now enable rsyslog

echo ">>>>>>>>>> 4.2.1.3 <<<<<<<<<<"
sed -i '/\*.emerg*/d' /etc/rsyslog.conf
sed -i '/\*.emerg*/d' /etc/rsyslog.d/*
sed -i '/auth,authpriv.*/d' /etc/rsyslog.conf
sed -i '/auth,authpriv.*/d' /etc/rsyslog.d/*
sed -i '/mail.*/d' /etc/rsyslog.conf
sed -i '/mail.*/d' /etc/rsyslog.d/*
sed -i '/news.*/d' /etc/rsyslog.conf
sed -i '/news.*/d' /etc/rsyslog.d/*
sed -i '/\*.=warning*/d' /etc/rsyslog.conf
sed -i '/\*.=warning*/d' /etc/rsyslog.d/*
sed -i '/\*.=err*/d' /etc/rsyslog.conf
sed -i '/\*.=err*/d' /etc/rsyslog.d/*
sed -i '/\*.crit*/d' /etc/rsyslog.conf
sed -i '/\*.crit*/d' /etc/rsyslog.d/*
sed -i '/\*.\**/d' /etc/rsyslog.conf
sed -i '/\*.\**/d' /etc/rsyslog.d/*
sed -i '/local*/d' /etc/rsyslog.conf
sed -i '/local*/d' /etc/rsyslog.d/*
echo "*.emerg :omusrmsg:*" >> /etc/rsyslog.d/hardening.conf
echo "auth,authpriv.* /var/log/auth.log" >> /etc/rsyslog.d/hardening.conf
echo "mail.* -/var/log/mail" >> /etc/rsyslog.d/hardening.conf
echo "mail.info -/var/log/mail.info" >> /etc/rsyslog.d/hardening.conf
echo "mail.warning -/var/log/mail.warn" >> /etc/rsyslog.d/hardening.conf
echo "mail.err /var/log/mail.err" >> /etc/rsyslog.d/hardening.conf
echo "news.crit -/var/log/news/news.crit" >> /etc/rsyslog.d/hardening.conf
echo "news.err -/var/log/news/news.err" >> /etc/rsyslog.d/hardening.conf
echo "news.notice -/var/log/news/news.notice" >> /etc/rsyslog.d/hardening.conf
echo "*.=warning;*.=err -/var/log/warn" >> /etc/rsyslog.d/hardening.conf
echo "*.crit /var/log/warn" >> /etc/rsyslog.d/hardening.conf
echo "*.*;mail.none;news.none -/var/log/messages" >> /etc/rsyslog.d/hardening.conf
echo "local0,local1.* -/var/log/localmessages" >> /etc/rsyslog.d/hardening.conf
echo "local2,local3.* -/var/log/localmessages" >> /etc/rsyslog.d/hardening.conf
echo "local4,local5.* -/var/log/localmessages" >> /etc/rsyslog.d/hardening.conf
echo "local6,local7.* -/var/log/localmessages" >> /etc/rsyslog.d/hardening.conf
systemctl reload rsyslog

echo ">>>>>>>>>> 4.2.1.4 <<<<<<<<<<"
sed -i '/$FileCreateMode*/d' /etc/rsyslog.conf
sed -i '/$FileCreateMode*/d' /etc/rsyslog.d/*
echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf

echo ">>>>>>>>>> 4.2.1.5 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 4.2.1.6 <<<<<<<<<<"
sed -i '/ModLoad im*/d' /etc/rsyslog.conf
sed -i '/ModLoad im*/d' /etc/rsyslog.d/*
sed -i '/InputTCPServerRun*/d' /etc/rsyslog.conf
sed -i '/InputTCPServerRun*/d' /etc/rsyslog.d/*
echo "\$ModLoad imtcp" >> /etc/rsyslog.conf
echo "\$InputTCPServerRun 514" >> /etc/rsyslog.conf
systemctl restart rsyslog

echo ">>>>>>>>>> 4.2.2.1 <<<<<<<<<<"
sed -i '/ForwardToSyslog*/d' /etc/systemd/journald.conf
echo "ForwardToSyslog=yes" >> /etc/systemd/journald.conf

echo ">>>>>>>>>> 4.2.2.2 <<<<<<<<<<"
sed -i '/Compress*/d' /etc/systemd/journald.conf
echo "Compress=yes" >> /etc/systemd/journald.conf

echo ">>>>>>>>>> 4.2.2.3 <<<<<<<<<<"
sed -i '/Storage*/d' /etc/systemd/journald.conf
echo "Storage=persistent" >> /etc/systemd/journald.conf

echo ">>>>>>>>>> 4.2.3 <<<<<<<<<<"
find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx "{}" +

echo ">>>>>>>>>> 4.3 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 5.1.1 <<<<<<<<<<"
systemctl --now enable cron

echo ">>>>>>>>>> 5.1.2 <<<<<<<<<<"
chown root:root /etc/crontab
chmod og-rwx /etc/crontab

echo ">>>>>>>>>> 5.1.3 <<<<<<<<<<"
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly

echo ">>>>>>>>>> 5.1.4 <<<<<<<<<<"
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

echo ">>>>>>>>>> 5.1.5 <<<<<<<<<<"
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

echo ">>>>>>>>>> 5.1.6 <<<<<<<<<<"
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

echo ">>>>>>>>>> 5.1.7 <<<<<<<<<<"
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

echo ">>>>>>>>>> 5.1.8 <<<<<<<<<<"
rm -rf /etc/cron.deny
rm -rf /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod o-rwx /etc/cron.allow
chmod g-wx /etc/cron.allow
chmod o-rwx /etc/at.allow
chmod g-wx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

echo ">>>>>>>>>> 5.2.1 <<<<<<<<<<"
chown root:root /etc/ssh/ssh*config
chmod og-rwx /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.2 <<<<<<<<<<"
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;

echo ">>>>>>>>>> 5.2.3 <<<<<<<<<<"
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;

echo ">>>>>>>>>> 5.2.4 <<<<<<<<<<"
sed -i '/Protocol*/d' /etc/ssh/ssh*config
echo "Protocol 2" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.5 <<<<<<<<<<"
sed -i '/LogLevel*/d' /etc/ssh/ssh*config
echo "LogLevel VERBOSE" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.6 <<<<<<<<<<"
sed -i '/X11Forwarding*/d' /etc/ssh/ssh*config
echo "X11Forwarding no" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.7 <<<<<<<<<<"
sed -i '/MaxAuthTries*/d' /etc/ssh/ssh*config
echo "MaxAuthTries 4" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.8 <<<<<<<<<<"
sed -i '/IgnoreRhosts*/d' /etc/ssh/ssh*config
echo "IgnoreRhosts yes" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.9 <<<<<<<<<<"
sed -i '/HostbasedAuthentication*/d' /etc/ssh/ssh*config
echo "HostbasedAuthentication no" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.10 <<<<<<<<<<"
sed -i '/PermitRootLogin*/d' /etc/ssh/ssh*config
echo "PermitRootLogin no" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.11 <<<<<<<<<<"
sed -i '/PermitEmptyPasswords*/d' /etc/ssh/ssh*config
echo "PermitEmptyPasswords no" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.12 <<<<<<<<<<"
sed -i '/PermitUserEnvironment*/d' /etc/ssh/ssh*config
echo "PermitUserEnvironment no" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.13 <<<<<<<<<<"
sed -i '/Ciphers*/d' /etc/ssh/ssh*config
echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.14 <<<<<<<<<<"
sed -i '/MACs*/d' /etc/ssh/ssh*config
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.15 <<<<<<<<<<"
sed -i '/KexAlgorithms*/d' /etc/ssh/ssh*config
echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.16 <<<<<<<<<<"
sed -i '/ClientAliveInterval*/d' /etc/ssh/ssh*config
sed -i '/ClientAliveCountMax*/d' /etc/ssh/ssh*config
echo "ClientAliveInterval 300" >> /etc/ssh/ssh*config
echo "ClientAliveCountMax 0" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.17 <<<<<<<<<<"
sed -i '/LoginGraceTime*/d' /etc/ssh/ssh*config
echo "LoginGraceTime 60" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.18 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 5.2.19 <<<<<<<<<<"
sed -i '/Banner*/d' /etc/ssh/ssh*config
echo "Banner /etc/issue.net" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.20 <<<<<<<<<<"
sed -i '/UsePAM*/d' /etc/ssh/ssh*config
echo "UsePAM yes" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.21 <<<<<<<<<<"
sed -i '/AllowTcpForwarding*/d' /etc/ssh/ssh*config
echo "AllowTcpForwarding no" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.22 <<<<<<<<<<"
sed -i '/MaxStartups*/d' /etc/ssh/ssh*config
echo "MaxStartups 10:30:60" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.2.23 <<<<<<<<<<"
sed -i '/MaxSessions*/d' /etc/ssh/ssh*config
echo "MaxSessions 4" >> /etc/ssh/ssh*config

echo ">>>>>>>>>> 5.3.1 <<<<<<<<<<"
apt install -y libpam-pwquality
sed -i '/minlen*/d' /etc/security/pwquality.conf
echo "minlen = 14" >> /etc/security/pwquality.conf
sed -i '/minclass*/d' /etc/security/pwquality.conf
echo "minclass = 4" >> /etc/security/pwquality.conf
sed -i '/password requisite pam_pwquality.so retry*/d' /etc/pam.d/common-password
echo "password requisite pam_pwquality.so retry=3" >> /etc/pam.d/common-password

echo ">>>>>>>>>> 5.3.2 <<<<<<<<<<"
sed -i '/auth\s*required*/d' /etc/pam.d/common-auth
echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth
sed -i '/account\s*requisite*/d' /etc/pam.d/common-account
sed -i '/account\s*required*/d' /etc/pam.d/common-account
echo "account requisite pam_deny.so" >> /etc/pam.d/common-account
echo "account required pam_tally.so" >> /etc/pam.d/common-account

echo ">>>>>>>>>> 5.3.3 <<<<<<<<<<"
sed -i '/password\s*required*/d' /etc/pam.d/common-password
echo "password required pam_pwhistory.so remember=5" >> /etc/pam.d/common-password

#echo ">>>>>>>>>> 5.3.4 <<<<<<<<<<"
#sed -i '/password\s*\[success=*/d' /etc/pam.d/common-password
#echo "password [success=1 default=ignore] pam_unix.so sha512" >> /etc/pam.d/common-password

echo ">>>>>>>>>> 5.4.1.1 <<<<<<<<<<"
sed -i '/PASS_MAX_DAYS*/d' /etc/login.defs
echo "PASS_MAX_DAYS 365" >> /etc/login.defs

echo ">>>>>>>>>> 5.4.1.2 <<<<<<<<<<"
sed -i '/PASS_MIN_DAYS*/d' /etc/login.defs
echo "PASS_MIN_DAYS 1" >> /etc/login.defs

echo ">>>>>>>>>> 5.4.1.3 <<<<<<<<<<"
sed -i '/PASS_WARN_AGE*/d' /etc/login.defs
echo "PASS_WARN_AGE 7" >> /etc/login.defs

echo ">>>>>>>>>> 5.4.1.4 <<<<<<<<<<"
useradd -D -f 30

echo ">>>>>>>>>> 5.4.1.5 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 5.4.2 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 5.4.3 <<<<<<<<<<"
usermod -g 0 root

echo ">>>>>>>>>> 5.4.4 <<<<<<<<<<"
sed -i '/umask*/d' /etc/bash.bashrc
sed -i '/umask*/d' /etc/profile
sed -i '/umask*/d' /etc/profile.d/*.sh
echo "umask 027" >> /etc/bash.bashrc
echo "umask 027" >> /etc/profile
echo "umask 027" >> /etc/profile.d/*.sh

echo ">>>>>>>>>> 5.4.5 <<<<<<<<<<"
echo "readonly TMOUT=900 ; export TMOUT" >> /etc/bash.bashrc
echo "readonly TMOUT=900 ; export TMOUT" >> /etc/profile
echo "readonly TMOUT=900 ; export TMOUT" >> /etc/profile.d/*.sh

echo ">>>>>>>>>> 5.5 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 5.6 <<<<<<<<<<"
groupadd sugroup
echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su

echo ">>>>>>>>>> 6.1.1 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.1.2 <<<<<<<<<<"
chown root:root /etc/passwd
chmod u-x,go-wx /etc/passwd

echo ">>>>>>>>>> 6.1.3 <<<<<<<<<<"
chown root:root /etc/gshadow

echo ">>>>>>>>>> 6.1.4 <<<<<<<<<<"
chmod o-rwx,g-wx /etc/shadow
chown root:shadow /etc/shadow

echo ">>>>>>>>>> 6.1.5 <<<<<<<<<<"
chown root:root /etc/group
chmod 644 /etc/group

echo ">>>>>>>>>> 6.1.6 <<<<<<<<<<"
chown root:root /etc/passwd-
chmod u-x,go-rwx /etc/passwd-

echo ">>>>>>>>>> 6.1.7 <<<<<<<<<<"
chown root:shadow /etc/shadow-
chmod u-x,go-rwx /etc/shadow-

echo ">>>>>>>>>> 6.1.8 <<<<<<<<<<"
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-

echo ">>>>>>>>>> 6.1.9 <<<<<<<<<<"
chown root:shadow /etc/gshadow
chmod o-rwx,g-wx /etc/gshadow

echo ">>>>>>>>>> 6.1.10 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.1.11 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.1.12 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.1.13 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.1.14 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.1 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.2 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.3 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.4 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.5 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.6 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.7 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.8 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.9 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.10 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.11 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.12 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.13 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.14 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.15 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.16 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.17 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.18 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.19 (skipped) <<<<<<<<<<"
echo ">>>>>>>>>> 6.2.20 (skipped) <<<<<<<<<<"


echo ">>>>>>>>>> DONE! <<<<<<<<<<"
reboot
##
