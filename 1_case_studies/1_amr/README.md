\newpage

## Mobile Industrial Robots' MiR-100

![Mobile Industrial Robots' MiR-100](images/2020/mir100.png)

Autonomous Mobile Robots (AMRs) are a popular trend for industrial automation. Besides in industries, they are also increasingly being used in public environments for tasks that include moving material around, or disinfecting environments with UltraViolet (UV) light (when no human is present, to avoid skin burns or worse).

Among the popular AMRs we encounter Mobile Industrial Robot's MiR-100 which is often used as a mobile base for building other robots.

Research performed in past engagements led to more than 100 flaws identified in robots from MiR. Here're some of the novel ones we published:

| CVE ID | Description | Scope    |  CVSS    | Notes  |
|--------|-------------|----------|----------|--------|
|[CVE-2020-10269](https://github.com/aliasrobotics/RVD/issues/2566) | Hardcoded Credentials on MiRX00 wireless Access Point | MiR100, MiR250, MiR200, MiR500, MiR1000, ER200, ER-Flex, ER-Lite, UVD Robots model A, model B | [9.8](https://github.com/aliasrobotics/RVD/issues/2566) | firmware v2.8.1.1 and before |
|[CVE-2020-10270](https://github.com/aliasrobotics/RVD/issues/2557) | Hardcoded Credentials on MiRX00 Control Dashboard | MiR100, MiR250, MiR200, MiR500, MiR1000, ER200, ER-Flex, ER-Lite, UVD Robots model A, model B | [9.8](https://github.com/aliasrobotics/RVD/issues/2557) | v2.8.1.1 and before |
|[CVE-2020-10271](https://github.com/aliasrobotics/RVD/issues/2555) | MiR ROS computational graph is exposed to all network interfaces, including poorly secured wireless networks and open wired ones | MiR100, MiR250, MiR200, MiR500, MiR1000, ER200, ER-Flex, ER-Lite, UVD Robots model A, model B | [10.0](https://github.com/aliasrobotics/RVD/issues/2555) | v2.8.1.1 and before |
|[CVE-2020-10272](https://github.com/aliasrobotics/RVD/issues/2554) | MiR ROS computational graph presents no authentication mechanisms | MiR100, MiR250, MiR200, MiR500, MiR1000, ER200, ER-Flex, ER-Lite, UVD Robots model A, model B | [10.0](https://github.com/aliasrobotics/RVD/issues/2554) | v2.8.1.1 and before |
|[CVE-2020-10273](https://github.com/aliasrobotics/RVD/issues/2560) | Unprotected intellectual property in Mobile Industrial Robots (MiR) controllers  | MiR100, MiR250, MiR200, MiR500, MiR1000, ER200, ER-Flex, ER-Lite, UVD Robots model A, model B | [7.5](https://github.com/aliasrobotics/RVD/issues/2560) | v2.8.1.1 and before|
|[CVE-2020-10274](https://github.com/aliasrobotics/RVD/issues/2556) | MiR REST API allows for data exfiltration by unauthorized attackers (e.g. indoor maps) | MiR100, MiR250, MiR200, MiR500, MiR1000, ER200, ER-Flex, ER-Lite, UVD Robots model A, model B | [7.1](https://github.com/aliasrobotics/RVD/issues/2556) | v2.8.1.1 and before |
|[CVE-2020-10275](https://github.com/aliasrobotics/RVD/issues/2565) | Weak token generation for the REST API | MiR100, MiR250, MiR200, MiR500, MiR1000, ER200, ER-Flex, ER-Lite, UVD Robots model A, model B | [9.8](https://github.com/aliasrobotics/RVD/issues/2565) | v2.8.1.1 and before |
|[CVE-2020-10276](https://github.com/aliasrobotics/RVD/issues/2558) | Default credentials on SICK PLC allows disabling safety features | MiR100, MiR250, MiR200, MiR500, MiR1000, ER200, ER-Flex, ER-Lite, UVD Robots model A, model B | [9.8](https://github.com/aliasrobotics/RVD/issues/2558) | v2.8.1.1 and before |
|[CVE-2020-10277](https://github.com/aliasrobotics/RVD/issues/2562) | Booting from a live image leads to exfiltration of sensible information and privilege escalation | MiR100, MiR250, MiR200, MiR500, MiR1000, ER200, ER-Flex, ER-Lite, UVD Robots model A, model B | [6.4](https://github.com/aliasrobotics/RVD/issues/2562) | v2.8.1.1 and before |
|[CVE-2020-10278](https://github.com/aliasrobotics/RVD/issues/2561) | Unprotected BIOS allows user to boot from live OS image | MiR100, MiR250, MiR200, MiR500, MiR1000, ER200, ER-Flex, ER-Lite, UVD Robots model A, model B | [6.1](https://github.com/aliasrobotics/RVD/issues/2561) | v2.8.1.1 and before |
|[CVE-2020-10279](https://github.com/aliasrobotics/RVD/issues/2569) | Insecure operating system defaults in MiR robots | MiR100, MiR250, MiR200, MiR500, MiR1000, ER200, ER-Flex, ER-Lite, UVD Robots model A, model B | [10.0](https://github.com/aliasrobotics/RVD/issues/2569) | v2.8.1.1 and before |
|[CVE-2020-10280](https://github.com/aliasrobotics/RVD/issues/2568) | Apache server is vulnerable to a DoS | MiR100, MiR250, MiR200, MiR500, MiR1000, ER200, ER-Flex, ER-Lite, UVD Robots model A, model B | [8.2](https://github.com/aliasrobotics/RVD/issues/2568) | v2.8.1.1 and before |

Below, we review briefly the file system and then discuss a few of these with their corresponding PoCs.

### Reviewing the robot's file system

Let's take a look at what's inside of the rootfs:

```bash
# Ubuntu 16.04  --> EoL
root@67817dedc5ca:/# cat /etc/issue
Ubuntu 16.04.2 LTS \n \l

# ROS 1 Kinetic   --> EoL
root@67817dedc5ca:/# ls /opt/ros/
kinetic
```

Fantastic EoL setup, both the file system as well as the ROS distro :(.
Let's look a bit deeper:

```bash
cd /root
root@67817dedc5ca:~# ls -a
.  ..  .bash_history  .bashrc  .cache  .config  .gnupg  .nano  .nmcli-history  .profile  .ros  .ssh  .viminfo  script_logs
```

This is fantastic :x:, :laughing:. Let's  inspect a bit the history, just for fun:

```bash
...
apt-get install ros-kinetic-openni-launch
apt-get install libnm-glib-dev
pip install --upgrade pip
pip install --upgrade mysql-connector
poweroff
ls /etc/polkit-1/localauthority/50-local.d/
cp 10-network-manager.pkla /etc/polkit-1/localauthority/50-local.d/
head connect_to_wifi.py
vi /etc/polkit-1/localauthority/50-local.d/10-network-manager.pkla
exit
cd /usr/local/mir/
ls
mkdir software
mv out.zip software/
cd software/
ls
unzip out.zip
ls
chmod -R 755 .
ll
rm out.zip
chmod -R 655 MIR_SOFTWARE_VERSION
ls
chmod 555 MIR_SOFTWARE_VERSION
ll
chmod 444 MIR_SOFTWARE_VERSION
ll
chmod 666 MIR_SOFTWARE_VERSION
ll
chmod 644 MIR_SOFTWARE_VERSION
ll
ls
cd ..
ls
ls
./install_mir_dependencies.bash
less setup_master_disk.bash
cd /usr/local/
ls
cd mir/
ls
ifconfig
ifcomfig
ifconfig
ping 8.8.8.8
sudo reboot
ls
./install_mir_dependencies.bash > out.txt
ls
./setup_master_disk.bash
cat /home/mirex/.bashrc
chmod +x setup_master_disk.bash
ls
./setup_master_disk.bash
cat .bashrc
ls /usr/local/mir/software/
./setup_master_disk.bash > out.txt
ls /usr/local/mir/software/
less setup_master_disk.bash
ls
nano setup_master_disk.bash
ls
./setup_master_disk.bash
less ./setup_master_disk.bash
roscd
cd /usr/local/mir/software/
ls
source robot/mir_ros_env.bash
roscd
rosnode
rosnode list
cd
cat .bashrc
ls
cd /etc/
ls
cd init.d/
ls
cat /home/mirex/.bashrc
ls
cd /etc/sudoers.d/
ls
cd /usr/local/mir/software/robot/conf/robot
ls
cd home/
ls
cd mirex/
ls
ls -lah
cat .bashrc
cat /home/mirex/.bashrc
cd
cd /home/mirex/
ls
less setup_master_disk.bash
ls
less out.txt
ls
less setup_master_disk.bash
source /usr/local/mir/software/robot/mir_ros_env.bash
grep python setup_master_disk.bash
grep python setup_master_disk.bash > temp.sh
chmod +x temp.sh
./temp.sh
nano -w temp.sh
ls
echo $MIR_SOFTWARE_PATH
nano -w setup_master_disk.bash
./temp.sh
ls -alh /home/mirex/.bashrc
date
echo $MIR_SOFTWARE_PATH/
ls /usr/local/mir/software/
cd /usr/local/mir/
ls
cd software/
la
cd shared/
ls
cd ..
ls
cd robot/release/
s
ls
less install_utils.py
less /home/mirex/setup_master_disk.bash
ls
less config_utils.py
nano -w config_utils.py
cd /home/mirex/
./temp.sh
cd -
nano -w config_utils.py
nano -w /home/mirex/setup_master_disk.bash
nano -w config_utils.py
cd -
./temp.sh
nano -w /usr/local/mir/software/robot/release/config_utils.py
./temp.sh
nano -w temp.sh
python
nano -w setup_master_disk.bash
python
ifconfig
ls
ifconfig
ls
tail -f out.txt
./setup_master_disk.bash
reboot
cd /etc/NetworkManager/system-connections/
ls
ll
nmcli con
nmcli con status
nmcli con show
nmcli con down
nmcli con reload
nmcli con
nmcli con delete Wired\ connection\ 1
nmcli con
ls
/home/mirex/setup_master_disk.bash
ifconfig
ls
nmcli connection show
nmcli connection edit Wired\ connection\ 1
nmcli con
nmcli con show Wired\ connection\ 1
ifconfig
ifdown enp0s25
ifconfig
ifup enp0s25
ifconfig
nmcli con show Wired\ connection\ 1
ifconfig
nmcli con show Wired\ connection\ 1
ifconfig
nmcli con show Wired\ connection\ 1
ifconfig
cat /etc/network/interfaces
vi /etc/network/interfaces
ls /etc/network/interfaces.d/
sudo reboot
ifconfig
cat /etc/network/interfaces
scp  /etc/network/interfaces morten@192.168.12.193
scp  /etc/network/interfaces morten@192.168.12.193:~
ls
rm morten@192.168.12.193
ls
llstat /Etc/network/interfaces
stat -c  /etc/network/interfaces
stat -c "%n"  /etc/network/interfaces
stat -c "%a"  /etc/network/interfaces
ls
cd /tmp/upgrade_ze7G5a/software/robot/
ls
cd release/
ls
sudo www-data
sudo su www-data
sudo su www-data
cat /etc/passwd
sudo vi /etc/passwd
sudo su www-data
rm /tmp/upgrade.lock
sudo su www-data
exit
apt-get purge modemmanager
apt-get install anacron
ps aux | grep anacron
apt-get install bluez
locale -a
apt-get install php-gettext
apt-get install php-intl
locale -a
locale-gen en_US da_DK
locale-gen en_US da_DK da_DK.utf8 de_DE de_DE.utf8 zh_CN zh_CN.utf8
update-locale
poweroff
cd /usr/local/mir
ls
cd software/
ls
ls -alh
less MIR_SOFTWARE_VERSION
startx
ifconfig
mount
cd /tmp/
ls
cd upgrade_tc4Z7G/
ls
tail -f mir_upgrade.log
cd ..
ls
poweroff
ls /usr/local/mir/backups/robot/
rm -r /usr/local/mir/backups/robot/*
ls /usr/local/mir/backups/robot/
ls /usr/local/mir/backups/
exit
```

Looking at this tells you a lot! We can guess how the update process works for these robots, we can also determine where to look for product's FW versions, hardware and even where to look for hardware/robot backups. We can also determine where to look for the ROS catkin overlay, which contains binaries for most packages developed by MiR (beyond the use of the ROS Common packages).

Let's now look at the flaws that one could find with one of the existing open source scanners:

```bash
root@67817dedc5ca:/Vulmap-Local-Vulnerability-Scanners/Vulmap-Linux# trivy fs --security-checks vuln,config /
2021-11-14T20:38:08.943+0100	INFO	Need to update DB
2021-11-14T20:38:08.943+0100	INFO	Downloading DB...
24.71 MiB / 24.71 MiB [-------------------------------------------------] 100.00% 27.77 MiB p/s 1s
2021-11-14T20:38:10.449+0100	INFO	Need to update the built-in policies
2021-11-14T20:38:10.449+0100	INFO	Downloading the built-in policies...
2021-11-14T20:38:14.903+0100	INFO	Detected OS: ubuntu
2021-11-14T20:38:14.903+0100	INFO	Detecting Ubuntu vulnerabilities...
2021-11-14T20:38:15.020+0100	INFO	Number of language-specific files: 1
2021-11-14T20:38:15.020+0100	INFO	Detecting jar vulnerabilities...
2021-11-14T20:38:15.020+0100	INFO	Detected config files: 7

67817dedc5ca (ubuntu 16.04)
===========================
Total: 15501 (UNKNOWN: 0, LOW: 5995, MEDIUM: 9069, HIGH: 432, CRITICAL: 5)
...
```

**15501** vulnerabilities found. **5** `CRITICAL`, 432 `HIGH`. A quick look while filtering:

```bash
root@67817dedc5ca:/# trivy fs --security-checks vuln --severity CRITICAL /
```

will tell you that packages impacted include `bluez`, `grub*`, (various) `libc`-components, `libssl`, `openssl`, or `wpasupplicant`. Among many others.

Shortly, lots of opportunities to exploit.


### Footprinting and fingerprinting

To be fair, most often you won't have access to the complete rootfs (or you do!), so let's take a look at things from the networking perspective and see if we can match the many findings. A quick scan of the robot's hotspot (or wired) network leads to various endpoints. Let's look deeper into some of the most interesting ones:

The hotspot itself:

```bash
root@attacker:~# nmap -sV -Pn 192.168.12.1
Starting Nmap 7.80SVN ( https://nmap.org ) at 2020-06-08 15:16 CEST
Nmap scan report for 192.168.12.1
Host is up (0.039s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE        VERSION
21/tcp   open  ftp            MikroTik router ftpd 6.46.2
22/tcp   open  ssh            MikroTik RouterOS sshd (protocol 2.0)
23/tcp   open  telnet         APC PDU/UPS devices or Windows CE telnetd
53/tcp   open  domain         (generic dns response: NOTIMP)
80/tcp   open  http           MikroTik router config httpd
2000/tcp open  bandwidth-test MikroTik bandwidth-test server
8291/tcp open  unknown
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port23-TCP:V=7.80SVN%I=7%D=6/8%Time=5EDE3A4D%P=x86_64-unknown-linux-gnu
SF:%r(NULL,C,"\xff\xfb\x01\xff\xfd\x18\xff\xfd'\xff\xfd\x1f")%r(GenericLin
SF:es,10,"\xff\xfb\x01\xff\xfd\x18\xff\xfd'\xff\xfd\x1f\r\n\r\n")%r(tn3270
SF:,1E,"\xff\xfb\x01\xff\xfd\x18\xff\xfd'\xff\xfd\x1f\xff\xfa\x18\x01\xff\
SF:xf0\xff\xfe\x19\xff\xfc\x19\xff\xfe\0\xff\xfc\0")%r(GetRequest,1E,"\xff
SF:\xfb\x01\xff\xfd\x18\xff\xfd'\xff\xfd\x1fGET\x20/\x20HTTP/1\.0\r\n\r\n"
SF:)%r(RPCCheck,16,"\xff\xfb\x01\xff\xfd\x18\xff\xfd'\xff\xfd\x1f\x80\^@\^
SF:@\(r\xfe\^\]")%r(Help,12,"\xff\xfb\x01\xff\xfd\x18\xff\xfd'\xff\xfd\x1f
SF:HELP\r\n")%r(SIPOptions,EB,"\xff\xfb\x01\xff\xfd\x18\xff\xfd'\xff\xfd\x
SF:1fOPTIONS\x20sip:nm\x20SIP/2\.0\r\nVia:\x20SIP/2\.0/TCP\x20nm;branch=fo
SF:o\r\nFrom:\x20<sip:nm@nm>;tag=root\r\nTo:\x20<sip:nm2@nm2>\r\nCall-ID:\
SF:x2050000\r\nCSeq:\x2042\x20OPTIONS\r\nMax-Forwards:\x2070\r\nContent-Le
SF:ngth:\x200\r\nContact:\x20<sip:nm@nm>\r\nAccept:\x20application/sdp\r\n
SF:\r\n")%r(NCP,C,"\xff\xfb\x01\xff\xfd\x18\xff\xfd'\xff\xfd\x1f");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.80SVN%I=7%D=6/8%Time=5EDE3A52%P=x86_64-unknown-linux-gnu
SF:%r(DNSVersionBindReqTCP,E,"\0\x0c\0\x06\x81\x84\0\0\0\0\0\0\0\0");
Service Info: OSs: Linux, RouterOS; Device: router; CPE: cpe:/o:mikrotik:routeros
```

The main robot computer (NUC):

```bash
root@attacker:~# nmap -sV -Pn 192.168.12.20
Starting Nmap 7.80SVN ( https://nmap.org ) at 2020-06-08 16:24 CEST
Stats: 0:00:08 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 20.00% done; ETC: 16:25 (0:00:24 remaining)
Stats: 0:00:33 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.53% done; ETC: 16:25 (0:00:00 remaining)
Nmap scan report for mir.com (192.168.12.20)
Host is up (0.11s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
8080/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
8888/tcp open  http    Werkzeug httpd 0.10.4 (Python 2.7.12)
9090/tcp open  http    Tornado httpd 4.0.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Reconnaissance in this case leads to lots of interesting information. The trail that's established by the resulting information from footprinting and fingerprinting will get us in a good track to identify many of the flaws existing in the rootfs and that are known.

Leaving those aside, let's look at some of the PoCs and novel vulnerabilities discovered.

### Vulnerabilities

#### Default credentials on SICK PLC allows disabling safety features
The password for the safety PLC is the default and thus easy to find (in manuals, etc.). This allows a manipulated program to be uploaded to the safety PLC, effectively disabling the emergency stop in case an object is too close to the robot. Navigation and any other components dependent on the laser scanner are not affected (thus it is hard to detect before something happens) though the laser scanner configuration can also be affected altering further the safety of the device.

[![asciicast](https://asciinema.org/a/cgGZfVcVmLD0h7bIso55mpMpI.svg)](https://asciinema.org/a/cgGZfVcVmLD0h7bIso55mpMpI)

[![](https://img.youtube.com/vi/3r-A-sRnMSE/0.jpg)](https://www.youtube.com/watch?v=3r-A-sRnMSE)

#### Hardcoded Credentials on MiRX00’s Control Dashboard

Out of the wired and wireless interfaces within MiR100, MiR200 and other vehicles from the MiR fleet, it's possible to access the Control Dashboard on a hardcoded IP address. Credentials to such wireless interface default to well known and widely spread users (omitted) and passwords (omitted). This information is also available in past User Guides and manuals which the vendor distributed. This flaw allows cyber attackers to take control of the robot remotely and make use of the default user interfaces MiR has created, **lowering the complexity of attacks and making them available to entry-level attackers.** More elaborated attacks can also be established by clearing authentication and sending network requests directly. We have confirmed this flaw in MiR100 and MiR200 but according to the vendor, it might also apply to MiR250, MiR500 and MiR1000.


[![asciicast](https://asciinema.org/a/dE9TfluHMWejpMVk0Zv3mpVtR.svg)](https://asciinema.org/a/dE9TfluHMWejpMVk0Zv3mpVtR)

[![](https://img.youtube.com/vi/E4MzhkIdkn8/0.jpg)](https://www.youtube.com/watch?v=E4MzhkIdkn8)

#### MiR REST API allows for data exfiltration by unauthorized attackers (e.g. indoor maps

The access tokens for the REST API are directly derived (sha256 and base64 encoding) from the publicly available default credentials from the Control Dashboard (refer to CVE-2020-10270 for related flaws). This flaw in combination with CVE-2020-10273 allows any attacker connected to the robot networks (wired or wireless) to exfiltrate all stored data (e.g. indoor mapping images) and associated metadata from the robot's database.

[![asciicast](https://asciinema.org/a/UBJ4l23a1ibnGWiMDPnasSub5.svg)](https://asciinema.org/a/UBJ4l23a1ibnGWiMDPnasSub5)

[![](https://img.youtube.com/vi/E4OCFmDXXqs/0.jpg)](https://www.youtube.com/watch?v=E4OCFmDXXqs)


#### MiR ROS computational graph is exposed to all network interfaces, including poorly secured wireless networks and open wired ones

MiR100, MiR200 and other MiR robots use the Robot Operating System (ROS) default packages exposing the computational graph to all network interfaces, wireless and wired. This is the result of a bad set up and can be mitigated by appropriately configuring ROS and/or applying custom patches as appropriate. Currently, the ROS computational graph can be accessed fully from the wired exposed ports. In combination with other flaws such as CVE-2020-10269, the computation graph can also be fetched and interacted from wireless networks. This allows a malicious operator to take control of the ROS logic and correspondingly, the complete robot given that MiR's operations are centered around the framework (ROS).

[![asciicast](https://asciinema.org/a/zZcMkxRHPdgXAEcyQEdHH2hzn.svg)](https://asciinema.org/a/zZcMkxRHPdgXAEcyQEdHH2hzn)

[![](https://img.youtube.com/vi/SNiz76i4RDc/0.jpg)](https://www.youtube.com/watch?v=SNiz76i4RDc)
