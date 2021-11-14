## Universal Robot UR3

![Universal Robots UR3 CB series collaborative arm](images/2020/ur3.png)

[Universal Robots](https://www.universal-robots.com), a division of Teradyne since 2015, is knowingly ignoring cyber security across their tenths of thousands of robots sold.

In 2017, IOActive, a world-leader firm in cybersecurity services opened a report [^21] where among others, described several flaws found in Universal Robots collaborative robots. These included: [RVD#6: UR3, UR5, UR10 Stack-based buffer overflow](https://github.com/aliasrobotics/RVD/issues/6), [RVD#15: Insecure transport in Universal Robots's robot-to-robot communications](https://github.com/aliasrobotics/RVD/issues/15), [RVD#34: Universal Robots Controller supports wireless mouse/keyboards on their USB interface](https://github.com/aliasrobotics/RVD/issues/34), [RVD#672: CB3.1 3.4.5-100 hard-coded public credentials for controller](https://github.com/aliasrobotics/RVD/issues/672), [RVD#673: CB3.1 3.4.5-100 listen and execution of arbitrary URScript code](https://github.com/aliasrobotics/RVD/issues/673).

In late 2019 I re-engaged with this work and started researching how insecure these popular robots were. As of 2021, these flaws remain an issue in affecting most of the robots from Universal Robots. Here're some of the novel findings my research led to:

| CVE ID | Description | Scope    |  CVSS    | Notes  |
|--------|-------------|----------|----------|--------|
| [CVE-2020-10264](https://github.com/aliasrobotics/RVD/issues/1444) | RTDE Interface allows unauthenticated reading of robot data and unauthenticated writing of registers and outputs | CB-series 3.1 UR3, UR5, UR10, e-series UR3e, UR5e, UR10e, UR16e | [9.8](https://github.com/aliasrobotics/RVD/issues/1444) |  CB 3.1 SW Version 3.3 and upwards, e-series SW version 5.0 and upwards |
| [CVE-2020-10265](https://github.com/aliasrobotics/RVD/issues/1443) | UR dashboard server enables unauthenticated remote control of core robot functions | CB-series 2 and 3.1 UR3, UR5, UR10, e-series UR3e, UR5e, UR10e, UR16e | [9.4](https://github.com/aliasrobotics/RVD/issues/1443) |  Version CB2 SW Version 1.4 upwards, CB3 SW Version 3.0 and upwards, e-series SW Version 5.0 and upwards |
| [CVE-2020-10266](https://github.com/aliasrobotics/RVD/issues/1487) | No integrity checks on UR+ platform artifacts when installed in the robot | CB-series 3.1 UR3, UR5, UR10 | [8.8](https://github.com/aliasrobotics/RVD/issues/1487) | CB-series 3.1 FW versions 3.3 up to 3.12.1. Possibly affects older robots and newer (e-series) |
|[CVE-2020-10267](https://github.com/aliasrobotics/RVD/issues/1489) | Unprotected intelectual property in Universal Robots controller CB 3.1 across firmware versions | CB-series 3.1 UR3, UR5 and UR10 | [7.5](https://github.com/aliasrobotics/RVD/issues/1489) | tested on 3.13.0, 3.12.1, 3.12, 3.11 and 3.10.0 |
|[CVE-2020-10290](https://github.com/aliasrobotics/RVD/issues/1495) | Universal Robots URCaps execute with unbounded privileges | CB-series 3.1 UR3, UR5 and UR10 | [6.8](https://github.com/aliasrobotics/RVD/issues/1495) |  |

An here are some additional examples of flaws identified within the technologies used in the robot, and were previously reported by others:

| ID | Description |
|------|-------------|
|[RVD#1406](https://github.com/aliasrobotics/RVD/issues/1406) | UR's felix shell console access without credentials on port 6666 (default)|
| [RVD#1409](https://github.com/aliasrobotics/RVD/issues/1409) | X.Org Server (before 1.19.4), replace shared memory segments of other X clients in the same session |
| [RVD#1410](https://github.com/aliasrobotics/RVD/issues/1410) | OpenSSH remote DoS in Universal Robots CB3.x |

### Context
#### Analyzing Universal Robots commercial success

Several articles cover and discuss the commercial success of Universal Robots. Often compared with Rethink Robotics, Universal Robots (UR) is generally acknowledged for *reading the market better* and focusing on solving the problem in a more pragmatic manner, focusing on delivering *just about* the needed safety capabilities, and no more. Carol Lawrence[^25] indicates the following:

> Universal succeeded because its robots were accurate and repeatable, yet safe enough to work next to people.

Anyone that has operated these robots will probably agree that it sounds about true. Instead of investing additional resources on risk assessment perspective (which from these articles I conclude Rethink Robotics did, at least better?), consider safety standards (using pre-existing norms for safety machinery and security) and focusing on human collaboration (as they were promising), Universal Robots focused on lobbying for market success. It was all about the market, and marketing.

If one pays close attention, she'll notice Universal Robots is actually behind the steering of ISO 10218-1 and ISO 10218-2. Reviewing these norms will make a roboticist scream in several senses. These norms are in many ways too tailored to a vendor. Tailored for lobbying. And likely this is the reason why ISO 10218-1/2 is not spreading as much as one would expect. Several countries have even disregarded ISO 10218-1, and their industries are not forced to comply with it.

More importantly, robots are connected devices. If one compares a robot to an IoT device she will quickly notice that such comparison makes no sense and it'd be more accurate to relate robots with IoT networks (leaving aside the actuation, rarely present in IoT). Robots may operate in an isolated manner, true, but frankly, for most applications that require additional sensing (most that demand adaptability), robots receive external control and coordination instructions from control stations.

The collaborative behavior that Universal Robots delivers is not only flawed from a safety design perspective but also from a robotics-functionality one. These systems will end up being connected. One should care about this.

Yet, it seems it still does for clients. Specially because Universal Robots are `open`. Not in software, but in their architecture[^25]:

> Universal’s business model differed from Rethink’s. Rather than provide an integrated system, it sold only robotic arms and embraced an open architecture that made it easy to add third-party sensors, cameras, grippers, and other accessories. This enabled users and integrators to customize robots for specific tasks.

Openness is great as model for innovation. I spent years working as an open source contributor first in software and hardware, then in robotics. I funded part of my early studies (as many surely did as well) enjoying summers of code funded by Google while working in different organizations. Also, while growing as a roboticist, I interned in several "open" places. Openness is also great (yet challenging) for business, I created and sold a business that contributed to the open source projects in the robotics space. Great learning experience.

Openness is great, but openness in industry needs to be a) funded and b)  backed with a responsible attitude in terms of security. Without care for these matters, you're simply exposing your creations to third party attacks. When those creations can influence thousands of businesses, you should start growing concerned.


#### An open architecture that doesn't care about security

Delivering an open architecture doesn't mean that you can disregard security. Security by obscurity is not security, true. But neither you should open it up and just disregard it if your systems will be used in industry, by people. That pitch doesn't work when robots get out of the lab and jump into real use cases. Universal Robots is well known from claims like:

> Security is up to the user.


A security-first approach must be adopted. One that goes from the design-phase, down to the post-production one. If you're interested in secure development and secure architectures, refer to some work on DevSecOps [^26] in robotics I co-authored and released not so long ago.

The ultimate proof however comes from the facts. So let's provide some evidence by bringing up the rootfs of UR robots in a Docker container and perform some investigations. Head to this tutorial's folder and do:

```bash
# 1. fetch the raw disk image inside of the container
docker build -t ur3_cb3.1_fetcher:3.9.1 .
# 2. create temporary directory
mkdir tmp
# 3. extract the compressed rootfs from the container
docker container run --rm --privileged -it -v ${PWD}/tmp:/outside ur3_cb3.1_fetcher:3.9.1
# 4. create container from the rootfs
docker import tmp/ur-fs.tar.gz ur3_cb3.1:3.9.1
# 5. cleanup
rm -r tmp
# 6. run the container
docker run -it ur3_cb3.1:3.9.1 /bin/bash
```

Now let's see how much UR cares about security:

```bash
docker run -it ur3_cb3.1:3.9.1 /bin/bash
dircolors: no SHELL environment variable, and no shell type option given
root@0ad90f762e89:/# ls
bin   bsp-MS-98G6.md5sums  dev  home        joint_firmware.md5sums  lost+found  mnt  pc.md5sums  programs  run   selinux  srv  tmp  var
boot  common.md5sums       etc  initrd.img  lib                     media       opt  proc        root      sbin  setup    sys  usr
root@0ad90f762e89:/#
root@0ad90f762e89:/# cat /etc/issue
Debian GNU/Linux 7 \n \l
```
Universal Robots controllers run Debian "wheezy" which was released in May 2013 and entered End-of-life (EoL) in May 2018 according to the Debian Long Term Support (LTS) page:

![Debian LTS time table from June 17,2018](https://cybersecurityrobotics.net/content/images/2020/04/Captura-de-pantalla-2020-04-19-a-las-16.11.31.png)

Some of you might be thinking that ELTS. There's **Extended** Long Term Support. One could think that Universal Robots is actively supporting openness (and open source) by financially supporting Debian and receiving extended support:

![Debian ELTS time table](https://cybersecurityrobotics.net/content/images/2020/04/Captura-de-pantalla-2020-04-19-a-las-16.16.39.png)

While plausible in terms of date, unfortunately, it doesn't seem to be the case. While it may sound harsh, one wonders: *regardless of the investments made in marketing and communication, how much is the "openness" pitch of Universal Robots worth it?*

### Searching for flaws in the rootfs

Let's now use a popular security tool to scan the rootfs for insecure components. You'll observe below how deb package sources are unmaintained, so we'll manually change those to install

```bash
# deb sources unmaintained
root@0ad90f762e89:/# apt-get update
Err http://packages.ur-update.dk ./ Release.gpg
  Could not resolve 'packages.ur-update.dk'
Reading package lists... Done
W: Failed to fetch http://packages.ur-update.dk/ubuntu/./Release.gpg  Could not resolve 'packages.ur-update.dk'

W: Some index files failed to download. They have been ignored, or old ones used instead.

# update source.list with archived packages
cat << EOF > /etc/apt/sources.list
deb http://archive.debian.org/debian wheezy main
deb http://archive.debian.org/debian-archive/debian-security/ wheezy updates/main
EOF

# install git
apt-get install git -y
...

# Fetch and run Lynis
root@0ad90f762e89:/etc# git clone https://github.com/CISOfy/lynis
Cloning into 'lynis'...
remote: Enumerating objects: 14350, done.
remote: Counting objects: 100% (492/492), done.
remote: Compressing objects: 100% (244/244), done.
remote: Total 14350 (delta 320), reused 389 (delta 248), pack-reused 13858
Receiving objects: 100% (14350/14350), 7.63 MiB, done.
Resolving deltas: 100% (10564/10564), done.
root@0ad90f762e89:/etc# cd lynis/
root@0ad90f762e89:/etc/lynis# ls
CHANGELOG.md        CONTRIBUTING.md  FAQ             INSTALL  README     SECURITY.md  db           developer.prf  include  lynis.8
CODE_OF_CONDUCT.md  CONTRIBUTORS.md  HAPPY_USERS.md  LICENSE  README.md  TODO.md      default.prf  extras         lynis    plugins
root@0ad90f762e89:/etc/lynis# ./lynis audit system

[ Lynis 3.0.7 ]

################################################################################
  Lynis comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
  welcome to redistribute it under the terms of the GNU General Public License.
  See the LICENSE file for details about using this software.

  2007-2021, CISOfy - https://cisofy.com/lynis/
  Enterprise support available (compliance, plugins, interface and tools)
################################################################################


[+] Initializing program
------------------------------------
  - Detecting OS...                                           [ DONE ]
  - Checking profiles...                                      [ DONE ]

  ---------------------------------------------------
  Program version:           3.0.7
  Operating system:          Linux
  Operating system name:     Debian
  Operating system version:  7
  Kernel version:            5.10.25
  Hardware platform:         x86_64
  Hostname:                  0ad90f762e89

...

* Check PAM configuration, add rounds if applicable and expire passwords to encrypt with new values [AUTH-9229]
    https://cisofy.com/lynis/controls/AUTH-9229/

* Configure password hashing rounds in /etc/login.defs [AUTH-9230]
    https://cisofy.com/lynis/controls/AUTH-9230/

* Install a PAM module for password strength testing like pam_cracklib or pam_passwdqc [AUTH-9262]
    https://cisofy.com/lynis/controls/AUTH-9262/

* When possible set expire dates for all password protected accounts [AUTH-9282]
    https://cisofy.com/lynis/controls/AUTH-9282/

* Configure minimum password age in /etc/login.defs [AUTH-9286]
    https://cisofy.com/lynis/controls/AUTH-9286/

* Configure maximum password age in /etc/login.defs [AUTH-9286]
    https://cisofy.com/lynis/controls/AUTH-9286/

* Default umask in /etc/login.defs could be more strict like 027 [AUTH-9328]
    https://cisofy.com/lynis/controls/AUTH-9328/

* Default umask in /etc/init.d/rc could be more strict like 027 [AUTH-9328]
    https://cisofy.com/lynis/controls/AUTH-9328/

* To decrease the impact of a full /home file system, place /home on a separate partition [FILE-6310]
    https://cisofy.com/lynis/controls/FILE-6310/
...

```

The incomplete trace of Lynis above already provides a number of hints on how to start breaking the system. I'll leave it there and jump into some examples of the findings.

### Vulnerabilities

#### Denial of Service exploiting an SSH vulnerability in Universal Robots

[RVD#1410](https://github.com/aliasrobotics/RVD/issues/1410) shows a) evidence that Universal Robots cares very little about security and b) the importance of having a security team working with your engineers.

This flaw was **found in 2016 and assigned a CVE ID `CVE-2016-6210`. We confirmed that this vulnerability applies to all the latest releases from Universal Robots over the past 12 months approximately:

- Universal Robots CB3.1, firmware version 3.12.1 (latest at the time of writing)
- Universal Robots CB3.1, firmware version 3.12
- Universal Robots CB3.1, firmware version 3.11
- Universal Robots CB3.1, firmware version 3.10

Having tested this far, we're somewhat certain that, if you own a UR3, UR5 or UR10, chances are your robot ships an openssh version that's vulnerable to Denial of Service by external aunthenticated users. Particularly, we found that the Universal Robots Controllers' file system (based in Debian) allows attackers with networking connection to the robot to cause a Denial of Service via the auth_password function in auth-passwd.c. `sshd` in OpenSSH, before 7.3 does not limit password lengths for password authentication, which allows remote attackers to cause a denial of service (crypt CPU consumption) via a long string.

[![asciicast](https://asciinema.org/a/315015.svg)](https://asciinema.org/a/315015)


#### UnZip 6.0 allows remote attackers to cause a denial of service (infinite loop) via empty bzip2 data in a ZIP archive

This is a fun one, so we decided to make a exploit, add it to `robotsploit` and record it. UR3, UR5 and UR10, powered by CB3.1 (with all the firmware versions we tested), are vulnerable to this security bug. A lack of security maintenance of UnZip allows one to perform Denial of Service. The video below shows how we can prevent the system from operating in normal conditions by simply unzipping a specially-crafted zip file.

[![asciicast](https://asciinema.org/a/J41V4mjoEAwVdfPBPstEdasTY.svg)](https://asciinema.org/a/J41V4mjoEAwVdfPBPstEdasTY)


#### User enumeration in Universal Robots Control Box CB3.x

We found that the Universal Robots' Controllers' file system based in Debian is subject to CVE-2016-6210 which allows attackers to perform unauthenticated user enumeration. The flaw affects OpenSSH which is exposed by default in port 22.

The reason why OpenSSH is vulnerable is because before version 7.3, when SHA256 or SHA512 are used for user password hashing, it uses BLOWFISH hashing on a static password when the username does not exist. This allows remote attackers to enumerate users by leveraging the time difference between responses when a large password is provided, figuring out which users are valid and which ones aren't.

[![asciicast](https://asciinema.org/a/315015.svg)](https://asciinema.org/a/315015)

#### Integer overflow in the get_data function, zipimport.c in Python 2.7

In this bug we explored an integer overflow in the `get_data` function in `zipimport.c` in CPython (aka Python) before `2.7.12`, `3.x` before `3.4.5`, and `3.5.x` before `3.5.2` allows remote attackers to have unspecified impact via a negative data size value, which triggers a heap-based buffer overflow.

The video below demonstrates how this flaw affects firmware versions CB3.1 `1.12.1`, `1.12`, `1.11` and `1.10`. Beyond our triaging is testing earlier version but we can only guess that it'll follow along. Further exploitation of the heap-based overflow is beyond the scope of this simple exercise but a sufficiently motivated attacker won't certainly stop here ;).

[![asciicast](https://asciinema.org/a/315891.svg)](https://asciinema.org/a/315891)


#### Unprotected intellectual property in Universal Robots controller CB 3.1 across firmware versions

This is **one of the most concerning bugs found**. Connected to [RVD#1487](https://github.com/aliasrobotics/RVD/issues/1487), the lack of protected Intellectual Property (IP) from third parties allows an attacker to exfiltrate all intellectual property living into the robot and acquired from UR+ platform or other means.

More specifically and as described in our report:
> Universal Robots control box CB 3.1 across firmware versions (tested on 1.12.1, 1.12, 1.11 and 1.10) does not encrypt or protect in any way the intellectual property artifacts installed from the UR+ platform of hardware and software components (URCaps). These files (.urcaps) are stored under '/root/.urcaps' as plain zip files containing all the logic to add functionality to the UR3, UR5 and UR10 robots. This flaw allows attackers with access to the robot or the robot network (while in combination with other flaws) to retrieve and easily exfiltrate all installed intellectual property.
>

The following video demonstrates this process chaining the attack with other vulnerabilities.

[![asciicast](https://asciinema.org/a/EJ5ZzqAbiVvPLyNABXyOk3iez.svg)](https://asciinema.org/a/EJ5ZzqAbiVvPLyNABXyOk3iez)


[^21]: Cerrudo, C., & Apa, L. (2017). Hacking robots before skynet. IOActive Website, 1-17.
[^25]: Carol Lawrence. Rise and Fall of Rethink Robotics (2019). https://www.asme.org/topics-resources/content/rise-fall-of-rethink-robotics
[^26]: Mayoral-Vilches, V., García-Maestro, N., Towers, M., & Gil-Uriarte, E. (2020). DevSecOps in Robotics. arXiv preprint arXiv:2003.10402.
