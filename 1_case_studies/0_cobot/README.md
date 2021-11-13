## Hacking a collaborative robot arm

![Universal Robots UR3 CB series collaborative arm](images/2020/ur3.png)

[Universal Robots](https://www.universal-robots.com), a division of Teradyne since 2015, is knowingly ignoring cyber security across their tenths of thousands of robots sold.

In 2017, IOActive, a world-leader firm in cybersecurity services opened a report [^21] where among others, described several flaws found in Universal Robots collaborative robots. These included: [RVD#6: UR3, UR5, UR10 Stack-based buffer overflow](https://github.com/aliasrobotics/RVD/issues/6), [RVD#15: Insecure transport in Universal Robots's robot-to-robot communications](https://github.com/aliasrobotics/RVD/issues/15), [RVD#34: Universal Robots Controller supports wireless mouse/keyboards on their USB interface](https://github.com/aliasrobotics/RVD/issues/34), [RVD#672: CB3.1 3.4.5-100 hard-coded public credentials for controller](https://github.com/aliasrobotics/RVD/issues/672), [RVD#673: CB3.1 3.4.5-100 listen and execution of arbitrary URScript code](https://github.com/aliasrobotics/RVD/issues/673).

In late 2019 I re-engaged with this work and started reseaching how insecure these popular robots were. As of 2021, these flaws remain an issue in affecting most of the robots from Universal Robots. Here're some of the findings my research led to:


| ID | Description |
|------|-------------|
|[RVD#1406](https://github.com/aliasrobotics/RVD/issues/1406) | UR's felix shell console access without credentials on port 6666 (default)|
|[RVD#1408](https://github.com/aliasrobotics/RVD/issues/1408) | Bash scripts (magic UR files) get launched automatically with root privileges and without validation or sanitizing |
| [RVD#1409](https://github.com/aliasrobotics/RVD/issues/1409) | X.Org Server (before 1.19.4), replace shared memory segments of other X clients in the same session |
| [RVD#1410](https://github.com/aliasrobotics/RVD/issues/1410) | OpenSSH remote DoS in Universal Robots CB3.x |

### Analyzing Universal Robots commercial success

Several articles cover and discuss the commercial success of Universal Robots. Often compared with Rethink Robotics, Universal Robots (UR) is generally acknowledged for *reading the market better* and focusing on solving the problem in a more pragmatic manner, focusing on delivering *just about* the needed safety capabitilies, and no more. Carol Lawrence[^25] indicates the following:

> Universal succeeded because its robots were accurate and repeatable, yet safe enough to work next to people.

Anyone that has operated these robots will probably agree that it sounds about true. Instead of investing additional resources on risk assessment perspective (which from these articles I conclude Rethink Robotics did, at least better?), consider safety standards (using pre-existing norms for safety machinery and security) and focusing on human collaboration (as they were promising), Universal Robots focused on lobbying for market success. It was all about the market, and marketing.

If one pays close attention, she'll notice Universal Robots is actually behind the steering of ISO 10218-1 and ISO 10218-2. Reviewing these norms will make a roboticist scream in several senses. These norms are in many ways too tailored to a vendor. Tailored for lobbying. And likely this is the reason why ISO 10218-1/2 is not spreading as much as one would expect. Several countries have even disregarded ISO 10218-1, and their industries are not forced to comply with it.

More importantly, robots are connected devices. If one compares a robot to an IoT device she will quickly notice that such comparison makes no sense and it'd be more accurate to relate robots with IoT networks (leaving aside the actuation, rarely present in IoT). Robots may operate in an isolated manner, true, but frankly, for most applications that require additional sensing (most that demand adaptability), robots receive external control and coordination instructions from control stations.

The collaborative behavior that Universal Robots delivers is not only flawed from a safety design perspective but also from a robotics-functionality one. These systems will end up being connected. One should care about this.

Yet, it seems it still does for clients. Specially because Universal Robots are `open`. Not in software, but in their architecture[^25]:

> Universal’s business model differed from Rethink’s. Rather than provide an integrated system, it sold only robotic arms and embraced an open architecture that made it easy to add third-party sensors, cameras, grippers, and other accessories. This enabled users and integrators to customize robots for specific tasks.

Openness is great as model for innovation. I spent years working as an open source contributor first in software and hardware, then in robotics. I funded part of my early studies (as many surely did as well) enjoying summers of code funded by Google while working in different organizations. Also, while growing as a roboticist, I interned in several "open" places. Openness is  also great (yet challenging) for business, I created and sold a business that contributed to the open source projects in the robotics space. Great learning experience.

Openness is great, but openness in industry needs to be a) funded and b)  backed with a responsible attitude in terms of security. Without care for these matters, you're simply exposing your creations to third party attacks. When those creations can influence thousands of businesses, you should start growing concerned.


### An open architecture that doesn't care about  security

Delivering an open architecture doesn't mean that you can disregard security. Security by obscurity is not security, true. But neither you should open it up and just disregard it if your systems will be used in industry, by people. That pitch doesn't work when robots get out of the lab and jump into real use cases. Universal Robots is well known from claims like:

> Security is up to the user.


A security-first approach must be adopted. One that goes from the design-phase, down to the post-production one. If you're interested in secure development and secure architectures, refer to some work on DevSecOps [^26] in robotics I co-authored and released not so long ago.

The ultimate proof however comes from the facts. So let's provide some evidence. Much of it was provided within [^24] but let's dig once again. Using [alurity toolbox](https://www.aliasrobotics.com/alurity.php), I construct a simple environment with one of the latest Universal Robots firmware images for the robot controllers and run some simple security auditing tool:

```bash
...
[+] Initializing program
------------------------------------
  - Detecting OS...                                           [ DONE ]
  - Checking profiles...                                      [ DONE ]

  ---------------------------------------------------
  Program version:           3.0.0
  Operating system:          Linux
  Operating system name:     Debian
  Operating system version:  7.8
  End-of-life:               YES
...
```

Universal Robots controllers run Debian "wheezy" which was released in May 2013 and entered End-of-life (EoL) in May 2018 according to the Debian Long Term Support (LTS) page:

<p align="center">
    <img alt="week_of_universal_robots_bugs_security" src="https://cybersecurityrobotics.net/content/images/2020/04/Captura-de-pantalla-2020-04-19-a-las-16.11.31.png">
    <figcaption>Debian LTS time table from June 17,2018.  Source <a href="https://wiki.debian.org/LTS">Debian LTS webpage</a></figcaption>
</p>

Some of you might be thinking that ELTS. There's **Extended** Long Term Support. One could think that Universal Robots is actively supporting openness (and open source) by financially supporting Debian and receiving extended support:

<p align="center">
    <img alt="week_of_universal_robots_bugs_security" src="https://cybersecurityrobotics.net/content/images/2020/04/Captura-de-pantalla-2020-04-19-a-las-16.16.39.png">
    <figcaption>Debian ELTS time table.  Source <a href="https://wiki.debian.org/LTS/Extended">Debian ELTS webpage</a></figcaption>
</p>

While plausible in terms of date, unfortunately, it doesn't seem to be the case. The results at https://news.aliasrobotics.com/week-of-universal-robots-bugs-exposing-insecurity/[^21][^24] show evidence that either Universal Robots does not care about security updates, or they are struggling to produce appropriate firmware updates.

While it may sound harsh, one wonders: *regardless of the investments made in marketing and communication, how much is the "openness" pitch of Universal Robots worth it?*


[^21]: Cerrudo, C., & Apa, L. (2017). Hacking robots before skynet. IOActive Website, 1-17.
[^24]: Alias Robotics. Week of Universal Robots' bugs. https://news.aliasrobotics.com/week-of-universal-robots-bugs-exposing-insecurity/
[^25]: Carol Lawrence. Rise and Fall of Rethink Robotics (2019). https://www.asme.org/topics-resources/content/rise-fall-of-rethink-robotics
[^26]: Mayoral-Vilches, V., García-Maestro, N., Towers, M., & Gil-Uriarte, E. (2020). DevSecOps in Robotics. arXiv preprint arXiv:2003.10402.
