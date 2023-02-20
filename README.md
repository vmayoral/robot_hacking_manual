# `RHM`: Robot Hacking Manual

[<ins>Download in PDF `RHM v0.5`<ins>](https://github.com/vmayoral/robot_hacking_manual/releases/download/0.5/RHM.pdf) ┃ <span style="background-color: #FFFF00">[Read online](https://rhm.cybersecurityrobotics.net/)</span> | <span style="background-color: #FFFF00">[Robot hacks](https://github.com/vmayoral/robot_hacking_manual#robot-hacks)</span>

The *Robot Hacking Manual* (`RHM`) is an introductory series about cybersecurity for robots, with an attempt to provide comprehensive case studies and step-by-step tutorials with the intent to raise awareness in the field and highlight the importance of taking a *security-first*[^0] approach. The material available here is also a personal learning attempt and it's disconnected from any particular organization. Content is provided as is and **by no means I encourage or promote the unauthorized tampering of robotic systems or related technologies**.

Cite this work:

```
@article{mayoral2022robot,
  title={Robot Hacking Manual (RHM)},
  author={Mayoral-Vilches, V{\'\i}ctor},
  journal={arXiv preprint arXiv:2203.04765},
  year={2022}
}
```

- [**Disclaimer**](DISCLAIMER.md)
- [**History**](MOTIVATION.md#history)
- [**Motivation**](MOTIVATION.md#motivation)
- [**A containerized approach**](MOTIVATION.md#a-containerized-approach)
- [**Contribute back**](CONTRIBUTE.md)
- [**Cite this work**](https://github.com/vmayoral/robot_hacking_manual/blob/master/0_introduction/README.md#cite-this-work)
- [**Introduction**](0_introduction/README.md)
  - [About robot cybersecurity](0_introduction/README.md#about-robot-cybersecurity)
  - [Robot hacks](https://github.com/vmayoral/robot_hacking_manual#robot-hacks)
- <ins>**Case studies**</ins>
  - [Universal Robots' UR3](1_case_studies/0_cobot/) (hacking a collaborative robot arm)
  - [Mobile Industrial Robots' MiR100](1_case_studies/1_amr/) (hacking an industrial mobile robot)
  - [Robot Operating System](1_case_studies/4_ros/) (hacking ROS 1)
  - [Robot Operating System 2](1_case_studies/2_ros2/) (hacking ROS 2)
  - [TurtleBot 3](1_case_studies/3_turtlebot3/) (hacking TurtleBot 3)
  - [PX4 autopilot](1_case_studies/5_px4/)
- [**Writeups**]()
  - <ins>Reconaissance</ins>
    - Footprinting
      - [Tutorial 1: Footprinting ROS systems](2_writeups/1_reconnaissance/robot_footprinting/tutorial1/)
      - [Tutorial 2: Footprinting Secure ROS systems](2_writeups/1_reconnaissance/robot_footprinting/tutorial2/)
      - [Tutorial 3: Footprinting ROS 2 and DDS systems](2_writeups/1_reconnaissance/robot_footprinting/tutorial3/)
  - <ins>Vulnerability research</ins>
    - Static analysis
      - [Tutorial 5: Static analysis of PyRobot](2_writeups/2_robot_vulnerabilities/tutorial5/)
    - Dynamic analysis
      - [Tutorial 1: Robot sanitizers in ROS 2 Dashing](2_writeups/2_robot_vulnerabilities/tutorial1/)
      - [Tutorial 2: Robot sanitizers in MoveIt 2](2_writeups/2_robot_vulnerabilities/tutorial2/)
      - [Tutorial 3: Debugging output of robot sanitizers with GDB, hunting and fixing bugs](2_writeups/2_robot_vulnerabilities/tutorial3/)
      - ~~Tutorial 4: Robot sanitizers with Gazebo~~
      - [Tutorial 5: Static analysis of PyRobot](2_writeups/2_robot_vulnerabilities/tutorial5/)
      - [Tutorial 6: Looking for vulnerabilities in ROS 2](2_writeups/2_robot_vulnerabilities/tutorial6/)
      - [Tutorial 7: Analyzing Turtlebot 3](2_writeups/2_robot_vulnerabilities/tutorial7/)
      - [Tutorial 8: SROS and SROS 2, exploring](2_writeups/2_robot_vulnerabilities/tutorial8/)
      - [Tutorial 9: Looking at DDS middleware flaws](2_writeups/2_robot_vulnerabilities/tutorial8/)
  - <ins>Exploitation</ins>
    - General
      - [Tutorial 1: Buffer overflows](2_writeups/3_robot_exploitation/tutorial1/)
      - [Tutorial 2: Building shellcode](2_writeups/3_robot_exploitation/tutorial2/)
      - [Tutorial 3: Exploiting](2_writeups/3_robot_exploitation/tutorial3/)
      - [Tutorial 4: Return to `libc`](2_writeups/3_robot_exploitation/tutorial4/)
      - [Tutorial 5: Return-Oriented Programming (ROP)](2_writeups/3_robot_exploitation/tutorial5/)
      - [Tutorial 6: Remote shell](2_writeups/3_robot_exploitation/tutorial6/)
      - [Tutorial 7: pwntools - CTF toolkit](2_writeups/3_robot_exploitation/tutorial7/)
      - [Tutorial 8: Linux Binary Protections](https://github.com/nnamon/linux-exploitation-course/blob/master/lessons/5_protections/lessonplan.md) (external)
      - [Tutorial 9: Building a pwnbox](2_writeups/3_robot_exploitation/tutorial9/)
      - [Tutorial 10: Bypassing NX with Return Oriented Programming](2_writeups/3_robot_exploitation/tutorial10/) (**WIP, unfinished**)
    - Robotics-specific
      - [Tutorial 11: Unauthenticated registration/unregistration with ROS Master API](2_writeups/3_robot_exploitation/tutorial11/)
      - [Tutorial 12: Unauthenticated updates in publisher list for specified topic](2_writeups/3_robot_exploitation/tutorial12)
      - [Tutorial 13: Sockets left open and in CLOSE_WAIT state in ROS](2_writeups/3_robot_exploitation/tutorial13)
  - <ins>Forensics</ins>
    - [Tutorial 1: Basic robot forensics, an unauthenticated unregistration in ROS](2_writeups/4_other/robot_forensics/tutorial1/)
    - [Tutorial 2: Locating ROS logs in memory](2_writeups/4_other/robot_forensics/tutorial2/) (**failed**)
    - [Tutorial 3: Capturing memory in Linux-based robots](2_writeups/4_other/robot_forensics/tutorial3/)
    - [Tutorial 4: Basic robot forensics 2, unauthenticated updates in publisher list for specified topic](2_writeups/4_other/robot_forensics/tutorial4/) (**unfinished**)
  - <ins>Hardening</ins>
    - [Tutorial 1: A study of container technologies](2_writeups/4_other/hardening/tutorial1/README.md)
- **Talks**:
  - <ins>2016</ins>
    - [Securing ROS over the wire, in the graph, and through the kernel](https://vimeo.com/187705073), ROSCon 2016
  - <ins>2017</ins>
    - [Hacking Robots Before Skynet](https://www.youtube.com/watch?v=LK43J-p1H3o), Ekoparty Security Conference 2017
    - [An Experimental Security Analysis of an Industrial Robot Controller](https://www.youtube.com/watch?v=tGcNefddfZM), IEEE Symposium on Security and Privacy 2017
    - [SROS: Current Progress and Developments](https://vimeo.com/236172830), ROSCon 2017
    - [Breaking the Laws of Robotics: Attacking Industrial Robots](https://www.youtube.com/watch?v=RKLUWnzIaP4), Black Hat USA 2017
  - <ins>2018</ins>
    - [Introducing the Robot Security Framework](https://www.youtube.com/watch?v=Gv4O2Xw8MUk&list=PLf4Fnww4KiFdjCAfs04ynv40xbpqFPibm&index=11) (spanish), Navaja Negra Conference 2018
    - [Arm DDS Security library: Adding secure security to ROS2](https://vimeo.com/292703899), ROSCon 2018
    - [Leveraging DDS Security in ROS 2](https://vimeo.com/292703074), ROSCon 2018
  - <ins>2019</ins>
    - [Defensive and offensive robot security](https://www.youtube.com/watch?v=aEQgga_MnO8&list=PLf4Fnww4KiFdjCAfs04ynv40xbpqFPibm&index=9), ROS-Industrial Conference 2019
    - [Black Block Recorder: Immutable Black Box Logging via rosbag2 and DLTs](https://vimeo.com/378682905), ROSCon 2019
    - *Lessons learned on real-time and security* ([slides](https://aliasrobotics.com/files/realtimesecurity.pdf)), ROS 2 Real-Time Workshop, ROSCon 2019
  - <ins>2020</ins>
    - [Current security threat landscape in robotics](https://www.youtube.com/watch?v=5pWqROTERgU&list=PLf4Fnww4KiFdjCAfs04ynv40xbpqFPibm&index=10), European Robotics Forum (ERF) 2020
    - [Security in ROS & ROS 2 robot setups](https://www.youtube.com/watch?v=n7BvyUgKP-M&list=PLf4Fnww4KiFdjCAfs04ynv40xbpqFPibm&index=11), European Robotics Forum (ERF) 2020
    - [Akerbeltz, industrial robot ransomware](https://www.youtube.com/watch?v=5dYmpKH_3EM), International Workshop on Engineering Resilient Robot Software Systems, International Conference on Robotic Computing (IRC 2020).
    - [Zero Trust Architecture in Robotics](https://www.youtube.com/watch?v=jfPw8gH1i2I), Workshop on Security and Privacy in Robotics, ICRA 2020
    - [The cybersecurity status of PX4](https://www.youtube.com/watch?v=phHYfAqjOuQ&list=PLf4Fnww4KiFdjCAfs04ynv40xbpqFPibm&index=13), PX4 Developer Summit Virtual 2020
    - [Detecting Insecure Code Patterns in Industrial Robot Programs](https://dl.acm.org/doi/10.1145/3320269.3384735#sec-supp), Proceedings of the 15th ACM Asia Conference on Computer and Communications Security 2020
    - [Protecting robot endpoints against cyber-threats](https://www.youtube.com/watch?v=jo_L9Ra8UqU&list=PLf4Fnww4KiFdjCAfs04ynv40xbpqFPibm&index=14), ROS-Industrial Conference 2020
    - [Robots and Privacy](https://www.youtube.com/watch?v=Yu3lgESCB8M), Shmoocon 2020
  - <ins>2021</ins>
    - [Uncovering Planned Obsolescence Practices in Robotics and What This Means for Cybersecurity](https://www.youtube.com/watch?v=PnVq_ThrDVI&list=PLf4Fnww4KiFdjCAfs04ynv40xbpqFPibm&index=15), BlackHat USA 2021
    - [The Data Distribution Service (DDS) Protocol is Critical: Let's Use it Securely!](https://www.youtube.com/watch?v=7IV49wKxs4c), BlackHat Europe 2021
    - [Breaking ROS 2 security assumptions: Targeting the top 6 DDS implementations](https://www.youtube.com/watch?v=aO3MEm8SCmU), ROS-Industrial Conference 2021
    - [DDS and ROS 2 cybersecurity](https://www.youtube.com/watch?v=SZXOOYDsjxc&t=1008s), ROS 2 Security Working Group
  - <ins>2022</ins>
    - A Deep Dive Into The DDS Protocol (*to appear*), S4x22 Security Conference


### Robot hacks
A non-exhaustive list of cybersecurity research in robotics containing various related robot vulnerabilities and attacks due to cybersecurity issues.

| 👹 Codename/theme | 🤖 Robotics technology affected | 👨‍🔬 Researchers | 📖 Description | 📅 Date |
|-----|-------|-------------|-------------|------|
| | [iRobot’s Roomba J7 series robot vacuum](https://www.technologyreview.com/2022/12/19/1065306/roomba-irobot-robot-vacuums-artificial-intelligence-training-data-privacy/) | N/A | Personal pictures in a home environment were found in the Internet taken by an iRobot’s Roomba J7 series robot vacuum. The photos vary in type and in sensitivity. The most intimate image we saw was the series of video stills featuring the young woman on the toilet, her face blocked in the lead image but unobscured in the grainy scroll of shots below. In another image, a boy who appears to be eight or nine years old, and whose face is clearly visible, is sprawled on his stomach across a hallway floor. A triangular flop of hair spills across his forehead as he stares, with apparent amusement, at the object recording him from just below eye level. Various other home pictures that tag objects in the environment were found. | 19-19-2022 |
|  | Unitree's [Go1](https://m.unitree.com/products/go1) | d0tslash (MAVProxyUser in GitHub) | A hacker found a kill switch for a gun–wielding legged robot[^19][^20][^21][^22]. The hack itself leverages a kill switch functionality/technology that ships in all units of the robot and that listens for a particular signal at 433Mhz. When it hears the signal, the robot shuts down. d0tslash used a portable multi-tool for pentesters ([Flipper Zero](https://flipperzero.one/)) to emulate the shutdown, copying the signal the robot dog’s remote broadcasts over the 433MHz frequency. | 09-08-2022 |
| | Enabot's [`Ebo Air`](https://na.enabot.com/shop/air001) | **Modux**[^1] |  Researchers from Modux found a security *flaw* in Enabot Ebo Air #robot and responsibly disclosed their findings. Attack vectors could lead to remote-controlled *robot* spy units. Major entry point appears to be a hardcoded system administrator password that is weak and shared across all of these robots. Researchers also found information disclosure issues that could lead attackers to exfiltrate home (e.g. home WiFi password) that could then be used to pivot into other devices through local network. | 21-07-2022 |
| <ins>Analyzing the Data Distribution Service (DDS) Protocol for Critical Industries</ins>[^6] | [`ROS 2`](https://ros.org), [eProsima](https://www.eprosima.com/)'s [`Fast-DDS`](https://github.com/eProsima/Fast-DDS), [OCI](https://objectcomputing.com/)'s [`OpenDDS`](https://github.com/objectcomputing/OpenDDS), [ADLINK](https://www.adlinktech.com/)'s (*now [ZettaScale](https://www.zettascale.tech/)'s*) [CycloneDDS](https://github.com/eclipse-cyclonedds/cyclonedds), [RTI](<https://www.rti.com>)'s [ConnextDDS](https://www.rti.com/products), [Gurum Networks](https://www.gurum.cc/home)'s [GurumDDS](https://www.gurum.cc/freetrial) and [Twin Oaks Computing](http://www.twinoakscomputing.com/)'s [CoreDX DDS](http://www.twinoakscomputing.com/coredx/download) | [Ta-Lun Yen](https://www.linkedin.com/in/evsfy/), [Federico Maggi](https://www.linkedin.com/in/phretor/), [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/), [Erik Boasson](https://www.linkedin.com/in/erik-boasson-21344912/) *et al.* (**various**)[^6] | This research looked at the OMG Data Distribution Service (DDS) standards and its implementations from a security angle. 12 CVE IDs were discovered 🆘, 1 specification-level vulnerability identified 💻, and 6 DDS implementations were analyzed (3 open source, 3 proprietary). Results hinted that DDS's security mechanisms were not secure and much effort on this side was required to protect sensitive industrial and military systems powered by this communication middleware. The research group detected that these security issues were present in almost 650 different devices exposed on the Internet, across 34 countries and affecting 100 organizations through 89 Internet Service Providers (ISPs). | 19-04-2022 |
| <ins>Hacking ROS 2, the Robot Operating System</ins>[^16] | [`ROS 2`](https://ros.org) | [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/) *et al.* (**various**)[^16][^17] |  A team of security researchers led by the spanish firm Alias Robotics on their robotics focus discovered various security vulnerabilities that led to compromising the Robot Operating System 2 (ROS 2) through its underlying communication middleware (the DDS communications middleware). Researchers demonstrated how to dissect ROS 2 communications and perform ROS 2 reconnaissance, ROS 2 network denial of service through reflection attacks, and ROS 2 (Node) crashing by exploiting memory overflows which could lead to remote execution of arbitrary code. To mitigate these security vulnerabilities, Alias Robotics contributed to various open source tools including to SROS2[^17] with a series of developer tool extensions that help detect some of these insecurities in ROS 2 and DDS. ROS 2 *community-owner* Open Robotics did not follow up with these results or contributions and disregarded overall its relevance, pushing security responsibility aside[^18]| 22-04-2022 |
| <ins>JekyllBot:5</ins>[^7] | Aethon TUG smart robots ([various](https://aethon.com/products/)) | **Cynerio**[^7] | JekyllBot:5 is a collection of five critical zero-day vulnerabilities that enable remote control of Aethon TUG smart autonomous mobile robots and their online console, devices that are increasingly used for deliveries in global hospitals. More tech details about security findings at [^8]. | 01-04-2022 |
| <ins>Robot Teardown, stripping industrial robots for good</ins>[^5] | Universal Robots' [`UR3`](https://www.universal-robots.com/cb3/), [`UR5`](https://www.universal-robots.com/cb3/), [`UR10`](https://www.universal-robots.com/cb3/), [`UR3e`](https://www.universal-robots.com/products/ur3-robot/), [`UR5e`](https://www.universal-robots.com/products/ur5-robot/), [`UR10e`](https://www.universal-robots.com/products/ur10-robot/) and [`UR16e`](https://www.universal-robots.com/products/ur16-robot/) | [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/) *et al.* (**various**)[^15]| This research led by Alias Robotics introduced and advocated for robot teardown as an approach to study robot hardware architectures and fuel security research. Security researchers showed how teardown can help understanding the underlying hardware for uncovering security vulnerabilities. The group showed how robot teardown helped uncover more than 100 security flaws with 17 new CVE IDs granted over a period of two years. The group also demonstrated how various robot manufacturers are employing various planned obsolescense practices and how through teardown, planned obsolescence hardware limitations can be identified and bypassed obtaining full control of the hardware and giving it back to users, which poses both an opportunity to claim the *right to repair* as well as a threat to various robot manufacturers’ business models | 20-07-2021|
| <ins>Rogue Automation</ins>[^5] | (*various robotic programming languages/frameworks*) ABB's `Rapid`, Comau's `PDL2`, Denso's `PacScript`, Fanuc's `Karel`, Kawasaki's `AS`, Kuka's `KRL`, Mitsubishi's `Melfa`, and Universal Robots's `URScript`| [Federico Maggi](https://www.linkedin.com/in/phretor/), [Marcello Pogliani](https://www.linkedin.com/in/marcellopogliani/) (**various**)[^5]| This research unveils various hidden risks of industrial automation programming languages and frameworks used in robots from ABB, Comau, Denso, Fanuc, Kawasaki, Kuka, Mitsubishi, and Universal Robots. The security analysis performed in here reveals critical flaws across these technologies and their repercussions for smart factories.| 01-08-2020|
| <ins>Securing disinfection robots in times of COVID-19</ins>[^12][^13] | UVD Robots' [`UVD Robot® Model B`](https://uvd.blue-ocean-robotics.com/modelb), `UVD Robot® Model A` | [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/) *et al.* (**Alias Robotics**)[^12][^13] | The robots used in many medical centres to fight against COVID-19 for disinfection tasks were found vulnerable to various previously reported vulnerabilities (see [^11]) while using Ultraviolet (UV) light, which can affect humans causing suntan, sunburn or even a reportedly increased risk of skin cancer, among others. The team at Alias Robotics confirmed experimentally these issues and found many of these robots insecure, with many unpatched security flaws and easily accessible in public spaces. This led them to develop mitigations for these outstanding security flaws and offered free licenses[^13] for such patches to hospitals and industry during the pandemic | 19-09-2020 |
| <ins>The week of Mobile Industrial Robots' bugs</ins>[^11] | Mobile Industrial Robots' [`MiR100`](https://www.mobile-industrial-robots.com/solutions/robots/mir100/), [`MiR200`](https://web.archive.org/web/20200702001019/https://www.mobile-industrial-robots.com/en/solutions/robots/mir200/), [`MiR250`](https://www.mobile-industrial-robots.com/solutions/robots/mir250/), [`MiR500`](https://web.archive.org/web/20200702031717/https://www.mobile-industrial-robots.com/en/solutions/robots/mir500/), [`MiR600`](https://www.mobile-industrial-robots.com/solutions/robots/mir600/), [`MiR1000`](https://web.archive.org/web/20200419094248/https://www.mobile-industrial-robots.com/en/solutions/robots/mir1000/), [`MiR1350`](https://www.mobile-industrial-robots.com/solutions/robots/mir1350/), Easy Robotics' [`ER200`](https://procobots.com/cnc-machine-tending/er200/), Enabled Robotics' [`ER-FLEX`](https://www.enabled-robotics.com/erflex), `ER-LITE`, `ER-ONE`, UVD Robots' [`UVD Robot® Model B`](https://uvd.blue-ocean-robotics.com/modelb), `UVD Robot® Model A`  | [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/) *et al.* (**Alias Robotics**)[^10] |  Having identified relevant preliminary security issues, after months of failed interactions with Mobile Industrial Robots’ (MiR) robot manufacturer while trying to help secure their robots, with this disclosure, Alias Robotics decided to empower end-users of Mobile Industrial Robots’ with information. The disclosure included a week of hacking efforts that finalized with the public release of  14 cybersecurity vulnerabilities affecting MiR industrial robots and other downstream manufacturers, impacting thousands of robots. More than 10 different robot types were affected operating across industrial spaces and all the way to public environments, such as airports and hospitals. 11 new CVE IDs were assigned as part of this effort |  24-06-2020 |
| <ins>Attacks on Smart Manufacturing Systems</ins>[^4] | Mitsubishi `Melfa V-2AJ` | [Federico Maggi](https://www.linkedin.com/in/phretor/), [Marcello Pogliani](https://www.linkedin.com/in/marcellopogliani/) (**various**)[^4] |  Systematic security analysis exploring a variety of attack vectors on a real smart manufacturing system, assessing the attacks that could be feasibly launched on a complex smart manufacturing system |  01-05-2020 |
| <ins>The week of Universal Robots' bugs</ins>[^10] | Universal Robots' [`UR3`](https://www.universal-robots.com/cb3/), [`UR5`](https://www.universal-robots.com/cb3/), [`UR10`](https://www.universal-robots.com/cb3/), [`UR3e`](https://www.universal-robots.com/products/ur3-robot/), [`UR5e`](https://www.universal-robots.com/products/ur5-robot/), [`UR10e`](https://www.universal-robots.com/products/ur10-robot/) and [`UR16e`](https://www.universal-robots.com/products/ur16-robot/) | [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/) *et al.* (**Alias Robotics**)[^10] | For years Universal Robots did not care nor responded about cybersecurity issues with their products. Motivated by this attitude, Alias Robotics' team launched an initiative to empower Universal Robots' end-users, distributors and system integrators with the information they so much require to make use of this technology securely. This effort was called the *week of Universal Robots' bugs* and in total, more than 80 security issues were reported in the robots of Universal robots|  31-03-2020 |
| <ins>Akerbeltz: Industrial robot ransomware</ins>[^14] | Universal Robots' [`UR3`](https://www.universal-robots.com/cb3/), [`UR5`](https://www.universal-robots.com/cb3/), [`UR10`](https://www.universal-robots.com/cb3/) | [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/) *et al.* (**Alias Robotics**)[^14] | In an attempt to raise awareness and illustrate the *”insecurity by design in robotics”*, the team at Alias Robotics created *Akerbeltz*, the first known instance of industrial robot ransomware. The malware was demonstrated using the UR3 robot from a leading brand for industrial collaborative robots, Universal Robots. The team of researchers discussed the general flow of the attack including the initial cyber-intrusion, lateral movement and later control phase | 16-12-2019 |
| <ins>Rogue Robots</ins>[^3] | ABB’s [IRB140](https://new.abb.com/products/robotics/es/robots-industriales/irb-140)| [Federico Maggi](https://www.linkedin.com/in/phretor/), [Davide Quarta](https://www.linkedin.com/in/dvqu/) *et al.* (**various**)[^3]| Explored, theoretically and experimentally, the challenges and impacts of the security of modern industrial robots. Researchers also simulated an entire attack algorithm from an entry point to infiltration and compromise to demonstrate how an attacker would make use of existing vulnerabilities in order to perform various attacks. | 01-05-2017 |
| <ins>Hacking Robots Before Skynet</ins>[^2] | SoftBank Robotics's [`NAO`](https://www.softbankrobotics.com/emea/es/nao) and [`Pepper`](https://www.softbankrobotics.com/emea/es/pepper), UBTECH Robotics' `Alpha 1S` and `Alpha 2`, ROBOTIS' `OP2` and `THORMANG3`, Universal Robots' [`UR3`](https://www.universal-robots.com/cb3/), [`UR5`](https://www.universal-robots.com/cb3/), [`UR10`](https://www.universal-robots.com/cb3/), Rethink Robotics' `Baxter` and `Sawyer` and several robots from Asratec Corp | [Lucas Apa](https://www.linkedin.com/in/lucasapa/) and [César Cerrudo](https://www.linkedin.com/in/cesarcerrudo/) (**IOActive**)[^2]|  Discovered critical cybersecurity issues in several robots from multiple vendors which hinted about the lack of security concern and awareness in robotics. | 30-01-2017 |
| <ins>Robot Operating System (ROS): Safe & Insecure</ins>[^9] | ROS | [Lubomir Stroetmann](https://www.linkedin.com/in/lubo-stroetmann/) (**softSCheck**)[^9] | This is one of the earliest studies touching on ROS and offers security insights and examples about the lack of security considerations in ROS and the wide attack surface exposed by it. The author hints that with ROS, protection mechanism depends on the (security) expertise of the user, which is not a good assumption in the yet security-immature robotics community. Moreover the author hints about various vulnerabilities that are easily exploitable due to the XMLRPC adoption within the ROS message-passing infrastructure including various XML bomb attacks (e.g. "billion laughs") | 28-02-2014 |


[^0]: Read on what a security-first approach in [here](https://www.darkreading.com/edge-articles/a-security-first-approach-to-devops).
[^1]: Serious security issues uncovered with the Enabot Smart Robot https://www.modux.co.uk/post/serious-security-issues-uncovered-with-the-enabot-smart-robot. Flaws in Enabot Ebo Air Home Security Robot Allowed Attackers to Spy on Users https://www.hackread.com/enabot-ebo-air-home-security-robot-flaws-spy-on-users/. Enabot Ebo Air smart robot hacking flaw found, and fixed https://www.which.co.uk/news/article/enabot-ebo-air-smart-robot-hacking-flaw-found-and-fixed-aJCkd2I4cxPs
[^2]: Hacking Robots Before Skynet https://ioactive.com/pdfs/Hacking-Robots-Before-Skynet.pdf
[^3]: Rogue Robots: Testing the Limits of an Industrial Robot’s Security https://www.blackhat.com/docs/us-17/thursday/us-17-Quarta-Breaking-The-Laws-Of-Robotics-Attacking-Industrial-Robots-wp.pdf
[^4]: Attacks on Smart Manufacturing Systems A Forward-looking Security Analysis https://robosec.org/downloads/wp-attacks-on-smart-manufacturing-systems.pdf
[^5]: Rogue Automation: Vulnerable and Malicious Code in Industrial Programming https://robosec.org/downloads/wp-rogue-automation-vulnerable-and-malicious-code-in-industrial-programming.pdf
[^6]: Analyzing the Data Distribution Service (DDS) Protocol for Critical Industries https://documents.trendmicro.com/assets/white_papers/wp-a-security-analysis-of-the-data-distribution-service-dds-protocol.pdf
[^7]: JekyllBot:5 https://www.cynerio.com/jekyllbot-5-vulnerability-disclosure-report
[^8]: JekyllBot:5 allows attackers who exploit these vulnerabilities to: **a)** See real-time footage ofa hospital through the robots’ cameras, **b)** Take videos and pictures of vulnerable patients and hospital interiors, **c)** Interfere with critical or time-sensitive patient care and operations by shutting down or obstructing hospital elevators and door locking systems, **d)** Access patient medical records inviolation of HIPAA and other international regulations regarding the protection ofpersonal health information, **e)** Take control of the robots’ movement and crash them into people and objects, or use them to harass patients and staff, **f)** Disrupt the regular maintenancetasks regularly performed by the robots, including house keeping, cleaning, and delivery errands, **g)** Disrupt or block robot delivery of critical patient medication, or stealit outright, with potentially damaging or fatal patient outcomes as a result, **h)** Hijack legitimate administrative user sessions in the robots’ online portal and inject malware through their browser to perpetrate further cyberattacks on IT and security team members at healthcare facilities.
[^9]: Robot Operating System (ROS): Safe & Insecure, Security Investigation of the Robot OS (ROS) https://www.researchgate.net/profile/Hartmut-Pohl/publication/263369999_Robot_Operating_System_ROS_Safe_Insecure/links/57fdf86108ae727563ffd5a6/Robot-Operating-System-ROS-Safe-Insecure.pdf
[^10]: The week of Universal Robots' bugs https://news.aliasrobotics.com/week-of-universal-robots-bugs-exposing-insecurity/
[^11]: The week of Mobile Industrial Robots' bugs https://news.aliasrobotics.com/the-week-of-mobile-industrial-robots-bugs/
[^12]: Securing disinfection robots in times of COVID-19 https://news.aliasrobotics.com/securing-uvdrobots/
[^13]: Insecure robots during COVID-19 https://www.youtube.com/watch?v=1lNNYpSP8Dg (see https://www.youtube.com/watch?v=QFubEoWm7bA for a version in spanish)
[^14]: Industrial robot ransomware: Akerbeltz https://arxiv.org/pdf/1912.07714.pdf
[^15]: Robot teardown, stripping industrial robots for good https://aliasrobotics.com/files/robot_teardown_paper.pdf
[^16]: Case study, hacking the *Robot Operating System (ROS) 2* https://github.com/vmayoral/robot_hacking_manual/tree/master/1_case_studies/2_ros2. See https://news.aliasrobotics.com/alias-robotics-dds-ros2-vulnerabilities/ and https://www.prnewswire.com/news-releases/alias-robotics-discovers-numerous-and-dangerous-vulnerabilities-in-the-robot-operating-systems-ros-communications-that-can-have-devastating-consequences-301513741.html for public announcements. See https://www.robotics247.com/article/alias_robotics_claims_to_find_security_flaws_in_ros_2_open_robotics_responds for some public discussions
[^17]: SROS2: Usable Cyber Security Tools for ROS 2 https://aliasrobotics.com/files/SROS2.pdf
[^18]: Alias Robotics Claims to Find Security Flaws in ROS 2; Open Robotics Responds https://www.robotics247.com/article/alias_robotics_claims_to_find_security_flaws_in_ros_2_open_robotics_responds
[^19]: Hacker detects a kill switch to take down the gun-toting robot dog https://interestingengineering.com/innovation/gun-toting-robot-dog-kill-switch
[^20]: Hacker Finds Kill Switch for Submachine Gun–Wielding Robot Dog https://www.vice.com/en/article/akeexk/hacker-finds-kill-switch-for-submachine-gun-wielding-robot-dog
[^21]: HangZhou Yushu Technology (Unitree) go1 development notes https://github.com/MAVProxyUser/YushuTechUnitreeGo1#pdb-emergency-shut-off-backdoor-no-way-to-disable
[^22]: Russia's new 'robot dog war machine' is just Chinese household 'toy' with gun taped on https://www.dailystar.co.uk/news/world-news/russias-new-robot-dog-war-27765427
