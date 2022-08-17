---
header-includes: |
 \usepackage{afterpage}
...

\newpage
\definecolor{titlebackground}{HTML}{313131}
\pagecolor{titlebackground!20}\afterpage{\nopagecolor}
# Introduction
\newpage

The *Robot Hacking Manual* (`RHM`) is an introductory series about cybersecurity for robots, with an attempt to provide comprehensive case studies and step-by-step tutorials with the intent to raise awareness in the field and highlight the importance of taking a *security-first*[^7] approach. The material available here is also a personal learning attempt and it's disconnected from any particular organization. Content is provided as is and **by no means I encourage or promote the unauthorized tampering of robotic systems or related technologies**.


## About robot cybersecurity
For the last fifty years, we have been witnessing the dawn of the robotics industry,  but robots are not being created with security as a concern, often an indicator of a technology that still needs to mature. Security in robotics is often mistaken with safety. From industrial to consumer robots, going through professional ones, most of these machines are not resilient to security attacks. Manufacturers' concerns, as well as existing standards, focus mainly on safety. Security is not being considered as a primary relevant matter.

The integration between these two areas from a risk assessment perspective was first studied by @1673343 and later discussed by @kirschgens2018robot which resulted in a unified security and safety risk framework. Commonly, robotics *safety is understood as developing protective mechanisms against accidents or malfunctions, whilst security is aimed to protect systems against risks posed by malicious actors* @safetysecurity. A slightly alternative view is the one that considers **safety as protecting the environment from a given robot, whereas security is about protecting the robot from a given environment**. In this manual we adopt the latter and refer the reader to [https://cybersecurityrobotics.net/quality-safety-security-robotics/](https://cybersecurityrobotics.net/quality-safety-security-robotics/) for a more detailed literature review that introduces the differences and correlation between safety, security and quality in robotics.

Security is *not a product, but a process* that needs to be continuously assessed in a periodic manner, as systems evolve and new cyber-threats are discovered. This becomes specially relevant with the increasing complexity of such systems as indicated by @bozic2017planning. Current robotic systems are of high complexity, a condition that in most cases leads to wide attack surfaces and a variety of potential attack vectors which makes difficult the use of traditional approaches.


> **Robotic systems and robots**
> Both literature and practice are often vague when using the terms `robot`/s and/or `robotic system`/s. Sometimes these terms are used to refer to one of the robot components (e.g. the robot is the robot arm mechanics while its HMI is the *teach pendant*). Some  other times, these terms are used to refer to the complete robot, including all its components, regardless of whether they are distributed or assembled into the same hull. Throughout this manual the latter is adopted and unless stated otherwise, the terms `robot`/s and/or `robotic system`/s will be used interchangeably to refer to the complete robotic system, including all its components.

<!-- To read more on how cybersecurity in robotics compares to IT, OT or IoT, refer to [this article](https://cybersecurityrobotics.net/it-ot-iot-and-robotics-security-comparison/). -->

## Cite this work

```
@article{mayoral2022robot,
  title={Robot Hacking Manual (RHM)},
  author={Mayoral-Vilches, V{\'\i}ctor},
  journal={arXiv preprint arXiv:2203.04765},
  year={2022}
}
```

\newpage

## Literature review

Arguably, the first installation of a cyber-physical system in a manufacturing plant was back in 1962 @historyofrobotics. The first human death caused by a robotic system is traced back to 1979 @firstkiller and the causes were safety-related according to the reports. From this point on, a series of actions involving agencies and corporations triggered to protect humans and environments from this machines, leading into safety standards.

Security however hasn't started being addressed in robotics until recently. Following after @mcclean2013preliminary early assessment, in one of the first published articles on the topic @lera2016ciberseguridad already warns about the security dangers of the Robot Operating System (ROS) @quigley2009ros. Following from this publication, the same group in Spain authored a series of articles touching into robot cybersecurity [@lera2016cybersecurity; @lera2017cybersecurity; @guerrero2017empirical; @balsa2017cybersecurity; @rodriguez2018message]. Around the same time period, @dieber2016application} led a series of publications that researched cybersecurity in robotics proposing defensive blueprints for robots built around ROS [@Dieber:2017:SRO:3165321.3165569; @dieber2017safety; @SecurecomROS; @taurer2018secure; @dieber2019security]. Their work introduced additions to the ROS APIs to support modern cryptography and security measures. Contemporary to @dieber2016application's work, @white2016sros also started delivering a series of articles [@caiazza2017security; @white2018procedurally; @white2019sros1; @caiazza2019enhancing; @white2019network; @white2019black] proposing defensive mechanisms for ROS.

A bit more than a year after that, starting in 2018, it's possible to observe how more groups start showing interest for the field and contribute. @vilches2018introducing initiated a series of security research efforts attempting to define offensive security blueprints and methodologies in robotics that led to various contributions [@vilches2018volatile; @kirschgens2018robot; @mayoral2018aztarna; @mayoral2020alurity; @mayoral2020can; @lacava2020current; @mayoral2020devsecops; @mayoral2020industrial]. Most notably, this group released publicly a framework for conducting security assessments in robotics @vilches2018introducing, a vulnerability scoring mechanism for robots @mayoral2018towardsRVSS, a robotics Capture-The-Flag environment for robotics whereto learn how to train robot cybersecurity engineers @mendia2018robotics or a robot-specific vulnerability database that third parties could use to track their threat landscape @mayoral2019introducing, among others. In 2021, @zhu2021cybersecurity published a comprehensive introduction of this emerging topic for theoreticians and practitioners working in the field to foster a sub-community in robotics and allow more contributors to become part of the robot cybersecurity effort.


\newpage

## Robot hacks
A non-exhaustive list of cybersecurity research in robotics containing various related robot vulnerabilities and attacks due to cybersecurity issues.

| 👹 Codename/theme | 🤖 Robotics technology affected | 👨‍🔬 Researchers | 📖 Description | 📅 Date |
|-----|-------|-------------|-------------|------|
|  | Unitree's [Go1](https://m.unitree.com/products/go1) | d0tslash (MAVProxyUser in GitHub) | A hacker found a kill switch for a gun–wielding legged robot. The hack itself leverages a kill switch functionality/technology that ships in all units of the robot and that listens for a particular signal at 433Mhz. When it hears the signal, the robot shuts down. d0tslash used a portable multi-tool for pentesters ([Flipper Zero](https://flipperzero.one/)) to emulate the shutdown, copying the signal the robot dog’s remote broadcasts over the 433MHz frequency. | 09-08-2022 |
| | Enabot's [`Ebo Air`](https://na.enabot.com/shop/air001) | **Modux** |  Researchers from Modux found a security *flaw* in Enabot Ebo Air #robot and responsibly disclosed their findings. Attack vectors could lead to remote-controlled *robot* spy units. Major entry point appears to be a hardcoded system administrator password that is weak and shared across all of these robots. Researchers also found information disclosure issues that could lead attackers to exfiltrate home (e.g. home WiFi password) that could then be used to pivot into other devices through local network. | 21-07-2022 |
| <ins>Analyzing the Data Distribution Service (DDS) Protocol for Critical Industries</ins> | [`ROS 2`](https://ros.org), [eProsima](https://www.eprosima.com/)'s [`Fast-DDS`](https://github.com/eProsima/Fast-DDS), [OCI](https://objectcomputing.com/)'s [`OpenDDS`](https://github.com/objectcomputing/OpenDDS), [ADLINK](https://www.adlinktech.com/)'s (*now [ZettaScale](https://www.zettascale.tech/)'s*) [CycloneDDS](https://github.com/eclipse-cyclonedds/cyclonedds), [RTI](<https://www.rti.com>)'s [ConnextDDS](https://www.rti.com/products), [Gurum Networks](https://www.gurum.cc/home)'s [GurumDDS](https://www.gurum.cc/freetrial) and [Twin Oaks Computing](http://www.twinoakscomputing.com/)'s [CoreDX DDS](http://www.twinoakscomputing.com/coredx/download) | [Ta-Lun Yen](https://www.linkedin.com/in/evsfy/), [Federico Maggi](https://www.linkedin.com/in/phretor/), [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/), [Erik Boasson](https://www.linkedin.com/in/erik-boasson-21344912/) *et al.* (**various**) | This research looked at the OMG Data Distribution Service (DDS) standards and its implementations from a security angle. 12 CVE IDs were discovered 🆘, 1 specification-level vulnerability identified 💻, and 6 DDS implementations were analyzed (3 open source, 3 proprietary). Results hinted that DDS's security mechanisms were not secure and much effort on this side was required to protect sensitive industrial and military systems powered by this communication middleware. The research group detected that these security issues were present in almost 650 different devices exposed on the Internet, across 34 countries and affecting 100 organizations through 89 Internet Service Providers (ISPs). | 19-04-2022 |
| <ins>Hacking ROS 2, the Robot Operating System</ins> | [`ROS 2`](https://ros.org) | [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/) *et al.* (**various**) |  A team of security researchers led by the spanish firm Alias Robotics on their robotics focus discovered various security vulnerabilities that led to compromising the Robot Operating System 2 (ROS 2) through its underlying communication middleware (the DDS communications middleware). Researchers demonstrated how to dissect ROS 2 communications and perform ROS 2 reconnaissance, ROS 2 network denial of service through reflection attacks, and ROS 2 (Node) crashing by exploiting memory overflows which could lead to remote execution of arbitrary code. To mitigate these security vulnerabilities, Alias Robotics contributed to various open source tools including to SROS2 with a series of developer tool extensions that help detect some of these insecurities in ROS 2 and DDS. ROS 2 *community-owner* Open Robotics did not follow up with these results or contributions and disregarded overall its relevance, pushing security responsibility aside| 22-04-2022 |
| <ins>JekyllBot:5</ins> | Aethon TUG smart robots ([various](https://aethon.com/products/)) | **Cynerio** | JekyllBot:5 is a collection of five critical zero-day vulnerabilities that enable remote control of Aethon TUG smart autonomous mobile robots and their online console, devices that are increasingly used for deliveries in global hospitals. More tech details about security findings at . | 01-04-2022 |
| <ins>Robot Teardown, stripping industrial robots for good</ins> | Universal Robots' [`UR3`](https://www.universal-robots.com/cb3/), [`UR5`](https://www.universal-robots.com/cb3/), [`UR10`](https://www.universal-robots.com/cb3/), [`UR3e`](https://www.universal-robots.com/products/ur3-robot/), [`UR5e`](https://www.universal-robots.com/products/ur5-robot/), [`UR10e`](https://www.universal-robots.com/products/ur10-robot/) and [`UR16e`](https://www.universal-robots.com/products/ur16-robot/) | [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/) *et al.* (**various**)| This research led by Alias Robotics introduced and advocated for robot teardown as an approach to study robot hardware architectures and fuel security research. Security researchers showed how teardown can help understanding the underlying hardware for uncovering security vulnerabilities. The group showed how robot teardown helped uncover more than 100 security flaws with 17 new CVE IDs granted over a period of two years. The group also demonstrated how various robot manufacturers are employing various planned obsolescense practices and how through teardown, planned obsolescence hardware limitations can be identified and bypassed obtaining full control of the hardware and giving it back to users, which poses both an opportunity to claim the *right to repair* as well as a threat to various robot manufacturers’ business models | 20-07-2021|
| <ins>Rogue Automation</ins> | (*various robotic programming languages/frameworks*) ABB's `Rapid`, Comau's `PDL2`, Denso's `PacScript`, Fanuc's `Karel`, Kawasaki's `AS`, Kuka's `KRL`, Mitsubishi's `Melfa`, and Universal Robots's `URScript`| [Federico Maggi](https://www.linkedin.com/in/phretor/), [Marcello Pogliani](https://www.linkedin.com/in/marcellopogliani/) (**various**)| This research unveils various hidden risks of industrial automation programming languages and frameworks used in robots from ABB, Comau, Denso, Fanuc, Kawasaki, Kuka, Mitsubishi, and Universal Robots. The security analysis performed in here reveals critical flaws across these technologies and their repercussions for smart factories.| 01-08-2020|
| <ins>Securing disinfection robots in times of COVID-19</ins> | UVD Robots' [`UVD Robot® Model B`](https://uvd.blue-ocean-robotics.com/modelb), `UVD Robot® Model A` | [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/) *et al.* (**Alias Robotics**) | The robots used in many medical centres to fight against COVID-19 for disinfection tasks were found vulnerable to various previously reported vulnerabilities (see ) while using Ultraviolet (UV) light, which can affect humans causing suntan, sunburn or even a reportedly increased risk of skin cancer, among others. The team at Alias Robotics confirmed experimentally these issues and found many of these robots insecure, with many unpatched security flaws and easily accessible in public spaces. This led them to develop mitigations for these outstanding security flaws and offered free licenses for such patches to hospitals and industry during the pandemic | 19-09-2020 |
| <ins>The week of Mobile Industrial Robots' bugs</ins> | Mobile Industrial Robots' [`MiR100`](https://www.mobile-industrial-robots.com/solutions/robots/mir100/), [`MiR200`](https://web.archive.org/web/20200702001019/https://www.mobile-industrial-robots.com/en/solutions/robots/mir200/), [`MiR250`](https://www.mobile-industrial-robots.com/solutions/robots/mir250/), [`MiR500`](https://web.archive.org/web/20200702031717/https://www.mobile-industrial-robots.com/en/solutions/robots/mir500/), [`MiR600`](https://www.mobile-industrial-robots.com/solutions/robots/mir600/), [`MiR1000`](https://web.archive.org/web/20200419094248/https://www.mobile-industrial-robots.com/en/solutions/robots/mir1000/), [`MiR1350`](https://www.mobile-industrial-robots.com/solutions/robots/mir1350/), Easy Robotics' [`ER200`](https://procobots.com/cnc-machine-tending/er200/), Enabled Robotics' [`ER-FLEX`](https://www.enabled-robotics.com/erflex), `ER-LITE`, `ER-ONE`, UVD Robots' [`UVD Robot® Model B`](https://uvd.blue-ocean-robotics.com/modelb), `UVD Robot® Model A`  | [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/) *et al.* (**Alias Robotics**) |  Having identified relevant preliminary security issues, after months of failed interactions with Mobile Industrial Robots’ (MiR) robot manufacturer while trying to help secure their robots, with this disclosure, Alias Robotics decided to empower end-users of Mobile Industrial Robots’ with information. The disclosure included a week of hacking efforts that finalized with the public release of  14 cybersecurity vulnerabilities affecting MiR industrial robots and other downstream manufacturers, impacting thousands of robots. More than 10 different robot types were affected operating across industrial spaces and all the way to public environments, such as airports and hospitals. 11 new CVE IDs were assigned as part of this effort |  24-06-2020 |
| <ins>Attacks on Smart Manufacturing Systems</ins> | Mitsubishi `Melfa V-2AJ` | [Federico Maggi](https://www.linkedin.com/in/phretor/), [Marcello Pogliani](https://www.linkedin.com/in/marcellopogliani/) (**various**) |  Systematic security analysis exploring a variety of attack vectors on a real smart manufacturing system, assessing the attacks that could be feasibly launched on a complex smart manufacturing system |  01-05-2020 |
| <ins>The week of Universal Robots' bugs</ins> | Universal Robots' [`UR3`](https://www.universal-robots.com/cb3/), [`UR5`](https://www.universal-robots.com/cb3/), [`UR10`](https://www.universal-robots.com/cb3/), [`UR3e`](https://www.universal-robots.com/products/ur3-robot/), [`UR5e`](https://www.universal-robots.com/products/ur5-robot/), [`UR10e`](https://www.universal-robots.com/products/ur10-robot/) and [`UR16e`](https://www.universal-robots.com/products/ur16-robot/) | [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/) *et al.* (**Alias Robotics**) | For years Universal Robots did not care nor responded about cybersecurity issues with their products. Motivated by this attitude, Alias Robotics' team launched an initiative to empower Universal Robots' end-users, distributors and system integrators with the information they so much require to make use of this technology securely. This effort was called the *week of Universal Robots' bugs* and in total, more than 80 security issues were reported in the robots of Universal robots|  31-03-2020 |
| <ins>Akerbeltz: Industrial robot ransomware</ins> | Universal Robots' [`UR3`](https://www.universal-robots.com/cb3/), [`UR5`](https://www.universal-robots.com/cb3/), [`UR10`](https://www.universal-robots.com/cb3/) | [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral/) *et al.* (**Alias Robotics**) | In an attempt to raise awareness and illustrate the *”insecurity by design in robotics”*, the team at Alias Robotics created *Akerbeltz*, the first known instance of industrial robot ransomware. The malware was demonstrated using the UR3 robot from a leading brand for industrial collaborative robots, Universal Robots. The team of researchers discussed the general flow of the attack including the initial cyber-intrusion, lateral movement and later control phase | 16-12-2019 |
| <ins>Rogue Robots</ins> | ABB’s [IRB140](https://new.abb.com/products/robotics/es/robots-industriales/irb-140)| [Federico Maggi](https://www.linkedin.com/in/phretor/), [Davide Quarta](https://www.linkedin.com/in/dvqu/) *et al.* (**various**)| Explored, theoretically and experimentally, the challenges and impacts of the security of modern industrial robots. Researchers also simulated an entire attack algorithm from an entry point to infiltration and compromise to demonstrate how an attacker would make use of existing vulnerabilities in order to perform various attacks. | 01-05-2017 |
| <ins>Hacking Robots Before Skynet</ins> | SoftBank Robotics's [`NAO`](https://www.softbankrobotics.com/emea/es/nao) and [`Pepper`](https://www.softbankrobotics.com/emea/es/pepper), UBTECH Robotics' `Alpha 1S` and `Alpha 2`, ROBOTIS' `OP2` and `THORMANG3`, Universal Robots' [`UR3`](https://www.universal-robots.com/cb3/), [`UR5`](https://www.universal-robots.com/cb3/), [`UR10`](https://www.universal-robots.com/cb3/), Rethink Robotics' `Baxter` and `Sawyer` and several robots from Asratec Corp | [Lucas Apa](https://www.linkedin.com/in/lucasapa/) and [César Cerrudo](https://www.linkedin.com/in/cesarcerrudo/) (**IOActive**)|  Discovered critical cybersecurity issues in several robots from multiple vendors which hinted about the lack of security concern and awareness in robotics. | 30-01-2017 |
| <ins>Robot Operating System (ROS): Safe & Insecure</ins> | ROS | [Lubomir Stroetmann](https://www.linkedin.com/in/lubo-stroetmann/) (**softSCheck**) | This is one of the earliest studies touching on ROS and offers security insights and examples about the lack of security considerations in ROS and the wide attack surface exposed by it. The author hints that with ROS, protection mechanism depends on the (security) expertise of the user, which is not a good assumption in the yet security-immature robotics community. Moreover the author hints about various vulnerabilities that are easily exploitable due to the XMLRPC adoption within the ROS message-passing infrastructure including various XML bomb attacks (e.g. "billion laughs") | 28-02-2014 |


\newpage

## Terminology

### Robot reconnaissance
Reconnaissance is the act of gathering preliminary data or intelligence on your target. The data is gathered in order to better plan for your attack. Reconnaissance can be performed actively (meaning that you are directly touching the target) or passively (meaning that your recon is being performed through an intermediary).

#### Robot footprinting
Footprinting, (also known as *reconnaissance*) is the technique used for gathering information about digital systems and the entities they belong to.


### Robot Threat Modeling
Threat modeling is the use of abstractions to aid in thinking about risks. The output of this activity is often named as the threat model. More commonly, a threat model enumerates the potential attackers, their capabilities and resources and their intended targets. In the context of robot cybersecurity, a threat model identifies security threats that apply to the robot and/or its components (both software and hardware) while providing means to address or mitigate them in the context of a use case.

A threat model is key to a focused security defense and generally answers the following questions:
- What are you building?
- What can go wrong (from a security perspective)?
- What should you do about those things that can go wrong?
- Did you do a decent job analysing the system?


### Bugs & vulnerability identification
#### Static analysis
Static analysis means inspecting the code to look for faults. Static analysis is using a program (instead of a human) to inspect the code for faults.

#### Dynamic analysis
Dynamic analysis, simply called “testing” as a rule, means executing the code while looking for errors and failures.

#### Fuzzing
Formally a sub-class of dynamic testing but we separated for convenience, fuzzing or fuzz testing implies challenging the security of your robotic software in a pseudo-automated manner providing invalid or random data as inputs wherever possible and looking for anomalous behaviors.

#### Dynamic analysis (sanitizers)
Sanitizers are dynamic bug finding tools. Sanitizers analyze a single program excution and output a precise analysis result valid for  that specific execution.

<details><summary>More details about sanitizers</summary>

As explained at https://arxiv.org/pdf/1806.04355.pdf:

>sanitizers are similar to many well-known *exploit mitigations* in that both types of tools insert inlined reference monitors (IRMs) into the program to enforce a fine-grained security policy. Despite this similarity, however, exploit mitigations and sanitizers significantly differ in what they aim to achieve and how they are used

The difference is better understood by the following table (also from the paper) that compares `exploit mitigations` and `sanitizers`:

| | Exploit Mitigations | Sanitizers |
|-----|-------|------|
| **The goal is to ...** |  Mitigate attacks | Find vulnerabilities |
| **Used in ...** | Production | Pre-release |
| **Performance budget ...** | Very limited | Much higher |
| **Policy violations lead to ...** | Program termination | Problem diagnosis |
| **Violations triggered at location of bug ...** | Sometimes  | Always |
| **Surviving benign errors is ...** | Desired | Not desired |

</details>


### Robot exploitation
An `exploit` is a piece of software, a chunk of data, or a sequence of commands that takes advantage of a bug or vulnerability to cause unintended or unanticipated behavior to occur on computer software, hardware, or something electronic (usually computerized). Exploitation is the art of taking advantage of vulnerabilities.

### Robot penetration testing (RPT)

Robot Penetration Testing (*robot pentesting* or RPT) is an offensive activity that seeks to find as many robot vulnerabilities as possible to risk-assess and  prioritize them. Relevant attacks are performed on the robot in order to confirm vulnerabilities. This exercise is effective at providing a thorough list of vulnerabilities, and should ideally be performed before shipping a product, and periodically after.

In a nutshell, robot penetration testing allows you to get a realistic and practical input of how vulnerable your robot is within a scope. A team of security researchers would then challenge the security of a robotic technology, find as many vulnerabilities as possible and develop exploits to take advantage of them.

See @dieber2020penetration for an example applied to ROS systems.


### Robot red teaming (RRT)

Robot red teaming is a targeted offensive cyber security exercise, suitable for use cases that have been already exposed to security flaws and wherein the objective is to fulfill a particular objective (attacker's goal). While robot penetration testing is much more effective at providing a thorough list of vulnerabilities and improvements to be made, a red team assessment provides a more accurate measure of a given technology’s preparedness for remaining resilient against cyber-attacks.

Overall, robot red teaming comprises a full-scope and multi-layered targeted (with specific goals) offensive attack simulation designed to measure how well your robotic technology can withstand an attack.

### Robot red teaming

### Other
#### Robot forensics
Robot forensics proposes a number of scientific tests and methods to obtain, preserve and document evidence from robot-related crimes. In particular, it focuses on recovering data from robotic systems to establish who committed the crime.

Review https://github.com/Cugu/awesome-forensics.

#### Robot reversing
Software reverse engineering (or *reversing*) is the process of extracting the knowledge or design blueprints from any software. When applied to robotics, robot reversing can be understood as the process of extracting information about the design elements in a robotic system.

\newpage

## Comparing robot cybersecurity with IT, OT and IoT

Security is often defined as the state of being free from danger or threat. But what does this mean in practice? What does it imply to be *free from danger*? Is it the same in enterprise and industrial systems? Well, short answer: no, it's not. Several reasons but one important is that the underlying technological architectures for each one of these environments, though shares technical bits, are significantly different which leads to a different interpretation of what security (again, being *free from danger and threats*) requires.

This section analyzes some of the cyber security aspects that apply in different domains including IT, OT, IoT or  robotics and compares them together. Particularly, the article focuses on clarifying how robotics differs from other technology areas and how a lack of clarity is leading to leave the user heavily unprotected against cyber attacks. Ultimately, this piece argues on why cyber security in robotics will be more important than in any other technology due to its safety implications, including IT, OT or even IoT.

### Introducing some common terms

Over the years, additional wording has developed to specify security for different contexts. Generically, and from my readings, we commonly refer to cyber security (or cybersecurity, shortened as just "security") as the state of a given system of being free from cyber dangers or cyber threats, those digital. As pointed out, we often mix "security" associated with  terms that further specify the domain of application, e.g. we often hear things such as `IT security` or `OT security`.

![IT, OT, IoT and robots comparison](https://cybersecurityrobotics.net/content/images/2020/06/IT_OT_IoT_robotics_ccomparison.png)

During the past two years, while reading, learning, attending to security conferences and participating on them, I've seen how both security practitioners and manufacturers caring about security do not clearly differentiate between `IT`, `OT`, `IoT` or `robotics`. Moreover, it's often a topic for arguments the comparison between `IT` and `IT security`. The following definitions aim to shed some light into this common topic:

- **Information Technology (IT)**:  the use of computers to store, retrieve, transmit, and manipulate data or information throughout and between organizations[^3].
- **Operational Technology (OT)**: the technology that manages industrial operations by monitoring and controlling specific devices and processes within industrial workflows and operations, as opposed to administrative (IT) operations.  This term is very closely related to:
- **Industrial Control System (ICS)**: is a major segment within the OT sector that comprises those systems that are used to monitor and control the industrial processes. ICS is a general term that encompasses several types of control systems (e.g. SCADA, DCS) in industry and can be understood as a subset of OT.
- **Internet of the Things (IoT)**: an extension of the Internet and other network connections to different sensors and devices — or "things" — affording even simple objects, such as lightbulbs, locks, and vents, a higher degree of computing and analytical capabilities. The IoT can be understood as an extension of the Internet and other network connections to different sensors and devices.
- **Industrial Internet of the Things (IIoT)**: refers to the extension and use of the Internet of Things (IoT) in industrial sectors and applications.
- **robotics**: A robot is a system of systems. One that comprises sensors to perceive its environment, actuators to act on it and computation to process it all and respond coherently to its application (could be industrial, professional, etc.). Robotics is the art of system integration. An art that aims to build machines that operate autonomously.

> Robotics is the art of system integration. Robots are systems of systems, devices that operate autonomously.

It's important to highlight that all the previous definitions refer to technologies. Some are domain specific (e.g. OT) while others are agnostic to the domain (e.g. robotics) but **each one of them are means that serve the user for and end**.


### Comparing the security across these technologies

Again, IT, OT, ICS, IoT, IIoT and robotics are all technologies. As such, each one of these is subject to operate securely, that is, free from danger or threats. For each one of these technologies, though might differ from each other, one may wonder, how do I apply security?

Let's look at what literature says about the security comparison of some of these:

From [^1]:

> *Initially, ICS had little resemblance to IT systems in that ICS were isolated systems running proprietary control protocols using specialized hardware and software. Widely available, low-cost Ethernet and Internet Protocol (IP) devices are now replacing the older proprietary technologies, which increases the possibility of cybersecurity vulnerabilities and incidents. As ICS are adopting IT solutions to promote corporate connectivity and remote access capabilities, and are being designed and implemented using industry standard computers, operating systems (OS) and network protocols, they are starting to resemble IT systems. This integration supports new IT capabilities, but it provides significantly less isolation for ICS from the outside world than predecessor systems, creating a greater need to secure these systems. While security solutions have been designed to deal with these security issues in typical IT systems, special precautions must be taken when introducing these same solutions to ICS environments. In some cases, new security solutions are needed that are tailored to the ICS environment.*

While Stouffer et al. [^1] focus on comparing ICS and IT, a similar rationale can easily apply to OT (as a superset of ICS).

To some, the phenomenon referred to as `IoT` is in large part about the physical merging of many traditional `OT` and `IT` components. There are many comparisons in literature (e.g. [^5] an interesting one that also touches into cloud systems, which I won't get into now) but most seem to agree that while I-o-T aims to merge both `IT` and `OT`, the security of `IoT` technologies requires a different skill set. In other words, the security of `IoT` should be treated independently to the one of `IT` or `OT`. Let's look at some representations:

![Comparison with IoT as the superset](https://cybersecurityrobotics.net/content/images/2020/06/tech_comparison_IoT_big.png)  

![Comparison with IoT as the intersection](https://cybersecurityrobotics.net/content/images/2020/06/tech_comparison_IoT_small.png)


What about robotics then? How does the security in robotics compare to the one in `IoT` or `IT`? Arguably, robotic systems are significantly more complex than the corresponding ones in `IT`, `OT` or even `IoT` setups. Shouldn't security be treated differently then as well? I definitely believe so and while much can be learned from other technologies, robotics deserves its own security treatment. Specially because I strongly believe that:

> cyber security in robotics will be more important than in any other technology due to its safety implications, including IT, OT or even IoT.

Of course, I'm a roboticist so expect a decent amount of bias on this claim. Let me however further argue on this. The following table is inspired by processing and extending [^1] and [^2] for robotics while including other works such as [^5], among others:


| **Security topic** | **IT** | **OT** (ICS) | **I(I)oT** | **Robotics** |
|----------------|----|----------|----------|-------|
| **Antivirus** | widely used, easily updated | complicated and often imposible, network detection and prevention solutions mostly | Similarly complicated, lots of technology fragmentation (different RTOSs, embedded frameworks and communication paradigms), network detection and prevention solutions exist | complicated and complex due to the technology nature, very few existing solutions (e.g. [RIS](https://aliasrobotics.com/ris.php)), network monitoring and prevention isn't enough due to safety implications |
| **Life cycle** | 3-5 years | 10-20 years | 5-10 years | 10+ years |
| **Awareness** | Decent |  Poor | Poor | None |
| **Patch management** | Often | Rare, requires approval from plant manufacturers | Rare, often requires permission (and/or action) from end-user | Very rare, production implications, complex set ups|
| **Change Management** | Regular and scheduled | Rare | Rare | Very rare, often specialized technitians |
| **Evaluation of log files** | Established practice | Unusual practice | Unusual practice | Non-established practice |
| **Time dependency** | Delays Accepted | Critical | Some delays accepted (depends of domain of application, e.g. IIoT might be more sensitive) |  Critical, both inter and intra robot communications |
| **Availability** | Not always available, failures accepted | 24*7 | Some failures accepted (again, domain specific) | 24*7 available |
| **Integrity** | Failures accepted | Critical  | Some failures accepted (again, domain specific) | Critical |
| **Confidentiality** | Critical | Relevant | Important | Important |
| **Safety** | Not relevant (does not apply generally) | Relevant | Not relevant (though depends of domain of application, but IoT systems are not known for their safety concerns) | Critical, autonomous systems may easily compromise safety if not operating as expected |
| **Security tests** | Widespread | Rare and problematic (infrastructure restrictions, etc.) | Rare |  Mostly not present ([first services of this kind for robotics](https://aliasrobotics.com/security-assessment.php) are starting to appear)  |
| **Testing environment** | Available | Rarely available | Rarely available | Rare and difficult to reproduce |
| **Determinism requirements** (refer to [^6] for definitions) | Non-real-time. Responses must be consistent. High throughput is demanded. High delay and jitter may be acceptable. Less critical emergency interaction. Tightly restricted access control can be implemented to the degree necessary for security | Hard real-time. Response is time-critical. Modest throughput is acceptable. High delay and/or jitter is not acceptable. Response to human and other emergency interaction is critical. Access to ICS should be strictly controlled, but should not hamper or interfere with human-machine interaction | Often non-real-time, though some environment will require soft or firm real-time | Hard real-time requirements for safety critical applications and firm/soft real-time for other tasks |

</div>

Looking at this table and comparing the different technologies, it seems reasonable to admit that robotics receives some of the heaviest restrictions when it comes to the different security properties, certainly, much more than IoT or IT.

Still, why do robotic manufacturers focus solely on `IT` security?

![MiR on IT security](https://cybersecurityrobotics.net/content/images/2020/06/mir-it-security.png)   

![MiR on how to improve IT security](https://cybersecurityrobotics.net/content/images/2020/06/mir-it-improve.png)

\newpage


## Understanding the robotics supply chain

Insecurities in robotics are not just in the robots themselves, they are also in the whole supply chain. The tremendous growth and popularity of collaborative robots have over the past years introduced flaws in the –already complicated– supply chain, which hinders serving safe and secure robotics solutions.

Traditionally,  `Manufacturer`, `Distributor` and `System Integrator` stakeholders were all into one single entity that served `End users` directly. This is the case of some of the biggest and oldest robot manufacturers including ABB or KUKA, among others.

Most recently, and specially with the advent of collaborative robots [^1] and their insecurities [^2], each one of these stakeholders acts independently, often with a blurred line between `Distributor` and `Integrator`. This brings additional complexity when it comes to responding to `End User` demands, or solving legal conflicts.

> Companies like Universal Robots (UR) or Mobile Industrial Robots (MiR) represent best this *fragmentation* of the supply chain. When analyzed from a cybersecurity angle, one wonders: which of these approaches is more responsive and responsible when applying security mitigations? Does fragmentation difficult responsive reaction against cyber-threats? Are `Manufacturers` like Universal Robots pushing the responsibility and liabilities to their `Distributors` and the subsequent `Integrators` by fragmenting the supply chain? What are the exact legal implications of such fragmentation?


### Stakeholders of the robotics supply chain

Some of the stakeholders of both the *new* and the *old* robotics supply chains are captured and defined in the figure below:


![Stakeholders of the robotics supply chain](https://cybersecurityrobotics.net/content/images/2020/05/The-supply-chain.png)

Not much to add. The diagram above is far from complete. There're indeed more players but these few allow one to already reason about the present issues that exist in the robotics supply chain.

### The 'new' supply chain in robotics

It really **isn't new**. The supply chain (and GTM strategy) presented by vendors like UR or MiR (both owned by Teradyne) was actually inspired by many others, across industries, yet, it's certainly been growing in popularity over the last years in robotics. In fact, one could argue that the popularity of collaborative robots is related to this *change in the supply chain*, where many stakeholders contributed to the spread of these new technologies.

This supply chain is depicted below, where a series of security-related interactions are captured:


![Liabilities and responsibilities in the robotics supply chain](https://cybersecurityrobotics.net/content/images/2020/05/C8C71179-CF96-46A3-9BCD-E69CA6F4CD6D.png)

The diagram presents several sub-cases, each deals with scenarios that may happen when robots present cybersecurity flaws. Beyond the interactions, what's outstanding is the more than 20 legal questions related to liabilities and responsibility that came up. This, in my opinion, **reflects clearly the complexity of the current supply chain in robotics, and the many compromises one needs to assume** when serving, distributing, integrating, or operating a robot.

What's more scary, is that most of the stakeholders involved in the supply chain I interact with <ins>ignore their responsibilities</ins> (different reasons, from what I can see). The security angle in here is critical. Security mitigations need to be supplied all the way down to the end-user products, otherwise, it'll lead to hazards.

While I am not a laywer, my discussions with lawyers on this topic made me believe that there's lack of legal frameworks and/or clear answers in Europe for most of these questions. Morever, the lack of security awareness from many of the stakeholders involved [^8] is not only compromising intermediaries (e.g. `Distributor`s and `System Integrator`s), but ultimately exposing end-users to risks.

Altogether, I strongly believe this 'new' supply chain and the clear lack of security awareness and reactions leads to a compromised supply chain in robotics. I'm listing below a few of the most relevant (refer to the diagram above for all of them) cybersecurity-related questions raised while building the figure above reasoning on the supply chain:

- Who is responsible (across the supply chain) and what are the liabilities if as a result of a cyber-attack there is human harm for a previously not known (or reported) flaw for a particular manufacturers's technology?[^11]
- Who is responsible (across the supply chain) and what are the liabilities if as a result of a cyber-attack there is a human harm for a known and disclosed but not mitigated flaw for a particular manufacturers's technology?
- Who is responsible (across the supply chain) and what are the liabilities if as a result of a cyber-attack there is a human harm for a known, disclosed and mitigated flaw, yet not patched?
- What happens if the harm is environmental?
- And if there is no harm? Is there any liability for the lack of responsible behavior in the supply chain?
- What about researchers? are they allowed to freely incentivate security awareness by ethically disclosing their results? (which you'd expect when one discovers something)
- Can researchers collect insecurity evidence to demonstrate non-responsible behavior without liabilities?

### So, what's better, fragmentation or the lack of it?

I see a huge growth through fragmentation yet,  still, reckon that the biggest and most successful robotics companies out there tend to integrate it all.

What's clear to me is that fragmentation of the supply chain (or the 'new' supply chain) presents clear challenges for cybersecurity. Maintaining security in a fragmented scenario is more challenging, requires more resources and a well coordinated and often distributed series of actions (which by reason is tougher).

> fragmentation of the supply chain (or the 'new' supply chain) presents clear challenges from a security perspective.

Investing in robot cybersecurity by either building your own security team or relying on external support is a must.


## Recommended readings

| Title | Description |
|-------|-------------|
| Introducing the Robot Security Framework (RSF) [@vilches2018introducing] |  A methodology to perform systematic security assessments in robots proposing a checklist-like approach that reviews most relevant aspects in a robot |
| Robot hazards: from safety to security [@kirschgens2018robot] | Discussion of the current status of insecurity in robotics and the relationship between safety and security, ignored by most vendors |
| The Robot Vulnerability Scoring System (RVSS) [@vilches2018towards] | Introduction of a new assessment scoring mechanisms for the severity of vulnerabilities in robotics that builds upon previous work and specializes it for robotics |
| Robotics CTF (RCTF), a playground for robot hacking [@mendia2018robotics] | Docker-based CTF environment for robotics |
| Volatile memory forensics for the Robot Operating System [@vilches2018volatile] | General overview of forensic techniques in robotics and discussion of a robotics-specific Volatility plugin named `linux_rosnode`, packaged within the `ros_volatility` project and aimed to extract evidence from robot's volatile memory |
| aztarna, a footprinting tool for robots [@vilches2018aztarna] | Tool for robot reconnaissance with particular focus in footprinting  |
| Introducing the robot vulnerability database (RVD) [@vilches2019introducing] | A database for robot-related vulnerabilities and bugs |
| Industrial robot ransomware: Akerbeltz [@mayoral2019industrial] | Ransomware for Industrial collaborative robots |
| Cybersecurity in Robotics: Challenges, Quantitative Modeling and Practice [@ROB-061] | Introduction to the robot cybersecurity field describing current challenges, quantitative modeling and practices |
| DevSecOps in Robotics [@mayoral2020devsecops] | A set of best practices designed to help roboticists implant security deep in the heart of their development and operations processes |
| alurity, a toolbox for robot cybersecurity [@mayoral2020alurity] | Alurity is a modular and composable toolbox for robot cybersecurity. It ensures that both roboticists and security  researchers working on a  project, have a common, consistent and easily reproducible development environment facilitating the security process and the collaboration across teams |
| Can ROS be used securely in industry? Red teaming ROS-Industrial [@mayoral2020can] | Red team ROS in an industrial environment to attempt answering the question: Can ROS be used securely for industrial use cases even though its origins didn't consider it? |
| Hacking planned obsolescense in robotics, towards security-oriented robot teardown [@mayoral2021hacking] | As robots get damaged or security compromised, their components will increasingly require updates and replacements. Contrary to the expectations, most manufacturers employ planned obsolescence practices and discourage repairs to evade competition. We introduce and advocate for robot teardown as an approach to study robot hardware architectures and fuel security research. We show how our approach helps uncovering security vulnerabilities, and provide evidence of planned obsolescence practices. |

## Recommended talks

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




[^1]: Stouffer, K., Falco, J., & Scarfone, K. (2011). Guide to industrial control systems (ICS) security. NIST special publication, 800(82), 16-16.
[^2]: TUViT, TÜV NORD GROUP. [Whitepaper Industrial Security based on IEC 62443](https://www.tuvit.de/fileadmin/Content/TUV_IT/pdf/Downloads/WhitePaper/whitepaper-iec-62443.pdf)
[^3]: Information technology. (2020). Retrieved June 23, 2020, from https://en.wikipedia.org/wiki/Information_technology.
[^5]: Atlam, Hany & Alenezi, Ahmed & Alshdadi, Abdulrahman & Walters, Robert & Wills, Gary. (2017). Integration of Cloud Computing with Internet of Things: Challenges and Open Issues. 10.1109/iThings-GreenCom-CPSCom-SmartData.2017.105.
[^6]: Gutiérrez, C. S. V., Juan, L. U. S., Ugarte, I. Z., & Vilches, V. M. (2018). Towards a distributed and real-time framework for robots: Evaluation of ROS 2.0 communications for real-time robotic applications. arXiv preprint arXiv:1809.02595.
[^7]: Read on what a security-first approach in [here](https://www.darkreading.com/edge-articles/a-security-first-approach-to-devops).

[^8]: Mayoral-Vilches, V. *Universal Robots cobots are not secure*. Cybersecurity and Robotics.
[^11]: Note this questions covers both, 0-days and known flaws that weren't previously reported.
