---
title: "Robot Hacking Manual"
author: [Víctor Mayoral Vilches]
date: "2019-07-20"
toc: true
subject: "Markdown"
keywords: [Robotics, Hacking, Robot]
subtitle: "Notes and writeups about a journey in robot cybersecurity."
lang: "en"
titlepage: true
titlepage-color: "313131"
titlepage-text-color: "FFFFFF"
titlepage-rule-color: "FFFFFF"
titlepage-rule-height: 1
pandoc-latex-fontsize:
  - classes: [smallcontent]
    size: tiny
  - classes: [largecontent, important]
    size: huge
bibliography: bibliography.bib
...

<!-- here goes the index -->

\newpage

# Basic robot cybersecurity
An introductory series about security and cybersecurity for robots and related topics, with comprehensive step-by-step tutorials. The material available here is a personal learning attempt and it's disconnected from any particular organization. **By no means I want to encourage or promote the unauthorized tampering of robotic systems or related technologies**.

## Index
- [Robot reconnaissance](#robot-reconnaissance)
  - [Robot footprinting](#robot-footprinting)
  - [Robot enumeration](#robot-enumeration)
- [Robot Threat Modeling, bugs & vulnerability Identification](https://github.com/vmayoral/basic_robot_cybersecurity#robot-threat-modeling-bugs--vulnerability-identification)
- [Robot exploitation](#robot-exploitation)
- [Cases of study](#cases-of-study)
- [Other](#other)
  - [Robot forensics](#robot-forensics)
  - [Robot reversing](#robot-reversing)
  - [CTF](#CTF)
  - [Web](#web)
  - [Privacy](#privacy)
  - [Cryptocurrencies](#privacy)
  - [Standards and methodologies](#standards)


<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!--        Robot reconnaissance  -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
## Robot reconnaissance
Reconnaissance is the act of gathering preliminary data or intelligence on your target. The data is gathered in order to better plan for your attack. Reconnaissance can be performed actively (meaning that you are directly touching the target) or passively (meaning that your recon is being performed through an intermediary).

#### Robot footprinting
Footprinting, (also known as *reconnaissance*) is the technique used for gathering information about digital systems and the entities they belong to.
- [Tutorial 1: Footprinting ROS systems](1_reconnaissance/robot_footprinting/tutorial1/)
- [Tutorial 2: Footprinting Secure ROS systems](1_reconnaissance/robot_footprinting/tutorial2/)

#### Robot enumeration
- Basic enumeration of a robotic system can be done with [ROSPenTo](https://github.com/jr-robotics/ROSPenTo)

<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!--        Robot Threat Modeling, bugs & vulnerability Identification -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
## Robot Threat Modeling, bugs & vulnerability Identification
Once you feel you have sufficient info about the robot, you can start modeling the threats that the client/user would realistically face and identify vulnerabilities that will allow for those attacks.

### Threat modeling
<details><summary>Attack surface generated while in a thread modeling process</summary>

![](http://design.ros2.org/articles/ros2_threat_model/threat_model_mara.png)

Refer to http://design.ros2.org/articles/ros2_threat_model.html#threat-analysis-for-the-mara-robotic-platform for a first publication on a preliminar thread model on an industrial robot manipulator. The analysis has been done from the perspective of ROS 2.

</details>

### Static analysis
Static analysis means inspecting the code to look for faults. Static analysis is using a program (instead of a human) to inspect the code for faults.
- [Tutorial 5: Static analysis of PyRobot](2_robot_vulnerabilities/tutorial5/)

### Dynamic analysis
Dynamic analysis, simply called “testing” as a rule, means executing the code while looking for errors and failures. 

#### Fuzzing
TODO

#### Sanitizers (dynamic analysis)
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

The following tutorials provide an introduction on how to run sanitizers in robot specific code:
- [Tutorial 1: Robot sanitizers in ROS 2 Dashing](2_robot_vulnerabilities/tutorial1/)
- [Tutorial 2: Robot sanitizers in MoveIt 2](2_robot_vulnerabilities/tutorial2/)
- [Tutorial 3: Debugging output of robot sanitizers with GDB, hunting and fixing bugs](2_robot_vulnerabilities/tutorial3/)
- Tutorial 4: Robot sanitizers with Gazebo: TODO
- [Tutorial 5: Static analysis of PyRobot](2_robot_vulnerabilities/tutorial5/)
- [Tutorial 6: Analyzing Turtlebot 3](2_robot_vulnerabilities/tutorial6/)
- [Tutorial 7: Looking for vulnerabilities in navigation2](2_robot_vulnerabilities/tutorial7/)


<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!--                          Robot exploitation -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
## Robot exploitation
An `exploit` is a piece of software, a chunk of data, or a sequence of commands that takes advantage of a bug or vulnerability to cause unintended or unanticipated behavior to occur on computer software, hardware, or something electronic (usually computerized). Exploitation is the art of taking advantage of vulnerabilities.

###### General
- [Tutorial 1: Buffer overflows](3_robot_exploitation/tutorial1/)
- [Tutorial 2: Building shellcode](3_robot_exploitation/tutorial2/)
- [Tutorial 3: Exploiting](3_robot_exploitation/tutorial3/)
- [Tutorial 4: Return to `libc`](3_robot_exploitation/tutorial4/)
- [Tutorial 5: Return-Oriented Programming (ROP)](3_robot_exploitation/tutorial5/)
- [Tutorial 6: Remote shell](3_robot_exploitation/tutorial6/)
- [Tutorial 7: pwntools - CTF toolkit](3_robot_exploitation/tutorial7/)
- [Tutorial 8: Linux Binary Protections](https://github.com/nnamon/linux-exploitation-course/blob/master/lessons/5_protections/lessonplan.md) (external)
- [Tutorial 9: Building a pwnbox](3_robot_exploitation/tutorial9/)
- [Tutorial 10: Bypassing NX with Return Oriented Programming](3_robot_exploitation/tutorial10/) (**WIP, unfinished**)

###### Robotics-specific
- [Tutorial 11: Unauthenticated registration/unregistration with ROS Master API](3_robot_exploitation/tutorial11/)
- [Tutorial 12: Unauthenticated updates in publisher list for specified topic](3_robot_exploitation/tutorial12)
- [Tutorial 13: Sockets left open and in CLOSE_WAIT state in ROS](3_robot_exploitation/tutorial13)


<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!--                          Cases of study -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
## Cases of study
TODO

<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!--                          Other -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
## Other
#### Robot forensics
Robot forensics proposes a number of scientific tests and methods to obtain, preserve and document evidence from robot-related crimes. In particular, it focuses on recovering data from robotic systems to establish who committed the crime.

Review https://github.com/Cugu/awesome-forensics

- [Tutorial 1: Basic robot forensics, an unauthenticated unregistration in ROS](other/robot_forensics/tutorial1/)
- [Tutorial 2: Locating ROS logs in memory](other/robot_forensics/tutorial2/) (**failed**)
- [Tutorial 3: Capturing memory in Linux-based robots](other/robot_forensics/tutorial3/)
- [Tutorial 4: Basic robot forensics 2, unauthenticated updates in publisher list for specified topic](other/robot_forensics/tutorial4/) (**ongoing**)

#### Robot reversing
Software reverse engineering (or *reversing*) is the process of extracting the knowledge or design blueprints from any software. When applied to robotics, robot reversing can be understood as the process of extracting information about the design elements in a robotic system.


<details><summary>Reversing roadmap</summary>

*None for now*. Some pointers:
- https://twitter.com/daeken/status/1025123319824244738. *Listing things below*

- [ ] Read: Reversing by Eldad Eilam 
- [ ] Assembly 
  - [ ] Do: Write some C, compile it, 
  - [ ] disassemble, hand-decompile to C 
  - [ ] Do: Have a friend write and compile some C, 
  - [ ] then disassemble and hand-decompile it and have friend check your work
- [ ] Do: Pick a game (some ideas in the CTF section, some hacking oriented games exist).  Reverse-engineer its archive format and write an unpacker 
- [ ] Read: The Dragon Book (Compilers by Aho et al)
- [ ] Do: Write a compiler from some high-level language (feel free to make one up) to another (Python) 7) 
- [ ] Do: Write an assembler 
- [ ] Do: Write a compiler from some language down to assembly 
  - [ ] C https://norasandler.com/2017/11/29/Write-a-Compiler.html
- [ ] Read: Reverse Compilation Techniques by Cifuentes [...]
- [ ] Do: Write a decompiler for CIL and/or Dalvik bytecode 
- [ ] Do: Write a decompiler for ARM (doesn't have to be ARM, but it's consistent and relatively sane) 
- [ ] Read: The osdev wiki, until your eyes can't focus anymore [...]
- [ ] Do: Write a toy kernel 
  - [ ] Do: Write it again, with slightly less suck 
  - [ ] Do: Port your kernel to a different platform 
- [ ] Do: Pick a well-known platform and write an interpreting emulator 
  - [ ] Do: Add a recompiler [...]
- [ ] Do: Pick a slightly-unknown platform 
  - [ ] Read: Everything you can find about it 
  - [ ] Do: Begin writing an emulator 
  - [ ] Read: All the assembly you can find, for bits that aren't known 
  - [ ] Go back to 16b, continuing your work [...]

</details>

#### CTF
Capture The Flag exercises available at:
- [CTF](CTF/)

#### Web
Web security is of relevance to most companies. Robotics' ones aren't any different. Often, the website of each one these companies reflects the reputation and its maintenance if of critical relevance. This section will cover some web aspects that most robotic companies should take into account. The content here represents merely a learning experience. **By no means I want to encourage or promote the unauthorized tampering of robotic systems or robotic-related services/infrastructure**,
- [Tutorial 1: Damn Vulnerable Web Application (DVWA)](web/tutorial1/)
- [~~Tutorial 2: BadStore.net~~](web/tutorial2/) (**unfinished**)

#### Privacy
WIP

#### Cryptocurrencies
WIP

#### Standards
WIP

-----

## Ideas and/or future, next steps?
A few ideas to implement/try in the future:

- Tutorial B: Remote Exploit. Shellcode without Sockets
  - https://0x00sec.org/t/remote-exploit-shellcode-without-sockets/1440
- Tutorial C: Infecting Running Processes
  - https://0x00sec.org/t/linux-infecting-running-processes/1097
- Tutorial A: Remote shell through remote vulnerability (e.g. buffer overflow)
- Tutorial Z: Fuzzing
   - https://fuzzing-project.org/tutorial1.html   
- Tutorial Y: Pen Testing
- Tutorial X: Remote buffer overflow exploiting
   - https://www.areanetworking.it/explanation-of-a-remote-buffer-overflow-vulnerability.html
   - https://www.cs.vu.nl/~herbertb/misc/bufferoverflow/
- Tutorial U: Sniffers
   - https://0x00sec.org/t/how-do-those-hackers-tools-work-sniffers-part-i/686
   - https://0x00sec.org/t/how-do-those-hackers-tools-work-sniffers-part-ii/777
- Tutorial D: Docker for forensics
   - https://hub.docker.com/r/nov3mb3r/dfir/~/dockerfile/
   - https://0x00sec.org/t/forensics-docker/6220

 - Continue with tutorials at https://github.com/nnamon/linux-exploitation-course
 - https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/
 - Automatic Exploit Generation (AEG) (https://github.com/ChrisTheCoolHut/Zeratool)
