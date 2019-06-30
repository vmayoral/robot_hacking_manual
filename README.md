# Basic robot cybersecurity
An introductory series of security and cybersecurity for robots with comprehensive step-by-step tutorials. The material available here is a personal learning attempt and it's disconnected from any particular organization. **By no means I want to encourage or promote the unauthorized tampering of robotic systems**.

- [Robot reconnaissance](#robot-reconnaissance)
  - [Robot footprinting](#robot-footprinting)
  - [Robot enumeration](#robot-enumeration)
- Robot Threat Modeling & Robot Vulnerability Identification
- [Robot exploitation](#robot-exploitation)
- [Other](#other)
  - [Robot forensics](#robot-forensics)
  - [Robot reversing](#robot-reversing)
  - [CTF](#CTF)
  - [Web](#web)


## Robot reconnaissance
Reconnaissance is the act of gathering preliminary data or intelligence on your target. The data is gathered in order to better plan for your attack. Reconnaissance can be performed actively (meaning that you are directly touching the target) or passively (meaning that your recon is being performed through an intermediary).

#### Robot footprinting
Footprinting, (also known as *reconnaissance*) is the technique used for gathering information about digital systems and the entities they belong to.
- [Tutorial 1: Footprinting ROS systems](robot_footprinting/tutorial1/)
- [Tutorial 2: Footprinting Secure ROS systems](robot_footprinting/tutorial2/)

#### Robot enumeration
- Basic enumeration of a robotic system can be done with [ROSPenTo](https://github.com/jr-robotics/ROSPenTo)

## Robot Threat Modeling & Vulnerability Identification
Once you feel you have sufficient info about the robot, you can start modeling the threats that the client/user would realistically face and identify vulnerabilities that will allow for those attacks.

### Threat modeling
<details><summary>Attack surface generated while in a thread modeling process</summary>

![](http://design.ros2.org/articles/ros2_threat_model/threat_model_mara.png)

Refer to http://design.ros2.org/articles/ros2_threat_model.html#threat-analysis-for-the-mara-robotic-platform for a first publication on a preliminar thread model on an industrial robot manipulator. The analysis has been done from the perspective of ROS 2.

</details>

### Static analysis
Static analysis means inspecting the code to look for faults. Static analysis is using a program (instead of a human) to inspect the code for faults.
- [Tutorial 5: Static analysis of PyRobot](robot_vulnerabilities/tutorial5/)

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
- [Tutorial 1: Robot sanitizers in ROS 2 Dashing](robot_vulnerabilities/tutorial1/)
- [Tutorial 2: Robot sanitizers in MoveIt 2](robot_vulnerabilities/tutorial2/)
- [Tutorial 3: Debugging output of robot sanitizers with GDB, hunting and fixing bugs](robot_vulnerabilities/tutorial3/)
- Tutorial 4: Robot sanitizers with Gazebo: TODO

## Robot exploitation
An `exploit` is a piece of software, a chunk of data, or a sequence of commands that takes advantage of a bug or vulnerability to cause unintended or unanticipated behavior to occur on computer software, hardware, or something electronic (usually computerized). Exploitation is the art of taking advantage of vulnerabilities.

###### General
- [Tutorial 1: Buffer overflows](robot_exploitation/tutorial1/)
- [Tutorial 2: Building shellcode](robot_exploitation/tutorial2/)
- [Tutorial 3: Exploiting](robot_exploitation/tutorial3/)
- [Tutorial 4: Return to `libc`](robot_exploitation/tutorial4/)
- [Tutorial 5: Return-Oriented Programming (ROP)](robot_exploitation/tutorial5/)
- [Tutorial 6: Remote shell](robot_exploitation/tutorial6/)
- [Tutorial 7: pwntools - CTF toolkit](robot_exploitation/tutorial7/)
- [Tutorial 8: Linux Binary Protections](https://github.com/nnamon/linux-exploitation-course/blob/master/lessons/5_protections/lessonplan.md) (external)
- [Tutorial 9: Building a pwnbox](robot_exploitation/tutorial9/)
- [Tutorial 10: Bypassing NX with Return Oriented Programming](robot_exploitation/tutorial10/) (**WIP, unfinished**)

###### Robotics-specific
- [Tutorial 11: Unauthenticated registration/unregistration with ROS Master API](robot_exploitation/tutorial11/)
- [Tutorial 12: Unauthenticated updates in publisher list for specified topic](robot_exploitation/tutorial12)
- [Tutorial 13: Sockets left open and in CLOSE_WAIT state in ROS](robot_exploitation/tutorial13)

## Other
#### Robot forensics
Robot forensics proposes a number of scientific tests and methods to obtain, preserve and document evidence from robot-related crimes. In particular, it focuses on recovering data from robotic systems to establish who committed the crime.

Review https://github.com/Cugu/awesome-forensics

- [Tutorial 1: Basic robot forensics, an unauthenticated unregistration in ROS](robot_forensics/tutorial1/)
- [Tutorial 2: Locating ROS logs in memory](robot_forensics/tutorial2/) (**failed**)
- [Tutorial 3: Capturing memory in Linux-based robots](robot_forensics/tutorial3/)
- [Tutorial 4: Basic robot forensics 2, unauthenticated updates in publisher list for specified topic](robot_forensics/tutorial4/) (**ongoing**)

#### Robot reversing
Software reverse engineering (or *reversing*) is the process of extracting the knowledge or design blueprints from any software. When applied to robotics, robot reversing can be understood as the process of extracting information about the design elements in a robotic system.

*None for now*

#### CTF
Capture The Flag exercises available at:
- [CTF](CTF/)

#### Web
Web security is of relevance to most companies. Robotics' ones aren't any different. Often, the website of each one these companies reflects the reputation and its maintenance if of critical relevance. This section will cover some web aspects that most robotic companies should take into account. The content here represents merely a learning experience. **By no means I want to encourage or promote the unauthorized tampering of robotic systems or robotic-related services/infrastructure**,
- [Tutorial 1: Damn Vulnerable Web Application (DVWA)](web/tutorial1/)
- [~~Tutorial 2: BadStore.net~~](web/tutorial2/) (**unfinished**)


## Future, next steps
- Continue with tutorials at https://github.com/nnamon/linux-exploitation-course
- https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/
- Automatic Exploit Generation (AEG) (https://github.com/ChrisTheCoolHut/Zeratool)
