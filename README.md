# Basic robot cybersecurity
An introductory series of security and cybersecurity for robots with comprehensive step-by-step tutorials. The material available here is a personal learning attempt and it's disconnected from any particular organization. **By no means I want to encourage or promote the unauthorized tampering of robotic systems**.

- [Robot footprinting](#robot-footprinting)
- [Robot enumeration](#robot-enumeration)
- [Robot exploitation](#robot-exploitation)
- [Robot reversing](#robot-reversing)
- [CTF](#CTF)


#### Robot footprinting
*None for now*

#### Robot enumeration
- Basic enumeration of a robotic system can be done with [ROSPenTo](https://github.com/jr-robotics/ROSPenTo)

#### Robot exploitation
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

#### Robot reversing
Software reverse engineering (or *reversing*) is the process of extracting the knowledge or design blueprints from any software. In a similar manner, forensics extracts also knowledge that's typically used as evidence for a particular investigation.
- [Basic robot forensics, an unauthenticated unregistration in ROS](robot_reversing/tutorial1/)

#### CTF
Capture The Flag exercises available at:
- [CTF](CTF/)

## Future, next steps
- Continue with tutorials at https://github.com/nnamon/linux-exploitation-course
- https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/
- Automatic Exploit Generation (AEG) (https://github.com/ChrisTheCoolHut/Zeratool)
