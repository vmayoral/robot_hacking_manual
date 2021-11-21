# `RHM`: Robot Hacking Manual

The *Robot Hacking Manual* (`RHM`) is an introductory series about cybersecurity for robots, with an attempt to provide comprehensive case studies and step-by-step tutorials with the intent to raise awareness in the field and highlight the importance of taking a *security-first*[^0] approach. The material available here is also a personal learning attempt and it's disconnected from any particular organization. Content is provided as is and **by no means I encourage or promote the unauthorized tampering of robotic systems or related technologies**.

- [**Disclaimer**](DISCLAIMER.md)
- [**History**](MOTIVATION.md#history)
- [**Motivation**](MOTIVATION.md#motivation)
- [**A containerized approach**](MOTIVATION.md#a-containerized-approach)
- [**Contribute back**](CONTRIBUTE.md)
- [**Introduction**](0_introduction/README.md)
  - [About robot cybersecurity](0_introduction/README.md#about-robot-cybersecurity)
- <ins>**Case studies**</ins>
  - [Universal Robots' UR3](1_case_studies/0_cobot/) (hacking a collaborative robot arm)
  - [Mobile Industrial Robots' MiR100](1_case_studies/1_amr/) (hacking an industrial mobile robot)
  - [Robot Operating System 2](1_case_studies/2_ros2/) (hacking ROS 2)
  - [TurtleBot 3](1_case_studies/3_turtlebot3/) (hacking TurtleBot 3)
- [**Writeups**]()
  - <ins>Reconaissance</ins>
    - [Footprinting]()
      - [Tutorial 1: Footprinting ROS systems](2_writeups/1_reconnaissance/robot_footprinting/tutorial1/)
      - [Tutorial 2: Footprinting Secure ROS systems](2_writeups/1_reconnaissance/robot_footprinting/tutorial2/)
      - [Tutorial 3: Footprinting ROS 2 and DDS systems](2_writeups/1_reconnaissance/robot_footprinting/tutorial3/)
  - <ins>Vulnerability research</ins>
    - [Static analysis]()
      - [Tutorial 5: Static analysis of PyRobot](2_writeups/2_robot_vulnerabilities/tutorial5/)
    - [Dynamic analysis]()
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
    - [General]()
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
    - [Robotics-specific]()
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

[^0]: Read on what a security-first approach in [here](https://www.darkreading.com/edge-articles/a-security-first-approach-to-devops).
