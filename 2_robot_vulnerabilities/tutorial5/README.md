# Static analysis of PyRobot

## Discussing PyRobot
This section briefly discusses `pyrobot` and provides a biased opinion on how valid the contribution is for the AI and robotic communities.

### The rationale behind PyRobot
PyRobot has been developed and published by Facebook Artificial Intelligence research group. From the Facebook announcement:

>PyRobot is a framework and ecosystem that enables AI researchers and students to get up and running with a robot in just a few hours, without specialized knowledge of the hardware or of details such as device drivers, control, and planning. PyRobot will help Facebook AI advance our long-term robotics research, which aims to develop embodied AI systems that can learn efficiently by interacting with the physical world. We are now open-sourcing PyRobot to help others in the AI and robotics community as well.

From this text one could say that the original authors not only aim to apply AI techniques to robots but specifically, come from an AI background and found the overall ROS ecosystem "too complex" (from my experience this is often the case of many software engineers diving into robotics). AI engineers often tend to disregard the complexity of robots and attempt find shortcuts that leave aside relevant technical aspects:

> PyRobot abstracts away details about low-level controllers and interprocess communication, so machine learning (ML) experts and others can simply focus on building high-level AI robotics applications.

There's still a strong discussion in the robotics community on whether AI techniques do actually outperform formal methods (traditional control mechanisms). This might indeed be the case on vision-powered applications but applying machine learning techniques end-to-end might not deliver the most optimal results as already reported in several articles.

Robotics is the art of system integration and requires roboticists to care strongly about things such as determinism, real-time, security or safety. These aspects aren't often the first priority for most AI engineers (changing policies is typically what most would expect). This is a recurrent situation that's happening over and over with engineers jumping from AI-related areas to robotics. The desire of AI-oriented groups to apply "only AI" in robotics justifies the creation of yet new robotic frameworks *reinventing the wheel* unnecessarily. This happens every now and then. Most of these tools fail to grasp the technical aspects of robots and fail to provide means for complying with critical aspects in robotics.

### Diving into PyRobot's architecture

According to its official paper [2], PyRobot is an open-source robotics framework for research and benchmarking. More specifically, PyRobot is defined as a *light-weight, high-level interface* **on top of ROS** *that provides a consistent set of hardware independent midlevel APIs to control different robots*.

(*this sounds surprisingly close to ROS 1 original goals in a way, years after though*)

![](pyrobot.png)

According to its authors, the main problems that this framework solves are:

>**ROS requires expertise**: Dominant robotic software packages like ROS and MoveIt! are complex and require
a substantial breadth of knowledge to understand the full stack of planners, kinematics libraries and low-level controllers. On the other hand, most new users do not have the necessary expertise or time to acquire a thorough understanding of the software stack. A light weight, high-level interface would ease the learning curve for AI practitioners, students and hobbyists interested in getting started in robotics.

This has historically been one of the main criticisims about ROS. ROS indeed has a learning curve however, there're good reasons behind the complexity and layered architecture of the framework. Building a robotic application is a complicated task and reusing software requires a modular architecture. ROS was originally designed with an academic purpose and later on extended for its deployment in the PR2.

Over the last few years ROS has transitioned from a research-oriented tool to an industrial-grade set of tools that power nowdays most complicated robotic behaviors. The result of this growth is clear when looking at ROS 2 which has been thought for industry-related use cases and with active discussions around security, safety or real-time.

>**Lack of hardware-independent APIs**: Writing hardware-independant software is extremely challenging. In the ROS ecosystem, this was partly handled by encapsulating hardware-specific details in the Universal Robot Description Format (URDF) which other downstream services

I'd argue against this. In fact, ROS is well known for its hardware abstraction layer that allows dozens of sensors and/or actuators to interoperate. Motion planning, manipulation and navigation stacks in the ROS world (namely the nav stack or moveit) have been built in a hardware agnostic manner and provide means of extension.

The most striking fact about PyRobot is that it seems to ommit that ROS provides upper layers of abstraction (what would match as High-Level in the ROS section of the graph above) that capture complete robots. ROS-I official repos[4] group a number of such.

----

While the aim of PyRobot seems to be clearly centered around *"accelerating AI robotics research"*, a somewhat simple way to compare PyRobot to existing de facto standards frameworks in robotics (such as ROS abstractions for a variety of robots) is to analyze the quality of the code generated. Quality Assurance (QA) methods are common in robotics and there're several open source  and community projects pushing towards the enhancement of open tools in the ROS community. 

There's a variety of ways to review the quality of code. One simple manner is to perform a static analysis of the overall framework code and assess potential security flaws. The next section looks into this.

## Performing a static analysis in the code

Let's quickly 

### Results of `bandit`

```bash
bandit -r .
[main]	INFO	profile include tests: None
[main]	INFO	profile exclude tests: None
[main]	INFO	cli include tests: None
[main]	INFO	cli exclude tests: None
[main]	INFO	running on Python 3.7.3
116 [0.. 50.. 100.. ]
Run started:2019-06-24 21:09:09.231683

Test results:
>> Issue: [B403:blacklist] Consider possible security implications associated with pickle module.
   Severity: Low   Confidence: High
   Location: ./examples/crash_detection/crash_utils/train.py:10
   More Info: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b403-import-pickle
9	import os
10	import pickle
11	import time

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: ./examples/crash_detection/locobot_kobuki.py:57
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
56	        print('CRASH MODEL NOT FOUND! DOWNLOADING IT!')
57	        os.system('wget {} -O {}'.format(url, model_path))
58

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: ./examples/grasping/grasp_samplers/grasp_model.py:46
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
45	        print('GRASP MODEL NOT FOUND! DOWNLOADING IT!')
46	        os.system('wget {} -O {}'.format(url, model_path))
47

...
--------------------------------------------------

Code scanned:
	Total lines of code: 10588
	Total lines skipped (#nosec): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0.0
		Low: 105.0
		Medium: 6.0
		High: 2.0
	Total issues (by confidence):
		Undefined: 0.0
		Low: 0.0
		Medium: 0.0
		High: 113.0
Files skipped (1):
	./examples/sim2real/test.py (syntax error while parsing AST from file)
```

8 relevant security issues with either Medium or High severity. This differs strongly from ROS python layers with approximately the same LOC. E.g. rclpy in ROS 2:

```bash
bandit -r ros2/rclpy/
[main]	INFO	profile include tests: None
[main]	INFO	profile exclude tests: None
[main]	INFO	cli include tests: None
[main]	INFO	cli exclude tests: None
[main]	INFO	running on Python 3.7.3
...
Code scanned:
	Total lines of code: 10516
	Total lines skipped (#nosec): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0.0
		Low: 256.0
		Medium: 0.0
		High: 0.0
	Total issues (by confidence):
		Undefined: 0.0
		Low: 0.0
		Medium: 0.0
		High: 256.0
Files skipped (0):
```

*Complete dump at https://gist.github.com/vmayoral/de2a2792e043b4c40b0380daff8a9760*

The two test results above display two potential points of code injection in the code.

### Results of `rats`

```bash
...
./examples/grasping/grasp_samplers/grasp_model.py:46: High: system
./examples/crash_detection/locobot_kobuki.py:57: High: system
Argument 1 to this function call should be checked to ensure that it does not
come from an untrusted source without first verifying that it contains nothing
dangerous.

./robots/LoCoBot/locobot_navigation/orb_slam2_ros/src/gen_cfg_file.cc:86: High: system
Argument 1 to this function call should be checked to ensure that it does not
come from an untrusted source without first verifying that it contains nothing
dangerous.

./examples/locobot/manipulation/pushing.py:24: Medium: signal
./examples/locobot/manipulation/realtime_point_cloud.py:21: Medium: signal
./examples/locobot/navigation/vis_3d_map.py:21: Medium: signal
./examples/sawyer/joint_torque_control.py:23: Medium: signal
./examples/sawyer/joint_velocity_control.py:23: Medium: signal
./examples/grasping/locobot.py:314: Medium: signal
./robots/LoCoBot/locobot_calibration/scripts/collect_calibration_data.py:58: Medium: signal
./robots/LoCoBot/locobot_control/nodes/robot_teleop_server.py:17: Medium: signal
When setting signal handlers, do not use the same function to handle multiple signals. There exists the possibility a race condition will result if 2 or more different signals are sent to the process at nearly the same time. Also, when writing signal handlers, it is best to do as little as possible in them. The best strategy is to use the signal handler to set a flag, that another part of the program tests and performs the appropriate action(s) when it is set.
See also: http://razor.bindview.com/publish/papers/signals.txt

./examples/locobot/manipulation/pushing.py:87: Medium: choice
./examples/locobot/manipulation/pushing.py:93: Medium: choice
./examples/locobot/manipulation/pushing.py:96: Medium: choice
./examples/locobot/manipulation/pushing.py:99: Medium: choice
./examples/grasping/grasp_samplers/grasp_model.py:227: Medium: choice
./src/pyrobot/locobot/bicycle_model.py:45: Medium: choice
Standard random number generators should not be used to
generate randomness used for security reasons.  For security sensitive randomness a crytographic randomness generator that provides sufficient entropy should be used.

```

*Complete report at https://gist.github.com/vmayoral/0e7fe9b1eabeaf7d184db3a33864efd9*

### Results of `safety`

```bash
safety check -r requirements.txt
Warning: unpinned requirement 'numpy' found in requirements.txt, unable to check.
Warning: unpinned requirement 'PyYAML' found in requirements.txt, unable to check.
Warning: unpinned requirement 'scipy' found in requirements.txt, unable to check.
Warning: unpinned requirement 'matplotlib' found in requirements.txt, unable to check.
Warning: unpinned requirement 'Pillow' found in requirements.txt, unable to check.
Warning: unpinned requirement 'pyassimp' found in requirements.txt, unable to check.
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                              │
│                               /$$$$$$            /$$                         │
│                              /$$__  $$          | $$                         │
│           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           │
│          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           │
│         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           │
│          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           │
│          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           │
│         |_______/  \_______/|__/     \_______/   \___/   \____  $$           │
│                                                          /$$  | $$           │
│                                                         |  $$$$$$/           │
│  by pyup.io                                              \______/            │
│                                                                              │
╞══════════════════════════════════════════════════════════════════════════════╡
│ REPORT                                                                       │
│ checked 10 packages, using default DB                                        │
╞══════════════════════════════════════════════════════════════════════════════╡
│ No known security vulnerabilities found.                                     │
╘══════════════════════════════════════════════════════════════════════════════╛
```

## Resources
- [1] https://github.com/facebookresearch/pyrobot
- [2] https://arxiv.org/pdf/1906.08236.pdf
- [3] https://ai.facebook.com/blog/open-sourcing-pyrobot-to-accelerate-ai-robotics-research/
- [4] https://github.com/ros-industrial