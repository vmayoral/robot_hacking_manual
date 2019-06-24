# Static analysis of PyRobot

## Discussing PyRobot
TODO

## Performing a static analysis in the code

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
```

*Complete dump at https://gist.github.com/vmayoral/de2a2792e043b4c40b0380daff8a9760*

The two test results above display two potential points of code injection in the code.

### Results of `rats`

```bash
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
