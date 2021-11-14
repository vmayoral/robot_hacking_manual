\newpage

## Tutorial 6: Looking for vulnerabilities in ROS 2
This tutorial aims to assess the flaws found in the navigation2 package and determine whether they can 
turn into vulnerabilities.

<!-- TOC depthFrom:1 depthTo:6 withLinks:1 updateOnSave:1 orderedList:0 -->

	- [Tutorial 6: Looking for vulnerabilities in ROS 2](#tutorial-6-looking-for-vulnerabilities-in-ros-2)
		- [Reconnaissance](#reconnaissance)
		- [Testing](#testing)
		- [Exploitation](#exploitation)
		- [Mitigation or remediation](#mitigation-or-remediation)
			- [nav2_util, https://github.com/aliasrobotics/RVD/issues/167](#nav2util-httpsgithubcomaliasroboticsrvdissues167)
				- [Exploring CLion IDE](#exploring-clion-ide)
				- [Case 1](#case-1)
				- [Case 2](#case-2)
				- [Case 3](#case-3)
				- [Remediation](#remediation)
			- [rclcpp: SEGV on unknown address https://github.com/aliasrobotics/RVD/issues/166](#rclcpp-segv-on-unknown-address-httpsgithubcomaliasroboticsrvdissues166)
			- [Network Reconnaissance and VulnerabilityExcavation of Secure DDS Systems](#network-reconnaissance-and-vulnerabilityexcavation-of-secure-dds-systems)
			- [ROS2-SecTest https://github.com/aws-robotics/ROS2-SecTest](#ros2-sectest-httpsgithubcomaws-roboticsros2-sectest)
			- [rclcpp, UBSAN: runtime error publisher_options https://github.com/aliasrobotics/RVD/issues/445](#rclcpp-ubsan-runtime-error-publisheroptions-httpsgithubcomaliasroboticsrvdissues445)
			- [Security and Performance Considerations in ROS 2: A Balancing Act](#security-and-performance-considerations-in-ros-2-a-balancing-act)
			- [Exception sending message over network https://github.com/ros2/rmw_fastrtps/issues/317](#exception-sending-message-over-network-httpsgithubcomros2rmwfastrtpsissues317)
	- [Resources](#resources)

<!-- /TOC -->

### Reconnaissance
(ommitted)

### Testing 
(omitted, results available at https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22robot+component%3A+navigation2%22)

### Exploitation
TODO

### Mitigation or remediation
Let's start patching a few of the flaws found

#### nav2_util, https://github.com/aliasrobotics/RVD/issues/167

For mitigating this we'll use `robocalypse` with the following configuration (the `robocalypserc` file):

```bash
 # robocalypserc file

export ADE_IMAGES="
  registry.gitlab.com/aliasrobotics/offensive-team/robocalypsepr/ros2_navigation2/navigation2:build-asan
"
```

This configuration of `robocalypse` uses only the `navigation2:build-asan` module. This module does not provide a volume with the contents mounted. We use the "build" (intermediary) image as the base image **to get access to a pre-compiled dev. environment**.

It's relevant to note that the stacktrace does not provide much:

```bash
 #0 0x7f9da732df40 in realloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdef40)
    #1 0x7f9da319db1d in rcl_lifecycle_register_transition /home/jenkins-agent/workspace/packaging_linux/ws/src/ros2/rcl/rcl_lifecycle/src/transition_map.c:131
```

*NOTE the similarity with https://github.com/aliasrobotics/RVD/issues/170*

What's worth noting here is that the issue seems to be in `rcl_lifecycle` however we don't get a clear picture because this issue was reported from a test that used an installation from deb files (which justifies the link to /home/jenkins ...).

Let's try and reproduce this leak:

Firt, let's start `robocalypse`:

```bash
$ robocalypse start
...
$ robocalypse enter
victor@robocalypse:~$
```

Let's now debug the particular flaw:
```bash
victor@robocalypse:/opt/ros2_navigation2/build-asan/nav2_util/test$ source /opt/ros2_ws/install-asan/setup.bash
victor@robocalypse:/opt/ros2_navigation2/build-asan/nav2_util/test$ ./test_lifecycle_utils
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 1 test from 1 test case.
[----------] Global test environment set-up.
[----------] 1 test from Lifecycle
[ RUN      ] Lifecycle.interface
[       OK ] Lifecycle.interface (667 ms)
[----------] 1 test from Lifecycle (667 ms total)

[----------] Global test environment tear-down
[==========] 1 test from 1 test case ran. (668 ms total)
[  PASSED  ] 1 test.

=================================================================
==92==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 96 byte(s) in 1 object(s) allocated from:
    #0 0x7fd0d003ef40 in realloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdef40)
    #1 0x7fd0cf1074ad in __default_reallocate /opt/ros2_ws/src/ros2/rcutils/src/allocator.c:49
    #2 0x7fd0cd8a0c52 in rcl_lifecycle_register_transition /opt/ros2_ws/src/ros2/rcl/rcl_lifecycle/src/transition_map.c:131
    #3 0x7fd0cd89c3fd in _register_transitions /opt/ros2_ws/src/ros2/rcl/rcl_lifecycle/src/default_state_machine.c:497
    #4 0x7fd0cd89c985 in rcl_lifecycle_init_default_state_machine /opt/ros2_ws/src/ros2/rcl/rcl_lifecycle/src/default_state_machine.c:680
    #5 0x7fd0cd89d70f in rcl_lifecycle_state_machine_init /opt/ros2_ws/src/ros2/rcl/rcl_lifecycle/src/rcl_lifecycle.c:210
    #6 0x7fd0cfcf9e3a in rclcpp_lifecycle::LifecycleNode::LifecycleNodeInterfaceImpl::init() /opt/ros2_ws/src/ros2/rclcpp/rclcpp_lifecycle/src/lifecycle_node_interface_impl.hpp:100
    #7 0x7fd0cfcf2f20 in rclcpp_lifecycle::LifecycleNode::LifecycleNode(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, rclcpp::NodeOptions const&) /opt/ros2_ws/src/ros2/rclcpp/rclcpp_lifecycle/src/lifecycle_node.cpp:105
    #8 0x7fd0cfcf1cf2 in rclcpp_lifecycle::LifecycleNode::LifecycleNode(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, rclcpp::NodeOptions const&) /opt/ros2_ws/src/ros2/rclcpp/rclcpp_lifecycle/src/lifecycle_node.cpp:53
    #9 0x55a04d116e63 in void __gnu_cxx::new_allocator<rclcpp_lifecycle::LifecycleNode>::construct<rclcpp_lifecycle::LifecycleNode, char const (&) [4]>(rclcpp_lifecycle::LifecycleNode*, char const (&) [4]) (/opt/ros2_navigation2/build-asan/nav2_util/test/test_lifecycle_utils+0x2be63)
    #10 0x55a04d116815 in void std::allocator_traits<std::allocator<rclcpp_lifecycle::LifecycleNode> >::construct<rclcpp_lifecycle::LifecycleNode, char const (&) [4]>(std::allocator<rclcpp_lifecycle::LifecycleNode>&, rclcpp_lifecycle::LifecycleNode*, char const (&) [4]) (/opt/ros2_navigation2/build-asan/nav2_util/test/test_lifecycle_utils+0x2b815)
    #11 0x55a04d1163ae in std::_Sp_counted_ptr_inplace<rclcpp_lifecycle::LifecycleNode, std::allocator<rclcpp_lifecycle::LifecycleNode>, (__gnu_cxx::_Lock_policy)2>::_Sp_counted_ptr_inplace<char const (&) [4]>(std::allocator<rclcpp_lifecycle::LifecycleNode>, char const (&) [4]) (/opt/ros2_navigation2/build-asan/nav2_util/test/test_lifecycle_utils+0x2b3ae)
    #12 0x55a04d115923 in std::__shared_count<(__gnu_cxx::_Lock_policy)2>::__shared_count<rclcpp_lifecycle::LifecycleNode, std::allocator<rclcpp_lifecycle::LifecycleNode>, char const (&) [4]>(std::_Sp_make_shared_tag, rclcpp_lifecycle::LifecycleNode*, std::allocator<rclcpp_lifecycle::LifecycleNode> const&, char const (&) [4]) (/opt/ros2_navigation2/build-asan/nav2_util/test/test_lifecycle_utils+0x2a923)
    #13 0x55a04d114dbc in std::__shared_ptr<rclcpp_lifecycle::LifecycleNode, (__gnu_cxx::_Lock_policy)2>::__shared_ptr<std::allocator<rclcpp_lifecycle::LifecycleNode>, char const (&) [4]>(std::_Sp_make_shared_tag, std::allocator<rclcpp_lifecycle::LifecycleNode> const&, char const (&) [4]) (/opt/ros2_navigation2/build-asan/nav2_util/test/test_lifecycle_utils+0x29dbc)
    #14 0x55a04d1143a6 in std::shared_ptr<rclcpp_lifecycle::LifecycleNode>::shared_ptr<std::allocator<rclcpp_lifecycle::LifecycleNode>, char const (&) [4]>(std::_Sp_make_shared_tag, std::allocator<rclcpp_lifecycle::LifecycleNode> const&, char const (&) [4]) (/opt/ros2_navigation2/build-asan/nav2_util/test/test_lifecycle_utils+0x293a6)
    #15 0x55a04d113569 in std::shared_ptr<rclcpp_lifecycle::LifecycleNode> std::allocate_shared<rclcpp_lifecycle::LifecycleNode, std::allocator<rclcpp_lifecycle::LifecycleNode>, char const (&) [4]>(std::allocator<rclcpp_lifecycle::LifecycleNode> const&, char const (&) [4]) (/opt/ros2_navigation2/build-asan/nav2_util/test/test_lifecycle_utils+0x28569)
    #16 0x55a04d1122a6 in std::shared_ptr<rclcpp_lifecycle::LifecycleNode> std::make_shared<rclcpp_lifecycle::LifecycleNode, char const (&) [4]>(char const (&) [4]) (/opt/ros2_navigation2/build-asan/nav2_util/test/test_lifecycle_utils+0x272a6)
    #17 0x55a04d11116f in std::shared_ptr<rclcpp_lifecycle::LifecycleNode> rclcpp_lifecycle::LifecycleNode::make_shared<char const (&) [4]>(char const (&) [4]) (/opt/ros2_navigation2/build-asan/nav2_util/test/test_lifecycle_utils+0x2616f)
    #18 0x55a04d10ea7d in Lifecycle_interface_Test::TestBody() /opt/ros2_navigation2/src/navigation2/nav2_util/test/test_lifecycle_utils.cpp:51
    #19 0x55a04d18d3e9 in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #20 0x55a04d17f254 in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #21 0x55a04d12aabb in testing::Test::Run() /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2522
    #22 0x55a04d12bef0 in testing::TestInfo::Run() /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2703
    #23 0x55a04d12cab5 in testing::TestCase::Run() /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2825
    #24 0x55a04d147d84 in testing::internal::UnitTestImpl::RunAllTests() /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:5216
    #25 0x55a04d18fec5 in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #26 0x55a04d181533 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #27 0x55a04d144ad3 in testing::UnitTest::Run() /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:4824
    #28 0x55a04d117d68 in RUN_ALL_TESTS() /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/include/gtest/gtest.h:2370
    #29 0x55a04d117cae in main /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:36

```


##### Exploring CLion IDE

Before grabbing gdb and digging into this, let's see if using an external IDE helps in the process (it should, generally) and increases productivity.

Tried out CLion's module for `robocalypse` using X11 (XQuartz). Works good. Followed https://www.jetbrains.com/help/clion/ros-setup-tutorial.html to set up ROS 2 ws. Used the second option and did build the symbols for most of the things in ROS 2. Navigating the code with this is much easier indeed.

Managed to get a simple `minimal_publisher` loaded (I first loaded the whole ws, the src file, and later "File->New CMake Project from Sources" and selected solely the `minimal_publisher`). 

![CLion launch of a ROS 2 publisher, fails due to ASan compilation](background/images/2019/09/clion-launch-of-a-ros-2-publisher-fails-due-to-asan-compilation.png)

What's interesting is that CLion builds using CMake a new folder `cmake-build-debug`

![ASan dependency creating issues](background/images/2019/09/asan-dependency-creating-issues.png)

The binary won't launch unless we `export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.4`. Then:

![After making ASan library available, it works from the command line](background/images/2019/09/after-making-asan-library-available-it-works-from-the-command-line.png)

Keeps failing however since thee terminal session we used to load the IDE didn't export the LD_PRELOAD env. variable. 
The only chance is to do it before launching CLion.

```bash
root@robocalypse:/opt/ros2_ws# export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.4
root@robocalypse:/opt/ros2_ws# clion.sh

=================================================================
==8119==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 8 byte(s) in 1 object(s) allocated from:
    #0 0x7ff004460b50 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb50)
    #1 0x560ebc5560dd in xmalloc (/bin/bash+0x870dd)

SUMMARY: AddressSanitizer: 8 byte(s) leaked in 1 allocation(s).

...

==8197==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 8 byte(s) in 1 object(s) allocated from:
    #0 0x7f0ffb943b50 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb50)
    #1 0x55a1b3c840dd in xmalloc (/bin/bash+0x870dd)

SUMMARY: AddressSanitizer: 8 byte(s) leaked in 1 allocation(s).

=================================================================
==8199==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 8 byte(s) in 1 object(s) allocated from:
    #0 0x7f0ffb943b50 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb50)
    #1 0x55a1b3c840dd in xmalloc (/bin/bash+0x870dd)

SUMMARY: AddressSanitizer: 8 byte(s) leaked in 1 allocation(s).
ERROR: Cannot start CLion
No JDK found. Please validate either CLION_JDK, JDK_HOME or JAVA_HOME environment variable points to valid JDK installation.

=================================================================
==8160==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 40 byte(s) in 2 object(s) allocated from:
    #0 0x7f0ffb943b50 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb50)
    #1 0x55a1b3c840dd in xmalloc (/bin/bash+0x870dd)

Indirect leak of 208 byte(s) in 7 object(s) allocated from:
    #0 0x7f0ffb943b50 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb50)
    #1 0x55a1b3c840dd in xmalloc (/bin/bash+0x870dd)

SUMMARY: AddressSanitizer: 248 byte(s) leaked in 9 allocation(s).
```

Note quite, it seems that that breaks things up and messes up the paths somehow. Let's then try a different approach:

![Configure the binary to include the env. variable](background/images/2019/09/configure-the-binary-to-include-the-env-variable.png)

This way, the binary can be launched perfectly fine and even debugged:

![Debugging ROS 2 with CLion](background/images/2019/09/debugging-ros-2-with-clion.png)

Let's now get back to our flaw in `nav2_util`. 

Managed to reproduce the issue from the Terminal of CLion:

![Reproducing the flaw https://github.com/aliasrobotics/RVD/issues/333](background/images/2019/09/reproducing-the-flaw-https-github-com-aliasrobotics-rvd-issues-333.png)

To debug it, had to configure also the env. variable as before:

![Configuring env. variables for the flaw of study](background/images/2019/09/configuring-env-variables-for-the-flaw-of-study.png)

Tremendously convenient to get hyperlinks to the code while running, this will help debugging:

![Running the flaw of study](background/images/2019/09/running-the-flaw-of-study.png)

Pretty outstanding capabilities, with GDB integrated within:

![Layout with CLion showing code, variables, GDB, navigable stack and more](background/images/2019/09/layout-with-clion-showing-code-variables-gdb-navigable-stack-and-more.png)

One down side is that I'm not able to bring the memory view https://www.jetbrains.com/help/clion/memory-view.html. **EDIT**: I actually was able to do it https://stackoverflow.com/questions/34801691/clion-memory-view. 

The only thing pending is the registers which can be visualized in the GDB window.

Enough of testing, let's get back to the code analysis.

----

Going back to the stack trade, the following seems relevant. Let's study the leak in more detail:

```Cpp
rcl_ret_t
rcl_lifecycle_register_transition(
  rcl_lifecycle_transition_map_t * transition_map,
  rcl_lifecycle_transition_t transition,
  const rcutils_allocator_t * allocator)
{
  RCUTILS_CHECK_ALLOCATOR_WITH_MSG(
    allocator, "invalid allocator", return RCL_RET_ERROR)

  rcl_lifecycle_state_t * state = rcl_lifecycle_get_state(transition_map, transition.start->id);
  if (!state) {
    RCL_SET_ERROR_MSG_WITH_FORMAT_STRING("state %u is not registered\n", transition.start->id);
    return RCL_RET_ERROR;
  }

  // we add a new transition, so increase the size
  transition_map->transitions_size += 1;
  rcl_lifecycle_transition_t * new_transitions = allocator->reallocate(
    transition_map->transitions,
    transition_map->transitions_size * sizeof(rcl_lifecycle_transition_t),
    allocator->state);
  if (!new_transitions) {
    RCL_SET_ERROR_MSG("failed to reallocate memory for new transitions");
    return RCL_RET_BAD_ALLOC;
  }
  transition_map->transitions = new_transitions;
  // finally set the new transition to the end of the array
  transition_map->transitions[transition_map->transitions_size - 1] = transition;

  // we have to copy the transitons here once more to the actual state
  // as we can't assign only the pointer. This pointer gets invalidated whenever
  // we add a new transition and re-shuffle/re-allocate new memory for it.
  state->valid_transition_size += 1;
  
  
  //////////////////
  // Issue seems to be here
  //////////////////
  
  rcl_lifecycle_transition_t * new_valid_transitions = allocator->reallocate(
    state->valid_transitions,
    state->valid_transition_size * sizeof(rcl_lifecycle_transition_t),
    allocator->state);
  
  //////////////////
  
  if (!new_valid_transitions) {
    RCL_SET_ERROR_MSG("failed to reallocate memory for new transitions on state");
    return RCL_RET_ERROR;
  }
  state->valid_transitions = new_valid_transitions;

  state->valid_transitions[state->valid_transition_size - 1] = transition;

  return RCL_RET_OK;
}
```

Further looking into the dump, it seems the issue is happening over differen parts of the code but always on the `rcl_lifecycle_register_transition` function and always at ``/opt/ros2_ws/src/ros2/rcl/rcl_lifecycle/src/transition_map.c:131` leaking 96 bytes which is equal to 3 pointers of 32 bytes.

Diving a bit more into the issue, it actually seems that it happens only in specific transitions and again, only in the second element of the transition (which probably corresponds to line 131 as pointed out above). The places where it happens are characterized by the following:

```Cpp
// register transition from configuring to errorprocessing
// register transition from cleaniningup to errorprocessing
// register transition from activating to errorprocessing
// register transition from deactivating to errorprocessing
// register transition from unconfigured to shuttingdown
// register transition from inactive to shuttingdown
// register transition from active to shuttingdown
// register transition from shutting down to errorprocessing
// register transition from errorprocessing to finalized
```

It does not happen in places such as:
```Cpp
// register transition from unconfigured to configuring
// register transition from configuring to inactive
// register transition from configuring to unconfigured
// register transition from inactive to cleaningup
// register transition from cleaningup to unconfigured
// register transition from cleaningup to inactive
// register transition from inactive to activating
...
```

and others with a somewhat non-final second state.

It seems reasonable to consider that only in those transition with an state that leads to an end there is a leak. Let further understand the code to try and figure out what's leaking.

**EDIT**: Previous assumption might not be true. States such as `// register transition from shutting down to finalized` do not leak.

Interesting to note the following two pieces of code:

```Cpp
// register transition from errorprocessing to finalized
{
  rcl_lifecycle_transition_t rcl_transition_on_error_failure = {
    rcl_lifecycle_transition_failure_label,
    lifecycle_msgs__msg__Transition__TRANSITION_ON_ERROR_FAILURE,
    errorprocessing_state, finalized_state
  };
  ret = rcl_lifecycle_register_transition(
    transition_map,
    rcl_transition_on_error_failure,
    allocator);
  if (ret != RCL_RET_OK) {
    return ret;
  }
}

// register transition from errorprocessing to finalized
{
  rcl_lifecycle_transition_t rcl_transition_on_error_error = {
    rcl_lifecycle_transition_error_label,
    lifecycle_msgs__msg__Transition__TRANSITION_ON_ERROR_ERROR,
    errorprocessing_state, finalized_state
  };
  ret = rcl_lifecycle_register_transition(
    transition_map,
    rcl_transition_on_error_error,
    allocator);
  if (ret != RCL_RET_OK) {
    return ret;
  }
}

```

The first piece does not leak while the second one **does leak**. The differences:
- First one using `rcl_lifecycle_transition_failure_label` and `lifecycle_msgs__msg__Transition__TRANSITION_ON_ERROR_FAILURE`
- (**leaky**) Second one using `rcl_lifecycle_transition_error_label` and `lifecycle_msgs__msg__Transition__TRANSITION_ON_ERROR_ERROR`


This does not lead to a lot. Let's analyze and see if there're more cases such as the one above. Found other two cases worth studying. In total, have three cases that are worth looking deeply into them:

##### Case 1

Leak in the last case

```Cpp
// register transition from errorprocessing to finalized
{
  rcl_lifecycle_transition_t rcl_transition_on_error_failure = {
    rcl_lifecycle_transition_failure_label,
    lifecycle_msgs__msg__Transition__TRANSITION_ON_ERROR_FAILURE,
    errorprocessing_state, finalized_state
  };
  ret = rcl_lifecycle_register_transition(
    transition_map,
    rcl_transition_on_error_failure,
    allocator);
  if (ret != RCL_RET_OK) {
    return ret;
  }
}

// register transition from errorprocessing to finalized
{
  rcl_lifecycle_transition_t rcl_transition_on_error_error = {
    rcl_lifecycle_transition_error_label,
    lifecycle_msgs__msg__Transition__TRANSITION_ON_ERROR_ERROR,
    errorprocessing_state, finalized_state
  };
  ret = rcl_lifecycle_register_transition(
    transition_map,
    rcl_transition_on_error_error,
    allocator);
  if (ret != RCL_RET_OK) {
    return ret;
  }
}
```

##### Case 2

Leak in the last case

```Cpp
// register transition from cleaningup to inactive
  {
    rcl_lifecycle_transition_t rcl_transition_on_cleanup_failure = {
      rcl_lifecycle_transition_failure_label,
      lifecycle_msgs__msg__Transition__TRANSITION_ON_CLEANUP_FAILURE,
      cleaningup_state, inactive_state
    };
    ret = rcl_lifecycle_register_transition(
      transition_map,
      rcl_transition_on_cleanup_failure,
      allocator);
    if (ret != RCL_RET_OK) {
      return ret;
    }
  }

  // register transition from cleaniningup to errorprocessing
  {
    rcl_lifecycle_transition_t rcl_transition_on_cleanup_error = {
      rcl_lifecycle_transition_error_label,
      lifecycle_msgs__msg__Transition__TRANSITION_ON_CLEANUP_ERROR,
      cleaningup_state, errorprocessing_state
    };
    ret = rcl_lifecycle_register_transition(
      transition_map,
      rcl_transition_on_cleanup_error,
      allocator);
    if (ret != RCL_RET_OK) {
      return ret;
    }
  }
```


##### Case 3

Leak in the last case

```Cpp
// register transition from activating to active
{
  rcl_lifecycle_transition_t rcl_transition_on_activate_success = {
    rcl_lifecycle_transition_success_label,
    lifecycle_msgs__msg__Transition__TRANSITION_ON_ACTIVATE_SUCCESS,
    activating_state, active_state
  };
  ret = rcl_lifecycle_register_transition(
    transition_map,
    rcl_transition_on_activate_success,
    allocator);
  if (ret != RCL_RET_OK) {
    return ret;
  }
}

// register transition from activating to inactive
{
  rcl_lifecycle_transition_t rcl_transition_on_activate_failure = {
    rcl_lifecycle_transition_failure_label,
    lifecycle_msgs__msg__Transition__TRANSITION_ON_ACTIVATE_FAILURE,
    activating_state, inactive_state
  };
  ret = rcl_lifecycle_register_transition(
    transition_map,
    rcl_transition_on_activate_failure,
    allocator);
  if (ret != RCL_RET_OK) {
    return ret;
  }
}

// register transition from activating to errorprocessing
{
  rcl_lifecycle_transition_t rcl_transition_on_activate_error = {
    rcl_lifecycle_transition_error_label,
    lifecycle_msgs__msg__Transition__TRANSITION_ON_ACTIVATE_ERROR,
    activating_state, errorprocessing_state
  };
  ret = rcl_lifecycle_register_transition(
    transition_map,
    rcl_transition_on_activate_error,
    allocator);
  if (ret != RCL_RET_OK) {
    return ret;
  }
}
```


(Note: dumping a .gdbinit in the home dir makes CLion fetch it but it seems to have some problems with `wget -P ~ git.io/.gdbinit` so skipping it for now and doing it manually)


![Debugging session, state->valid_transitions has a previous value when leaks](background/images/2019/09/debugging-session-state-valid-transitions-has-a-previous-value-when-leaks.png)

After debugging for a while, it appears that whenever there's a leak in 131 is because `state->valid_transitions` has a value before. Note that `state->valid_transition_size` is 3 (which matches the 32*3 = 96 bytes leaked) in those cases. 

*I checked similar calls and also presents situation where it has a value thereby I'm discarding the leak due to the realloc call.*

Similarly, I validated that there're also leaks when `state->valid_transition_size` is 2 which leads to a 64 byte leak.

Let's dive into the memory and try to figure out when `new_valid_transitions` (asigned later to `state->valid_transition`) is released and when isn't. Let's start in the case of no leak:

`transition_map` presents a memory layout as follows:

![memory layout of transition_map, non-leaky call](background/images/2019/09/memory-layout-of-transition-map-non-leaky-call.png)

Note that `transition_map` has an element states `transition_map->states` and this one starts at `0x613000001700`. Since there're 11 states in the map (see `transitions_size` variable), the transition_map states go from `0x613000001700` til 

```bash
(gdb) p/x 0x613000001700 + 11*64
$6 = 0x6130000019c0
```

For the purpose of this analysis, what's relevant here is the address of `state` which is `0x613000001840` and its content highlighted in green below:

![content in memory of the state variable](background/images/2019/09/content-in-memory-of-the-state-variable.png)

Now, in line 115, a call to `allocator->reallocate` happens which is going to increase the memory of `transition_map->transitions` in 32 bytes (sizeof(rcl_lifecycle_transition_t)). Before the reallocation, memory looks as follows:

```bash
(gdb) p transition_map->transitions
$15 = (rcl_lifecycle_transition_t *) 0x617000004680
(gdb) p transition_map->transitions_size
$16 = 24
(gdb) p sizeof(rcl_lifecycle_transition_t)
$17 = 32
(gdb) p sizeof(rcl_lifecycle_transition_t)*23 # 23, 24 - 1 because it has already iterated
$18 = 736
(gdb) x/736b 0x617000004680
0x617000004680:	0x40	0x16	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004688:	0x01	0x00	0x00	0x00	0xe0	0x60	0x00	0x00
0x617000004690:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004698:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000046a0:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000046a8:	0x0a	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x6170000046b0:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000046b8:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000046c0:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000046c8:	0x0b	0x00	0x00	0x00	0xff	0x0f	0x00	0x00
0x6170000046d0:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000046d8:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000046e0:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000046e8:	0x0c	0x00	0x00	0x00	0xe4	0x7f	0x00	0x00
0x6170000046f0:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000046f8:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004700:	0x80	0x16	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004708:	0x02	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004710:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004718:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004720:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004728:	0x14	0x00	0x00	0x00	0xe4	0x7f	0x00	0x00
0x617000004730:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004738:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004740:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004748:	0x15	0x00	0x00	0x00	0xfc	0x7f	0x00	0x00
0x617000004750:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004758:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004760:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004768:	0x16	0x00	0x00	0x00	0xfd	0xfd	0xfd	0xfd
0x617000004770:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004778:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004780:	0xc0	0x16	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004788:	0x03	0x00	0x00	0x00	0x6e	0x73	0x00	0x00
0x617000004790:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004798:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000047a0:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000047a8:	0x1e	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x6170000047b0:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000047b8:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000047c0:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000047c8:	0x1f	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x6170000047d0:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000047d8:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000047e0:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000047e8:	0x20	0x00	0x00	0x00	0xe4	0x7f	0x00	0x00
0x6170000047f0:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000047f8:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004800:	0x00	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004808:	0x04	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004810:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004818:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004820:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004828:	0x28	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004830:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004838:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004840:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004848:	0x29	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004850:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004858:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004860:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004868:	0x2a	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004870:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004878:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004880:	0x40	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004888:	0x05	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004890:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004898:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048a0:	0x40	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000048a8:	0x06	0x00	0x00	0x00	0xfc	0x7f	0x00	0x00
0x6170000048b0:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048b8:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048c0:	0x40	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000048c8:	0x07	0x00	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048d0:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048d8:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048e0:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000048e8:	0x32	0x00	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048f0:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048f8:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004900:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004908:	0x33	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004910:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004918:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004920:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004928:	0x34	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004930:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004938:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004940:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004948:	0x3c	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004950:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004958:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
```

After the new allocation, should be 32 bytes more:

```bash
(gdb) x/768b 0x617000004680
0x617000004680:	0x40	0x16	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004688:	0x01	0x00	0x00	0x00	0xe0	0x60	0x00	0x00
0x617000004690:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004698:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000046a0:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000046a8:	0x0a	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x6170000046b0:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000046b8:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000046c0:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000046c8:	0x0b	0x00	0x00	0x00	0xff	0x0f	0x00	0x00
0x6170000046d0:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000046d8:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000046e0:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000046e8:	0x0c	0x00	0x00	0x00	0xe4	0x7f	0x00	0x00
0x6170000046f0:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000046f8:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004700:	0x80	0x16	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004708:	0x02	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004710:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004718:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004720:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004728:	0x14	0x00	0x00	0x00	0xe4	0x7f	0x00	0x00
0x617000004730:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004738:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004740:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004748:	0x15	0x00	0x00	0x00	0xfc	0x7f	0x00	0x00
0x617000004750:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004758:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004760:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004768:	0x16	0x00	0x00	0x00	0xfd	0xfd	0xfd	0xfd
0x617000004770:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004778:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004780:	0xc0	0x16	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004788:	0x03	0x00	0x00	0x00	0x6e	0x73	0x00	0x00
0x617000004790:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004798:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000047a0:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000047a8:	0x1e	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x6170000047b0:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000047b8:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000047c0:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000047c8:	0x1f	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x6170000047d0:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000047d8:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000047e0:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000047e8:	0x20	0x00	0x00	0x00	0xe4	0x7f	0x00	0x00
0x6170000047f0:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000047f8:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004800:	0x00	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004808:	0x04	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004810:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004818:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004820:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004828:	0x28	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004830:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004838:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004840:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004848:	0x29	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004850:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004858:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004860:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004868:	0x2a	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004870:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004878:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004880:	0x40	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004888:	0x05	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004890:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004898:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048a0:	0x40	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000048a8:	0x06	0x00	0x00	0x00	0xfc	0x7f	0x00	0x00
0x6170000048b0:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048b8:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048c0:	0x40	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000048c8:	0x07	0x00	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048d0:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048d8:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048e0:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x6170000048e8:	0x32	0x00	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048f0:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x6170000048f8:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004900:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004908:	0x33	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004910:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004918:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004920:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004928:	0x34	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004930:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004938:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004940:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004948:	0x3c	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004950:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004958:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004960:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004968:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004970:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004978:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
```

Note how the last 32 bytes are empty:

```bash
0x617000004960:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004968:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004970:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004978:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
```

Stepping over, `new_transitions` receives the pointer `0x617000004a00` and theorethically, should have 768 bytes, as `transition_map->transitions`:

```bash
(gdb) x/768b 0x617000004a00
0x617000004a00:	0x40	0x16	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004a08:	0x01	0x00	0x00	0x00	0xe0	0x60	0x00	0x00
0x617000004a10:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a18:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a20:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004a28:	0x0a	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004a30:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a38:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a40:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004a48:	0x0b	0x00	0x00	0x00	0xff	0x0f	0x00	0x00
0x617000004a50:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a58:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a60:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004a68:	0x0c	0x00	0x00	0x00	0xe4	0x7f	0x00	0x00
0x617000004a70:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a78:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a80:	0x80	0x16	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004a88:	0x02	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004a90:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a98:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004aa0:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004aa8:	0x14	0x00	0x00	0x00	0xe4	0x7f	0x00	0x00
0x617000004ab0:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ab8:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ac0:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004ac8:	0x15	0x00	0x00	0x00	0xfc	0x7f	0x00	0x00
0x617000004ad0:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ad8:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ae0:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004ae8:	0x16	0x00	0x00	0x00	0xfd	0xfd	0xfd	0xfd
0x617000004af0:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004af8:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b00:	0xc0	0x16	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004b08:	0x03	0x00	0x00	0x00	0x6e	0x73	0x00	0x00
0x617000004b10:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b18:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b20:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004b28:	0x1e	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004b30:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b38:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b40:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004b48:	0x1f	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004b50:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b58:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b60:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004b68:	0x20	0x00	0x00	0x00	0xe4	0x7f	0x00	0x00
0x617000004b70:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b78:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b80:	0x00	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004b88:	0x04	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004b90:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b98:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ba0:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004ba8:	0x28	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004bb0:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004bb8:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004bc0:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004bc8:	0x29	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004bd0:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004bd8:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004be0:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004be8:	0x2a	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004bf0:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004bf8:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c00:	0x40	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004c08:	0x05	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004c10:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c18:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c20:	0x40	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004c28:	0x06	0x00	0x00	0x00	0xfc	0x7f	0x00	0x00
0x617000004c30:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c38:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c40:	0x40	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004c48:	0x07	0x00	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c50:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c58:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c60:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004c68:	0x32	0x00	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c70:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c78:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c80:	0xc0	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004c88:	0x33	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004c90:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c98:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ca0:	0x00	0x18	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004ca8:	0x34	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004cb0:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004cb8:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004cc0:	0x80	0x17	0x09	0x2b	0xe4	0x7f	0x00	0x00
0x617000004cc8:	0x3c	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004cd0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004cd8:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ce0:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
0x617000004ce8:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
0x617000004cf0:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
0x617000004cf8:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
```

The new portion of memory has been marked with `0xbe`s. `transition_map->transitions` has been updated and then:

```bash
(gdb) p &transition
$2 = (rcl_lifecycle_transition_t *) 0x7fffeab22d90
(gdb) x/32b 0x7fffeab22d90
0x7fffeab22d90:	0xc0	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x7fffeab22d98:	0x3d	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x7fffeab22da0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x7fffeab22da8:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
(gdb) x/768b 0x617000004a00

0x617000004a00:	0x40	0x96	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004a08:	0x01	0x00	0x00	0x00	0xe0	0x60	0x00	0x00
0x617000004a10:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a18:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a20:	0x80	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004a28:	0x0a	0x00	0x00	0x00	0x01	0x00	0x00	0x00
0x617000004a30:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a38:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a40:	0xc0	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004a48:	0x0b	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004a50:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a58:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a60:	0x00	0x98	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004a68:	0x0c	0x00	0x00	0x00	0xb9	0x7f	0x00	0x00
0x617000004a70:	0xa0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a78:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a80:	0x80	0x96	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004a88:	0x02	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004a90:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004a98:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004aa0:	0x80	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004aa8:	0x14	0x00	0x00	0x00	0xff	0x7f	0x00	0x00
0x617000004ab0:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ab8:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ac0:	0xc0	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004ac8:	0x15	0x00	0x00	0x00	0x01	0x00	0x00	0x00
0x617000004ad0:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ad8:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ae0:	0x00	0x98	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004ae8:	0x16	0x00	0x00	0x00	0xb9	0x7f	0x00	0x00
0x617000004af0:	0xc0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004af8:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b00:	0xc0	0x96	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004b08:	0x03	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004b10:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b18:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b20:	0x80	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004b28:	0x1e	0x00	0x00	0x00	0x65	0x5f	0x6d	0x73
0x617000004b30:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b38:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b40:	0xc0	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004b48:	0x1f	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004b50:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b58:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b60:	0x00	0x98	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004b68:	0x20	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004b70:	0x00	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b78:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b80:	0x00	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004b88:	0x04	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004b90:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004b98:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ba0:	0x80	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004ba8:	0x28	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004bb0:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004bb8:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004bc0:	0xc0	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004bc8:	0x29	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004bd0:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004bd8:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004be0:	0x00	0x98	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004be8:	0x2a	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004bf0:	0x20	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004bf8:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c00:	0x40	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004c08:	0x05	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004c10:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c18:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c20:	0x40	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004c28:	0x06	0x00	0x00	0x00	0xff	0x7f	0x00	0x00
0x617000004c30:	0x40	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c38:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c40:	0x40	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004c48:	0x07	0x00	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c50:	0x60	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c58:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c60:	0x80	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004c68:	0x32	0x00	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c70:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c78:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c80:	0xc0	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004c88:	0x33	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004c90:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004c98:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ca0:	0x00	0x98	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004ca8:	0x34	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004cb0:	0xe0	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004cb8:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004cc0:	0x80	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004cc8:	0x3c	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004cd0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004cd8:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004ce0:	0xc0	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x617000004ce8:	0x3d	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x617000004cf0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x617000004cf8:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00

```

Transition is at the bottom, as expected.


Let's now inspect the memory of the leaky function:

```bash
(gdb) p state->valid_transition_size
$4 = 2
[Switching to thread 7 (Thread 0x7fb920bca700 (LWP 7487))](running)
[Switching to thread 7 (Thread 0x7fb920bca700 (LWP 7487))](running)
[Switching to thread 7 (Thread 0x7fb920bca700 (LWP 7487))](running)
[Switching to thread 7 (Thread 0x7fb920bca700 (LWP 7487))](running)
[Switching to thread 7 (Thread 0x7fb920bca700 (LWP 7487))](running)
(gdb) 32*2
Undefined command: "32".  Try "help".
(gdb) p 32*2
$5 = 64
(gdb) x/64x 0x60300005fda0 # state-> valid_transitions
0x60300005fda0:	0x18	0x00	0x80	0x67	0xb9	0x7f	0x00	0x00
0x60300005fda8:	0x3c	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x60300005fdb0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x60300005fdb8:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x60300005fdc0:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x60300005fdc8:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x60300005fdd0:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x60300005fdd8:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00

```
the newly generated memory portion (initialized to `0xbe`)

```bash
(gdb) x/64x 0x606000046e20 # new_valid_transitions
0x606000046e20:	0x80	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x606000046e28:	0x3c	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x606000046e30:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x606000046e38:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x606000046e40:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
0x606000046e48:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
0x606000046e50:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
0x606000046e58:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe

```

After the asignation:

```bash
(gdb) x/64x 0x606000046e20 # state->valid_transitions
0x606000046e20:	0x80	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x606000046e28:	0x3c	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x606000046e30:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x606000046e38:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x606000046e40:	0xc0	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x606000046e48:	0x3d	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x606000046e50:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x606000046e58:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
(gdb) p &transition 
$6 = (rcl_lifecycle_transition_t *) 0x7fffeab22d90
(gdb) x/32x 0x7fffeab22d90 # transition
0x7fffeab22d90:	0xc0	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x7fffeab22d98:	0x3d	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x7fffeab22da0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x7fffeab22da8:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
```

Now for the leaky one:

Before the re-allocation:

```bash
(gdb) x/96x 0x606000046e20 # state->valid_transition
0x606000046e20:	0x80	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x606000046e28:	0x3c	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x606000046e30:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x606000046e38:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x606000046e40:	0xc0	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x606000046e48:	0x3d	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x606000046e50:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x606000046e58:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x606000046e60:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x606000046e68:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x606000046e70:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x606000046e78:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
```

After having allocated:

```bash
gdb) x/96x 0x60800002f7a0 # new_valid_transitions
0x60800002f7a0:	0x80	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x60800002f7a8:	0x3c	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x60800002f7b0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x60800002f7b8:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x60800002f7c0:	0xc0	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x60800002f7c8:	0x3d	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x60800002f7d0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x60800002f7d8:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x60800002f7e0:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
0x60800002f7e8:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
0x60800002f7f0:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
0x60800002f7f8:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
```

once overwritted:

```bash
(gdb) x/96x 0x60800002f7a0
0x60800002f7a0:	0x80	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x60800002f7a8:	0x3c	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x60800002f7b0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x60800002f7b8:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x60800002f7c0:	0xc0	0x97	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x60800002f7c8:	0x3d	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x60800002f7d0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x60800002f7d8:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x60800002f7e0:	0x00	0x98	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x60800002f7e8:	0x3e	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x60800002f7f0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x60800002f7f8:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
(gdb) p &transition
$7 = (rcl_lifecycle_transition_t *) 0x7fffeab22d90
(gdb) x/32x 0x7fffeab22d90
0x7fffeab22d90:	0x00	0x98	0xec	0x2c	0xb9	0x7f	0x00	0x00
0x7fffeab22d98:	0x3e	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x7fffeab22da0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x7fffeab22da8:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00
```

All good so far. Let's now proceed to the place where memory is released an inspect how `state->valid_transitions` is released for both the first state (non-leaky) and the second one (leaky). 

Before doing so, let's first record the memory address of the corresponding states which will help later on debug things altogether from the `transition_map`. This is relevant because the `transition_map` has the following structure:

```bash
transition_map = {rcl_lifecycle_transition_map_t * | 0x613000001548} 0x613000001548
   states = {rcl_lifecycle_state_t * | 0x613000001700} 0x613000001700
   states_size = {unsigned int} 11
   transitions = {rcl_lifecycle_transition_t * | 0x618000004c80} 0x618000004c80
   transitions_size = {unsigned int} 25
```

Moreover, each state:
```bash
states = {rcl_lifecycle_state_t * | 0x613000001700} 0x613000001700
 label = {const char * | 0x7fb92cec98e0} "unknown"
 id = {unsigned int} 0
 valid_transitions = {rcl_lifecycle_transition_t * | 0x0} NULL
 valid_transition_size = {unsigned int} 0
 ```
 
 Let's then record things for the leaky and non-leaky cases. Here's the plan:
 
  - Reach non-leaky, place breakpoint in new_valid_transitions
  - Determine memory of `transition_map->states` and `transition_map->states->valid_transitions` and keep it handy
  - Record address of state
    - Validate that state is within transition_map
  - Record structure of state taking special care for to `valid_transitions`
  - Head to `rcl_lifecycle_transition_map_fini` and debug memory release
 
Let's execute:

```bash
transition_map = {rcl_lifecycle_transition_map_t * | 0x613000001548} 0x613000001548
   states = {rcl_lifecycle_state_t * | 0x613000001700} 0x613000001700
   states_size = {unsigned int} 11
   transitions = {rcl_lifecycle_transition_t * | 0x617000004a00} 0x617000004a00
   transitions_size = {unsigned int} 24
```

Let's figure out the size of the structures within transition_map, in particular, states:

```bash
(gdb) p sizeof(rcl_lifecycle_transition_map_t)
$1 = 32
(gdb) x/32b 0x613000001548
0x613000001548:	0x00	0x17	0x00	0x00	0x30	0x61	0x00	0x00
0x613000001550:	0x0b	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001558:	0x00	0x4a	0x00	0x00	0x70	0x61	0x00	0x00
0x613000001560:	0x18	0x00	0x00	0x00	0x00	0x00	0x00	0x00
```

This matches perfectly fine the content above, let's now read through the memory of the `transition_map->states`:

```bash
states = {rcl_lifecycle_state_t * | 0x613000001700} 0x613000001700
   label = {const char * | 0x7f102f99c8e0} "unknown"
   id = {unsigned int} 0
   valid_transitions = {rcl_lifecycle_transition_t * | 0x0} NULL
   valid_transition_size = {unsigned int} 0
   
(gdb) p sizeof(rcl_lifecycle_state_t)
$2 = 32
(gdb) p sizeof(rcl_lifecycle_state_t)*transition_map->states_size
$3 = 352
(gdb) x/352x transition_map->states
0x613000001700:	0xe0	0xc8	0x99	0x2f	0x10	0x7f	0x00	0x00
0x613000001708:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001710:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001718:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001720:	0x20	0xc9	0x99	0x2f	0x10	0x7f	0x00	0x00
0x613000001728:	0x01	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001730:	0x00	0x6d	0x04	0x00	0x60	0x60	0x00	0x00
0x613000001738:	0x02	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001740:	0x60	0xc9	0x99	0x2f	0x10	0x7f	0x00	0x00
0x613000001748:	0x02	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001750:	0xa0	0xf6	0x02	0x00	0x80	0x60	0x00	0x00
0x613000001758:	0x03	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001760:	0xa0	0xc9	0x99	0x2f	0x10	0x7f	0x00	0x00
0x613000001768:	0x03	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001770:	0x60	0x6d	0x04	0x00	0x60	0x60	0x00	0x00
0x613000001778:	0x02	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001780:	0xe0	0xc9	0x99	0x2f	0x10	0x7f	0x00	0x00
0x613000001788:	0x04	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001790:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001798:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x6130000017a0:	0x00	0xcb	0x99	0x2f	0x10	0x7f	0x00	0x00
0x6130000017a8:	0x0a	0x00	0x00	0x00	0x30	0x61	0x00	0x00
0x6130000017b0:	0xa0	0xf4	0x02	0x00	0x80	0x60	0x00	0x00
0x6130000017b8:	0x03	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x6130000017c0:	0x40	0xcb	0x99	0x2f	0x10	0x7f	0x00	0x00
0x6130000017c8:	0x0b	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x6130000017d0:	0x20	0xf5	0x02	0x00	0x80	0x60	0x00	0x00
0x6130000017d8:	0x03	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x6130000017e0:	0x80	0xcb	0x99	0x2f	0x10	0x7f	0x00	0x00
0x6130000017e8:	0x0c	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x6130000017f0:	0x20	0xf7	0x02	0x00	0x80	0x60	0x00	0x00
0x6130000017f8:	0x03	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001800:	0xc0	0xcb	0x99	0x2f	0x10	0x7f	0x00	0x00
0x613000001808:	0x0d	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001810:	0xa0	0xf5	0x02	0x00	0x80	0x60	0x00	0x00
0x613000001818:	0x03	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001820:	0x00	0xcc	0x99	0x2f	0x10	0x7f	0x00	0x00
0x613000001828:	0x0e	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001830:	0x20	0xf6	0x02	0x00	0x80	0x60	0x00	0x00
0x613000001838:	0x03	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001840:	0x40	0xcc	0x99	0x2f	0x10	0x7f	0x00	0x00
0x613000001848:	0x0f	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x613000001850:	0xa0	0xfd	0x05	0x00	0x30	0x60	0x00	0x00
0x613000001858:	0x02	0x00	0x00	0x00	0x00	0x00	0x00	0x00

```

or its shorter version:

```bash
(gdb) p sizeof(rcl_lifecycle_state_t)*transition_map->states_size/4
$4 = 88
(gdb) x/88w transition_map->states
0x613000001700:	0x2f99c8e0	0x00007f10	0x00000000	0x00000000
0x613000001710:	0x00000000	0x00000000	0x00000000	0x00000000
0x613000001720:	0x2f99c920	0x00007f10	0x00000001	0x00000000
0x613000001730:	0x00046d00	0x00006060	0x00000002	0x00000000
0x613000001740:	0x2f99c960	0x00007f10	0x00000002	0x00000000
0x613000001750:	0x0002f6a0	0x00006080	0x00000003	0x00000000
0x613000001760:	0x2f99c9a0	0x00007f10	0x00000003	0x00000000
0x613000001770:	0x00046d60	0x00006060	0x00000002	0x00000000
0x613000001780:	0x2f99c9e0	0x00007f10	0x00000004	0x00000000
0x613000001790:	0x00000000	0x00000000	0x00000000	0x00000000
0x6130000017a0:	0x2f99cb00	0x00007f10	0x0000000a	0x00006130
0x6130000017b0:	0x0002f4a0	0x00006080	0x00000003	0x00000000
0x6130000017c0:	0x2f99cb40	0x00007f10	0x0000000b	0x00000000
0x6130000017d0:	0x0002f520	0x00006080	0x00000003	0x00000000
0x6130000017e0:	0x2f99cb80	0x00007f10	0x0000000c	0x00000000
0x6130000017f0:	0x0002f720	0x00006080	0x00000003	0x00000000
0x613000001800:	0x2f99cbc0	0x00007f10	0x0000000d	0x00000000
0x613000001810:	0x0002f5a0	0x00006080	0x00000003	0x00000000
0x613000001820:	0x2f99cc00	0x00007f10	0x0000000e	0x00000000
0x613000001830:	0x0002f620	0x00006080	0x00000003	0x00000000
0x613000001840:	0x2f99cc40	0x00007f10	0x0000000f	0x00000000
0x613000001850:	0x0005fda0	0x00006030	0x00000002	0x00000000
```

Actually, the memory above can be decomposed as follows using the variables information:

```bash
transition_map = {rcl_lifecycle_transition_map_t * | 0x613000001548} 0x613000001548
 states = {rcl_lifecycle_state_t * | 0x613000001700} 0x613000001700
   label = {const char * | 0x7f102f99c8e0} "unknown"
   id = {unsigned int} 0
   valid_transitions = {rcl_lifecycle_transition_t * | 0x0} NULL
   valid_transition_size = {unsigned int} 0
 
              transition_map->states->label    transition_map->states->id
 0x613000001700:	[0x2f99c8e0	0x00007f10]	[0x00000000	0x00000000]
        transition_map->states->valid_transitions  transition_map->states->valid_transitions_size
 0x613000001710:	[0x00000000	0x00000000]	[0x00000000	0x00000000]
 ...
```

Going back to the example:

```bash
state = {rcl_lifecycle_state_t * | 0x613000001840} 0x613000001840
 label = {const char * | 0x7f102f99cc40} "errorprocessing"
 id = {unsigned int} 15
 valid_transitions = {rcl_lifecycle_transition_t * | 0x60300005fda0} 0x60300005fda0
 valid_transition_size = {unsigned int} 2
 
new_valid_transitions = {rcl_lifecycle_transition_t * | 0x606000046e20} 0x606000046e20
 label = {const char * | 0x7f102f99c780} "transition_success"
 id = {unsigned int} 60
 start = {rcl_lifecycle_state_t * | 0x613000001840} 0x613000001840
 goal = {rcl_lifecycle_state_t * | 0x613000001720} 0x613000001720
```

`new_valid_transitions` points to `0x606000046e20` whereas `state->valid_transitions` to `0x60300005fda0` (both should match after the function). Finally, state points to `0x613000001840`.

Let's start by validating that `state` is indeed within the `transition_map` states:

```bash

p sizeof(rcl_lifecycle_state_t)*transition_map->states_size/8
$15 = 44

(gdb) x/44g transition_map->states
0x613000001700:	0x00007f102f99c8e0	0x0000000000000000
0x613000001710:	0x0000000000000000	0x0000000000000000
0x613000001720:	0x00007f102f99c920	0x0000000000000001
0x613000001730:	0x0000606000046d00	0x0000000000000002
0x613000001740:	0x00007f102f99c960	0x0000000000000002
0x613000001750:	0x000060800002f6a0	0x0000000000000003
0x613000001760:	0x00007f102f99c9a0	0x0000000000000003
0x613000001770:	0x0000606000046d60	0x0000000000000002
0x613000001780:	0x00007f102f99c9e0	0x0000000000000004
0x613000001790:	0x0000000000000000	0x0000000000000000
0x6130000017a0:	0x00007f102f99cb00	0x000061300000000a
0x6130000017b0:	0x000060800002f4a0	0x0000000000000003
0x6130000017c0:	0x00007f102f99cb40	0x000000000000000b
0x6130000017d0:	0x000060800002f520	0x0000000000000003
0x6130000017e0:	0x00007f102f99cb80	0x000000000000000c
0x6130000017f0:	0x000060800002f720	0x0000000000000003
0x613000001800:	0x00007f102f99cbc0	0x000000000000000d
0x613000001810:	0x000060800002f5a0	0x0000000000000003
0x613000001820:	0x00007f102f99cc00	0x000000000000000e
0x613000001830:	0x000060800002f620	0x0000000000000003
0x613000001840:	0x00007f102f99cc40	0x000000000000000f

      transition_map->states->valid_transitions
0x613000001850:	[0x000060300005fda0]	0x0000000000000002

```

After line 139 in transition_map.c:

```bash
(gdb) x/44g transition_map->states
0x613000001700:	0x00007f102f99c8e0	0x0000000000000000
0x613000001710:	0x0000000000000000	0x0000000000000000

0x613000001720:	0x00007f102f99c920	0x0000000000000001
0x613000001730:	0x0000606000046d00	0x0000000000000002

0x613000001740:	0x00007f102f99c960	0x0000000000000002
0x613000001750:	0x000060800002f6a0	0x0000000000000003

0x613000001760:	0x00007f102f99c9a0	0x0000000000000003
0x613000001770:	0x0000606000046d60	0x0000000000000002

0x613000001780:	0x00007f102f99c9e0	0x0000000000000004
0x613000001790:	0x0000000000000000	0x0000000000000000

0x6130000017a0:	0x00007f102f99cb00	0x000061300000000a
0x6130000017b0:	0x000060800002f4a0	0x0000000000000003

0x6130000017c0:	0x00007f102f99cb40	0x000000000000000b
0x6130000017d0:	0x000060800002f520	0x0000000000000003

0x6130000017e0:	0x00007f102f99cb80	0x000000000000000c
0x6130000017f0:	0x000060800002f720	0x0000000000000003

0x613000001800:	0x00007f102f99cbc0	0x000000000000000d
0x613000001810:	0x000060800002f5a0	0x0000000000000003

0x613000001820:	0x00007f102f99cc00	0x000000000000000e
0x613000001830:	0x000060800002f620	0x0000000000000003

0x613000001840:	0x00007f102f99cc40	0x000000000000000f
          transition_map->states->valid_transitions
0x613000001850:	[0x0000606000046e20]	0x0000000000000002
```

The element is the last one apparently (**11th** element or [10]). The memory has changed to point to `new_valid_transitions` and the content now to be freed is:

```bash
(gdb) p transition_map->states[10]->valid_transition_size
$21 = 2
(gdb) p transition_map->states[10]->valid_transitions
$18 = (rcl_lifecycle_transition_t *) 0x606000046e20

(which matches with)

(gdb) p &transition_map->states[10]->valid_transitions[0]
$25 = (rcl_lifecycle_transition_t *) 0x606000046e20
(gdb) p &transition_map->states[10]->valid_transitions[1]
$26 = (rcl_lifecycle_transition_t *) 0x606000046e40
```

Let's look at the leaky case:
  - `new_valid_transitions`: `0x60800002f7a0` 
  - `state->valid_transitions`: `0x606000046e20` (both should match after the function).
  - `state`: `0x613000001840`

Before line 139 in transition_map.c:
```bash
(gdb) x/44g transition_map->states
0x613000001700:	0x00007f102f99c8e0	0x0000000000000000
0x613000001710:	0x0000000000000000	0x0000000000000000
0x613000001720:	0x00007f102f99c920	0x0000000000000001
0x613000001730:	0x0000606000046d00	0x0000000000000002
0x613000001740:	0x00007f102f99c960	0x0000000000000002
0x613000001750:	0x000060800002f6a0	0x0000000000000003
0x613000001760:	0x00007f102f99c9a0	0x0000000000000003
0x613000001770:	0x0000606000046d60	0x0000000000000002
0x613000001780:	0x00007f102f99c9e0	0x0000000000000004
0x613000001790:	0x0000000000000000	0x0000000000000000
0x6130000017a0:	0x00007f102f99cb00	0x000061300000000a
0x6130000017b0:	0x000060800002f4a0	0x0000000000000003
0x6130000017c0:	0x00007f102f99cb40	0x000000000000000b
0x6130000017d0:	0x000060800002f520	0x0000000000000003
0x6130000017e0:	0x00007f102f99cb80	0x000000000000000c
0x6130000017f0:	0x000060800002f720	0x0000000000000003
0x613000001800:	0x00007f102f99cbc0	0x000000000000000d
0x613000001810:	0x000060800002f5a0	0x0000000000000003
0x613000001820:	0x00007f102f99cc00	0x000000000000000e
0x613000001830:	0x000060800002f620	0x0000000000000003
0x613000001840:	0x00007f102f99cc40	0x000000000000000f
0x613000001850:	0x0000606000046e20	0x0000000000000003
```
After line 139 in transition_map.c:

```bash
(gdb) x/44g transition_map->states
0x613000001700:	0x00007f102f99c8e0	0x0000000000000000
0x613000001710:	0x0000000000000000	0x0000000000000000
0x613000001720:	0x00007f102f99c920	0x0000000000000001
0x613000001730:	0x0000606000046d00	0x0000000000000002
0x613000001740:	0x00007f102f99c960	0x0000000000000002
0x613000001750:	0x000060800002f6a0	0x0000000000000003
0x613000001760:	0x00007f102f99c9a0	0x0000000000000003
0x613000001770:	0x0000606000046d60	0x0000000000000002
0x613000001780:	0x00007f102f99c9e0	0x0000000000000004
0x613000001790:	0x0000000000000000	0x0000000000000000
0x6130000017a0:	0x00007f102f99cb00	0x000061300000000a
0x6130000017b0:	0x000060800002f4a0	0x0000000000000003
0x6130000017c0:	0x00007f102f99cb40	0x000000000000000b
0x6130000017d0:	0x000060800002f520	0x0000000000000003
0x6130000017e0:	0x00007f102f99cb80	0x000000000000000c
0x6130000017f0:	0x000060800002f720	0x0000000000000003
0x613000001800:	0x00007f102f99cbc0	0x000000000000000d
0x613000001810:	0x000060800002f5a0	0x0000000000000003
0x613000001820:	0x00007f102f99cc00	0x000000000000000e
0x613000001830:	0x000060800002f620	0x0000000000000003
0x613000001840:	0x00007f102f99cc40	0x000000000000000f
0x613000001850:	0x000060800002f7a0	0x0000000000000003
```

Indeed, now points to `0x60800002f7a0`. The content now to be freed is:

```bash
(gdb) p transition_map->states[10]->valid_transition_size
$27 = 3
(gdb) p &transition_map->states[10]->valid_transitions[0]
$28 = (rcl_lifecycle_transition_t *) 0x60800002f7a0
(gdb) p &transition_map->states[10]->valid_transitions[1]
$29 = (rcl_lifecycle_transition_t *) 0x60800002f7c0
(gdb) p &transition_map->states[10]->valid_transitions[2]
$30 = (rcl_lifecycle_transition_t *) 0x60800002f7e0
```

This somehow matches with:

```bash
(gdb) x/96b 0x000060800002f7a0
0x60800002f7a0:	0x80	0xc7	0x99	0x2f	0x10	0x7f	0x00	0x00
0x60800002f7a8:	0x3c	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x60800002f7b0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x60800002f7b8:	0x20	0x17	0x00	0x00	0x30	0x61	0x00	0x00

0x60800002f7c0:	0xc0	0xc7	0x99	0x2f	0x10	0x7f	0x00	0x00
0x60800002f7c8:	0x3d	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x60800002f7d0:	0x40	0x18	0x00	0x00	0x30	0x61	0x00	0x00
0x60800002f7d8:	0x80	0x17	0x00	0x00	0x30	0x61	0x00	0x00

0x60800002f7e0:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
0x60800002f7e8:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
0x60800002f7f0:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
0x60800002f7f8:	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe	0xbe
```

Great, so going back to the action plan:
- [x] Reach non-leaky, place breakpoint in new_valid_transitions
- [x] Determine memory of `transition_map->states` and `transition_map->states->valid_transitions` and keep it handy
- [x] Record address of state
  - [x] Validate that state is within transition_map
- [x] Record structure of state taking special care for to `valid_transitions`
- [ ] Head to `rcl_lifecycle_transition_map_fini` and debug memory release

Now, we need to check whether that memory is released or not (we'd expect it in the first case). Before doing so, let's make a table with the leaky/non-leaky cases and most relevant values:

(*Note, this is for the first iteration, the one related to `nodes.push_back(rclcpp_lifecycle::LifecycleNode::make_shared("foo"));`. The second one will have other values.*)

|                                                        |   Non-leaky            |    Leaky             |
|--------------------------------------------------------|------------------------|----------------------|
| `&transition_map->states[10]->valid_transitions[0]`    | `0x0000606000046e20`   | `0x000060800002f7a0` |
| `transition_map->states[10]->valid_transition_size`    | 2  | 3  |
| `transition_map` |   `0x613000001548`| `0x613000001548`  |

Let's head to transition_map.c:52 which is where `rcl_lifecycle_transition_map_fini` lives. The function itself is pretty straightforward:

```Cpp
rcl_ret_t
rcl_lifecycle_transition_map_fini(
  rcl_lifecycle_transition_map_t * transition_map,
  const rcutils_allocator_t * allocator)
{
  rcl_ret_t fcn_ret = RCL_RET_OK;

  // free the primary states
  allocator->deallocate(transition_map->states, allocator->state);
  transition_map->states = NULL;
  // free the tansitions
  allocator->deallocate(transition_map->transitions, allocator->state);
  transition_map->transitions = NULL;

  return fcn_ret;
}
```

![Layout for the rcl_lifecycle_transition_map_fini](background/images/2019/09/layout-for-the-rcl-lifecycle-transition-map-fini.png)

**FIRST INTUITION**: It looks like the allocator is freeing `transition_map->states` and `transition_map->transitions` however, for `transition_map->states`, it's not releasing `transition_map->states->valid_transitions` which was dynamically allocated and populated.

A closer look into the `allocator->deallocate(transition_map->states, allocator->state);`:

```Cpp
static void
__default_deallocate(void * pointer, void * state)
{
  RCUTILS_UNUSED(state);
  free(pointer);
}

```

Let's make that fix and see how things work out.

```bash
colcon build --build-base=build-asan --install-base=install-asan \
                  --cmake-args -DOSRF_TESTING_TOOLS_CPP_DISABLE_MEMORY_TOOLS=ON \
                   -DINSTALL_EXAMPLES=OFF -DSECURITY=ON --no-warn-unused-cli \
                   -DCMAKE_BUILD_TYPE=Debug --mixin asan-gcc \
                  --symlink-install --packages-select rcl_lifecycle
```

When recompiling the workspace, weird thing happening:
```bash
root@robocalypse:/opt/ros2_ws# colcon build --build-base=build-asan --install-base=install-asan                   --cmake-args -DOSRF_TESTING_TOOLS_CPP_DISABLE_MEMORY_TOOLS=ON                    -DINSTALL_EXAMPLES=OFF -DSECURITY=ON --no-warn-unused-cli                    -DCMAKE_BUILD_TYPE=Debug --mixin asan-gcc                   --symlink-install
Starting >>> ros2_ws
--- stderr: ros2_ws
CMake Error at CMakeLists.txt:1 (cmake_minimum_required):
  CMake 3.14 or higher is required.  You are running version 3.10.2


---
Failed   <<< ros2_ws	[ Exited with code 1 ]

Summary: 0 packages finished [18.6s]
  1 package failed: ros2_ws
  1 package had stderr output: ros2_ws
```

I checked all ROS2 packages an none of them seem to depend on version 3.14. I have no idea why this is happening. Probably some meta information. Same happening in the navigation2_ws. Ok, found why:

```bash
root@robocalypse:/opt/ros2_navigation2# ls
CMakeLists.txt  build  build-asan  install  install-asan  log  src
root@robocalypse:/opt/ros2_navigation2# rm CMakeLists.txt
root@robocalypse:/opt/ros2_navigation2# ls
build  build-asan  install  install-asan  log  src
```

CLion was creating a CMakeLists.txt file.

As a workaround anyhow, I found that creating another ws and sourcing it before launching the editor works equally fine.


Introducing then:
```bash
rcl_ret_t
rcl_lifecycle_transition_map_fini(
  rcl_lifecycle_transition_map_t * transition_map,
  const rcutils_allocator_t * allocator)
{
  rcl_ret_t fcn_ret = RCL_RET_OK;

  // free the primary states
  allocator->deallocate(transition_map->states->valid_transitions, allocator->state);
  allocator->deallocate(transition_map->states, allocator->state);
  transition_map->states = NULL;
  // free the tansitions
  allocator->deallocate(transition_map->transitions, allocator->state);
  transition_map->transitions = NULL;

  return fcn_ret;
}
```

Does not really help very much. Memory remain the same, leaking the same. Let's follow the pointer of `new_valid_transitions`:
- `0x6080000305a0` when allocated
- NULL when released

See the following image:

![valid_transitions dissapears!](background/images/2019/09/valid-transitions-dissapears.png)

https://github.com/aliasrobotics/RVD/issues/333 fix.


##### Remediation
See https://github.com/aliasrobotics/RVD/issues/333


#### rclcpp: SEGV on unknown address https://github.com/aliasrobotics/RVD/issues/166

Tried reproducing this issue but tests passed. Tried with all of them in the corresponding package:
```bash
/opt/ros2_ws/build-asan/rclcpp# du -a|grep "\./test_" | awk '{print $2}' | bash
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 3 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 3 tests from TestNodeOptions
[ RUN      ] TestNodeOptions.ros_args_only
[       OK ] TestNodeOptions.ros_args_only (102 ms)
[ RUN      ] TestNodeOptions.ros_args_and_non_ros_args
[       OK ] TestNodeOptions.ros_args_and_non_ros_args (1 ms)
[ RUN      ] TestNodeOptions.bad_ros_args
[       OK ] TestNodeOptions.bad_ros_args (6 ms)
[----------] 3 tests from TestNodeOptions (109 ms total)

[----------] Global test environment tear-down
[==========] 3 tests from 1 test case ran. (110 ms total)
[  PASSED  ] 3 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 14 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 14 tests from TestParameter
[ RUN      ] TestParameter.not_set_variant
[       OK ] TestParameter.not_set_variant (2 ms)
[ RUN      ] TestParameter.bool_variant
[       OK ] TestParameter.bool_variant (1 ms)
[ RUN      ] TestParameter.integer_variant
[       OK ] TestParameter.integer_variant (0 ms)
[ RUN      ] TestParameter.long_integer_variant
[       OK ] TestParameter.long_integer_variant (1 ms)
[ RUN      ] TestParameter.float_variant
[       OK ] TestParameter.float_variant (1 ms)
[ RUN      ] TestParameter.double_variant
[       OK ] TestParameter.double_variant (1 ms)
[ RUN      ] TestParameter.string_variant
[       OK ] TestParameter.string_variant (2 ms)
[ RUN      ] TestParameter.byte_array_variant
[       OK ] TestParameter.byte_array_variant (2 ms)
[ RUN      ] TestParameter.bool_array_variant
[       OK ] TestParameter.bool_array_variant (1 ms)
[ RUN      ] TestParameter.integer_array_variant
[       OK ] TestParameter.integer_array_variant (4 ms)
[ RUN      ] TestParameter.long_integer_array_variant
[       OK ] TestParameter.long_integer_array_variant (1 ms)
[ RUN      ] TestParameter.float_array_variant
[       OK ] TestParameter.float_array_variant (1 ms)
[ RUN      ] TestParameter.double_array_variant
[       OK ] TestParameter.double_array_variant (1 ms)
[ RUN      ] TestParameter.string_array_variant
[       OK ] TestParameter.string_array_variant (0 ms)
[----------] 14 tests from TestParameter (20 ms total)

[----------] Global test environment tear-down
[==========] 14 tests from 1 test case ran. (20 ms total)
[  PASSED  ] 14 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 10 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 10 tests from TestIntraProcessManager
[ RUN      ] TestIntraProcessManager.nominal
[       OK ] TestIntraProcessManager.nominal (1 ms)
[ RUN      ] TestIntraProcessManager.remove_publisher_before_trying_to_take
[       OK ] TestIntraProcessManager.remove_publisher_before_trying_to_take (1 ms)
[ RUN      ] TestIntraProcessManager.removed_subscription_affects_take
[       OK ] TestIntraProcessManager.removed_subscription_affects_take (0 ms)
[ RUN      ] TestIntraProcessManager.multiple_subscriptions_one_publisher
[       OK ] TestIntraProcessManager.multiple_subscriptions_one_publisher (0 ms)
[ RUN      ] TestIntraProcessManager.multiple_publishers_one_subscription
[       OK ] TestIntraProcessManager.multiple_publishers_one_subscription (1 ms)
[ RUN      ] TestIntraProcessManager.multiple_publishers_multiple_subscription
[       OK ] TestIntraProcessManager.multiple_publishers_multiple_subscription (1 ms)
[ RUN      ] TestIntraProcessManager.ring_buffer_displacement
[       OK ] TestIntraProcessManager.ring_buffer_displacement (1 ms)
[ RUN      ] TestIntraProcessManager.subscription_creation_race_condition
[       OK ] TestIntraProcessManager.subscription_creation_race_condition (1 ms)
[ RUN      ] TestIntraProcessManager.publisher_out_of_scope_take
[       OK ] TestIntraProcessManager.publisher_out_of_scope_take (0 ms)
[ RUN      ] TestIntraProcessManager.publisher_out_of_scope_store
[       OK ] TestIntraProcessManager.publisher_out_of_scope_store (1 ms)
[----------] 10 tests from TestIntraProcessManager (8 ms total)

[----------] Global test environment tear-down
[==========] 10 tests from 1 test case ran. (9 ms total)
[  PASSED  ] 10 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 7 tests from 2 test cases.
[----------] Global test environment set-up.
[----------] 6 tests from TestFunctionTraits
[ RUN      ] TestFunctionTraits.arity
[       OK ] TestFunctionTraits.arity (0 ms)
[ RUN      ] TestFunctionTraits.argument_types
[       OK ] TestFunctionTraits.argument_types (0 ms)
[ RUN      ] TestFunctionTraits.check_arguments
[       OK ] TestFunctionTraits.check_arguments (0 ms)
[ RUN      ] TestFunctionTraits.same_arguments
[       OK ] TestFunctionTraits.same_arguments (0 ms)
[ RUN      ] TestFunctionTraits.return_type
[       OK ] TestFunctionTraits.return_type (0 ms)
[ RUN      ] TestFunctionTraits.sfinae_match
[       OK ] TestFunctionTraits.sfinae_match (0 ms)
[----------] 6 tests from TestFunctionTraits (2 ms total)

[----------] 1 test from TestMember
[ RUN      ] TestMember.bind_member_functor
[       OK ] TestMember.bind_member_functor (0 ms)
[----------] 1 test from TestMember (0 ms total)

[----------] Global test environment tear-down
[==========] 7 tests from 2 test cases ran. (4 ms total)
[  PASSED  ] 7 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 2 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 2 tests from TestCreateTimer
[ RUN      ] TestCreateTimer.timer_executes
[       OK ] TestCreateTimer.timer_executes (147 ms)
[ RUN      ] TestCreateTimer.call_with_node_wrapper_compiles
[       OK ] TestCreateTimer.call_with_node_wrapper_compiles (52 ms)
[----------] 2 tests from TestCreateTimer (199 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test case ran. (200 ms total)
[  PASSED  ] 2 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 2 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 2 tests from TestWithDifferentNodeOptions/TestSubscriptionPublisherCount
[ RUN      ] TestWithDifferentNodeOptions/TestSubscriptionPublisherCount.increasing_and_decreasing_counts/one_context_test




[       OK ] TestWithDifferentNodeOptions/TestSubscriptionPublisherCount.increasing_and_decreasing_counts/one_context_test (8205 ms)
[ RUN      ] TestWithDifferentNodeOptions/TestSubscriptionPublisherCount.increasing_and_decreasing_counts/two_contexts_test
[       OK ] TestWithDifferentNodeOptions/TestSubscriptionPublisherCount.increasing_and_decreasing_counts/two_contexts_test (8294 ms)
[----------] 2 tests from TestWithDifferentNodeOptions/TestSubscriptionPublisherCount (16499 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test case ran. (16502 ms total)
[  PASSED  ] 2 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 6 tests from 3 test cases.
[----------] Global test environment set-up.
[----------] 2 tests from TestPublisher
[ RUN      ] TestPublisher.construction_and_destruction
[       OK ] TestPublisher.construction_and_destruction (74 ms)
[ RUN      ] TestPublisher.various_creation_signatures
[       OK ] TestPublisher.various_creation_signatures (36 ms)
[----------] 2 tests from TestPublisher (110 ms total)

[----------] 1 test from TestPublisherSub
[ RUN      ] TestPublisherSub.construction_and_destruction
[       OK ] TestPublisherSub.construction_and_destruction (36 ms)
[----------] 1 test from TestPublisherSub (36 ms total)

[----------] 3 tests from TestPublisherThrows/TestPublisherInvalidIntraprocessQos
unknown file: Failure
C++ exception with description "context is already initialized" thrown in SetUpTestCase().
[ RUN      ] TestPublisherThrows/TestPublisherInvalidIntraprocessQos.test_publisher_throws/transient_local_qos
[       OK ] TestPublisherThrows/TestPublisherInvalidIntraprocessQos.test_publisher_throws/transient_local_qos (60 ms)
[ RUN      ] TestPublisherThrows/TestPublisherInvalidIntraprocessQos.test_publisher_throws/keep_last_qos_with_zero_history_depth
[       OK ] TestPublisherThrows/TestPublisherInvalidIntraprocessQos.test_publisher_throws/keep_last_qos_with_zero_history_depth (49 ms)
[ RUN      ] TestPublisherThrows/TestPublisherInvalidIntraprocessQos.test_publisher_throws/keep_all_qos
[       OK ] TestPublisherThrows/TestPublisherInvalidIntraprocessQos.test_publisher_throws/keep_all_qos (47 ms)
[----------] 3 tests from TestPublisherThrows/TestPublisherInvalidIntraprocessQos (158 ms total)

[----------] Global test environment tear-down
[==========] 6 tests from 3 test cases ran. (330 ms total)
[  PASSED  ] 6 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 7 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 7 tests from TestTime
[ RUN      ] TestTime.clock_type_access
[       OK ] TestTime.clock_type_access (0 ms)
[ RUN      ] TestTime.time_sources
[       OK ] TestTime.time_sources (1 ms)
[ RUN      ] TestTime.conversions
[       OK ] TestTime.conversions (0 ms)
[ RUN      ] TestTime.operators
[       OK ] TestTime.operators (1 ms)
[ RUN      ] TestTime.overflow_detectors
[       OK ] TestTime.overflow_detectors (14 ms)
[ RUN      ] TestTime.overflows
[       OK ] TestTime.overflows (0 ms)
[ RUN      ] TestTime.seconds
[       OK ] TestTime.seconds (0 ms)
[----------] 7 tests from TestTime (16 ms total)

[----------] Global test environment tear-down
[==========] 7 tests from 1 test case ran. (17 ms total)
[  PASSED  ] 7 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 36 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 36 tests from TestNode
[ RUN      ] TestNode.construction_and_destruction
[       OK ] TestNode.construction_and_destruction (74 ms)
[ RUN      ] TestNode.get_name_and_namespace
[       OK ] TestNode.get_name_and_namespace (545 ms)
[ RUN      ] TestNode.subnode_get_name_and_namespace
[       OK ] TestNode.subnode_get_name_and_namespace (273 ms)
[ RUN      ] TestNode.subnode_construction_and_destruction
[       OK ] TestNode.subnode_construction_and_destruction (371 ms)
[ RUN      ] TestNode.get_logger
[       OK ] TestNode.get_logger (238 ms)
[ RUN      ] TestNode.get_clock
[       OK ] TestNode.get_clock (43 ms)
[ RUN      ] TestNode.now
[       OK ] TestNode.now (39 ms)
[ RUN      ] TestNode.declare_parameter_with_no_initial_values
[       OK ] TestNode.declare_parameter_with_no_initial_values (51 ms)
[ RUN      ] TestNode.test_registering_multiple_callbacks_api
[       OK ] TestNode.test_registering_multiple_callbacks_api (43 ms)
[ RUN      ] TestNode.declare_parameter_with_overrides
[       OK ] TestNode.declare_parameter_with_overrides (53 ms)
[ RUN      ] TestNode.declare_parameters_with_no_initial_values
[       OK ] TestNode.declare_parameters_with_no_initial_values (49 ms)
[ RUN      ] TestNode.undeclare_parameter
[       OK ] TestNode.undeclare_parameter (45 ms)
[ RUN      ] TestNode.has_parameter
[       OK ] TestNode.has_parameter (44 ms)
[ RUN      ] TestNode.set_parameter_undeclared_parameters_not_allowed
[       OK ] TestNode.set_parameter_undeclared_parameters_not_allowed (72 ms)
[ RUN      ] TestNode.set_parameter_undeclared_parameters_allowed
[       OK ] TestNode.set_parameter_undeclared_parameters_allowed (44 ms)
[ RUN      ] TestNode.set_parameters_undeclared_parameters_not_allowed
[       OK ] TestNode.set_parameters_undeclared_parameters_not_allowed (54 ms)
[ RUN      ] TestNode.set_parameters_undeclared_parameters_allowed
[       OK ] TestNode.set_parameters_undeclared_parameters_allowed (44 ms)
[ RUN      ] TestNode.set_parameters_atomically_undeclared_parameters_not_allowed
[       OK ] TestNode.set_parameters_atomically_undeclared_parameters_not_allowed (52 ms)
[ RUN      ] TestNode.set_parameters_atomically_undeclared_parameters_allowed
[       OK ] TestNode.set_parameters_atomically_undeclared_parameters_allowed (45 ms)
[ RUN      ] TestNode.get_parameter_undeclared_parameters_not_allowed
[       OK ] TestNode.get_parameter_undeclared_parameters_not_allowed (47 ms)
[ RUN      ] TestNode.get_parameter_undeclared_parameters_allowed
[       OK ] TestNode.get_parameter_undeclared_parameters_allowed (46 ms)
[ RUN      ] TestNode.get_parameter_or_undeclared_parameters_not_allowed
[       OK ] TestNode.get_parameter_or_undeclared_parameters_not_allowed (45 ms)
[ RUN      ] TestNode.get_parameter_or_undeclared_parameters_allowed
[       OK ] TestNode.get_parameter_or_undeclared_parameters_allowed (25 ms)
[ RUN      ] TestNode.get_parameters_undeclared_parameters_not_allowed
[       OK ] TestNode.get_parameters_undeclared_parameters_not_allowed (65 ms)
[ RUN      ] TestNode.get_parameters_undeclared_parameters_allowed
[       OK ] TestNode.get_parameters_undeclared_parameters_allowed (30 ms)
[ RUN      ] TestNode.describe_parameter_undeclared_parameters_not_allowed
[       OK ] TestNode.describe_parameter_undeclared_parameters_not_allowed (37 ms)
[ RUN      ] TestNode.describe_parameter_undeclared_parameters_allowed
[       OK ] TestNode.describe_parameter_undeclared_parameters_allowed (27 ms)
[ RUN      ] TestNode.describe_parameters_undeclared_parameters_not_allowed
[       OK ] TestNode.describe_parameters_undeclared_parameters_not_allowed (28 ms)
[ RUN      ] TestNode.describe_parameters_undeclared_parameters_allowed
[       OK ] TestNode.describe_parameters_undeclared_parameters_allowed (29 ms)
[ RUN      ] TestNode.get_parameter_types_undeclared_parameters_not_allowed
[       OK ] TestNode.get_parameter_types_undeclared_parameters_not_allowed (26 ms)
[ RUN      ] TestNode.get_parameter_types_undeclared_parameters_allowed
[       OK ] TestNode.get_parameter_types_undeclared_parameters_allowed (30 ms)
[ RUN      ] TestNode.set_on_parameters_set_callback_get_parameter
[       OK ] TestNode.set_on_parameters_set_callback_get_parameter (32 ms)
[ RUN      ] TestNode.set_on_parameters_set_callback_set_parameter
[       OK ] TestNode.set_on_parameters_set_callback_set_parameter (26 ms)
[ RUN      ] TestNode.set_on_parameters_set_callback_declare_parameter
[       OK ] TestNode.set_on_parameters_set_callback_declare_parameter (28 ms)
[ RUN      ] TestNode.set_on_parameters_set_callback_undeclare_parameter
[       OK ] TestNode.set_on_parameters_set_callback_undeclare_parameter (26 ms)
[ RUN      ] TestNode.set_on_parameters_set_callback_set_on_parameters_set_callback
[       OK ] TestNode.set_on_parameters_set_callback_set_on_parameters_set_callback (35 ms)
[----------] 36 tests from TestNode (2766 ms total)

[----------] Global test environment tear-down
[==========] 36 tests from 1 test case ran. (2790 ms total)
[  PASSED  ] 36 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 4 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 4 tests from TestUtilities
[ RUN      ] TestUtilities.remove_ros_arguments
[       OK ] TestUtilities.remove_ros_arguments (1 ms)
[ RUN      ] TestUtilities.remove_ros_arguments_null
[       OK ] TestUtilities.remove_ros_arguments_null (2 ms)
[ RUN      ] TestUtilities.init_with_args
[       OK ] TestUtilities.init_with_args (21 ms)
[ RUN      ] TestUtilities.multi_init
[       OK ] TestUtilities.multi_init (2 ms)
[----------] 4 tests from TestUtilities (30 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 1 test case ran. (33 ms total)
[  PASSED  ] 4 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 2 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 2 tests from TestFindWeakNodes
[ RUN      ] TestFindWeakNodes.allocator_strategy_with_weak_nodes
[       OK ] TestFindWeakNodes.allocator_strategy_with_weak_nodes (127 ms)
[ RUN      ] TestFindWeakNodes.allocator_strategy_no_weak_nodes
[       OK ] TestFindWeakNodes.allocator_strategy_no_weak_nodes (72 ms)
[----------] 2 tests from TestFindWeakNodes (199 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test case ran. (222 ms total)
[  PASSED  ] 2 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 2 tests from 2 test cases.
[----------] Global test environment set-up.
[----------] 1 test from TestService
[ RUN      ] TestService.construction_and_destruction
[       OK ] TestService.construction_and_destruction (70 ms)
[----------] 1 test from TestService (70 ms total)

[----------] 1 test from TestServiceSub
[ RUN      ] TestServiceSub.construction_and_destruction
[       OK ] TestServiceSub.construction_and_destruction (30 ms)
[----------] 1 test from TestServiceSub (31 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 2 test cases ran. (123 ms total)
[  PASSED  ] 2 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 4 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 4 tests from TestWithDifferentNodeOptions/TestPublisherSubscriptionCount
[ RUN      ] TestWithDifferentNodeOptions/TestPublisherSubscriptionCount.increasing_and_decreasing_counts/two_subscriptions_intraprocess_comm
[       OK ] TestWithDifferentNodeOptions/TestPublisherSubscriptionCount.increasing_and_decreasing_counts/two_subscriptions_intraprocess_comm (8152 ms)
[ RUN      ] TestWithDifferentNodeOptions/TestPublisherSubscriptionCount.increasing_and_decreasing_counts/two_subscriptions_one_intraprocess_one_not
[       OK ] TestWithDifferentNodeOptions/TestPublisherSubscriptionCount.increasing_and_decreasing_counts/two_subscriptions_one_intraprocess_one_not (8140 ms)
[ RUN      ] TestWithDifferentNodeOptions/TestPublisherSubscriptionCount.increasing_and_decreasing_counts/two_subscriptions_in_two_contexts_with_intraprocess_comm
[       OK ] TestWithDifferentNodeOptions/TestPublisherSubscriptionCount.increasing_and_decreasing_counts/two_subscriptions_in_two_contexts_with_intraprocess_comm (8116 ms)
[ RUN      ] TestWithDifferentNodeOptions/TestPublisherSubscriptionCount.increasing_and_decreasing_counts/two_subscriptions_in_two_contexts_without_intraprocess_comm
[       OK ] TestWithDifferentNodeOptions/TestPublisherSubscriptionCount.increasing_and_decreasing_counts/two_subscriptions_in_two_contexts_without_intraprocess_comm (8105 ms)
[----------] 4 tests from TestWithDifferentNodeOptions/TestPublisherSubscriptionCount (32513 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 1 test case ran. (32514 ms total)
[  PASSED  ] 4 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 2 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 2 tests from TestSerializedMessageAllocator
[ RUN      ] TestSerializedMessageAllocator.default_allocator
[       OK ] TestSerializedMessageAllocator.default_allocator (1 ms)
[ RUN      ] TestSerializedMessageAllocator.borrow_from_subscription
[       OK ] TestSerializedMessageAllocator.borrow_from_subscription (112 ms)
[----------] 2 tests from TestSerializedMessageAllocator (114 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test case ran. (114 ms total)
[  PASSED  ] 2 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 4 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 4 tests from TestTimer
[ RUN      ] TestTimer.test_simple_cancel
[       OK ] TestTimer.test_simple_cancel (90 ms)
[ RUN      ] TestTimer.test_is_canceled_reset
[       OK ] TestTimer.test_is_canceled_reset (34 ms)
[ RUN      ] TestTimer.test_run_cancel_executor
[       OK ] TestTimer.test_run_cancel_executor (135 ms)
[ RUN      ] TestTimer.test_run_cancel_timer
[       OK ] TestTimer.test_run_cancel_timer (135 ms)
[----------] 4 tests from TestTimer (394 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 1 test case ran. (394 ms total)
[  PASSED  ] 4 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 2 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 2 tests from TestRate
[ RUN      ] TestRate.rate_basics
[       OK ] TestRate.rate_basics (504 ms)
[ RUN      ] TestRate.wall_rate_basics
[       OK ] TestRate.wall_rate_basics (507 ms)
[----------] 2 tests from TestRate (1011 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test case ran. (1011 ms total)
[  PASSED  ] 2 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 2 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 2 tests from TestExecutors
[ RUN      ] TestExecutors.detachOnDestruction
[       OK ] TestExecutors.detachOnDestruction (66 ms)
[ RUN      ] TestExecutors.addTemporaryNode
[       OK ] TestExecutors.addTemporaryNode (79 ms)
[----------] 2 tests from TestExecutors (145 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test case ran. (168 ms total)
[  PASSED  ] 2 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 15 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 15 tests from Test_parameter_map_from
[ RUN      ] Test_parameter_map_from.null_c_parameter
[       OK ] Test_parameter_map_from.null_c_parameter (3 ms)
[ RUN      ] Test_parameter_map_from.null_node_names
[       OK ] Test_parameter_map_from.null_node_names (2 ms)
[ RUN      ] Test_parameter_map_from.null_node_params
[       OK ] Test_parameter_map_from.null_node_params (0 ms)
[ RUN      ] Test_parameter_map_from.null_node_name_in_node_names
[       OK ] Test_parameter_map_from.null_node_name_in_node_names (0 ms)
[ RUN      ] Test_parameter_map_from.null_node_param_value
[       OK ] Test_parameter_map_from.null_node_param_value (2 ms)
[ RUN      ] Test_parameter_map_from.null_node_param_name
[       OK ] Test_parameter_map_from.null_node_param_name (0 ms)
[ RUN      ] Test_parameter_map_from.bool_param_value
[       OK ] Test_parameter_map_from.bool_param_value (1 ms)
[ RUN      ] Test_parameter_map_from.integer_param_value
[       OK ] Test_parameter_map_from.integer_param_value (0 ms)
[ RUN      ] Test_parameter_map_from.double_param_value
[       OK ] Test_parameter_map_from.double_param_value (0 ms)
[ RUN      ] Test_parameter_map_from.string_param_value
[       OK ] Test_parameter_map_from.string_param_value (0 ms)
[ RUN      ] Test_parameter_map_from.byte_array_param_value
[       OK ] Test_parameter_map_from.byte_array_param_value (1 ms)
[ RUN      ] Test_parameter_map_from.bool_array_param_value
[       OK ] Test_parameter_map_from.bool_array_param_value (1 ms)
[ RUN      ] Test_parameter_map_from.integer_array_param_value
[       OK ] Test_parameter_map_from.integer_array_param_value (2 ms)
[ RUN      ] Test_parameter_map_from.double_array_param_value
[       OK ] Test_parameter_map_from.double_array_param_value (0 ms)
[ RUN      ] Test_parameter_map_from.string_array_param_value
[       OK ] Test_parameter_map_from.string_array_param_value (1 ms)
[----------] 15 tests from Test_parameter_map_from (13 ms total)

[----------] Global test environment tear-down
[==========] 15 tests from 1 test case ran. (14 ms total)
[  PASSED  ] 15 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 3 tests from 2 test cases.
[----------] Global test environment set-up.
[----------] 2 tests from TestClient
[ RUN      ] TestClient.construction_and_destruction
[       OK ] TestClient.construction_and_destruction (71 ms)
[ RUN      ] TestClient.construction_with_free_function
[       OK ] TestClient.construction_with_free_function (36 ms)
[----------] 2 tests from TestClient (107 ms total)

[----------] 1 test from TestClientSub
[ RUN      ] TestClientSub.construction_and_destruction
[       OK ] TestClientSub.construction_and_destruction (32 ms)
[----------] 1 test from TestClientSub (32 ms total)

[----------] Global test environment tear-down
[==========] 3 tests from 2 test cases ran. (162 ms total)
[  PASSED  ] 3 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 1 test from 1 test case.
[----------] Global test environment set-up.
[----------] 1 test from TestMultiThreadedExecutor
[ RUN      ] TestMultiThreadedExecutor.timer_over_take
[       OK ] TestMultiThreadedExecutor.timer_over_take (687 ms)
[----------] 1 test from TestMultiThreadedExecutor (687 ms total)

[----------] Global test environment tear-down
[==========] 1 test from 1 test case ran. (710 ms total)
[  PASSED  ] 1 test.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 2 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 2 tests from TestSubscriptionTraits
[ RUN      ] TestSubscriptionTraits.is_serialized_callback
[       OK ] TestSubscriptionTraits.is_serialized_callback (0 ms)
[ RUN      ] TestSubscriptionTraits.callback_messages
[       OK ] TestSubscriptionTraits.callback_messages (0 ms)
[----------] 2 tests from TestSubscriptionTraits (0 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test case ran. (1 ms total)
[  PASSED  ] 2 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 2 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 2 tests from TestNodeWithGlobalArgs
[ RUN      ] TestNodeWithGlobalArgs.local_arguments_before_global
[       OK ] TestNodeWithGlobalArgs.local_arguments_before_global (63 ms)
[ RUN      ] TestNodeWithGlobalArgs.use_or_ignore_global_arguments
[       OK ] TestNodeWithGlobalArgs.use_or_ignore_global_arguments (59 ms)
[----------] 2 tests from TestNodeWithGlobalArgs (122 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test case ran. (146 ms total)
[  PASSED  ] 2 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 10 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 10 tests from TestTimeSource
[ RUN      ] TestTimeSource.detachUnattached
[       OK ] TestTimeSource.detachUnattached (63 ms)
[ RUN      ] TestTimeSource.reattach
[       OK ] TestTimeSource.reattach (34 ms)
[ RUN      ] TestTimeSource.ROS_time_valid_attach_detach
[       OK ] TestTimeSource.ROS_time_valid_attach_detach (33 ms)
[ RUN      ] TestTimeSource.ROS_time_valid_wall_time
[       OK ] TestTimeSource.ROS_time_valid_wall_time (30 ms)
[ RUN      ] TestTimeSource.ROS_time_valid_sim_time
[       OK ] TestTimeSource.ROS_time_valid_sim_time (1122 ms)
[ RUN      ] TestTimeSource.clock
[       OK ] TestTimeSource.clock (5103 ms)
[ RUN      ] TestTimeSource.callbacks
[       OK ] TestTimeSource.callbacks (5127 ms)
[ RUN      ] TestTimeSource.callback_handler_erasure
[       OK ] TestTimeSource.callback_handler_erasure (73 ms)
[ RUN      ] TestTimeSource.parameter_activation
[       OK ] TestTimeSource.parameter_activation (5527 ms)
[ RUN      ] TestTimeSource.no_pre_jump_callback
[       OK ] TestTimeSource.no_pre_jump_callback (60 ms)
[----------] 10 tests from TestTimeSource (17174 ms total)

[----------] Global test environment tear-down
[==========] 10 tests from 1 test case ran. (17195 ms total)
[  PASSED  ] 10 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 4 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 4 tests from TestExternallyDefinedServices
[ RUN      ] TestExternallyDefinedServices.default_behavior
[       OK ] TestExternallyDefinedServices.default_behavior (72 ms)
[ RUN      ] TestExternallyDefinedServices.extern_defined_uninitialized
[       OK ] TestExternallyDefinedServices.extern_defined_uninitialized (31 ms)
[ RUN      ] TestExternallyDefinedServices.extern_defined_initialized
[       OK ] TestExternallyDefinedServices.extern_defined_initialized (32 ms)
[ RUN      ] TestExternallyDefinedServices.extern_defined_destructor
[       OK ] TestExternallyDefinedServices.extern_defined_destructor (30 ms)
[----------] 4 tests from TestExternallyDefinedServices (165 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 1 test case ran. (186 ms total)
[  PASSED  ] 4 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 6 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 6 tests from TestParameterEventFilter
[ RUN      ] TestParameterEventFilter.full_by_type
[       OK ] TestParameterEventFilter.full_by_type (1 ms)
[ RUN      ] TestParameterEventFilter.full_by_name
[       OK ] TestParameterEventFilter.full_by_name (1 ms)
[ RUN      ] TestParameterEventFilter.empty
[       OK ] TestParameterEventFilter.empty (0 ms)
[ RUN      ] TestParameterEventFilter.singular
[       OK ] TestParameterEventFilter.singular (0 ms)
[ RUN      ] TestParameterEventFilter.multiple
[       OK ] TestParameterEventFilter.multiple (0 ms)
[ RUN      ] TestParameterEventFilter.validate_data
[       OK ] TestParameterEventFilter.validate_data (0 ms)
[----------] 6 tests from TestParameterEventFilter (3 ms total)

[----------] Global test environment tear-down
[==========] 6 tests from 1 test case ran. (3 ms total)
[  PASSED  ] 6 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 4 tests from 2 test cases.
[----------] Global test environment set-up.
[----------] 3 tests from TestSubscription
[ RUN      ] TestSubscription.construction_and_destruction
[       OK ] TestSubscription.construction_and_destruction (67 ms)
[ RUN      ] TestSubscription.various_creation_signatures
[       OK ] TestSubscription.various_creation_signatures (38 ms)
[ RUN      ] TestSubscription.callback_bind
[       OK ] TestSubscription.callback_bind (136 ms)
[----------] 3 tests from TestSubscription (241 ms total)

[----------] 1 test from TestSubscriptionSub
[ RUN      ] TestSubscriptionSub.construction_and_destruction
[       OK ] TestSubscriptionSub.construction_and_destruction (36 ms)
[----------] 1 test from TestSubscriptionSub (36 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 2 test cases ran. (298 ms total)
[  PASSED  ] 4 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 7 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 7 tests from TestDuration
[ RUN      ] TestDuration.operators
[       OK ] TestDuration.operators (0 ms)
[ RUN      ] TestDuration.chrono_overloads
[       OK ] TestDuration.chrono_overloads (0 ms)
[ RUN      ] TestDuration.overflows
[       OK ] TestDuration.overflows (0 ms)
[ RUN      ] TestDuration.negative_duration
[       OK ] TestDuration.negative_duration (0 ms)
[ RUN      ] TestDuration.maximum_duration
[       OK ] TestDuration.maximum_duration (0 ms)
[ RUN      ] TestDuration.from_seconds
[       OK ] TestDuration.from_seconds (0 ms)
[ RUN      ] TestDuration.std_chrono_constructors
[       OK ] TestDuration.std_chrono_constructors (0 ms)
[----------] 7 tests from TestDuration (1 ms total)

[----------] Global test environment tear-down
[==========] 7 tests from 1 test case ran. (2 ms total)
[  PASSED  ] 7 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 4 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 4 tests from TestParameterClient
[ RUN      ] TestParameterClient.async_construction_and_destruction
[       OK ] TestParameterClient.async_construction_and_destruction (117 ms)
[ RUN      ] TestParameterClient.sync_construction_and_destruction
[       OK ] TestParameterClient.sync_construction_and_destruction (96 ms)
[ RUN      ] TestParameterClient.async_parameter_event_subscription
[       OK ] TestParameterClient.async_parameter_event_subscription (61 ms)
[ RUN      ] TestParameterClient.sync_parameter_event_subscription
[       OK ] TestParameterClient.sync_parameter_event_subscription (58 ms)
[----------] 4 tests from TestParameterClient (333 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 1 test case ran. (355 ms total)
[  PASSED  ] 4 tests.
Running main() from gmock_main.cc
[==========] Running 7 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 7 tests from TestLoggingMacros
[ RUN      ] TestLoggingMacros.test_logging_named
[       OK ] TestLoggingMacros.test_logging_named (0 ms)
[ RUN      ] TestLoggingMacros.test_logging_string
[       OK ] TestLoggingMacros.test_logging_string (1 ms)
[ RUN      ] TestLoggingMacros.test_logging_once
[       OK ] TestLoggingMacros.test_logging_once (0 ms)
[ RUN      ] TestLoggingMacros.test_logging_expression
[       OK ] TestLoggingMacros.test_logging_expression (0 ms)
[ RUN      ] TestLoggingMacros.test_logging_function
[       OK ] TestLoggingMacros.test_logging_function (0 ms)
[ RUN      ] TestLoggingMacros.test_logging_skipfirst
[       OK ] TestLoggingMacros.test_logging_skipfirst (1 ms)
[ RUN      ] TestLoggingMacros.test_log_from_node
[       OK ] TestLoggingMacros.test_log_from_node (0 ms)
[----------] 7 tests from TestLoggingMacros (2 ms total)

[----------] Global test environment tear-down
[==========] 7 tests from 1 test case ran. (3 ms total)
[  PASSED  ] 7 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 2 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 2 tests from TestLogger
[ RUN      ] TestLogger.factory_functions
[       OK ] TestLogger.factory_functions (0 ms)
[ RUN      ] TestLogger.hierarchy
[       OK ] TestLogger.hierarchy (1 ms)
[----------] 2 tests from TestLogger (1 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test case ran. (1 ms total)
[  PASSED  ] 2 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 2 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 2 tests from TestExpandTopicOrServiceName
[ RUN      ] TestExpandTopicOrServiceName.normal
[       OK ] TestExpandTopicOrServiceName.normal (1 ms)
[ RUN      ] TestExpandTopicOrServiceName.exceptions
[       OK ] TestExpandTopicOrServiceName.exceptions (1 ms)
[----------] 2 tests from TestExpandTopicOrServiceName (2 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test case ran. (3 ms total)
[  PASSED  ] 2 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 1 test from 1 test case.
[----------] Global test environment set-up.
[----------] 1 test from TestInit
[ RUN      ] TestInit.is_initialized
[       OK ] TestInit.is_initialized (29 ms)
[----------] 1 test from TestInit (29 ms total)

[----------] Global test environment tear-down
[==========] 1 test from 1 test case ran. (30 ms total)
[  PASSED  ] 1 test.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 7 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 7 tests from TestGetNodeInterfaces
[ RUN      ] TestGetNodeInterfaces.rclcpp_node_shared_ptr
[       OK ] TestGetNodeInterfaces.rclcpp_node_shared_ptr (0 ms)
[ RUN      ] TestGetNodeInterfaces.node_shared_ptr
[       OK ] TestGetNodeInterfaces.node_shared_ptr (0 ms)
[ RUN      ] TestGetNodeInterfaces.rclcpp_node_reference
[       OK ] TestGetNodeInterfaces.rclcpp_node_reference (0 ms)
[ RUN      ] TestGetNodeInterfaces.node_reference
[       OK ] TestGetNodeInterfaces.node_reference (0 ms)
[ RUN      ] TestGetNodeInterfaces.rclcpp_node_pointer
[       OK ] TestGetNodeInterfaces.rclcpp_node_pointer (0 ms)
[ RUN      ] TestGetNodeInterfaces.node_pointer
[       OK ] TestGetNodeInterfaces.node_pointer (0 ms)
[ RUN      ] TestGetNodeInterfaces.interface_shared_pointer
[       OK ] TestGetNodeInterfaces.interface_shared_pointer (0 ms)
[----------] 7 tests from TestGetNodeInterfaces (2 ms total)

[----------] Global test environment tear-down
[==========] 7 tests from 1 test case ran. (155 ms total)
[  PASSED  ] 7 tests.
Running main() from /opt/ros2_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 8 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 8 tests from TestMappedRingBuffer
[ RUN      ] TestMappedRingBuffer.empty
[       OK ] TestMappedRingBuffer.empty (0 ms)
[ RUN      ] TestMappedRingBuffer.temporary_l_value_with_shared_get_pop
[       OK ] TestMappedRingBuffer.temporary_l_value_with_shared_get_pop (0 ms)
[ RUN      ] TestMappedRingBuffer.temporary_l_value_with_unique_get_pop
[       OK ] TestMappedRingBuffer.temporary_l_value_with_unique_get_pop (0 ms)
[ RUN      ] TestMappedRingBuffer.nominal_push_shared_get_pop_shared
[       OK ] TestMappedRingBuffer.nominal_push_shared_get_pop_shared (0 ms)
[ RUN      ] TestMappedRingBuffer.nominal_push_shared_get_pop_unique
[       OK ] TestMappedRingBuffer.nominal_push_shared_get_pop_unique (1 ms)
[ RUN      ] TestMappedRingBuffer.nominal_push_unique_get_pop_unique
[       OK ] TestMappedRingBuffer.nominal_push_unique_get_pop_unique (0 ms)
[ RUN      ] TestMappedRingBuffer.nominal_push_unique_get_pop_shared
[       OK ] TestMappedRingBuffer.nominal_push_unique_get_pop_shared (1 ms)
[ RUN      ] TestMappedRingBuffer.non_unique_keys
[       OK ] TestMappedRingBuffer.non_unique_keys (0 ms)
[----------] 8 tests from TestMappedRingBuffer (4 ms total)

[----------] Global test environment tear-down
[==========] 8 tests from 1 test case ran. (5 ms total)
[  PASSED  ] 8 tests.
```

Couldn't find a way to reproduce it. 

#### Network Reconnaissance and VulnerabilityExcavation of Secure DDS Systems
https://arxiv.org/pdf/1908.05310.pdf

#### ROS2-SecTest https://github.com/aws-robotics/ROS2-SecTest
https://github.com/aws-robotics/ROS2-SecTest/tree/master/include/ros_sec_test/attacks

#### rclcpp, UBSAN: runtime error publisher_options https://github.com/aliasrobotics/RVD/issues/445
This might require to add support for ubsan in the tests. Accounting for the amount of time that this would require is hard beforehand.

#### Security and Performance Considerations in ROS 2: A Balancing Act
Potentially connected with Real-Time impact
TODO: read, explore

#### Exception sending message over network https://github.com/ros2/rmw_fastrtps/issues/317
TODO: go through it and validate it.



## Resources
- https://yurichev.com/writings/UAL-EN.pdf as a great resource for assembly. Particularly, 1.30.2 for free/malloc