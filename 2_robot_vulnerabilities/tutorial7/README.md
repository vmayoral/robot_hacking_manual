\newpage

## Tutorial 7: Looking for vulnerabilities in navigation2
This tutorial aims to assess the flaws found in the navigation2 package and determine whether they can 
turn into vulnerabilities.

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


#### Exploring CLion IDE

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

```bash
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
```bash
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







## Resources