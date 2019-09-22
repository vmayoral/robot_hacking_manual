\newpage

## Robot sanitizers in MoveIt 2

In this tutorial we'll apply the robot santizers over the the moveit2 alpha release code and review the results. This tutorial builds on top of [tutorial1](../tutorial1/), originally inspired by [1].

### Looking for bugs and vulnerabilities in MoveIt 2 with AddressSanitizer (ASan)
We'll dockerize the process to simplify reproduction of results. 
Let's compile the moveit2 code with the right flags for dynamic bugs finding:

```bash
docker build -t basic_cybersecurity_vulnerabilities2:latest .
```

And now, let's jump inside of the container, launch the tests and review the results:
```bash
docker run --privileged -it -v /tmp/log:/opt/ros2_moveit2_ws/log basic_cybersecurity_vulnerabilities2:latest /bin/bash
colcon test --build-base=build-asan --install-base=install-asan \
  --event-handlers sanitizer_report+ --merge-install --packages-up-to moveit_core
```

*NOTE: To keep things simple I've restricted the packages reviewed to moveit_core and its core dependencies solely. A complete review including all moveit packages is recommended in case one wanted to catch all bugs*.

Results are summarized in the `sanitizer_report.csv` (https://gist.github.com/vmayoral/25b3cff2c954b099eeb4d1471c1830e2). A quick look through the `log/` directory gives us an intuition into the different bugs detected:
```bash
grep -R '==.*==ERROR: .*Sanitizer' log/latest_test | grep stdout_stderr
log/latest_test/octomap/stdout_stderr.log:1: ==36465==ERROR: LeakSanitizer: detected memory leaks
log/latest_test/octomap/stdout_stderr.log:12: ==36587==ERROR: LeakSanitizer: detected memory leaks
log/latest_test/octomap/stdout_stderr.log:13: ==36589==ERROR: LeakSanitizer: detected memory leaks
log/latest_test/geometric_shapes/stdout_stderr.log:2: ==36631==ERROR: LeakSanitizer: detected memory leaks
log/latest_test/geometric_shapes/stdout_stderr.log:3: ==36634==ERROR: LeakSanitizer: detected memory leaks
log/latest_test/moveit_core/stdout_stderr.log:13: ==36756==ERROR: LeakSanitizer: detected memory leaks
```

Interesting! That's a bunch of errors in a rather small amount of code. Let's look at the relationship of the packages (often we want to start fixing bugs of packages with less dependencies so that the overall sanitizing process becomes easier):

```bash
colcon list -g --packages-up-to moveit_core
[0.580s] WARNING:colcon.colcon_core.package_selection:the --packages-skip-regex ament.* doesnt match any of the package names
angles                   +              *
eigen_stl_containers      +            **
joint_state_publisher      +        *   .
libcurl_vendor              +        * ..
object_recognition_msgs      +     *    .
octomap                       +        **
octomap_msgs                   +   *    *
random_numbers                  +      **
tf2_kdl                          +      *
urdfdom_py                        +   * .
moveit_msgs                        +    *
moveit_resources                    +   *
resource_retriever                   + *.
srdfdom                               + *
geometric_shapes                       +*
moveit_core                             +
```

This translates as follows[2]:

![](deps.png)

```bash
# made with:
apt-get install ros-dashing-qt-dotgraph
colcon list --packages-up-to moveit_core --topological-graph-dot | dot -Tpng -o deps.png
```

Both, `geometric_shapes` and `moveit_core` depend on quite a few other packages so one would probably pick `octomap` for starters and try fixing that bug first scaliting into other packages.

#### Fixing bugs
As per the original [report](https://gist.github.com/vmayoral/25b3cff2c954b099eeb4d1471c1830e2) the `moveit_core` related bug detected by ASan is listed below:

```bash
13: ==36756==ERROR: LeakSanitizer: detected memory leaks
13:
13: Direct leak of 40 byte(s) in 1 object(s) allocated from:
13:     #0 0x7fcbf6a7b458 in operator new(unsigned long) (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xe0458)
13:     #1 0x7fcbf5d0c0fd in shapes::constructShapeFromText(std::istream&) /opt/ros2_moveit2_ws/src/geometric_shapes/src/shape_operations.cpp:505
13:     #2 0x7fcbf6641561 in planning_scene::PlanningScene::loadGeometryFromStream(std::istream&, Eigen::Transform<double, 3, 1, 0> const&) /opt/ros2_moveit2_ws/src/moveit2/moveit_core/planning_scene/src/planning_scene.cpp:1077
13:     #3 0x7fcbf6640336 in planning_scene::PlanningScene::loadGeometryFromStream(std::istream&) /opt/ros2_moveit2_ws/src/moveit2/moveit_core/planning_scene/src/planning_scene.cpp:1043
13:     #4 0x562e70b1ea9d in PlanningScene_loadBadSceneGeometry_Test::TestBody() /opt/ros2_moveit2_ws/src/moveit2/moveit_core/planning_scene/test/test_planning_scene.cpp:223
13:     #5 0x562e70ba7039 in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2447
13:     #6 0x562e70b9918d in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2483
13:     #7 0x562e70b458b5 in testing::Test::Run() /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2522
13:     #8 0x562e70b46ce0 in testing::TestInfo::Run() /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2703
13:     #9 0x562e70b47884 in testing::TestCase::Run() /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2825
13:     #10 0x562e70b62995 in testing::internal::UnitTestImpl::RunAllTests() /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:5216
13:     #11 0x562e70ba9aec in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2447
13:     #12 0x562e70b9b456 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2483
13:     #13 0x562e70b5f729 in testing::UnitTest::Run() /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:4824
13:     #14 0x562e70b20ba5 in RUN_ALL_TESTS() (/opt/ros2_moveit2_ws/build/moveit_core/planning_scene/test_planning_scene+0x55ba5)
13:     #15 0x562e70b1f0be in main /opt/ros2_moveit2_ws/src/moveit2/moveit_core/planning_scene/test/test_planning_scene.cpp:229
13:     #16 0x7fcbf3c66b96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
13:
13: SUMMARY: AddressSanitizer: 40 byte(s) leaked in 1 allocation(s).
13: -- run_test.py: return code 1
13: -- run_test.py: inject classname prefix into gtest result file '/opt/ros2_moveit2_ws/build/moveit_core/test_results/moveit_core/test_planning_scene.gtest.xml'
13: -- run_test.py: verify result file '/opt/ros2_moveit2_ws/build/moveit_core/test_results/moveit_core/test_planning_scene.gtest.xml'
13/17 Test #13: test_planning_scene ..............***Failed    3.57 sec
```

This can be easily reproduced by launching the corresponding test file:

```bash
root@bf916bb1a977:/opt/ros2_moveit2_ws# source install/setup.bash
root@bf916bb1a977:/opt/ros2_moveit2_ws# build/moveit_core/planning_scene/test_planning_scene
[==========] Running 6 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 6 tests from PlanningScene
[ RUN      ] PlanningScene.LoadRestore
[INFO] [robot_model]: Loading robot model 'pr2'...
[INFO] [robot_model]: No root/virtual joint specified in SRDF. Assuming fixed joint
[       OK ] PlanningScene.LoadRestore (796 ms)
[ RUN      ] PlanningScene.LoadRestoreDiff
[INFO] [robot_model]: Loading robot model 'pr2'...
[INFO] [robot_model]: No root/virtual joint specified in SRDF. Assuming fixed joint
[       OK ] PlanningScene.LoadRestoreDiff (699 ms)
[ RUN      ] PlanningScene.MakeAttachedDiff
[INFO] [robot_model]: Loading robot model 'pr2'...
[INFO] [robot_model]: No root/virtual joint specified in SRDF. Assuming fixed joint
[       OK ] PlanningScene.MakeAttachedDiff (697 ms)
[ RUN      ] PlanningScene.isStateValid
[INFO] [robot_model]: Loading robot model 'pr2'...
[       OK ] PlanningScene.isStateValid (547 ms)
[ RUN      ] PlanningScene.loadGoodSceneGeometry
[INFO] [robot_model]: Loading robot model 'pr2'...
[       OK ] PlanningScene.loadGoodSceneGeometry (437 ms)
[ RUN      ] PlanningScene.loadBadSceneGeometry
[INFO] [robot_model]: Loading robot model 'pr2'...
[ERROR] [moveit.planning_scene]: Bad input stream when loading marker in scene geometry
[ERROR] [moveit.planning_scene]: Improperly formatted color in scene geometry file
[       OK ] PlanningScene.loadBadSceneGeometry (466 ms)
[----------] 6 tests from PlanningScene (3643 ms total)

[----------] Global test environment tear-down
[==========] 6 tests from 1 test case ran. (3645 ms total)
[  PASSED  ] 6 tests.

=================================================================
==38461==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 40 byte(s) in 1 object(s) allocated from:
    #0 0x7f9a7e0b7458 in operator new(unsigned long) (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xe0458)
    #1 0x7f9a7d3480fd in shapes::constructShapeFromText(std::istream&) /opt/ros2_moveit2_ws/src/geometric_shapes/src/shape_operations.cpp:505
    #2 0x7f9a7dc7d561 in planning_scene::PlanningScene::loadGeometryFromStream(std::istream&, Eigen::Transform<double, 3, 1, 0> const&) /opt/ros2_moveit2_ws/src/moveit2/moveit_core/planning_scene/src/planning_scene.cpp:1077
    #3 0x7f9a7dc7c336 in planning_scene::PlanningScene::loadGeometryFromStream(std::istream&) /opt/ros2_moveit2_ws/src/moveit2/moveit_core/planning_scene/src/planning_scene.cpp:1043
    #4 0x555a087ffa9d in PlanningScene_loadBadSceneGeometry_Test::TestBody() /opt/ros2_moveit2_ws/src/moveit2/moveit_core/planning_scene/test/test_planning_scene.cpp:223
    #5 0x555a08888039 in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2447
    #6 0x555a0887a18d in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2483
    #7 0x555a088268b5 in testing::Test::Run() /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2522
    #8 0x555a08827ce0 in testing::TestInfo::Run() /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2703
    #9 0x555a08828884 in testing::TestCase::Run() /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2825
    #10 0x555a08843995 in testing::internal::UnitTestImpl::RunAllTests() /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:5216
    #11 0x555a0888aaec in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2447
    #12 0x555a0887c456 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:2483
    #13 0x555a08840729 in testing::UnitTest::Run() /opt/ros/dashing/src/gtest_vendor/./src/gtest.cc:4824
    #14 0x555a08801ba5 in RUN_ALL_TESTS() (/opt/ros2_moveit2_ws/build/moveit_core/planning_scene/test_planning_scene+0x55ba5)
    #15 0x555a088000be in main /opt/ros2_moveit2_ws/src/moveit2/moveit_core/planning_scene/test/test_planning_scene.cpp:229
    #16 0x7f9a7b2a2b96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)

SUMMARY: AddressSanitizer: 40 byte(s) leaked in 1 allocation(s).
```

The bug is patched by https://github.com/AcutronicRobotics/moveit2/pull/113. After having patched the bug:

```bash
root@bf916bb1a977:/opt/ros2_moveit2_ws# build-asan/moveit_core/planning_scene/test_planning_scene
[==========] Running 6 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 6 tests from PlanningScene
[ RUN      ] PlanningScene.LoadRestore
[INFO] [robot_model]: Loading robot model 'pr2'...
[INFO] [robot_model]: No root/virtual joint specified in SRDF. Assuming fixed joint
[       OK ] PlanningScene.LoadRestore (601 ms)
[ RUN      ] PlanningScene.LoadRestoreDiff
[INFO] [robot_model]: Loading robot model 'pr2'...
[INFO] [robot_model]: No root/virtual joint specified in SRDF. Assuming fixed joint
[       OK ] PlanningScene.LoadRestoreDiff (535 ms)
[ RUN      ] PlanningScene.MakeAttachedDiff
[INFO] [robot_model]: Loading robot model 'pr2'...
[INFO] [robot_model]: No root/virtual joint specified in SRDF. Assuming fixed joint
[       OK ] PlanningScene.MakeAttachedDiff (526 ms)
[ RUN      ] PlanningScene.isStateValid
[INFO] [robot_model]: Loading robot model 'pr2'...
[       OK ] PlanningScene.isStateValid (465 ms)
[ RUN      ] PlanningScene.loadGoodSceneGeometry
[INFO] [robot_model]: Loading robot model 'pr2'...
[       OK ] PlanningScene.loadGoodSceneGeometry (431 ms)
[ RUN      ] PlanningScene.loadBadSceneGeometry
[INFO] [robot_model]: Loading robot model 'pr2'...
[ERROR] [moveit.planning_scene]: Bad input stream when loading marker in scene geometry
[ERROR] [moveit.planning_scene]: Improperly formatted color in scene geometry file
[       OK ] PlanningScene.loadBadSceneGeometry (425 ms)
[----------] 6 tests from PlanningScene (2984 ms total)

[----------] Global test environment tear-down
[==========] 6 tests from 1 test case ran. (2985 ms total)
[  PASSED  ] 6 tests.
```

### Looking for bugs and vulnerabilities in MoveIt 2 with ThreadSanitizer (TSan)

To use TSan [3] we rebuild the container (uncommenting and commenting the right sections) access it and manually launch the tests:

```bash
docker build -t basic_cybersecurity_vulnerabilities2:latest .
docker run --privileged -it -v /tmp/log:/opt/ros2_moveit2_ws/log basic_cybersecurity_vulnerabilities2:latest /bin/bash
colcon test --build-base=build-tsan --install-base=install-tsan --event-handlers sanitizer_report+ --packages-up-to moveit_core --merge-install
```

No issues where found while running TSan (up until `moveit_core`).

### Resources
- [1] https://github.com/colcon/colcon-sanitizer-reports/blob/master/README.rst
- [2] https://discourse.ros.org/t/exploring-package-dependencies/4719
- [3] TSan Cpp manual https://github.com/google/sanitizers/wiki/ThreadSanitizerCppManual