# Debugging output of robot sanitizers with GDB, hunting and fixing bugs (*UNFINISHED*)

This article aims to describe the process of introspecting memory leaks by directly connecting the debugger with the sanitizer-tests/binaries. The tutorial builds on top of the previous two articles, refer to [tutorial1](../tutorial1) and [tutorial2](../tutorial2).

## Fetch the bugs
Similar to [1]:
```bash
# Build the code with ASan
colcon build --build-base=build-asan --install-base=install-asan --cmake-args -DOSRF_TESTING_TOOLS_CPP_DISABLE_MEMORY_TOOLS=ON -DINSTALL_EXAMPLES=OFF -DSECURITY=ON --no-warn-unused-cli -DCMAKE_BUILD_TYPE=Debug --mixin asan-gcc --symlink-install

# Launch tests with ASan
colcon test --build-base=build-asan --install-base=install-asan --event-handlers sanitizer_report+
``

The complete set of bugs found has been captured and dumped at [sanitizer_report_ros2dashing.csv](sanitizer_report_ros2dashing.csv) file. 


## Gaining some additional understanding

Let's pick the first vulnerability and start exploring it and the structure of its code and relationships:

<details><summary>First vulnerability: detected memory leak in rcl</summary>

```bash
rcl,detected memory leaks,__default_zero_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56,4,"    
    #0 0x7f762845bd38 in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xded38)
    #1 0x7f7627a484d6 in __default_zero_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
    #2 0x7f7627a5ae77 in rcutils_string_array_init /opt/ros2_asan_ws/src/ros2/rcutils/src/string_array.c:54
    #3 0x7f7627839b4a in rmw_names_and_types_init /opt/ros2_asan_ws/src/ros2/rmw/rmw/src/names_and_types.c:66
    #4 0x7f7624cdf362 in rmw_fastrtps_shared_cpp::__copy_data_to_results(std::map<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::pair<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > > > > const&, rcutils_allocator_t*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:199
    #5 0x7f7624ce1c4d in rmw_fastrtps_shared_cpp::__rmw_get_topic_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, std::function<LockedObject<TopicCache> const& (CustomParticipantInfo&)>&, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:349
    #6 0x7f7624ce20d4 in rmw_fastrtps_shared_cpp::__rmw_get_publisher_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:385
    #7 0x7f7627dd4a25 in rmw_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_dynamic_cpp/src/rmw_node_info_and_types.cpp:64
    #8 0x7f762811a875 in rcl_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/graph.c:60
    #9 0x5565b057589d in TestGraphFixture__rmw_fastrtps_dynamic_cpp_test_rcl_get_publisher_names_and_types_by_node_Test::TestBody() /opt/ros2_asan_ws/src/ros2/rcl/rcl/test/rcl/test_graph.cpp:342
    #10 0x5565b062d9c5 in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #11 0x5565b061fb19 in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #12 0x5565b05cc601 in testing::Test::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2522
    #13 0x5565b05cda2c in testing::TestInfo::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2703
    #14 0x5565b05ce5d0 in testing::TestCase::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2825
    #15 0x5565b05e96e1 in testing::internal::UnitTestImpl::RunAllTests() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:5216
    #16 0x5565b0630478 in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #17 0x5565b0621de2 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #18 0x5565b05e6475 in testing::UnitTest::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:4824
    #19 0x5565b05b99c4 in RUN_ALL_TESTS() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/include/gtest/gtest.h:2370
    #20 0x5565b05b990a in main /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:36
    #21 0x7f7626a81b96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)"
```

</details>

This first bug seems to apply to `rcl` but crashies in `rcutils`. Let's see if we can visualize its relationship with detected bugs. First, let's plot the complete graph of relationships:
```bash
colcon list --topological-graph-dot | dot -Tpng -o deps.png
```
This will generate a report of **all** dynamic bugs found while reviewing ROS 2 Dashing Diademata with ASan sanitizer. The plot generated is available in [deps_all.png](deps_all.png) (*warning*: this file is 27M). This is frankly to bussy to make sense of it so let's try to simplify the plot:
```bash
colcon list --topological-graph-dot --packages-above-depth 1 rcutils | dot -Tpng -o deps.png
```

![](deps_rcutils.png)

*legend: blue=build, red=run, tan=test, dashed=indirect*

In this graph we can see that `rcutils` package is used by a variety of other packages and likely, it seems that the leak is happening through one of the rcl-related tests. Let's next try to reproduce the bug by finding the right test that triggers the memory leak.

## Getting ready to debug

Let's find the test that actually allows us to reproduce this:
```bash
# source the install directory
source /opt/ros2_asan_ws/install-asan/setup.bash
cd /opt/ros2_asan_ws/build-asan/rcl
./test_graph__rmw_fastrtps_cpp
```

this will produce:

<details><summary>Dump of `test_graph__rmw_fastrtps_cpp`</summary>

```bash
# source the worspace itself
source install-asan/setup.bash
# cd <whatever test dir>
  
## Launch the actual failing test
./test_graph__rmw_fastrtps_cpp
Running main() from /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 14 tests from 2 test cases.
[----------] Global test environment set-up.
[----------] 11 tests from TestGraphFixture__rmw_fastrtps_cpp
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_get_and_destroy_topic_names_and_types
[       OK ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_get_and_destroy_topic_names_and_types (23 ms)
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_get_service_names_and_types
[       OK ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_get_service_names_and_types (20 ms)
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_names_and_types_init
[       OK ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_names_and_types_init (22 ms)
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_get_publisher_names_and_types_by_node
[ERROR] [rmw_fastrtps_shared_cpp]: Unable to find GUID for node:
[ERROR] [rmw_fastrtps_shared_cpp]: Unable to find GUID for node: _InvalidNodeName
[ERROR] [rmw_fastrtps_shared_cpp]: Unable to find GUID for node: /test_rcl_get_publisher_names_and_types_by_node
[       OK ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_get_publisher_names_and_types_by_node (19 ms)
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_get_subscriber_names_and_types_by_node
[ERROR] [rmw_fastrtps_shared_cpp]: Unable to find GUID for node:
[ERROR] [rmw_fastrtps_shared_cpp]: Unable to find GUID for node: _InvalidNodeName
[ERROR] [rmw_fastrtps_shared_cpp]: Unable to find GUID for node: /test_rcl_get_subscriber_names_and_types_by_node
[       OK ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_get_subscriber_names_and_types_by_node (21 ms)
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_get_service_names_and_types_by_node
[ERROR] [rmw_fastrtps_shared_cpp]: Unable to find GUID for node:
[ERROR] [rmw_fastrtps_shared_cpp]: Unable to find GUID for node: _InvalidNodeName
[ERROR] [rmw_fastrtps_shared_cpp]: Unable to find GUID for node: /test_rcl_get_service_names_and_types_by_node
[       OK ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_get_service_names_and_types_by_node (24 ms)
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_count_publishers
[       OK ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_count_publishers (19 ms)
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_count_subscribers
[       OK ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_count_subscribers (20 ms)
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_graph_query_functions
[INFO] [rcl]:  Try 1: 0 publishers, 0 subscribers, and that the topic is not in the graph.
[INFO] [rcl]:   state correct!
[INFO] [rcl]:  Try 1: 1 publishers, 0 subscribers, and that the topic is in the graph.
[INFO] [rcl]:   state correct!
[INFO] [rcl]:  Try 1: 1 publishers, 1 subscribers, and that the topic is in the graph.
[INFO] [rcl]:   state correct!
[INFO] [rcl]:  Try 1: 0 publishers, 1 subscribers, and that the topic is in the graph.
[INFO] [rcl]:   state correct!
[INFO] [rcl]:  Try 1: 0 publishers, 0 subscribers, and that the topic is not in the graph.
[INFO] [rcl]:   state correct!
[       OK ] TestGraphFixture__rmw_fastrtps_cpp.test_graph_query_functions (22 ms)
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_graph_guard_condition_topics
[INFO] [rcl]: waiting up to '400000000' nanoseconds for graph changes
[INFO] [rcl]: waiting up to '400000000' nanoseconds for graph changes
[INFO] [rcl]: waiting up to '400000000' nanoseconds for graph changes
[INFO] [rcl]: waiting up to '400000000' nanoseconds for graph changes
[INFO] [rcl]: waiting up to '400000000' nanoseconds for graph changes
[INFO] [rcl]: waiting up to '400000000' nanoseconds for graph changes
[       OK ] TestGraphFixture__rmw_fastrtps_cpp.test_graph_guard_condition_topics (1234 ms)
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_service_server_is_available
[INFO] [rcl]: waiting up to '1000000000' nanoseconds for graph changes
[INFO] [rcl]: waiting up to '1000000000' nanoseconds for graph changes
[       OK ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_service_server_is_available (36 ms)
[----------] 11 tests from TestGraphFixture__rmw_fastrtps_cpp (1460 ms total)

[----------] 3 tests from NodeGraphMultiNodeFixture
[ RUN      ] NodeGraphMultiNodeFixture.test_node_info_subscriptions
[       OK ] NodeGraphMultiNodeFixture.test_node_info_subscriptions (1037 ms)
[ RUN      ] NodeGraphMultiNodeFixture.test_node_info_publishers
[       OK ] NodeGraphMultiNodeFixture.test_node_info_publishers (1040 ms)
[ RUN      ] NodeGraphMultiNodeFixture.test_node_info_services
[       OK ] NodeGraphMultiNodeFixture.test_node_info_services (1035 ms)
[----------] 3 tests from NodeGraphMultiNodeFixture (3112 ms total)

[----------] Global test environment tear-down
[==========] 14 tests from 2 test cases ran. (4572 ms total)
[  PASSED  ] 14 tests.

=================================================================
==30425==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 56 byte(s) in 1 object(s) allocated from:
    #0 0x7f5278a99d38 in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xded38)
    #1 0x7f52781e54d6 in __default_zero_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
    #2 0x7f5277fd6c7e in rmw_names_and_types_init /opt/ros2_asan_ws/src/ros2/rmw/rmw/src/names_and_types.c:72
    #3 0x7f5275880362 in rmw_fastrtps_shared_cpp::__copy_data_to_results(std::map<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::pair<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > > > > const&, rcutils_allocator_t*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:199
    #4 0x7f5275882c4d in rmw_fastrtps_shared_cpp::__rmw_get_topic_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, std::function<LockedObject<TopicCache> const& (CustomParticipantInfo&)>&, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:349
    #5 0x7f52758830d4 in rmw_fastrtps_shared_cpp::__rmw_get_publisher_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:385
    #6 0x7f52784931eb in rmw_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_cpp/src/rmw_node_info_and_types.cpp:53
    #7 0x7f5278758875 in rcl_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/graph.c:60
    #8 0x55d37431a0ed in TestGraphFixture__rmw_fastrtps_cpp_test_rcl_get_publisher_names_and_types_by_node_Test::TestBody() /opt/ros2_asan_ws/src/ros2/rcl/rcl/test/rcl/test_graph.cpp:342
    #9 0x55d3743d2215 in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #10 0x55d3743c4369 in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #11 0x55d374370e51 in testing::Test::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2522
    #12 0x55d37437227c in testing::TestInfo::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2703
    #13 0x55d374372e20 in testing::TestCase::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2825
    #14 0x55d37438df31 in testing::internal::UnitTestImpl::RunAllTests() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:5216
    #15 0x55d3743d4cc8 in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #16 0x55d3743c6632 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #17 0x55d37438acc5 in testing::UnitTest::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:4824
    #18 0x55d37435e214 in RUN_ALL_TESTS() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/include/gtest/gtest.h:2370
    #19 0x55d37435e15a in main /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:36
    #20 0x7f527721eb96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)

Direct leak of 8 byte(s) in 1 object(s) allocated from:
    #0 0x7f5278a99d38 in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xded38)
    #1 0x7f52781e54d6 in __default_zero_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
    #2 0x7f52781f7e77 in rcutils_string_array_init /opt/ros2_asan_ws/src/ros2/rcutils/src/string_array.c:54
    #3 0x7f5277fd6b4a in rmw_names_and_types_init /opt/ros2_asan_ws/src/ros2/rmw/rmw/src/names_and_types.c:66
    #4 0x7f5275880362 in rmw_fastrtps_shared_cpp::__copy_data_to_results(std::map<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::pair<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > > > > const&, rcutils_allocator_t*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:199
    #5 0x7f5275882c4d in rmw_fastrtps_shared_cpp::__rmw_get_topic_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, std::function<LockedObject<TopicCache> const& (CustomParticipantInfo&)>&, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:349
    #6 0x7f52758830d4 in rmw_fastrtps_shared_cpp::__rmw_get_publisher_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:385
    #7 0x7f52784931eb in rmw_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_cpp/src/rmw_node_info_and_types.cpp:53
    #8 0x7f5278758875 in rcl_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/graph.c:60
    #9 0x55d37431a0ed in TestGraphFixture__rmw_fastrtps_cpp_test_rcl_get_publisher_names_and_types_by_node_Test::TestBody() /opt/ros2_asan_ws/src/ros2/rcl/rcl/test/rcl/test_graph.cpp:342
    #10 0x55d3743d2215 in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #11 0x55d3743c4369 in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #12 0x55d374370e51 in testing::Test::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2522
    #13 0x55d37437227c in testing::TestInfo::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2703
    #14 0x55d374372e20 in testing::TestCase::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2825
    #15 0x55d37438df31 in testing::internal::UnitTestImpl::RunAllTests() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:5216
    #16 0x55d3743d4cc8 in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #17 0x55d3743c6632 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #18 0x55d37438acc5 in testing::UnitTest::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:4824
    #19 0x55d37435e214 in RUN_ALL_TESTS() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/include/gtest/gtest.h:2370
    #20 0x55d37435e15a in main /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:36
    #21 0x7f527721eb96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)

Indirect leak of 23 byte(s) in 1 object(s) allocated from:
    #0 0x7f5278a99b50 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb50)
    #1 0x7f52781e5465 in __default_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:35
    #2 0x7f52781f7c2f in rcutils_strndup /opt/ros2_asan_ws/src/ros2/rcutils/src/strdup.c:42
    #3 0x7f52781f7bae in rcutils_strdup /opt/ros2_asan_ws/src/ros2/rcutils/src/strdup.c:33
    #4 0x7f5275880a99 in rmw_fastrtps_shared_cpp::__copy_data_to_results(std::map<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::pair<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > > > > const&, rcutils_allocator_t*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:248
    #5 0x7f5275882c4d in rmw_fastrtps_shared_cpp::__rmw_get_topic_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, std::function<LockedObject<TopicCache> const& (CustomParticipantInfo&)>&, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:349
    #6 0x7f52758830d4 in rmw_fastrtps_shared_cpp::__rmw_get_publisher_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:385
    #7 0x7f52784931eb in rmw_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_cpp/src/rmw_node_info_and_types.cpp:53
    #8 0x7f5278758875 in rcl_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/graph.c:60
    #9 0x55d37431a0ed in TestGraphFixture__rmw_fastrtps_cpp_test_rcl_get_publisher_names_and_types_by_node_Test::TestBody() /opt/ros2_asan_ws/src/ros2/rcl/rcl/test/rcl/test_graph.cpp:342
    #10 0x55d3743d2215 in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #11 0x55d3743c4369 in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #12 0x55d374370e51 in testing::Test::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2522
    #13 0x55d37437227c in testing::TestInfo::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2703
    #14 0x55d374372e20 in testing::TestCase::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2825
    #15 0x55d37438df31 in testing::internal::UnitTestImpl::RunAllTests() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:5216
    #16 0x55d3743d4cc8 in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #17 0x55d3743c6632 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #18 0x55d37438acc5 in testing::UnitTest::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:4824
    #19 0x55d37435e214 in RUN_ALL_TESTS() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/include/gtest/gtest.h:2370
    #20 0x55d37435e15a in main /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:36
    #21 0x7f527721eb96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)

Indirect leak of 8 byte(s) in 1 object(s) allocated from:
    #0 0x7f5278a99d38 in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xded38)
    #1 0x7f52781e54d6 in __default_zero_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
    #2 0x7f52781f7e77 in rcutils_string_array_init /opt/ros2_asan_ws/src/ros2/rcutils/src/string_array.c:54
    #3 0x7f527588077a in rmw_fastrtps_shared_cpp::__copy_data_to_results(std::map<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::pair<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > > > > const&, rcutils_allocator_t*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:238
    #4 0x7f5275882c4d in rmw_fastrtps_shared_cpp::__rmw_get_topic_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, std::function<LockedObject<TopicCache> const& (CustomParticipantInfo&)>&, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:349
    #5 0x7f52758830d4 in rmw_fastrtps_shared_cpp::__rmw_get_publisher_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:385
    #6 0x7f52784931eb in rmw_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_cpp/src/rmw_node_info_and_types.cpp:53
    #7 0x7f5278758875 in rcl_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/graph.c:60
    #8 0x55d37431a0ed in TestGraphFixture__rmw_fastrtps_cpp_test_rcl_get_publisher_names_and_types_by_node_Test::TestBody() /opt/ros2_asan_ws/src/ros2/rcl/rcl/test/rcl/test_graph.cpp:342
    #9 0x55d3743d2215 in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #10 0x55d3743c4369 in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #11 0x55d374370e51 in testing::Test::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2522
    #12 0x55d37437227c in testing::TestInfo::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2703
    #13 0x55d374372e20 in testing::TestCase::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2825
    #14 0x55d37438df31 in testing::internal::UnitTestImpl::RunAllTests() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:5216
    #15 0x55d3743d4cc8 in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #16 0x55d3743c6632 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #17 0x55d37438acc5 in testing::UnitTest::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:4824
    #18 0x55d37435e214 in RUN_ALL_TESTS() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/include/gtest/gtest.h:2370
    #19 0x55d37435e15a in main /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:36
    #20 0x7f527721eb96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)

Indirect leak of 8 byte(s) in 1 object(s) allocated from:
    #0 0x7f5278a99b50 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb50)
    #1 0x7f52781e5465 in __default_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:35
    #2 0x7f52781f7c2f in rcutils_strndup /opt/ros2_asan_ws/src/ros2/rcutils/src/strdup.c:42
    #3 0x7f52781f7bae in rcutils_strdup /opt/ros2_asan_ws/src/ros2/rcutils/src/strdup.c:33
    #4 0x7f5275880638 in rmw_fastrtps_shared_cpp::__copy_data_to_results(std::map<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::pair<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > > > > const&, rcutils_allocator_t*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:226
    #5 0x7f5275882c4d in rmw_fastrtps_shared_cpp::__rmw_get_topic_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, std::function<LockedObject<TopicCache> const& (CustomParticipantInfo&)>&, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:349
    #6 0x7f52758830d4 in rmw_fastrtps_shared_cpp::__rmw_get_publisher_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:385
    #7 0x7f52784931eb in rmw_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_cpp/src/rmw_node_info_and_types.cpp:53
    #8 0x7f5278758875 in rcl_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/graph.c:60
    #9 0x55d37431a0ed in TestGraphFixture__rmw_fastrtps_cpp_test_rcl_get_publisher_names_and_types_by_node_Test::TestBody() /opt/ros2_asan_ws/src/ros2/rcl/rcl/test/rcl/test_graph.cpp:342
    #10 0x55d3743d2215 in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #11 0x55d3743c4369 in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #12 0x55d374370e51 in testing::Test::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2522
    #13 0x55d37437227c in testing::TestInfo::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2703
    #14 0x55d374372e20 in testing::TestCase::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2825
    #15 0x55d37438df31 in testing::internal::UnitTestImpl::RunAllTests() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:5216
    #16 0x55d3743d4cc8 in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
    #17 0x55d3743c6632 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
    #18 0x55d37438acc5 in testing::UnitTest::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:4824
    #19 0x55d37435e214 in RUN_ALL_TESTS() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/include/gtest/gtest.h:2370
    #20 0x55d37435e15a in main /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:36
    #21 0x7f527721eb96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)

SUMMARY: AddressSanitizer: 103 byte(s) leaked in 5 allocation(s).
```
</details>

We can clearly see that the two direct leaks are related to `/opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56`. As pointed out in the first tutorial and according to ASan documentation [8]:

> LSan also differentiates between direct and indirect leaks in its output. This gives useful information about which leaks should be prioritized, because fixing the direct leaks is likely to fix the indirect ones as well.

this tells us where to focus first. Direct leaks from this first report are:
```
Direct leak of 56 byte(s) in 1 object(s) allocated from:
    #0 0x7f4eaf189d38 in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xded38)
    #1 0x7f4eae8d54d6 in __default_zero_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
    #2 0x7f4eae6c6c7e in rmw_names_and_types_init /opt/ros2_asan_ws/src/ros2/rmw/rmw/src/names_and_types.c:72
    ...
```
and
```
Direct leak of 8 byte(s) in 1 object(s) allocated from:
    #0 0x7f4eaf189d38 in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xded38)
    #1 0x7f4eae8d54d6 in __default_zero_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
    #2 0x7f4eae8e7e77 in rcutils_string_array_init /opt/ros2_asan_ws/src/ros2/rcutils/src/string_array.c:54
    ...
```
Both correspond to the `calloc` call at https://github.com/ros2/rcutils/blob/master/src/allocator.c#L56 however with different callers:
- https://github.com/ros2/rcutils/blob/master/src/string_array.c#L54 (1)
- https://github.com/ros2/rmw/blob/master/rmw/src/names_and_types.c#L72 (2)

At this point, we could go ahead and inspect the part of the code that fails ``src/ros2/rcl/rcl/test/rcl/test_graph.cpp:342` however instead, let's dive a bit into the bug and try to gain more understanding about it deriving it differently.

Let's grab gdb and jump into it.

## Using GDB to understand better the leak
First, let's get the environment ready for the debugging:
```bash
ccache -M 20G # increase cache size
# Add the following to your .bashrc or .zshrc file and restart your terminal:
export CC=/usr/lib/ccache/gcc
export CXX=/usr/lib/ccache/g++
source /opt/ros2_asan_ws/install-asan/setup.bash
```

We already know where this memory leak is happening, let's now try to identify the exact environment and cause of it using gdb. We'll follow a similar strategy to what's described at [4]:

- Everytime we enter 'malloc()' we will 'save' the memory allocation requested size in a variable.
- Everytime we return from 'malloc()' we will print the size and the return address from 'malloc()'.
- Everytime we enter 'free()' we will print the 'pointer' we are about to free.

Now we use two terminals:
- In one we launch the binary `test_graph__rmw_fastrtps_cpp`
- In the other one we'll be launching gdb as `sudo gdb -p $(pgrep test_graph__rmw)`

Moreover in the GDB terminal, we'll be executing the following script [4]:

```bash
set pagination off
set breakpoint pending on
set logging file gdbcmd1.out
set logging on
hbreak malloc
commands
  set $mallocsize = (unsigned long long) $rdi
  continue
end
hbreak *(malloc+191)
commands
  printf "malloc(%lld) = 0x%016llx\n", $mallocsize, $rax
  continue
end
hbreak free
commands
  printf "free(0x%016llx)\n", (unsigned long long) $rdi
  continue
end
continue
```

This will fail with a message as follows:

```
(gdb) continue
Continuing.
Warning:
Cannot insert hardware breakpoint 1.
Cannot insert hardware breakpoint 2.
Could not insert hardware breakpoints:
You may have requested too many hardware breakpoints/watchpoints.

Command aborted.
```

Note that this script was literally taken from [4] and there's no real certainty that the `malloc+191` offset leads to the point where we can fetch the pointer that points to the allocated portion of memory in the heap. A quick check with gdb points out that the debugger never breaks here.

Moreover, it seems that the way this script is coded, we need to limit the places where we insert hardware breakpoints or simply dig more specifically. We need to dig deeper.

Let's get a more comfortable environment for debugging (note that depending on what you're doing with gdb, this can be anying so feel free to remove the `~/.gdbinit` file if that's the case):

```bash
wget -P ~ git.io/.gdbinit
```

Breaking in `__default_zero_allocate` shows us the information we need to diagnose the leak size:

<details><summary>Debug session 1</summary>

```bash
gdb ./test_graph__rmw_fastrtps_cpp
GNU gdb (Ubuntu 8.1-0ubuntu3) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./test_graph__rmw_fastrtps_cpp...done.
>>> b __default_zero_allocate
Function "__default_zero_allocate" not defined.
Make breakpoint pending on future shared library load? (y or [n]) y
Breakpoint 1 (__default_zero_allocate) pending.
>>> r
Starting program: /opt/ros2_asan_ws/build-asan/rcl/test/test_graph__rmw_fastrtps_cpp
─── Output/messages ────────────────────────────────────────────────────────────────────
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Running main() from /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 14 tests from 2 test cases.
[----------] Global test environment set-up.
[----------] 11 tests from TestGraphFixture__rmw_fastrtps_cpp
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_get_and_destroy_topic_names_and_types
─── Assembly ───────────────────────────────────────────────────────────────────────────
0x00007ffff66444b8 __default_zero_allocate+8  mov    %rdi,-0x8(%rbp)
0x00007ffff66444bc __default_zero_allocate+12 mov    %rsi,-0x10(%rbp)
0x00007ffff66444c0 __default_zero_allocate+16 mov    %rdx,-0x18(%rbp)
0x00007ffff66444c4 __default_zero_allocate+20 mov    -0x10(%rbp),%rdx
0x00007ffff66444c8 __default_zero_allocate+24 mov    -0x8(%rbp),%rax
0x00007ffff66444cc __default_zero_allocate+28 mov    %rdx,%rsi
0x00007ffff66444cf __default_zero_allocate+31 mov    %rax,%rdi
─── Expressions ────────────────────────────────────────────────────────────────────────
─── History ────────────────────────────────────────────────────────────────────────────
─── Memory ─────────────────────────────────────────────────────────────────────────────
─── Registers ──────────────────────────────────────────────────────────────────────────
   rax 0x00007ffff66444b0       rbx 0x00007fffffff1cf0       rcx 0x0000000000000000
   rdx 0x0000000000000000       rsi 0x0000000000000058       rdi 0x0000000000000001
   rbp 0x00007ffffffefe40       rsp 0x00007ffffffefe20        r8 0x0000000000000000
    r9 0x0000000000000000       r10 0x0000000000000022       r11 0x00007ffff6648fab
   r12 0x00000fffffffdfde       r13 0x00007ffffffefef0       r14 0x0000603000033730
   r15 0x00007ffffffefef0       rip 0x00007ffff66444c4    eflags [ IF ]
    cs 0x00000033                ss 0x0000002b                ds 0x00000000
    es 0x00000000                fs 0x00000000                gs 0x00000000
─── Source ─────────────────────────────────────────────────────────────────────────────
51
52 static void *
53 __default_zero_allocate(size_t number_of_elements, size_t size_of_element, void * state)
54 {
55   RCUTILS_UNUSED(state);
56   return calloc(number_of_elements, size_of_element);
57 }
58
59 rcutils_allocator_t
60 rcutils_get_zero_initialized_allocator(void)
61 {
─── Stack ──────────────────────────────────────────────────────────────────────────────
[0] from 0x00007ffff66444c4 in __default_zero_allocate+20 at /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
arg number_of_elements = 1
arg size_of_element = 88
arg state = 0x0
[1] from 0x00007ffff6bba48a in rcl_init+1991 at /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/init.c:78
arg argc = 0
arg argv = 0x0
arg options = 0x7fffffff2000
arg context = 0x603000033730
[+]
─── Threads ────────────────────────────────────────────────────────────────────────────
[1] id 16950 name test_graph__rmw from 0x00007ffff66444c4 in __default_zero_allocate+20 at /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, __default_zero_allocate (number_of_elements=1, size_of_element=88, state=0x0) at /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
56	  return calloc(number_of_elements, size_of_element);
```

</details>

in this case, the `size_of_element` is 88 bytes, we will focus first on the 56 bytes leaked.
Searching, eventually we'll find:

<details><summary>Debug session 2</summary>

```bash
─── Assembly ───────────────────────────────────────────────────────────────────────────
0x00007ffff66444b8 __default_zero_allocate+8  mov    %rdi,-0x8(%rbp)
0x00007ffff66444bc __default_zero_allocate+12 mov    %rsi,-0x10(%rbp)
0x00007ffff66444c0 __default_zero_allocate+16 mov    %rdx,-0x18(%rbp)
0x00007ffff66444c4 __default_zero_allocate+20 mov    -0x10(%rbp),%rdx
0x00007ffff66444c8 __default_zero_allocate+24 mov    -0x8(%rbp),%rax
0x00007ffff66444cc __default_zero_allocate+28 mov    %rdx,%rsi
0x00007ffff66444cf __default_zero_allocate+31 mov    %rax,%rdi
─── Expressions ────────────────────────────────────────────────────────────────────────
─── History ────────────────────────────────────────────────────────────────────────────
─── Memory ─────────────────────────────────────────────────────────────────────────────
─── Registers ──────────────────────────────────────────────────────────────────────────
   rax 0x00007ffff66444b0       rbx 0x00007fffffff0a90       rcx 0x0000000000000001
   rdx 0x0000000000000000       rsi 0x0000000000000038       rdi 0x0000000000000001
   rbp 0x00007ffffffef990       rsp 0x00007ffffffef970        r8 0x0000000000000000
    r9 0x0000000000000000       r10 0x00007ffffffef190       r11 0x00007ffffffef190
   r12 0x00007ffffffef9d0       r13 0x00000fffffffdf3a       r14 0x00007ffffffef9d0
   r15 0x00007fffffff0b70       rip 0x00007ffff66444c4    eflags [ IF ]
    cs 0x00000033                ss 0x0000002b                ds 0x00000000
    es 0x00000000                fs 0x00000000                gs 0x00000000
─── Source ─────────────────────────────────────────────────────────────────────────────
51
52 static void *
53 __default_zero_allocate(size_t number_of_elements, size_t size_of_element, void * state)
54 {
55   RCUTILS_UNUSED(state);
56   return calloc(number_of_elements, size_of_element);
57 }
58
59 rcutils_allocator_t
60 rcutils_get_zero_initialized_allocator(void)
61 {
─── Stack ──────────────────────────────────────────────────────────────────────────────
[0] from 0x00007ffff66444c4 in __default_zero_allocate+20 at /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
arg number_of_elements = 1
arg size_of_element = 56
arg state = 0x0
[1] from 0x00007ffff6435c7f in rmw_names_and_types_init+629 at /opt/ros2_asan_ws/src/ros2/rmw/rmw/src/names_and_types.c:72
arg names_and_types = 0x7fffffff1e40
arg size = 1
arg allocator = 0x7fffffff1330
[+]
─── Threads ────────────────────────────────────────────────────────────────────────────
[10] id 16963 name test_graph__rmw from 0x00007ffff6000567 in __libc_recvmsg+71 at ../sysdeps/unix/sysv/linux/recvmsg.c:28
[9] id 16962 name test_graph__rmw from 0x00007ffff5fff10d in __lll_lock_wait+29 at ../sysdeps/unix/sysv/linux/x86_64/lowlevellock.S:135
[8] id 16961 name test_graph__rmw from 0x00007ffff295f4c0 in std::chrono::duration_cast<std::chrono::duration<long, std::ratio<1l, 1000000000l> >, long, std::ratio<1l, 1000000l> >+0 at /usr/include/c++/7/chrono:194
[7] id 16960 name test_graph__rmw from 0x00007ffff2967be6 in std::vector<asio::detail::timer_queue<asio::detail::chrono_time_traits<std::chrono::_V2::steady_clock, asio::wait_traits<std::chrono::_V2::steady_clock> > >::heap_entry, std::allocator<asio::detail::timer_queue<asio::detail::chrono_time_traits<std::chrono::_V2::steady_clock, asio::wait_traits<std::chrono::_V2::steady_clock> > >::heap_entry> >::end at /usr/include/c++/7/bits/stl_vector.h:591
[6] id 16959 name test_graph__rmw from 0x00007ffff5ffb9f3 in futex_wait_cancelable+27 at ../sysdeps/unix/sysv/linux/futex-internal.h:88
[5] id 16958 name test_graph__rmw from 0x00007ffff6000567 in __libc_recvmsg+71 at ../sysdeps/unix/sysv/linux/recvmsg.c:28
[4] id 16957 name test_graph__rmw from 0x00007ffff6000567 in __libc_recvmsg+71 at ../sysdeps/unix/sysv/linux/recvmsg.c:28
[3] id 16956 name test_graph__rmw from 0x00007ffff28f77c6 in eprosima::fastrtps::rtps::ReaderProxy** std::__copy_move_a<true, eprosima::fastrtps::rtps::ReaderProxy**, eprosima::fastrtps::rtps::ReaderProxy**>(eprosima::fastrtps::rtps::ReaderProxy**, eprosima::fastrtps::rtps::ReaderProxy**, eprosima::fastrtps::rtps::ReaderProxy**)@plt
[2] id 16955 name test_graph__rmw from 0x00007ffff577dbb7 in epoll_wait+87 at ../sysdeps/unix/sysv/linux/epoll_wait.c:30
[1] id 16950 name test_graph__rmw from 0x00007ffff66444c4 in __default_zero_allocate+20 at /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
────────────────────────────────────────────────────────────────────────────────────────

Thread 1 "test_graph__rmw" hit Breakpoint 1, __default_zero_allocate (number_of_elements=1, size_of_element=56, state=0x0) at /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
56	  return calloc(number_of_elements, size_of_element);
```
</details>


Let's debug and play with calloc (not malloc) and free again. To do so, we'll break at `__default_zero_allocate` and manually figure out the returned address:

<details><summary>Debug session 3</summary>

```bash
─── Assembly ─────────────────────────────────────────────────────────────────────────────────
0x00007ffff66444cc __default_zero_allocate+28 mov    %rdx,%rsi
0x00007ffff66444cf __default_zero_allocate+31 mov    %rax,%rdi
0x00007ffff66444d2 __default_zero_allocate+34 callq  0x7ffff6643dd0 <calloc@plt>
0x00007ffff66444d7 __default_zero_allocate+39 leaveq
0x00007ffff66444d8 __default_zero_allocate+40 retq
─── Expressions ──────────────────────────────────────────────────────────────────────────────
─── History ──────────────────────────────────────────────────────────────────────────────────
$$0 = 88
─── Memory ───────────────────────────────────────────────────────────────────────────────────
─── Registers ────────────────────────────────────────────────────────────────────────────────
   rax 0x0000608000000120         rbx 0x00007fffffff1cf0         rcx 0x0000000000000000
   rdx 0x0000000000000058         rsi 0x0000000000000000         rdi 0x0000608000000120
   rbp 0x00007ffffffefe40         rsp 0x00007ffffffefe20          r8 0x0000000000000000
    r9 0x0000000000000000         r10 0x00007ffffffef650         r11 0x00007ffffffef650
   r12 0x00000fffffffdfde         r13 0x00007ffffffefef0         r14 0x0000603000033730
   r15 0x00007ffffffefef0         rip 0x00007ffff66444d7      eflags [ PF ZF IF ]
    cs 0x00000033                  ss 0x0000002b                  ds 0x00000000
    es 0x00000000                  fs 0x00000000                  gs 0x00000000
─── Source ───────────────────────────────────────────────────────────────────────────────────
52 static void *
53 __default_zero_allocate(size_t number_of_elements, size_t size_of_element, void * state)
54 {
55   RCUTILS_UNUSED(state);
56   return calloc(number_of_elements, size_of_element);
57 }
58
59 rcutils_allocator_t
60 rcutils_get_zero_initialized_allocator(void)
61 {
62   static rcutils_allocator_t zero_allocator = {
```
</details>

It seems that `__default_zero_allocate+39` is the point where we can fetch the memory address allocated in the heap (from `rax` register). In the example above `0x0000608000000120`. This can be double checked by putting a breakpoint at `b rcl/init.c:79` and checking the address of `context->impl`:

<details><summary>Debug session 4</summary>

```bash
>>> b rcl/init.c:79
Breakpoint 15 at 0x7ffff6bba4c0: file /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/init.c, line 79.
>>> down
#0  __default_zero_allocate (number_of_elements=1, size_of_element=88, state=0x0) at /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:57
57	}
>>> c
Continuing.
─── Output/messages ──────────────────────────────────────────────────────────────────────────
─── Assembly ─────────────────────────────────────────────────────────────────────────────────
0x00007ffff6bba4b0 rcl_init+2029 callq  0x7ffff6ba4e80 <__asan_report_store8@plt>
0x00007ffff6bba4b5 rcl_init+2034 mov    -0x1ea0(%rbp),%rax
0x00007ffff6bba4bc rcl_init+2041 mov    %rcx,0x8(%rax)
0x00007ffff6bba4c0 rcl_init+2045 mov    -0x1ea0(%rbp),%rax
0x00007ffff6bba4c7 rcl_init+2052 mov    0x8(%rax),%rax
0x00007ffff6bba4cb rcl_init+2056 test   %rax,%rax
0x00007ffff6bba4ce rcl_init+2059 jne    0x7ffff6bba4f2 <rcl_init+2095>
─── Expressions ──────────────────────────────────────────────────────────────────────────────
─── History ──────────────────────────────────────────────────────────────────────────────────
$$0 = 88
─── Memory ───────────────────────────────────────────────────────────────────────────────────
─── Registers ────────────────────────────────────────────────────────────────────────────────
   rax 0x0000603000033730         rbx 0x00007fffffff1cf0         rcx 0x0000608000000120
   rdx 0x0000000000000000         rsi 0x0000000000000000         rdi 0x0000608000000120
   rbp 0x00007fffffff1d20         rsp 0x00007ffffffefe50          r8 0x0000000000000000
    r9 0x0000000000000000         r10 0x00007ffffffef650         r11 0x00007ffffffef650
   r12 0x00000fffffffdfde         r13 0x00007ffffffefef0         r14 0x0000603000033730
   r15 0x00007ffffffefef0         rip 0x00007ffff6bba4c0      eflags [ PF ZF IF ]
    cs 0x00000033                  ss 0x0000002b                  ds 0x00000000
    es 0x00000000                  fs 0x00000000                  gs 0x00000000
─── Source ───────────────────────────────────────────────────────────────────────────────────
74   context->global_arguments = rcl_get_zero_initialized_arguments();
75
76   // Setup impl for context.
77   // use zero_allocate so the cleanup function will not try to clean up uninitialized parts later
78   context->impl = allocator.zero_allocate(1, sizeof(rcl_context_impl_t), allocator.state);
79   RCL_CHECK_FOR_NULL_WITH_MSG(
80     context->impl, "failed to allocate memory for context impl", return RCL_RET_BAD_ALLOC);
81
82   // Zero initialize rmw context first so its validity can by checked in cleanup.
83   context->impl->rmw_context = rmw_get_zero_initialized_context();
84
─── Stack ────────────────────────────────────────────────────────────────────────────────────
[0] from 0x00007ffff6bba4c0 in rcl_init+2045 at /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/init.c:79
arg argc = 0
arg argv = 0x0
arg options = 0x7fffffff2000
arg context = 0x603000033730
[1] from 0x00005555555b4e08 in TestGraphFixture__rmw_fastrtps_cpp::SetUp at /opt/ros2_asan_ws/src/ros2/rcl/rcl/test/rcl/test_graph.cpp:77
arg this = 0x606000001ca0
[+]
─── Threads ──────────────────────────────────────────────────────────────────────────────────
[1] id 19574 name test_graph__rmw from 0x00007ffff6bba4c0 in rcl_init+2045 at /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/init.c:79
──────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 15, rcl_init (argc=0, argv=0x0, options=0x7fffffff2000, context=0x603000033730) at /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/init.c:79
79	  RCL_CHECK_FOR_NULL_WITH_MSG(
>>> p context
$2 = (rcl_context_t *) 0x603000033730
>>> p context->impl
$3 = (struct rcl_context_impl_t *) 0x608000000120
```
</details>


For fun, let's try to see what's the offset in `calloc` that provides the pointer that addresses the portion of memory allocated in the heap. We start by breaking in `__default_zero_allocate` (`b __default_zero_allocate`)  and then (once in here), in `calloc` (`b calloc`).

We know that the address will be in the `0x60800000XXXX` range (more or less, look at the heap boundaries for more specific answer) and to speed up the process, we can take a peek at the assembly code of calloc once we've broken there:

<details><summary>Debug session 5</summary>

```bash
>>> x/90i $pc
=> 0x7ffff6ef8d6c <calloc+252>:	cmpb   $0x0,0xd8c0(%rax)
   0x7ffff6ef8d73 <calloc+259>:	jne    0x7ffff6ef8cf3 <calloc+131>
   0x7ffff6ef8d79 <calloc+265>:	mov    %rax,%rdi
   0x7ffff6ef8d7c <calloc+268>:	mov    %rax,-0x860(%rbp)
   0x7ffff6ef8d83 <calloc+275>:	callq  0x7ffff6f07c20
   0x7ffff6ef8d88 <calloc+280>:	mov    -0x860(%rbp),%r10
   0x7ffff6ef8d8f <calloc+287>:	mov    %rax,-0x868(%rbp)
   0x7ffff6ef8d96 <calloc+294>:	mov    %r10,%rdi
   0x7ffff6ef8d99 <calloc+297>:	callq  0x7ffff6f07c80
   0x7ffff6ef8d9e <calloc+302>:	mov    -0x860(%rbp),%r10
   0x7ffff6ef8da5 <calloc+309>:	mov    -0x854(%rbp),%esi
   0x7ffff6ef8dab <calloc+315>:	mov    %rbp,%rcx
   0x7ffff6ef8dae <calloc+318>:	mov    -0x868(%rbp),%r9
   0x7ffff6ef8db5 <calloc+325>:	xor    %r8d,%r8d
   0x7ffff6ef8db8 <calloc+328>:	mov    %r15,%rdx
   0x7ffff6ef8dbb <calloc+331>:	mov    %rbx,%rdi
   0x7ffff6ef8dbe <calloc+334>:	movb   $0x1,0xd8c0(%r10)
   0x7ffff6ef8dc6 <calloc+342>:	push   %r14
   0x7ffff6ef8dc8 <calloc+344>:	push   %rax
   0x7ffff6ef8dc9 <calloc+345>:	callq  0x7ffff6f1ddf0
   0x7ffff6ef8dce <calloc+350>:	mov    -0x860(%rbp),%r10
   0x7ffff6ef8dd5 <calloc+357>:	movb   $0x0,0xd8c0(%r10)
   0x7ffff6ef8ddd <calloc+365>:	pop    %rcx
   0x7ffff6ef8dde <calloc+366>:	pop    %rsi
   0x7ffff6ef8ddf <calloc+367>:	jmpq   0x7ffff6ef8cf3 <calloc+131>
   0x7ffff6ef8de4 <calloc+372>:	nopl   0x0(%rax)
   0x7ffff6ef8de8 <calloc+376>:	mov    %rbp,-0x40(%rbp)
   0x7ffff6ef8dec <calloc+380>:	callq  0x7ffff6f1d890
   0x7ffff6ef8df1 <calloc+385>:	mov    %rax,-0x840(%rbp)
   0x7ffff6ef8df8 <calloc+392>:	callq  0x7ffff6f06df0
   0x7ffff6ef8dfd <calloc+397>:	cmp    $0x1,%eax
   0x7ffff6ef8e00 <calloc+400>:	jbe    0x7ffff6ef8cf3 <calloc+131>
   0x7ffff6ef8e06 <calloc+406>:	mov    0x8(%rbp),%rax
   0x7ffff6ef8e0a <calloc+410>:	mov    %rax,-0x838(%rbp)
   0x7ffff6ef8e11 <calloc+417>:	jmpq   0x7ffff6ef8cf3 <calloc+131>
   0x7ffff6ef8e16 <calloc+422>:	nopw   %cs:0x0(%rax,%rax,1)
   0x7ffff6ef8e20 <calloc+432>:	test   %r14b,%r14b
   0x7ffff6ef8e23 <calloc+435>:	jne    0x7ffff6ef8cf3 <calloc+131>
   0x7ffff6ef8e29 <calloc+441>:	mov    -0x854(%rbp),%esi
   0x7ffff6ef8e2f <calloc+447>:	pushq  $0x0
   0x7ffff6ef8e31 <calloc+449>:	mov    %r15,%rdx
   0x7ffff6ef8e34 <calloc+452>:	pushq  $0x0
   0x7ffff6ef8e36 <calloc+454>:	xor    %r9d,%r9d
   0x7ffff6ef8e39 <calloc+457>:	xor    %r8d,%r8d
   0x7ffff6ef8e3c <calloc+460>:	mov    %rbp,%rcx
   0x7ffff6ef8e3f <calloc+463>:	mov    %rbx,%rdi
   0x7ffff6ef8e42 <calloc+466>:	callq  0x7ffff6f1ddf0
   0x7ffff6ef8e47 <calloc+471>:	pop    %rax
   0x7ffff6ef8e48 <calloc+472>:	pop    %rdx
   0x7ffff6ef8e49 <calloc+473>:	jmpq   0x7ffff6ef8cf3 <calloc+131>
   0x7ffff6ef8e4e <calloc+478>:	xchg   %ax,%ax
   0x7ffff6ef8e50 <calloc+480>:	imul   %rsi,%rdi
   0x7ffff6ef8e54 <calloc+484>:	callq  0x7ffff6ef8690
   0x7ffff6ef8e59 <calloc+489>:	jmpq   0x7ffff6ef8d01 <calloc+145>
   0x7ffff6ef8e5e <calloc+494>:	callq  0x7ffff6e3a780 <__stack_chk_fail@plt>
   0x7ffff6ef8e63:	nopl   (%rax)
   0x7ffff6ef8e66:	nopw   %cs:0x0(%rax,%rax,1)
   0x7ffff6ef8e70 <realloc>:	push   %rbp
   0x7ffff6ef8e71 <realloc+1>:	mov    %rsp,%rbp
   0x7ffff6ef8e74 <realloc+4>:	push   %r15
   0x7ffff6ef8e76 <realloc+6>:	push   %r14
```
</details>


In short, to verify that we indeed are getting the right values for the dynamica memory allocated:

```bash
# within gdb
b main
b __default_zero_allocate
b *(calloc-15694047)
b rcl/init.c:79
p context->impl
```

Putting it together in a gdb script:

```bash
set pagination off
set breakpoint pending on
set logging file gdbcmd1.out
set logging on
hbreak calloc
commands
  set $callocsize = (unsigned long long) $rsi  
  continue
end
hbreak *(calloc-15694047)
commands
  printf "calloc(%lld) = 0x%016llx\n", $callocsize, $rax
  continue
end
hbreak free
commands
  printf "free(0x%016llx)\n", (unsigned long long) $rdi
  continue
end
continue
```

(after disabling a few of the hw breakpoints) generating a big file https://gist.github.com/vmayoral/57ea38f9614cbfd1b5d7e93d92c15e13.
Browsing through this file, let's coun the calloc counts in those cases where we allocate 56 bytes (where the leak is):

```bash
cat gdbcmd1.out | grep "calloc(56)" | awk '{print $3}' | sed "s/^/cat gdbcmd1.out | grep -c /g"
cat gdbcmd1.out | grep -c 0x000060600000af40
cat gdbcmd1.out | grep -c 0x0000602000008f90
cat gdbcmd1.out | grep -c 0x0000616000012c80
cat gdbcmd1.out | grep -c 0x000060600001dba0
cat gdbcmd1.out | grep -c 0x0000606000039bc0
cat gdbcmd1.out | grep -c 0x000060b0000cf4c0
cat gdbcmd1.out | grep -c 0x000060b0000cf990
cat gdbcmd1.out | grep -c 0x000060b0000cfd00
cat gdbcmd1.out | grep -c 0x00006060000436a0
cat gdbcmd1.out | grep -c 0x000060600005c060
cat gdbcmd1.out | grep -c 0x000060600005c1e0
cat gdbcmd1.out | grep -c 0x000060600005c300
cat gdbcmd1.out | grep -c 0x000060600005c420
cat gdbcmd1.out | grep -c 0x000060600005c5a0
cat gdbcmd1.out | grep -c 0x000060600005c720
cat gdbcmd1.out | grep -c 0x000060600005c840
cat gdbcmd1.out | grep -c 0x000060600005c960
cat gdbcmd1.out | grep -c 0x000060600005cae0
cat gdbcmd1.out | grep -c 0x000060600005cc00
cat gdbcmd1.out | grep -c 0x000060600005cd20
cat gdbcmd1.out | grep -c 0x000060600005cea0
cat gdbcmd1.out | grep -c 0x000060600005cfc0
cat gdbcmd1.out | grep -c 0x000060600005d0e0
cat gdbcmd1.out | grep -c 0x000060600005d260
cat gdbcmd1.out | grep -c 0x000060600005d380
cat gdbcmd1.out | grep -c 0x000060600005d4a0
cat gdbcmd1.out | grep -c 0x000060600005d5c0
cat gdbcmd1.out | grep -c 0x000060b000148830
cat gdbcmd1.out | grep -c 0x0000606000069b60
cat gdbcmd1.out | grep -c 0x000060b000148d00
cat gdbcmd1.out | grep -c 0x0000606000069e00
cat gdbcmd1.out | grep -c 0x0000606000069f20
cat gdbcmd1.out | grep -c 0x000060600006a040
cat gdbcmd1.out | grep -c 0x000060600006a160
cat gdbcmd1.out | grep -c 0x000060600006a280
cat gdbcmd1.out | grep -c 0x00006060000717e0
cat gdbcmd1.out | grep -c 0x00006060000718a0
cat gdbcmd1.out | grep -c 0x00006060000719c0
cat gdbcmd1.out | grep -c 0x0000606000071c00
cat gdbcmd1.out | grep -c 0x0000606000071cc0
cat gdbcmd1.out | grep -c 0x0000606000071de0
cat gdbcmd1.out | grep -c 0x0000606000071f00
cat gdbcmd1.out | grep -c 0x0000606000072020
cat gdbcmd1.out | grep -c 0x0000606000072140
cat gdbcmd1.out | grep -c 0x0000606000072260
```

which launched gets the following output:

```bash
cat gdbcmd1.out | grep "calloc(56)" | awk '{print $3}' | sed "s/^/cat gdbcmd1.out | grep -c /g" | bash
2
2
2
1
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
2
```

We're filtering by the address and we should expect to *always* get an even number (each calloc with its free) however we get an odd number for the address `0x000060600001dba0`:

```bash
cat gdbcmd1.out  | grep "0x000060600001dba0"
calloc(56) = 0x000060600001dba0
```

It seems this is not getting released! Let's get back to gdb and debug where does this happens with a combination as follows:

```bash
set pagination off
hbreak calloc
commands
  set $callocsize = (unsigned long long) $rsi  
  continue
end
break *(calloc-15694047) if $callocsize == 56
printf "calloc(%d) = 0x%016llx\n", $callocsize, $rax
```

In combination with:

```bash
break free
p $rdi
c
```

It's easy to validate that the 4th iteration is leaky. Further investigating here:

```bash
>>> where
#0  0x00007ffff6ef8d01 in calloc () from /usr/lib/x86_64-linux-gnu/libasan.so.4
#1  0x00007ffff66444d7 in __default_zero_allocate (number_of_elements=1, size_of_element=56, state=0x0) at /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
#2  0x00007ffff6435c7f in rmw_names_and_types_init (names_and_types=0x7fffffff11e0, size=1, allocator=0x7fffffff03c0) at /opt/ros2_asan_ws/src/ros2/rmw/rmw/src/names_and_types.c:72
#3  0x00007ffff3cde35b in rmw_fastrtps_shared_cpp::__copy_data_to_results (topics=std::map with 1 element = {...}, allocator=0x7fffffff03c0, no_demangle=false, topic_names_and_types=0x7fffffff11e0) at /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:199
#4  0x00007ffff3ce0c46 in rmw_fastrtps_shared_cpp::__rmw_get_topic_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, std::function<LockedObject<TopicCache> const& (CustomParticipantInfo&)>&, rmw_names_and_types_t*) (identifier=0x7ffff6919660 "rmw_fastrtps_cpp", node=0x604000011990, allocator=0x7fffffff03c0, node_name=0x55555566a560 "test_graph_node", node_namespace=0x7ffff6bf4620 "/", no_demangle=false, retrieve_cache_func=..., topic_names_and_types=0x7fffffff11e0) at /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:349
#5  0x00007ffff3ce10cd in rmw_fastrtps_shared_cpp::__rmw_get_publisher_names_and_types_by_node (identifier=0x7ffff6919660 "rmw_fastrtps_cpp", node=0x604000011990, allocator=0x7fffffff03c0, node_name=0x55555566a560 "test_graph_node", node_namespace=0x7ffff6bf4620 "/", no_demangle=false, topic_names_and_types=0x7fffffff11e0) at /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:385
#6  0x00007ffff68f21ec in rmw_get_publisher_names_and_types_by_node (node=0x604000011990, allocator=0x7fffffff03c0, node_name=0x55555566a560 "test_graph_node", node_namespace=0x7ffff6bf4620 "/", no_demangle=false, topic_names_and_types=0x7fffffff11e0) at /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_cpp/src/rmw_node_info_and_types.cpp:53
#7  0x00007ffff6bb7876 in rcl_get_publisher_names_and_types_by_node (node=0x60200000bb90, allocator=0x7fffffff1120, no_demangle=false, node_name=0x55555566a560 "test_graph_node", node_namespace=0x555555669ae0 "", topic_names_and_types=0x7fffffff11e0) at /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/graph.c:60
#8  0x00005555555910ee in TestGraphFixture__rmw_fastrtps_cpp_test_rcl_get_publisher_names_and_types_by_node_Test::TestBody (this=0x606000015fe0) at /opt/ros2_asan_ws/src/ros2/rcl/rcl/test/rcl/test_graph.cpp:342
#9  0x0000555555649216 in testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void> (object=0x606000015fe0, method=&virtual testing::Test::TestBody(), location=0x555555676dc0 "the test body") at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
#10 0x000055555563b36a in testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void> (object=0x606000015fe0, method=&virtual testing::Test::TestBody(), location=0x555555676dc0 "the test body") at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
#11 0x00005555555e7e52 in testing::Test::Run (this=0x606000015fe0) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2522
#12 0x00005555555e927d in testing::TestInfo::Run (this=0x6120000004c0) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2703
#13 0x00005555555e9e21 in testing::TestCase::Run (this=0x611000000400) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2825
#14 0x0000555555604f32 in testing::internal::UnitTestImpl::RunAllTests (this=0x615000000800) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:5216
#15 0x000055555564bcc9 in testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool> (object=0x615000000800, method=(bool (testing::internal::UnitTestImpl::*)(testing::internal::UnitTestImpl * const)) 0x555555604842 <testing::internal::UnitTestImpl::RunAllTests()>, location=0x55555567ae60 "auxiliary test code (environments or event listeners)") at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
#16 0x000055555563d633 in testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool> (object=0x615000000800, method=(bool (testing::internal::UnitTestImpl::*)(testing::internal::UnitTestImpl * const)) 0x555555604842 <testing::internal::UnitTestImpl::RunAllTests()>, location=0x55555567ae60 "auxiliary test code (environments or event listeners)") at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
#17 0x0000555555601cc6 in testing::UnitTest::Run (this=0x5555558bea80 <testing::UnitTest::GetInstance()::instance>) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:4824
#18 0x00005555555d5215 in RUN_ALL_TESTS () at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/include/gtest/gtest.h:2370
#19 0x00005555555d515b in main (argc=1, argv=0x7fffffff4b28) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:36
```

Which tells us the exact same information Asan did already :). In other words, we reached the same conclusion, the problem seems to be at 
`src/ros2/rcl/rcl/test/rcl/test_graph.cpp:342`.

Inspecting the code, it seems like key might be in the call to `rmw_names_and_types_init` which in exchange  gets deallocated by `rmw_names_and_types_fini`. Let's check whether all the memory reservations of 56 bytes do call `rmw_names_and_types_fini`. Let's first analyze the typical call to `rmw_names_and_types_fini` after hitting one of the points we're interested in (we break in `rmw_names_and_types_fini` (`b rmw_names_and_types_fini`)):

<details><summary>Debug session 6</summary>

```bash
gdb ./test_graph__rmw_fastrtps_cpp
GNU gdb (Ubuntu 8.1-0ubuntu3) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./test_graph__rmw_fastrtps_cpp...done.
>>> b main
Breakpoint 1 at 0x8112b: file /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc, line 34.
>>> r
Starting program: /opt/ros2_asan_ws/build-asan/rcl/test/test_graph__rmw_fastrtps_cpp
─── Output/messages ───────────────────────────────────────────────────────────────────────────────
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
─── Assembly ──────────────────────────────────────────────────────────────────────────────────────
0x00005555555d5120 main+4  sub    $0x10,%rsp
0x00005555555d5124 main+8  mov    %edi,-0x4(%rbp)
0x00005555555d5127 main+11 mov    %rsi,-0x10(%rbp)
0x00005555555d512b main+15 lea    0x9d70e(%rip),%rsi        # 0x555555672840
0x00005555555d5132 main+22 lea    0x9d787(%rip),%rdi        # 0x5555556728c0
0x00005555555d5139 main+29 mov    $0x0,%eax
0x00005555555d513e main+34 callq  0x5555555868e0 <printf@plt>
─── Expressions ───────────────────────────────────────────────────────────────────────────────────
─── History ───────────────────────────────────────────────────────────────────────────────────────
─── Memory ────────────────────────────────────────────────────────────────────────────────────────
─── Registers ─────────────────────────────────────────────────────────────────────────────────────
   rax 0x00005555555d511c           rbx 0x0000000000000000           rcx 0x0000000000000360
   rdx 0x00007fffffff4b38           rsi 0x00007fffffff4b28           rdi 0x0000000000000001
   rbp 0x00007fffffff4a40           rsp 0x00007fffffff4a30            r8 0x0000619000073f80
    r9 0x0000000000000000           r10 0x00007fffffff3e78           r11 0x00007fffffff3e78
   r12 0x0000555555586ba0           r13 0x00007fffffff4b20           r14 0x0000000000000000
   r15 0x0000000000000000           rip 0x00005555555d512b        eflags [ PF IF ]
    cs 0x00000033                    ss 0x0000002b                    ds 0x00000000
    es 0x00000000                    fs 0x00000000                    gs 0x00000000
─── Source ────────────────────────────────────────────────────────────────────────────────────────
29
30 #include <stdio.h>
31 #include "gtest/gtest.h"
32
33 GTEST_API_ int main(int argc, char **argv) {
34   printf("Running main() from %s\n", __FILE__);
35   testing::InitGoogleTest(&argc, argv);
36   return RUN_ALL_TESTS();
37 }
─── Stack ─────────────────────────────────────────────────────────────────────────────────────────
[0] from 0x00005555555d512b in main+15 at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:34
arg argc = 1
arg argv = 0x7fffffff4b28
─── Threads ───────────────────────────────────────────────────────────────────────────────────────
[1] id 1308 name test_graph__rmw from 0x00005555555d512b in main+15 at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:34
───────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, main (argc=1, argv=0x7fffffff4b28) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:34
34	  printf("Running main() from %s\n", __FILE__);
>>> set pagination off
>>> hbreak calloc
Hardware assisted breakpoint 2 at 0x7ffff56f6030: calloc. (3 locations)
>>> commands
Type commands for breakpoint(s) 2, one per line.
End with a line saying just "end".
>  set $callocsize = (unsigned long long) $rsi
>  continue
>end
>>> break *(calloc-15694047) if $callocsize == 56
Breakpoint 3 at 0x7ffff6ef8d01
>>> c
Continuing.
─── Output/messages ───────────────────────────────────────────────────────────────────────────────
Running main() from /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc
[==========] Running 14 tests from 2 test cases.
[----------] Global test environment set-up.
[----------] 11 tests from TestGraphFixture__rmw_fastrtps_cpp
[ RUN      ] TestGraphFixture__rmw_fastrtps_cpp.test_rcl_get_and_destroy_topic_names_and_types
─── Output/messages ───────────────────────────────────────────────────────────────────────────────
─── Assembly ──────────────────────────────────────────────────────────────────────────────────────
Selected thread is running.
─── Expressions ───────────────────────────────────────────────────────────────────────────────────
─── History ───────────────────────────────────────────────────────────────────────────────────────
─── Memory ────────────────────────────────────────────────────────────────────────────────────────
─── Registers ─────────────────────────────────────────────────────────────────────────────────────
─── Source ────────────────────────────────────────────────────────────────────────────────────────
─── Stack ─────────────────────────────────────────────────────────────────────────────────────────
─── Threads ───────────────────────────────────────────────────────────────────────────────────────
[1] id 1308 name test_graph__rmw (running)
───────────────────────────────────────────────────────────────────────────────────────────────────
Selected thread is running.
>>>
─── Output/messages ───────────────────────────────────────────────────────────────────────────────
─── Assembly ──────────────────────────────────────────────────────────────────────────────────────
Selected thread is running.
─── Expressions ───────────────────────────────────────────────────────────────────────────────────
─── History ───────────────────────────────────────────────────────────────────────────────────────
─── Memory ────────────────────────────────────────────────────────────────────────────────────────
─── Registers ─────────────────────────────────────────────────────────────────────────────────────
─── Source ────────────────────────────────────────────────────────────────────────────────────────
─── Stack ─────────────────────────────────────────────────────────────────────────────────────────
─── Threads ───────────────────────────────────────────────────────────────────────────────────────
[1] id 1308 name test_graph__rmw (running)
───────────────────────────────────────────────────────────────────────────────────────────────────
...
>>> ─── Assembly ──────────────────────────────────────────────────────────────────────────────────────
0x00007ffff643611f rmw_names_and_types_fini+111 movl   $0xf1f1f1f1,0x7fff8000(%r13)
0x00007ffff643612a rmw_names_and_types_fini+122 movl   $0xf2f2f2f2,0x7fff8084(%r13)
0x00007ffff6436135 rmw_names_and_types_fini+133 movl   $0xf3f3f3f3,0x7fff8108(%r13)
0x00007ffff6436140 rmw_names_and_types_fini+144 mov    %fs:0x28,%rax
0x00007ffff6436149 rmw_names_and_types_fini+153 mov    %rax,-0x28(%rbp)
0x00007ffff643614d rmw_names_and_types_fini+157 xor    %eax,%eax
0x00007ffff643614f rmw_names_and_types_fini+159 cmpq   $0x0,-0x8b8(%rbp)
─── Expressions ───────────────────────────────────────────────────────────────────────────────────
─── History ───────────────────────────────────────────────────────────────────────────────────────
─── Memory ────────────────────────────────────────────────────────────────────────────────────────
─── Registers ─────────────────────────────────────────────────────────────────────────────────────
   rax 0x00007ffff64360b0           rbx 0x00007fffffff0af0           rcx 0x0000000000000000
   rdx 0x0000000000000000           rsi 0x0000000000000000           rdi 0x00007fffffff1e40
   rbp 0x00007fffffff1390           rsp 0x00007fffffff0ad0            r8 0x00007fffffff1400
    r9 0x0000000000000000           r10 0x0000000000000024           r11 0x00007ffff64360b0
   r12 0x00007fffffff1370           r13 0x00000fffffffe15e           r14 0x00007fffffff0af0
   r15 0x0000000000000000           rip 0x00007ffff6436140        eflags [ IF ]
    cs 0x00000033                    ss 0x0000002b                    ds 0x00000000
    es 0x00000000                    fs 0x00000000                    gs 0x00000000
─── Source ────────────────────────────────────────────────────────────────────────────────────────
81   return RMW_RET_OK;
82 }
83
84 rmw_ret_t
85 rmw_names_and_types_fini(rmw_names_and_types_t * names_and_types)
86 {
87   if (!names_and_types) {
88     RMW_SET_ERROR_MSG("names_and_types is null");
89     return RMW_RET_INVALID_ARGUMENT;
90   }
91   if (names_and_types->names.size && !names_and_types->types) {
─── Stack ─────────────────────────────────────────────────────────────────────────────────────────
[0] from 0x00007ffff6436140 in rmw_names_and_types_fini+144 at /opt/ros2_asan_ws/src/ros2/rmw/rmw/src/names_and_types.c:86
arg names_and_types = 0x7fffffff1e40
[1] from 0x00007ffff6bb8756 in rcl_names_and_types_fini+62 at /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/graph.c:213
arg topic_names_and_types = 0x7fffffff1e40
[+]
─── Threads ───────────────────────────────────────────────────────────────────────────────────────
[10] id 1335 name test_graph__rmw from 0x00007ffff6000567 in __libc_recvmsg+71 at ../sysdeps/unix/sysv/linux/recvmsg.c:28
[9] id 1334 name test_graph__rmw from 0x00007ffff6000567 in __libc_recvmsg+71 at ../sysdeps/unix/sysv/linux/recvmsg.c:28
[8] id 1333 name test_graph__rmw from 0x00007ffff6000567 in __libc_recvmsg+71 at ../sysdeps/unix/sysv/linux/recvmsg.c:28
[7] id 1319 name test_graph__rmw from 0x00007ffff577dbb7 in epoll_wait+87 at ../sysdeps/unix/sysv/linux/epoll_wait.c:30
[6] id 1318 name test_graph__rmw from 0x00007ffff5ffb9f3 in futex_wait_cancelable+27 at ../sysdeps/unix/sysv/linux/futex-internal.h:88
[5] id 1315 name test_graph__rmw from 0x00007ffff6000567 in __libc_recvmsg+71 at ../sysdeps/unix/sysv/linux/recvmsg.c:28
[4] id 1314 name test_graph__rmw from 0x00007ffff6000567 in __libc_recvmsg+71 at ../sysdeps/unix/sysv/linux/recvmsg.c:28
[3] id 1313 name test_graph__rmw from 0x00007ffff6000567 in __libc_recvmsg+71 at ../sysdeps/unix/sysv/linux/recvmsg.c:28
[2] id 1312 name test_graph__rmw from 0x00007ffff577dbb7 in epoll_wait+87 at ../sysdeps/unix/sysv/linux/epoll_wait.c:30
[1] id 1308 name test_graph__rmw from 0x00007ffff6436140 in rmw_names_and_types_fini+144 at /opt/ros2_asan_ws/src/ros2/rmw/rmw/src/names_and_types.c:86
───────────────────────────────────────────────────────────────────────────────────────────────────

Thread 1 "test_graph__rmw" hit Breakpoint 4, rmw_names_and_types_fini (names_and_types=0x7fffffff1e40) at /opt/ros2_asan_ws/src/ros2/rmw/rmw/src/names_and_types.c:86
86	{
bt
#0  rmw_names_and_types_fini (names_and_types=0x7fffffff1e40) at /opt/ros2_asan_ws/src/ros2/rmw/rmw/src/names_and_types.c:86
#1  0x00007ffff6bb8756 in rcl_names_and_types_fini (topic_names_and_types=0x7fffffff1e40) at /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/graph.c:213
#2  0x0000555555588de1 in TestGraphFixture__rmw_fastrtps_cpp_test_rcl_get_and_destroy_topic_names_and_types_Test::TestBody (this=0x606000001ca0) at /opt/ros2_asan_ws/src/ros2/rcl/rcl/test/rcl/test_graph.cpp:174
#3  0x0000555555649216 in testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void> (object=0x606000001ca0, method=&virtual testing::Test::TestBody(), location=0x555555676dc0 "the test body") at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
#4  0x000055555563b36a in testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void> (object=0x606000001ca0, method=&virtual testing::Test::TestBody(), location=0x555555676dc0 "the test body") at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
#5  0x00005555555e7e52 in testing::Test::Run (this=0x606000001ca0) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2522
#6  0x00005555555e927d in testing::TestInfo::Run (this=0x612000000040) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2703
#7  0x00005555555e9e21 in testing::TestCase::Run (this=0x611000000400) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2825
#8  0x0000555555604f32 in testing::internal::UnitTestImpl::RunAllTests (this=0x615000000800) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:5216
#9  0x000055555564bcc9 in testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool> (object=0x615000000800, method=(bool (testing::internal::UnitTestImpl::*)(testing::internal::UnitTestImpl * const)) 0x555555604842 <testing::internal::UnitTestImpl::RunAllTests()>, location=0x55555567ae60 "auxiliary test code (environments or event listeners)") at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
#10 0x000055555563d633 in testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool> (object=0x615000000800, method=(bool (testing::internal::UnitTestImpl::*)(testing::internal::UnitTestImpl * const)) 0x555555604842 <testing::internal::UnitTestImpl::RunAllTests()>, location=0x55555567ae60 "auxiliary test code (environments or event listeners)") at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
#11 0x0000555555601cc6 in testing::UnitTest::Run (this=0x5555558bea80 <testing::UnitTest::GetInstance()::instance>) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:4824
#12 0x00005555555d5215 in RUN_ALL_TESTS () at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/include/gtest/gtest.h:2370
#13 0x00005555555d515b in main (argc=1, argv=0x7fffffff4b28) at /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:36
```
</details>

Note that this comes from [rcl/test/rcl/test_graph.cpp#L172](https://github.com/ros2/rcl/blob/master/rcl/test/rcl/test_graph.cpp#L172). Inspecting the code that creates the leak below, we observe that there's simply no call to such `rcl_names_and_types_fini` function.

Fix for the bug is available at https://github.com/vmayoral/rcl/commit/ec0e62cd04453f7968fa47f580289d3d06734a1d.


## Resources
- [1] [Tutorial 1: Robot sanitizers in ROS 2 Dashing](../tutorial1/)
- [2] https://github.com/google/sanitizers/wiki/AddressSanitizerAndDebugger
- [3] https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizerVsHeapChecker
- [4] https://www.ibm.com/developerworks/community/blogs/IMSupport/entry/LINUX_GDB_IDENTIFY_MEMORY_LEAKS?lang=en
- [5] https://www.usenix.org/system/files/conference/atc12/atc12-final39.pdf