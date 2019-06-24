# Robot sanitizers with GDB

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
rcl,detected memory leaks,__default_zero_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56,4,"    #0 0x7f762845bd38 in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xded38)
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

We can clearly see that the two direct leaks are related to `/opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56`. Let's grab gdb and jump into it.

## Using GDB to understand better the leak
We'll be using GDB while in combination with [2]. Let's start by setting up a proper (comfortable) gdb environment:
```bash
cd ~
wget -P ~ git.io/.gdbinit
```

---

After some work with [2] and related sources, it appears that `LeakSanitizer does not work under ptrace (strace, gdb, etc)`. Haven't been able to dig more details about the use of gdb here.

---

TODO: dig a bit more on the code of this vulnerability and attempt to fix it if time allows for it.

## Trying with another vulnerability
TODO

## Resources
- [1] [Tutorial 1: Robot sanitizers in ROS 2 Dashing](../tutorial1/)
- [2] https://github.com/google/sanitizers/wiki/AddressSanitizerAndDebugger