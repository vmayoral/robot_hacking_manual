\newpage

## Robot sanitizers in ROS 2 Dashing

Sanitizers are dynamic bug finding tools[1]. In this tutorial we'll use some common and open source sanitizers over the ROS 2 codebase. In particular, by reproducing previously available results[2,3], we'll review the security status of ROS 2 Dashing Diademata.

The first few sections provide a walkthrough on the attempt to make things run in OS X. The sections that follow automate the process through a Docker container.

### OS X

<details><summary>Setup in OS X, natively</summary>

### Setup
For the setup, I'm working in an OS X 10.14 machine:
```bash
# mixins are configuration files used to compile ROS 2 easily
pip3 install colcon-mixin
colcon mixin add default https://raw.githubusercontent.com/colcon/colcon-mixin-repository/master/index.yaml
colcon mixin update default

# Create workspace
mkdir -p ~/ros2_asan_ws/src
cd ~/ros2_asan_ws

# colcon-santizer-reports for analyzing ROS 2
#   a plugin for colcon test that parses sanitizer issues 
#   from stdout/stderr, deduplicates the issues, and outputs them to a CSV.
git clone https://github.com/colcon/colcon-sanitizer-reports.git
cd colcon-sanitizer-reports
sudo python3 setup.py install

# setup ccache to speed-up dev. process
#  speeds up recompilation by caching the result of previous compilations 
#  and detecting when the same compilation is being done again
#  https://github.com/ccache/ccache
brew install ccache
ccache -M 20G # increase cache size
# # Add the following to your .bashrc or .zshrc file and restart your terminal:
# echo 'export CC=/usr/lib/ccache/gcc' >> ~/.bash_profile
# echo 'export CXX=/usr/lib/ccache/g++' >> ~/.bash_profile
export PATH="/usr/local/opt/ccache/libexec:$PATH" >> ~/.bash_profile

# Fetch ROS 2 Dashing code (at the time of writing, it's the lastest release)
wget https://raw.githubusercontent.com/ros2/ros2/release-latest/ros2.repos
# wget https://raw.githubusercontent.com/ros2/ros2/master/ros2.repos # fetch latest status of the code instead
vcs import src < ros2.repos

# Ignore a bunch of packages that aren't intentended to be tested
touch src/ros2/common_interfaces/actionlib_msgs/COLCON_IGNORE
touch src/ros2/common_interfaces/common_interfaces/COLCON_IGNORE
touch src/ros2/rosidl_typesupport_opensplice/opensplice_cmake_module/COLCON_IGNORE
touch src/ros2/rmw_fastrtps/rmw_fastrtps_dynamic_cpp/COLCON_IGNORE
touch src/ros2/rmw_opensplice/rmw_opensplice_cpp/COLCON_IGNORE
touch src/ros2/ros1_bridge/COLCON_IGNORE
touch src/ros2/rosidl_typesupport_opensplice/rosidl_typesupport_opensplice_c/COLCON_IGNORE
touch src/ros2/rosidl_typesupport_opensplice/rosidl_typesupport_opensplice_cpp/COLCON_IGNORE
touch src/ros2/common_interfaces/shape_msgs/COLCON_IGNORE
touch src/ros2/common_interfaces/stereo_msgs/COLCON_IGNORE
touch src/ros2/common_interfaces/trajectory_msgs/COLCON_IGNORE

```

#### Compile the code with sanitizers enabled (OS X)
##### AddressSanitizer (ASan)
For ASan[6] we compile the ROS 2 Dashing code as follows:
```bash
# Get last version of FastRTPS
cd src/eProsima/Fast-RTPS/
git checkout master
git pull

# Install openssl
brew install openssl

# Env variables to compile from source in OS X
export CMAKE_PREFIX_PATH=$CMAKE_PREFIX_PATH:/usr/local/opt/qt
export PATH=$PATH:/usr/local/opt/qt/bin
export OPENSSL_ROOT_DIR=`brew --prefix openssl`

# Compile code 
colcon build --build-base=build-asan --install-base=install-asan \
    --cmake-args -DOSRF_TESTING_TOOLS_CPP_DISABLE_MEMORY_TOOLS=ON \
                 -DINSTALL_EXAMPLES=OFF -DSECURITY=ON --no-warn-unused-cli \
                 -DCMAKE_BUILD_TYPE=Debug \
    --mixin asan-gcc \
    --packages-up-to test_communication \
    --symlink-install
```

and then launch the tests:
```bash
colcon test --build-base=build-asan --install-base=install-asan \
    --event-handlers sanitizer_report+ --packages-up-to test_communication
```

##### ThreadSanitizer (TSan)
For TSan[7] TODO
```bash
# Build the code with tsan
colcon build --build-base=build-tsan --install-base=install-tsan \
    --cmake-args -DOSRF_TESTING_TOOLS_CPP_DISABLE_MEMORY_TOOLS=ON \
                 -DINSTALL_EXAMPLES=OFF -DSECURITY=ON --no-warn-unused-cli \
                 -DCMAKE_BUILD_TYPE=Debug \
    --mixin tsan \
    --packages-up-to test_communication \
    --symlink-install

# Run the tests
colcon test --build-base=build-tsan --install-base=install-tsan \
    --event-handlers sanitizer_report+ --packages-up-to test_communication
```

#### Known Issues
##### Linking issues in FastRTPS when enabling security
The following happens with the version included in the Dashing Release:
```bash
--- stderr: fastrtps
Undefined symbols for architecture x86_64:
  "_DH_get_2048_256", referenced from:
      generate_dh_key(int, eprosima::fastrtps::rtps::security::SecurityException&) in PKIDH.cpp.o
      generate_dh_peer_key(std::__1::vector<unsigned char, std::__1::allocator<unsigned char> > const&, eprosima::fastrtps::rtps::security::SecurityException&, int) in PKIDH.cpp.o
  "_X509_get0_signature", referenced from:
      get_signature_algorithm(x509_st*, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&, eprosima::fastrtps::rtps::security::SecurityException&) in PKIDH.cpp.o
      get_signature_algorithm(x509_st*, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&, eprosima::fastrtps::rtps::security::SecurityException&) in Permissions.cpp.o
ld: symbol(s) not found for architecture x86_64
clang: error: linker command failed with exit code 1 (use -v to see invocation)
make[2]: *** [src/cpp/libfastrtps.1.8.0.dylib] Error 1
make[1]: *** [src/cpp/CMakeFiles/fastrtps.dir/all] Error 2
make: *** [all] Error 2
---
Failed   <<< fastrtps	[ Exited with code 2 ]
```

Solution: install latest version of Fast-RTPS

##### Results of the test indicate `Interceptors are not working. This may be because AddressSanitizer is loaded too late ... interceptors not installed`

```bash
...
--
log/latest_test/test_communication/stdout.log:21: [test_subscriber-12] ==3301==ERROR: Interceptors are not working. This may be because AddressSanitizer is loaded too late (e.g. via dlopen). Please launch the executable with:
log/latest_test/test_communication/stdout.log-21: [test_subscriber-12] DYLD_INSERT_LIBRARIES=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/10.0.1/lib/darwin/libclang_rt.asan_osx_dynamic.dylib
log/latest_test/test_communication/stdout.log-21: [test_subscriber-12] "interceptors not installed" && 0
log/latest_test/test_communication/stdout.log-21: [ERROR] [test_subscriber-12]: process has died [pid 3301, exit code -6, cmd '/usr/local/opt/python/bin/python3.7 /Users/victor/ros2_asan_ws/src/ros2/system_tests/test_communication/test/subscriber_py.py Defaults /test_time_15_20_17'].
--
log/latest_test/test_communication/stdout.log:21: [test_subscriber-14] ==3303==ERROR: Interceptors are not working. This may be because AddressSanitizer is loaded too late (e.g. via dlopen). Please launch the executable with:
log/latest_test/test_communication/stdout.log-21: [test_subscriber-14] DYLD_INSERT_LIBRARIES=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/10.0.1/lib/darwin/libclang_rt.asan_osx_dynamic.dylib
log/latest_test/test_communication/stdout.log-21: [test_subscriber-14] "interceptors not installed" && 0
log/latest_test/test_communication/stdout.log-21: [ERROR] [test_subscriber-14]: process has died [pid 3303, exit code -6, cmd '/usr/local/opt/python/bin/python3.7 /Users/victor/ros2_asan_ws/src/ros2/system_tests/test_communication/test/subscriber_py.py Empty /test_time_15_20_17'].
--
log/latest_test/test_communication/stdout.log:21: [test_subscriber-16] ==3305==ERROR: Interceptors are not working. This may be because AddressSanitizer is loaded too late (e.g. via dlopen). Please launch the executable with:
log/latest_test/test_communication/stdout.log-21: [test_subscriber-16] DYLD_INSERT_LIBRARIES=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/10.0.1/lib/darwin/libclang_rt.asan_osx_dynamic.dylib
log/latest_test/test_communication/stdout.log-21: [test_subscriber-16] "interceptors not installed" && 0
log/latest_test/test_communication/stdout.log-21: [ERROR] [test_subscriber-16]: process has died [pid 3305, exit code -6, cmd '/usr/local/opt/python/bin/python3.7 /Users/victor/ros2_asan_ws/src/ros2/system_tests/test_communication/test/subscriber_py.py MultiNested /test_time_15_20_18'].
--
```

Complete dump at https://gist.github.com/vmayoral/ffcba20d29fc3546ceffeb112d473dd1. It indicates that it should be run with
```bash
DYLD_INSERT_LIBRARIES=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/10.0.1/lib/darwin/libclang_rt.asan_osx_dynamic.dylib
```
</details>

### Docker
```bash
docker build -t basic_cybersecurity_vulnerabilities1:latest .
docker run --privileged -it -v /tmp/log:/opt/ros2_asan_ws/log basic_cybersecurity_vulnerabilities1:latest /bin/bash
```
and now run the tests:
```bash
colcon test --build-base=build-asan --install-base=install-asan \
  --event-handlers sanitizer_report+ --packages-up-to test_communication
```
results are under `/tmp/log`.

### Analyzing results
#### Analyzing example
I'll try and analyze here the example provided at https://github.com/colcon/colcon-sanitizer-reports/blob/master/README.rst before jumping into a new one to gain additional understanding:

It appears that ASan detected memory leaks in the `rcpputils` module:
```bash
grep -R '==.*==ERROR: .*Sanitizer' -A 3
[..]
--
rcpputils/stdout_stderr.log:1: ==32481==ERROR: LeakSanitizer: detected memory leaks
rcpputils/stdout_stderr.log-1:
rcpputils/stdout_stderr.log-1: Direct leak of 4 byte(s) in 1 object(s) allocated from:
rcpputils/stdout_stderr.log-1:     #0 0x7f7d99dac458 in operator new(unsigned long) (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xe0458)
```

Particularly, it appears that the leaks are as follows:
```bash
Direct leak of 4 byte(s) in 1 object(s) allocated from:
    #0 0x7fbefcd0b458 in operator new(unsigned long) (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xe0458)
    #1 0x5620b4c650a9 in FakeGuarded::FakeGuarded() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x190a9)
    #2 0x5620b4c63444 in **test_tsa_shared_capability_Test**::TestBody() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x17444)
    #3 0x5620b4cdc4fd in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x904fd)
    #4 0x5620b4cce1e7 in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x821e7)
    #5 0x5620b4c79f0f in testing::Test::Run() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x2df0f)
    #6 0x5620b4c7b33a in testing::TestInfo::Run() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x2f33a)
    #7 0x5620b4c7bede in testing::TestCase::Run() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x2fede)
    #8 0x5620b4c96fef in testing::internal::UnitTestImpl::RunAllTests() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x4afef)
    #9 0x5620b4cdefb0 in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x92fb0)
    #10 0x5620b4cd04b0 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x844b0)
    #11 0x5620b4c93d83 in testing::UnitTest::Run() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x47d83)
    #12 0x5620b4c672d2 in RUN_ALL_TESTS() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x1b2d2)
    #13 0x5620b4c67218 in main (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x1b218)
    #14 0x7fbefc09bb96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)

Direct leak of 4 byte(s) in 1 object(s) allocated from:
    #0 0x7fbefcd0b458 in operator new(unsigned long) (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xe0458)
    #1 0x5620b4c650a9 in FakeGuarded::FakeGuarded() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x190a9)
    #2 0x5620b4c62d4b in **test_tsa_capability_Test**::TestBody() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x16d4b)
    #3 0x5620b4cdc4fd in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x904fd)
    #4 0x5620b4cce1e7 in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x821e7)
    #5 0x5620b4c79f0f in testing::Test::Run() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x2df0f)
    #6 0x5620b4c7b33a in testing::TestInfo::Run() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x2f33a)
    #7 0x5620b4c7bede in testing::TestCase::Run() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x2fede)
    #8 0x5620b4c96fef in testing::internal::UnitTestImpl::RunAllTests() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x4afef)
    #9 0x5620b4cdefb0 in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x92fb0)
    #10 0x5620b4cd04b0 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x844b0)
    #11 0x5620b4c93d83 in testing::UnitTest::Run() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x47d83)
    #12 0x5620b4c672d2 in RUN_ALL_TESTS() (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x1b2d2)
    #13 0x5620b4c67218 in main (/home/ANT.AMAZON.COM/tmoulard/ros2_ws/build-asan/rcpputils/test_basic+0x1b218)
    #14 0x7fbefc09bb96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
```

Inspecting the dumps, there seems to be an issue in `test_basic` related to `FakeGuarded::FakeGuarded()`. In particular, this [line](https://github.com/ros2/rcpputils/pull/9/files#diff-be1f2d1334d30376c4dec7b53eda0f55L247) wasn't necessary and was replaced by a destructor instead.


#### Processing new bugs
Let's now analyze a new bug and try to reason about it. Let's take the first the `sanitizer_report.csv` generated and from it, the first item (dumped at [sanitizer_report_ros2dashing_asan.csv](sanitizer_report_ros2dashing_asan.csv)):

```bash
rcl,detected memory leaks,__default_zero_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56,2,
 "#0 0x7f1475ca7d38 in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xded38)
  #1 0x7f14753f34d6 in __default_zero_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
  #2 0x7f1475405e77 in rcutils_string_array_init /opt/ros2_asan_ws/src/ros2/rcutils/src/string_array.c:54
  #3 0x7f14751e4b4a in rmw_names_and_types_init /opt/ros2_asan_ws/src/ros2/rmw/rmw/src/names_and_types.c:66
  #4 0x7f1472cda362 in rmw_fastrtps_shared_cpp::__copy_data_to_results(std::map<std::__cxx11::basic_string<char,
    std::char_traits<char>, std::allocator<char> >, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::pair<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > > > > const&, rcutils_allocator_t*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:199
  #5 0x7f1472cdcc4d in rmw_fastrtps_shared_cpp::__rmw_get_topic_names_and_types_by_node(char const*, rmw_node_t const*,
    rcutils_allocator_t*, char const*, char const*, bool, std::function<LockedObject<TopicCache> const& (CustomParticipantInfo&)>&, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:349
  #6 0x7f1472cdd0d4 in rmw_fastrtps_shared_cpp::__rmw_get_publisher_names_and_types_by_node(char const*, rmw_node_t const*,
    rcutils_allocator_t*, char const*, char const*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:385
  #7 0x7f14756a11eb in rmw_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_cpp/src/rmw_node_info_and_types.cpp:53
  #8 0x7f14759669b5 in rcl_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/graph.c:60
  #9 0x55d928637fdd in TestGraphFixture__rmw_fastrtps_cpp_test_rcl_get_publisher_names_and_types_by_node_Test::TestBody() 
    /opt/ros2_asan_ws/src/ros2/rcl/rcl/test/rcl/test_graph.cpp:342
  #10 0x55d9286f0105 in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, 
    void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
  #11 0x55d9286e2259 in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, 
    void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
  #12 0x55d92868ed41 in testing::Test::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2522
  #13 0x55d92869016c in testing::TestInfo::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2703
  #14 0x55d928690d10 in testing::TestCase::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2825
  #15 0x55d9286abe21 in testing::internal::UnitTestImpl::RunAllTests() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/
    gtest_vendor/./src/gtest.cc:5216
  #16 0x55d9286f2bb8 in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, 
    bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
  #17 0x55d9286e4522 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl,
   bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
  #18 0x55d9286a8bb5 in testing::UnitTest::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:4824
  #19 0x55d92867c104 in RUN_ALL_TESTS() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/include/gtest/gtest.h:2370
  #20 0x55d92867c04a in main /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:36
  #21 0x7f1474449b96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)"
```

When browsing through `ros2_asan_ws/log/latest_test`, we can find a similar report under rcl (in the `rcl/stdout_stderr.log` file):
```bash
14: Direct leak of 8 byte(s) in 1 object(s) allocated from:
14:     #0 0x7f1475ca7d38 in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xded38)
14:     #1 0x7f14753f34d6 in __default_zero_allocate /opt/ros2_asan_ws/src/ros2/rcutils/src/allocator.c:56
14:     #2 0x7f1475405e77 in rcutils_string_array_init /opt/ros2_asan_ws/src/ros2/rcutils/src/string_array.c:54
14:     #3 0x7f14751e4b4a in rmw_names_and_types_init /opt/ros2_asan_ws/src/ros2/rmw/rmw/src/names_and_types.c:66
14:     #4 0x7f1472cda362 in rmw_fastrtps_shared_cpp::__copy_data_to_results(std::map<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::pair<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const, std::set<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::less<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > > > > const&, rcutils_allocator_t*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:199
14:     #5 0x7f1472cdcc4d in rmw_fastrtps_shared_cpp::__rmw_get_topic_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, std::function<LockedObject<TopicCache> const& (CustomParticipantInfo&)>&, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:349
14:     #6 0x7f1472cdd0d4 in rmw_fastrtps_shared_cpp::__rmw_get_publisher_names_and_types_by_node(char const*, rmw_node_t const*, rcutils_allocator_t*, char const*, char const*, bool, rmw_names_and_types_t*) /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_shared_cpp/src/rmw_node_info_and_types.cpp:385
14:     #7 0x7f14756a11eb in rmw_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rmw_fastrtps/rmw_fastrtps_cpp/src/rmw_node_info_and_types.cpp:53
14:     #8 0x7f14759669b5 in rcl_get_publisher_names_and_types_by_node /opt/ros2_asan_ws/src/ros2/rcl/rcl/src/rcl/graph.c:60
14:     #9 0x55d928637fdd in TestGraphFixture__rmw_fastrtps_cpp_test_rcl_get_publisher_names_and_types_by_node_Test::TestBody() /opt/ros2_asan_ws/src/ros2/rcl/rcl/test/rcl/test_graph.cpp:342
14:     #10 0x55d9286f0105 in void testing::internal::HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
14:     #11 0x55d9286e2259 in void testing::internal::HandleExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
14:     #12 0x55d92868ed41 in testing::Test::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2522
14:     #13 0x55d92869016c in testing::TestInfo::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2703
14:     #14 0x55d928690d10 in testing::TestCase::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2825
14:     #15 0x55d9286abe21 in testing::internal::UnitTestImpl::RunAllTests() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:5216
14:     #16 0x55d9286f2bb8 in bool testing::internal::HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2447
14:     #17 0x55d9286e4522 in bool testing::internal::HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2483
14:     #18 0x55d9286a8bb5 in testing::UnitTest::Run() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/./src/gtest.cc:4824
14:     #19 0x55d92867c104 in RUN_ALL_TESTS() /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/include/gtest/gtest.h:2370
14:     #20 0x55d92867c04a in main /opt/ros2_asan_ws/install-asan/gtest_vendor/src/gtest_vendor/src/gtest_main.cc:36
14:     #21 0x7f1474449b96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
```

which means that the corresponding test that triggers this memory leak lives within `build-asan/rcl`. Reviewing stack and the directory, it's fairly easy to find that `test_graph__rmw_fastrtps_cpp` is the test that triggers this error https://gist.github.com/vmayoral/44214f6290a6647e606d716d8fe2ca68.

According to ASan documentation [8]:

> LSan also differentiates between direct and indirect leaks in its output. This gives useful information about which leaks should be prioritized, because fixing the direct leaks is likely to fix the indirect ones as well.

which tells us where to focus first. Direct leaks from this first report are:
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

A complete report with all the bugs found is available at [sanitizer_report_ros2dashing_asan.csv](sanitizer_report_ros2dashing_asan.csv).

A further discussion into this bug and an analysis with GDB is available at [tutorial3](../tutorial3).

### Looking for bugs and vulnerabilities with ThreadSanitizer (TSan)

Similar to ASan, we can use the ThreadSanitizer:

```bash
docker build -t basic_cybersecurity_vulnerabilities1:latest .
docker run --privileged -it -v /tmp/log:/opt/ros2_moveit2_ws/log basic_cybersecurity_vulnerabilities1:latest /bin/bash
colcon test --build-base=build-tsan --install-base=install-tsan --event-handlers sanitizer_report+ --packages-up-to test_communication
```

A complete report with all the bugs found is available at [sanitizer_report_ros2dashing_tsan.csv](sanitizer_report_ros2dashing_tsan.csv).



### Resources
- [1] https://arxiv.org/pdf/1806.04355.pdf
- [2] https://discourse.ros.org/t/introducing-ros2-sanitizer-report-and-analysis/9287
- [3] https://github.com/colcon/colcon-sanitizer-reports/blob/master/README.rst
- [4] https://github.com/colcon/colcon-sanitizer-reports
- [5] https://github.com/ccache/ccache
- [6] https://github.com/google/sanitizers/wiki/AddressSanitizer
- [7] https://github.com/google/sanitizers/wiki/ThreadSanitizerCppManual
- [8] https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizerVsHeapChecker