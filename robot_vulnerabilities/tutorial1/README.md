# Robot sanitizers in ROS 2 Dashing

Sanitizers are dynamic bug finding tools[1]. In this tutorial we'll use some common and open source sanitizers over the ROS 2 codebase. In particular, by reproducing previously available results[2,3], we'll review the security status of ROS 2 Dashing Diademata.

The first few sections provide a walkthrough on the attempt to make things run in OS X. The sections that follow automate the process through a Docker container.

## OS X
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

### Compile the code with sanitizers enabled (OS X)
#### AddressSanitizer (ASan)
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

#### ThreadSanitizer (TSan)
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

### Known Issues
#### Linking issues in FastRTPS when enabling security
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

#### Results of the test indicate `Interceptors are not working. This may be because AddressSanitizer is loaded too late ... interceptors not installed`

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

## Docker
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

## Resources
- [1] https://arxiv.org/pdf/1806.04355.pdf
- [2] https://discourse.ros.org/t/introducing-ros2-sanitizer-report-and-analysis/9287
- [3] https://github.com/colcon/colcon-sanitizer-reports/blob/master/README.rst
- [4] https://github.com/colcon/colcon-sanitizer-reports
- [5] https://github.com/ccache/ccache
- [6] https://github.com/google/sanitizers/wiki/AddressSanitizer
- [7] https://github.com/google/sanitizers/wiki/ThreadSanitizerCppManual