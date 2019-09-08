# Robot sanitizers with Gazebo

Let's start by compiling the moveit2 workspace by hand using ASan flags:

```bash
colcon build --build-base=build-asan --install-base=install-asan --cmake-args -DOSRF_TESTING_TOOLS_CPP_DISABLE_MEMORY_TOOLS=ON  -DINSTALL_EXAMPLES=OFF -DSECURITY=ON --no-warn-unused-cli -DCMAKE_BUILD_TYPE=Debug --mixin asan-gcc --merge-install
```


## Resources
- [1] https://www.usenix.org/system/files/conference/atc12/atc12-final39.pdf
