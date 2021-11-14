\newpage

## WIP: Tutorial 9: Looking at DDS middleware flaws 

### Looking at RTPS
Several potential vulnerabilities have been detected in RTPS's , refer to the annotated version of the standard available in this same folder.

In order to look at these potential flaws in RTPS, we'll be implementing an RTPS layer in scapy and use it as the bases of robosploit's tool. The following paragraphs describe this:



### DDS implementations
Ideally, several DDS implementation would allow for comparisons.

`LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.4`

#### FastRTPS

Let's review some of the flaws found though FastRTPS

##### rcl: heap-use-after-free on address, https://github.com/aliasrobotics/RVD/issues/223

Couldn't reproduce the flaw with ASan, trying with TSan. Neither

##### <Race conditions>
Read a bit about them:
- https://resources.securitycompass.com/blog/moving-beyond-the-owasp-top-10-part-1-race-conditions-2#
- https://sakurity.com/blog/2015/05/21/starbucks.html
