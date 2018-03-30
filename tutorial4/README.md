# Return-Oriented Programming (ROP)

Return-Oriented Programming or ROP for short combines a large number of short instruction sequences to build *gadgets* that  allow arbitrary computation. From [3]:

> Return Oriented Programming (ROP) is a powerful technique used to counter common exploit prevention strategies. In particular, ROP is useful for circumventing Address Space Layout Randomization (ASLR)1 and DEP2. When using ROP, an attacker uses his/her control over the stack right before the return from a function to direct code execution to some other location in the program. Except on very hardened binaries, attackers can easily find a portion of code that is located in a fixed location (circumventing ASLR) and which is executable (circumventing DEP). Furthermore, it is relatively straightforward to chain several payloads to achieve (almost) arbitrary code execution.


----

**Note**: as in previous tutorials, there's a docker container that facilitates reproducing the work of this tutorial. The container can be built with:
```bash
docker build -t basic_cybersecurity3:latest .
```
and runned with:
```bash
docker run --privileged -it basic_cybersecurity3:latest
```

----

The structure of a ROP attack can be summarized as follows:
- Find a vulnerability that allows the attacker to gain control over the stack
- ...

### Finding a vulnerability, a simple overflow


### Additional resources
- ROP
  - https://cseweb.ucsd.edu/~hovav/dist/geometry.pdf
  - https://www.usenix.org/legacy/event/sec11/tech/full_papers/Schwartz.pdf
  - http://www.scs.stanford.edu/brop/
- ROP practical
  - https://github.com/0vercl0k/rp
  - http://codearcana.com/posts/2013/05/28/introduction-to-return-oriented-programming-rop.html
  - https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/
