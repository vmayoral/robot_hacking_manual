### Exploiting

In this tutorial we'll review how to proceed with a buffer overflow and exploit it.

Content is heavily based on [1]:

----

**Note**: as in previous tutorials, there's a docker container that facilitates reproducing the work of this tutorial. The container can be built with:
```bash
docker build -t basic_cybersecurity3:latest .
```
and run with:
```bash
docker run --privileged -v $(pwd):/root/tutorial -it basic_cybersecurity3:latest
```

----

### Bibliography
- [1] A. One (1996). Smashing the Stack for Fun and Profit. Phrack, 7. Retrieved from http://insecure.org/stf/smashstack.html.
