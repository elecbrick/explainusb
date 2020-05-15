# explainusb
## USB Protocol Analyzer: decode data transfers
Simplify learning and see what logical fields differ between actual with
expected results during testing and verification.
Decode, Analyze and Explain the differences between received and expected
packets in a simulation environment.
Several tools are provided that include:
- USB packet decoding and analysis
  * Convert D+/D- signals to NRZI signals
  * Convert NRZI signals to USB packets
  * Unpack standard USB packets into named fields
- USB signal extractor to reduce the size of VCD files

USB Protocol Decoder and comparator for testing and verification of USB
support. Routines are provided to show details of what was received and
to show differences in packet fields from what was expected.

### Environment:
For maximum flexibility, this module works stand-alone reading vcd signal dump
files or with a simulator using [cocotb](https://docs.cocotb.org/en/latest/) and
[cocotb_usb](https://github.com/antmicro/usb-test-suite-cocotb-usb).

### Design Philosophy:
No exceptions are thrown from this code.  Violations encountered while decoding
will issue a message through the logging system. These logs will indicate the
severity.  A mismatch between actual and expected results will result in an
error message.  It is left to the application to determine whether to abort or
proceede when an error is encountered.  Simulation should not be aborted just
because a slightly different response was received than was expected.

## Modules:
### explainusb
The Analyze class maintains stream state by monitoring the bidirectional packet
flow in order to provide correct decoding of data packets as packet content
is dependent on the state of the connection.

The calls sent, received and explain take packets as their parameters. These
parameters can be a previously decoded packet or any of the valid initializers
for the packet sub-module.

#### Usage:
```Python
from explainusb import Analyze
...
def from_host_to_device:
    # Update flow state whenever the host sends a packet to the device:
    Analyze.sent(packet)
    ...

def from_device_to_host:
    # Update flow state whenever the host receives a packet from the device:
    Analyze.received(actual)
    ...

def compare_received_with_expected:
    # If the received packet is not the same as the expected one, show each
    # field in the recevied and expected packets and highlight the differences.
    if actual != expected:
	Analyze.explain(actual, expected)
	# Application can allow test to continue or raise an exception
    ...
```

### explainusb.packet
The USBPacket object is the main part of this module. It may be initialized by
passing:
1. A string of JK characters starting with SYNC and ending with EOP pattern
2. A pair of strings or lists of '0','1' characters or 0,1 digits for D+/D-
3. A list of bytes, the content between but excluding SYNC and EOP

For example, the following are all equivalent initializers:
```Python
    USBPacket("KJKJKJKKJJKJJKKK__J")
    USBPacket(("0101010011011000001", "1010101100100111000"))
    USBPacket(((0,1,0,1,0,1,0,0,1,1,0,1,1,0,0,0,0,0,1,),
	  (1,0,1,0,1,0,1,1,0,0,1,0,0,1,1,1,0,0,0,)))
    USBPacket([210])
```
and each one creates an ACK packet.  

### explainusb.descriptor
Standard descriptors are supported along with a few others at the moment.
In particular, HID and mass storage are works in progress.

The descriptor module is data-driven and designed so that new protocols can be
easily added.
