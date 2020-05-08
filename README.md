# explainusb
## USB Protocol Analyzer that decodes USB data transfers to simplify learning and compares actual with expected results for testing and verification.

Decode, Analyze and Explain the differences between received and expected packets in a simulation environment.
Several tools are provided that include:
* USB packet decoding and analysis
  * Convert D+/D- signals to JK format NRZI signals
  * Convert NRZI signals to USB packets
  * Unpack standard USB packets into named fields
* USB signal extractor from VCD files

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

#### Usage:
```Python
from explainusb import Analyze
...
def from_host_to_device:
    # Update flow state on outgoing packet:
    Analyze.sent(packet)
    ...

def from_device_to_host:
    # Incoming packet:
    Analyze.received(actual)
    ...

def discrepency_detected:
    # If the received packet is not the same as the expected one, this function
    # can show each field in the recevied and expected packets and highlight
    # any differences.
    Analyze.explain(actual, expected)
    ...
```

### explainusb.packet
Packet: May be initialized by passing:
1. A string of JK characters starting with SYNC and ending with EOP pattern
2. A pair of strings or lists of '0','1' characters or 0,1 digits for D+/D-
3. A list of bytes, the content between but excluding SYNC and EOP
For example:
```Python
"
### explainusb.descriptor
Standard descriptors are supported along with a few others at the moment.
In particular, HID and mass storage are works in progress.
