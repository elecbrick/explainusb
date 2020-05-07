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
For maximum flexibility, this module works with stand-alone or with cocotb_usb.

### Design Philosophy:
Mismatch handling can give a warning, an error or be fatal.
Simulation should be allowed to proceed and not aborted just because
the client gave a different response than expected.

## Modules:
### explainusb
The Analyze class handles stream state including end point management and
remembering the transfer state of endpoint 0 in order to provide correct
decoding of data packets.
### explainusb.packet
Packet: May be initialized by passing:
1. A string of JK characters starting with SYNC and ending with EOP pattern
2. A pair of strings of 01 characters for D+/D-
3. A list of bytes, the content between but excluding SYNC and EOP
### explainusb.descriptor
Standard descriptors are supported along with a few others at the moment.
In particular, HID and mass storage are works in progress.

## Usage:
`from explainusb import Analyze`

In order to decode incomming packets correctly, outgoing packets should call:
```Python
    Analyze.sent(packet)
```

Likewise, all ingoing packets should call:
```Python
    Analyze.received(actual)
```

If the received packet is not the same as the expected one, this last function
show each field in the recevied and expected packets and highlights the
differences.
```Python
    Analyze.explain(actual, expected)
```
