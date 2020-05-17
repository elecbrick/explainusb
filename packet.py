#!/usr/bin/python3.6

# Copyright (c) 2020, Doug Eaton
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'''
USB Protocol Decoder and comparator for testing and verification of USB
support. Routines are provided to show details of what was received and
a clearly show differences from what was expected.

Environment:
-----------
Works with stand-alone or with cocotb_usb.

Design Philosophy:
-----------------

Packet: May be initialized by
    1. a string of JK characters starting with SYNC and ending with EOP pattern
    2. a pair of strings of 01 characters for D+/D-
    3. a list of bytes, the content between but excluding SYNC and EOP

Mismatch handling can give a warning, an error or be fatal.
Simulation should be allowed to proceed and not aborted just because
the client gave a different response than expected.
------------------------------------------------------------------- '''

from enum import Enum, IntEnum
from array import array
import inspect
import fileinput
import pprint
import logging
import sys
import re
from explainusb.descriptors import descriptor_data

# Use cocotb logging if available. Use the built in logging module otherwise.
# The color routines check if stdout is a tty.
SAME_COLOR=''
DIFF_COLOR=''
try:
    from cocotb.log import SimLog
    from cocotb.utils import want_color_output
    import cocotb.ANSI as ANSI
    logger = SimLog("cocotb.usb.explain")
    #logger.setLevel(logging.DEBUG)
    if want_color_output():
        SAME_COLOR=ANSI.COLOR_INFO
        DIFF_COLOR=ANSI.COLOR_ERROR
except ImportError:
    logger = logging


# Create a pretty printer object to display descriptors as structures.
# Leave list unsorted if the option is available.
if sys.version_info >= (3, 8):
    pp=pprint.PrettyPrinter(sort_dicts=False)
else:
    pp=pprint.PrettyPrinter()

# Use UTF empty set symbol for non-existant field in packet comparisons as long
# as environment is not limited to 8-bit characters.
import locale
NONEXISTENT='-'
if 'UTF-8' in locale.getdefaultlocale():
    NONEXISTENT="∅"

class DecodeError(Enum):
    # Link Level Errors (incorrect bit patterns or signal integrity)
    InvalidToken =      "Unexpected character in bitstream"
    BitStuffViolation = "Bit stuffing violation"
    FalseEOP =          "False EOP detected"
    InvalidSync =       "Packet does not start with Sync pattern"
    InvalidEOP =        "EOP expected but not present"
    # Network Level Errors (incorrect packet size or contents)
    IncorrectCRC =      "CRC Mismatch"
    InvalidPID =        "Invalid PID" # likely bit error
    # Application Level Errors (mismatch from expected result)
    IncorrectLength =   "Packet length not required size"
    UnimplementedPacket="Format not supported"
    UnexpectedResult =  "Response differs from expected"

def bytes2bitstring(data):
    # Convert array of 8-bit bytes into string of 0s and 1s.
    bitstring = ""
    for b in data:
        bitstring += ("{0:08b}".format(b))[::-1]
    return bitstring

def bitstring2bytes(bitstring):
    # Convert string of 0s and 1s into array of 8-bit bytes.
    data = []
    while (len(bitstring)>8):
        data.append(int(bitstring[:8][::-1], 2))
        bitstring=bitstring[8:]
    data.append(int(bitstring[::-1], 2))
    return data

def xor(x, y):
    # perform xor on two lists or strings of the same length
    assert len(x)==len(y)
    result = []
    for i in range(0,len(x)):
        if x[i]==y[i]:
            result.append('0')
        else:
            result.append('1')
    return result

def crc5(bitstring):
    # Input:  bitstring, length=11
    # Output: bitstring, length=5
    #logger.debug(f"Calculating CRC5 of {bitstring}")
    G5 = ('0','0','1','0','1')  # 0x14
    crc = ['1','1','1','1','1'] # 0x1F
    data = list(bitstring)
    while (len(data)>0):
        nextb=data.pop(0);
        if nextb!='0' and nextb!='1':
            continue  # ignore invalid characters
        if nextb == crc.pop(0):
            crc.append('0')
        else:
            crc.append('0')
            crc=xor(crc, G5)
    # invert shift reg contents to produce final crc value
    bitstring=""
    for nextb in crc: 
        bitstring+=chr(ord(nextb)^1)
    #logger.debug(f"Calculated CRC5 is {bitstring}")
    return bitstring

def crc16(data):
    # Input:  array of bytes
    # Output: 16-bit integer
    #logger.debug(f"Calculating CRC16 of {data}")
    G16 = 0xA001        # 1000000000000101 (lsb first)
    crc = 0xFFFF
    for byte in data:
        for i in range(0,8):
            bit=byte&1
            byte>>=1
            if bit==crc&1:
                crc=crc>>1
            else:
                crc=crc>>1
                crc^=G16
    # invert shift reg contents to produce final crc value
    crc^=0xFFFF
    #logger.debug(f"Calculated CRC16 is {crc}")
    return crc

def hexdump(a):
    ''' Turn list of bytes into `od` style hex plus ascii display
    >>> a=[i for i in range(133)]
    >>> print(hexdump(a), end='')
    00010203 04050607 08090a0b 0c0d0e0f  ................
    10111213 14151617 18191a1b 1c1d1e1f  ................
    20212223 24252627 28292a2b 2c2d2e2f   !"#$%&'()*+,-./
    30313233 34353637 38393a3b 3c3d3e3f  0123456789:;<=>?
    40414243 44454647 48494a4b 4c4d4e4f  @ABCDEFGHIJKLMNO
    50515253 54555657 58595a5b 5c5d5e5f  PQRSTUVWXYZ[\]^_
    60616263 64656667 68696a6b 6c6d6e6f  `abcdefghijklmno
    70717273 74757677 78797a7b 7c7d7e7f  pqrstuvwxyz{|}~.
    80818283 84                          .....
    '''
    out=''
    one=array("B", a).tobytes().hex()
    lines=[one[i:i+32] for i in range(0, len(one), 32)]
    for line in lines:
        asc=bytes.fromhex(line).decode("ascii", 'replace')
        asc=''.join([c if 31<ord(c)<127 else '.' for c in asc])
        if len(line)<32:
            line+=' '*(32-len(line))
        out+=' '.join([line[0:8], line[8:16], line[16:24], line[24:32]])
        out+='  '+asc+'\n'
    return out

PIDPacketID = [
    # Not to be confused with device PID/VID Product ID
    "EXT",      #  0 USB 2.01 Protocol Extension Transaction
    "OUT",      #  1 Initiate host-to-device transfer
    "ACK",      #  2 Data packet accepted
    "DATA0",    #  3 Even-numbered data packet
    "PING",     #  4 Check if endpoint can accept data
    "SOF",      #  5 Start of time frame marker
    "NYET",     #  6 Data not ready yet
    "DATA2",    #  7 Data packet for hish-speed isochronous transfer
    "SPLIT",    #  8 High-bandwidth hish-speed split transaction
    "IN",       #  9 Initiate device-to-host transfer
    "NAK",      # 10 Data packet not accepted; retransmit request
    "DATA1",    # 11 Odd-numbered data packet
    "PRE",      # 12 Low-speed preamble or high-speed split transaction error
    "SETUP",    # 13 Initiate host-to-device control transfer
    "STALL",    # 14 Transfer impossible; perform error recovery
    "MDATA"]    # 15 Data packet for high-speed isochronous transfer

class USBPacket():
    def __init__(self, packet, transfer=None):
        self.error=None
        if isinstance(packet, str):
            if re.search(r'^[01]+$', packet):
                # String consisting solely of 0 and 1 : bitstring
                self.bitstring=packet
                self.byte=bitstring2bytes(self.bitstring)
            elif re.search(r'^[jkJK01_]+$', packet):
                # String with JK and SE0
                self.nrzi=packet
                self.byte=nrzi2bytes(self.nrzi)
            elif packet.count('\n')>8:
                # Prety printed by cocotb_usb with one J or K token per line
                self.nrzi=unpp_packet(packet)
                self.byte=nrzi2bytes(self.nrzi)
            else:
                self.error=DecodeError.InvalidToken
                logger.critical(f"Unrecognized packet format: '{packet}'")
                return self
        elif len(packet)==2:
            # Pair of iterables containing D+ and D- signals
            self.differential=packet
            self.nrzi=differential2nrzi(packet[0], packet[1])
            self.byte=nrzi2bytes(self.nrzi)
        else:
            # Must be a list of bytes
            self.byte=packet
        logger.debug(f"Packet as bytes: {self.byte}")
        self.pid=USBPacket.decode_pid(self.byte[0])
        if transfer and self.pid[:4]=="DATA":
            if isinstance(transfer, USBPacket):
                logger.debug(f"Decoding packet as {transfer.fields['Command']}")
            else:
                logger.debug(f"Decoding packet as {transfer}")
            self.currentTransfer=transfer
        self.fields = {"PID": self.pid}
        decode=PacketDecoder[self.pid]
        decode(self)
        logger.debug(str(self))
        if self.error:
            logger.error(self.error);

    def __str__(self):
        ''' Provide the str() function with beutified output.
        '''
        if self.error:
            # Return the error itself along with the PID if present
            return str(self.error)+(' '+str(self.pid) if pid in self else '')
        out=str(self.pid)
        for f in self.fields:
            if f=="PID" or f=="CRC5" or f=="CRC16":
                continue
            out+=f", {f}: {self.fields[f]}"
        if hasattr(self, "descriptor") and self.descriptor!=None:
            out=hexdump(self.data) + pp.pformat(self.descriptor)
            # Old code that does what the pretty printer simplifies
            #if isinstance(self.descriptor, list):
            #    for d in self.descriptor:
            #        out+="\n..."
            #        for f in d:
            #            out+=f", {f}: {d[f]}"
            #else:
            #    for f in self.descriptor:
            #        out+=f", {f}: {self.descriptor[f]}"
        return out


    def summarize(self):
        if hasattr(self, 'error') and self.error:
            if hasattr(self, 'pid'):
                return f"{self.error} {self.pid}"
            else:
                return str(self.error)
        out=self.pid
        if hasattr(self, "descriptor"):
            if isinstance(self.descriptor, list):
                try:
                    out=f"List of {len(self.descriptor)} descriptors"
                except:
                    out="List of descriptors"
            else:
                try:
                    out=f"{self.descriptor['bDescriptorType']} descriptor"
                except:
                    out="Partial descriptor"
        else:
            try:
                out=f"{self.fields['Command']} command"
            except:
                pass
        return out

    def compare(self, expected, display=False):
        ''' Compare expected result (parameter) with the received result (self)
        '''
        # Try binary comparison before field-by-field
        if self.byte == expected.byte:
            logger.debug(f"{self.pid} Packets are identical")
            return True
        else:
            logger.error(f"{self.pid} Packets differ")
            message=""
            # Show fields that are expected. Current routine does not show
            # unexpected fields that were received.
            for f in self.fields:
                other=(expected.fields[f] if f in expected.fields else
                        NONEXISTENT)
                message+=(SAME_COLOR if self.fields[f]==other else DIFF_COLOR)
                message+=("{:20} {:20} {}\n".format(self.fields[f], other, f))
            if hasattr(self, "descriptor"):
                if isinstance(self.descriptor, list):
                    for d in self.descriptor:
                        for f in d:
                            other=(expected.descriptor[f] if hasattr(expected,
                                    'descriptor') and f in expected.descriptor
                                    else NONEXISTENT)
                            message+=(SAME_COLOR if d[f]==other else DIFF_COLOR)
                            message+=("{:20} {:20} {}\n".format(d[f], other, f))
                else:
                    for f in self.descriptor:
                        other=(expected.descriptor[f] if hasattr(expected,
                                'descriptor') and f in expected.descriptor
                                else NONEXISTENT)
                        message+=(SAME_COLOR if self.descriptor[f]==other
                                else DIFF_COLOR)
                        message+=("{:20} {:20} {}\n".format(self.descriptor[f],
                                other, f))
            logger.error(message)
        return False

    def decode_pid(pid):
        code=pid&0xf
        if pid==(code|(code<<4))^0xf0:
            return PIDPacketID[code]
        else:
            logger.error(f"L3 Error: Invalid PID [0x{pid:02X}]")
            return DecodeError.InvalidPID

    def decode_handshake(self):
        ''' Handshake packets
        Sync      PID       EOP
        KJKJKJKK  XXXXXXXX  00J
        The only content of this packet is the protocol id itself
        Nothing further to be done as the protocol has already been determined
        '''
        logger.debug(self.pid)
        return self.error


    def decode_token(self):
        '''Token packets
        Sync      PID       ADDR 7   ENDP  CRC5   EOP
        KJKJKJKK  XXXXXXXX  XXXXXXX  XXXX  XXXXX  00J
        '''
        self.fields.update(
               {"Address"  : self.byte[1]&0x7f,
                "Endpoint" : ((self.byte[2]&7)<<1)|(self.byte[1]>>7),
                "CRC5"     : self.byte[2]>>3})
        crc=bitstring2bytes(crc5(bytes2bitstring(self.byte[1:3])[0:11]))[0]
        if self.fields["CRC5"]!=crc:
            self.error=DecodeError.IncorrectCRC
            logger.error("Calculated CRC {:02X}, Expected {:02X}".format(crc,
                    self.fields["CRC5"]))
        logger.debug(f"{self.pid}, {self.fields['Address']}:"
                f"{self.fields['Endpoint']}, crc={crc}, error={self.error}")
        return self.error

    def decode_sof(self):
        ''' SOF packet
        Sync      PID       Frame no.    CRC5   EOP
        KJKJKJKK  XXXXXXXX  XXXXXXXXXXX  XXXXX  00J
        '''
        self.fields.update(
               {"Frame Number" : ((self.byte[2]&7)<<8)|(self.byte[1]),
                "CRC5"         : self.byte[2]>>3})
        crc=bitstring2bytes(crc5(bytes2bitstring(self.byte[1:3])[0:11]))[0]
        if self.fields["CRC5"]!=crc:
            self.error=DecodeError.IncorrectCRC
            logger.error("Calculated CRC {:02X}, Expected {:02X}".format(crc,
                    self.fields["CRC5"]))
        logger.debug(f"{self.pid}, {self.fields['Frame Number']}, "
                f"crc={crc}, error={self.error}")
        return self.error

    def decode_data(self):
        '''Data packets
        Sync      PID       DATA            CRC16             EOP
        KJKJKJKK  XXXXXXXX  XXXXXXXX*Count  XXXXXXXXXXXXXXXX  00J
        '''
        self.data=self.byte[1:-2]
        logger.debug(f"Data: {self.data}")
        self.fields["CRC16"]=(self.byte[-1]<<8)|self.byte[-2]
        crc=crc16(self.byte[1:-2])
        if self.fields["CRC16"]!=crc:
            self.error=DecodeError.IncorrectCRC
            logger.error("Calculated CRC {:04X}, Expected {:04X}".format(crc,
                self.fields["CRC16"]))
        if hasattr(self, "currentTransfer"):
            transfer=self.currentTransfer
            if len(self.data)==0:
                # Zero-byte data transfer does not get decoded
                pass
            elif transfer=="SETUP":
                #logger.debug(f"Current transfer: {transfer}")
                DataPacket.decode_setup_data(self)
            elif transfer in DataDecoder:
                #logger.debug(f"Current transfer: {transfer}")
                if DataDecoder[transfer]!=None:
                    DataDecoder[transfer](self)
            elif isinstance(transfer, USBPacket):
                transfer=transfer.fields["Command"]
                #logger.debug(f"Current transfer: {transfer}")
                if DataDecoder[transfer]!=None:
                    DataDecoder[transfer](self)
            else:
                logger.warning(f"No decoder for {transfer}")
        return self.error

    def decode_split(self):
        ''' SSPLIT CSPLIT packet
        Sync      PID       Hub addr  S/C  Port 7   S  E  ET  CRC5   EOP
        KJKJKJKK  XXXXXXXX  XXXXXXX    X   XXXXXXX  X  X  XX  XXXXX  00J
        S/C: Start split transaction / Complete split transaction
        S/C: 0 = SSPLIT: Start split transaction, 1 = CSPLIT: Complete split
        S: Speed, 1 = Low speed, 0 = High speed
        E: End of full speed payload
        U: U bit is reserved/unused and must be reset to zero (0 B)
        EP: End point type: 00=control, 01=isochronous, 10=bulk, 11=interrupt
        '''
        # High speed not yet verified
        self.error = DecodeError.UnimplementedPacket
        logger.warning("Decoder error: Unimplimented packet")
        return self.error

    def decode_pre(self):
        '''PRE packet
        Full speed preamble encapsulating Low speed packet after possible delay
        Sync      PID(PRE)  Sync      PID       ADDR     ENDP  CRC5   EOP
        KJKJKJKK  XXXXXXXX  KJKJKJKK  XXXXXXXX  XXXXXXX  XXXX  XXXXX  00J
        '''
        # Low speed not yet verified
        self.error = DecodeError.UnimplementedPacket
        logger.warning("Decoder error: Unimplimented packet")
        return self.error

    def decode_ext(self):
        '''EXT packet - Changes the interpretation of the supsequent packet
        Sync      PID       ADDR 7   ENDP  CRC5   EOP
        KJKJKJKK  XXXXXXXX  XXXXXXX  XXXX  XXXXX  00J
        '''
        # This is easy to decode but is only an indicator that the following
        # packet has a SubPID and that it should not be taken as a real PID.
        # Issue a warning that the next packet will not be decoded correctly.
        self.error = DecodeError.UnimplementedPacket
        logger.warning("Decoder error: Unimplimented packet")
        return self.error

    '''Transaction
    OUT transaction: OUT, DATAx, ACK
    IN transaction: IN, DATAx, ACK
    SETUP transaction: SETUP, DATA0, ACK
    '''

class DataPacket(USBPacket):
    ''' Interpretation for Data packets sent as part of Setup transaction '''
    def decode_setup_data(self):
        ''' 8-byte data packet followup to a SETUP request '''  
        bmRequestTypeRecipient = (
            # bmRequestType	bits 0–4 Recipient
            # Only 4 of 32 values are defined. Show (reserved) for 4–31
            "Device",    # 0
            "Interface", # 1
            "Endpoint",  # 2
            "Other")     # 3
        bmRequestTypeType = (
            # bmRequestType bits 5–6 Type: Used with bRequest byte
            "Standard", # 0
            "Class",    # 1
            "Vendor",   # 2
            "Reserved") # 3
        bmRequestTypeDirection = (
            # bmRequestType bit 7 Direction
            "Host to device", # 0 # or when wLength=0 indicating no data needed
            "Device to host") # 1 # wLength bytes of status expected
        bRequestStandardSetup = (
            # Standard Setup command: Recipient is Device and Type is Standard
            "GET_STATUS",        # 0  2-byte read
            "CLEAR_FEATURE",     # 1  0-byte write, feature selected by wValue
            "RFU_2",             # 2  
            "SET_FEATURE",       # 3  0-byte write, feature selected by wValue
            "RFU_4",             # 4  
            "SET_ADDRESS",       # 5  0-byte write, address in wValue
            "GET_DESCRIPTOR",    # 6  wLength-byte read, type & index in wValue
            "SET_DESCRIPTOR",    # 7  wLength-byte write, type & index in wValue
            "GET_CONFIGURATION", # 8  1-byte read, config selected by wValue
            "SET_CONFIGURATION", # 9  0-byte write, config selected by wValue
            "GET_INTERFACE",     # 10 returns alternate setting for interface
            "SET_INTERFACE",     # 11
            "SYNCH_FRAME",       # 12 Frame number in data
            # Requests below this point are USB 3 specific
            # TODO Not implemented in current version
            "SET_ENCRYPTION",    # 13 
            "GET_ENCRYPTION",    # 14 
            "SET_HANDSHAKE",     # 15 
            "GET_HANDSHAKE",     # 16 
            "SET_CONNECTION",    # 17 
            "SET_SECURITY_DATA", # 18 
            "GET_SECURITY_DATA", # 19 
            "SET_WUSB_DATA",     # 20 
            "LOOPBACK_DATA_WRITE",#21 
            "LOOPBACK_DATA_READ",# 22 
            "SET_INTERFACE_DS",  # 23 
            # Structure should be changed to dict for the following additions
            #"SET_SEL",           # 48 
            #"SET_ISOCH_DELAY",   # 49 
            )
        # promote generic packet to data sub-class
        self.__class__ = DataPacket
        self.fields.update({
                "Recipient" : bmRequestTypeRecipient[self.byte[1]&0x1f],
                "Type"      : bmRequestTypeType[(self.byte[1]>>5)&3],
                "Direction" : bmRequestTypeDirection[(self.byte[1]>>7)&1],
                "Command"   : bRequestStandardSetup[self.byte[2]],
                "Value"     : self.byte[3]+(self.byte[4]<<8), # See Command defn
                "Index"     : self.byte[5]+(self.byte[6]<<8),
                "Length"    : self.byte[7]+(self.byte[8]<<8), # of followup Data
                })
        if self.fields["Command"][4:]=="DESCRIPTOR": # GET and SET
            self.fields.update({"Descriptor Type":  self.byte[4],
                                "Descriptor Index": self.byte[3]})
        logger.debug(f"{self.pid} error={self.error}")
        #if self.fields["Type"]=="Standard" and self.fields["Recipient"]=="Device":
        #    USBPacket.currentTransfer=self.fields["Command"]
        #    if self.fields["Command"]=="GET_STATUS":
        #        USBPacket.currentTransfer+="_"+self.fields["Recipient"]
        #else:
        #    # Only Standard commands are restricted to standard formats
        #    USBPacket.currentTransfer=None
        return self.error

    def decode_get_status_device(self):
        # Status has 14 bits of reserved (0) TODO Pedantic should verify
        self.fields.update({
                "Self Powered" : self.byte[1]&1,
                "Remote Wakeup": self.byte[1]&2})
        return self.error

    def decode_get_status_interface(self):
        # Status is 16 bits of reserved (0) TODO Pedantic should verify
        return self.error

    def decode_get_status_endpoint(self):
        # Status is 15 bits of reserved (0) TODO Pedantic should verify
        self.fields.update({
                "Halt": self.byte[1]&1})
        return self.error

    def decode_get_descriptor(self):
        if isinstance(self.currentTransfer, USBPacket):
            self.descriptor=descriptor_data(self.data,
                self.currentTransfer.fields)
        return self.error

    def decode_get_configuration(self):
        self.error = DecodeError.UnimplementedPacket
        return self.error

    def decode_get_interface(self):
        self.error = DecodeError.UnimplementedPacket
        return self.error

    def decode_synch_frame(self):
        self.fields.update({
                "Frame Number": self.byte[1]+(self.byte[2]<<8)})
        return self.error

PacketDecoder = {
    "ACK":   USBPacket.decode_handshake,
    "NAK":   USBPacket.decode_handshake,
    "STALL": USBPacket.decode_handshake,
    "NYET":  USBPacket.decode_handshake,
    "ERR":   USBPacket.decode_handshake,
    "IN":    USBPacket.decode_token,
    "OUT":   USBPacket.decode_token,
    "SETUP": USBPacket.decode_token,
    "PING":  USBPacket.decode_token,
    "MDATA": USBPacket.decode_data,
    "DATA0": USBPacket.decode_data,
    "DATA1": USBPacket.decode_data,
    "DATA2": USBPacket.decode_data,
    "SPLIT": USBPacket.decode_split,
    "SOF":   USBPacket.decode_sof,
    "PRE":   USBPacket.decode_pre,
    "EXT":   USBPacket.decode_ext,
    }

DataDecoder = {
    #"SETUP":                DataPacket.decode_setup_data,
    "GET_STATUS_Device":    DataPacket.decode_get_status_device,
    "GET_STATUS_Interface": DataPacket.decode_get_status_interface,
    "GET_STATUS_Endpoint":  DataPacket.decode_get_status_endpoint,
    "GET_DESCRIPTOR":       DataPacket.decode_get_descriptor,
    "SET_DESCRIPTOR":       DataPacket.decode_get_descriptor,
    "GET_CONFIGURATION":    DataPacket.decode_get_configuration,
    "GET_INTERFACE":        DataPacket.decode_get_interface,
    "SET_INTERFACE":        DataPacket.decode_get_interface,
    "SYNCH_FRAME":          DataPacket.decode_synch_frame,
    "CLEAR_FEATURE":        None,
    "SET_FEATURE":          None,
    "SET_ADDRESS":          None,
    "SET_CONFIGURATION":    None,
    #"get_device_descriptor":        DataPacket.decode_get_descriptor,
    #"get_configuration_descriptor": DataPacket.decode_get_descriptor,
    #"get_string_descriptor":        DataPacket.decode_get_descriptor,
}

# Decode USB where LSB is sent first and 0 a state transition and 1 is no change

def unpp_packet(dump):
    """ Recover packet from cocotb_usb pretty print.
    >>> # Only the first word of each line is used.
    >>> # This assumes the pp_packet output is captured as a python string.
    The following is a doctest statement that expects cocotb_usb is installed:
        packet=unpp_packet(pp_packet(wrap_packet(handshake_packet(PID.ACK))))
    """
    #logger.debug(f"Recovering packet from: {dump}")
    nrzi=""
    i=0
    for line in dump.splitlines():
        i+=1
        words=re.findall(r"\S+", line)
        if len(words)==0:
            continue    # ignore blank lines
        signal=words[0]
        if signal=="JJJJ" or signal=="J":
            nrzi+='J'
        elif signal=="KKKK" or signal=="K":
            nrzi+='K'
        elif signal=="----" or signal=="-":
            pass
        elif signal=="____" or signal=="_":
            nrzi+='0'
        else:
            logger.error(f"Unexpected token '{signal}' in line {i}: {line}")
            return DecodeError.InvalidToken
    return nrzi

def differential2nrzi(dpi, dmi):
    ''' Join two iterables (strings or arrays) containing D+ and D- signals

    >>> # Examples of proper usage:
    >>> differential2nrzi([0,0,1,1], [0,1,0,1])
    '0KJ1'
    >>> differential2nrzi('0011', '0101')
    '0KJ1'
    '''

    if len(dpi)!=len(dmi):
        logger.critical(f"Length mismatch between inputs ({dpi}', {dmi})")
        return DecodeError.InvalidToken
    nrzi=""
    for (dp,dm) in zip(dpi, dmi):
        if dp and dp!='0':
            if dm and dm!='0':
                nrzi+='1'
            else:
                nrzi+='J'
        else:
            if dm and dm!='0':
                nrzi+='K'
            else:
                nrzi+='0'
    return nrzi

def nrzi2bytes(received, wrapped=True):
    """ Convert NRZI string of JK tokens to list of bytes

    Parameters:
    received: String containing J, K and SE0 tokens. The SE0 (Single Ended Zero)
      may appear as '0' or '_' in the bitstring.
    wrapped: Packet must start with Sync (KJKJKJKK) and end with EOP (__J) which
      are removed from the returned value.  If False, these must have already
      been stripped from the bitstream.

    Return value:
    • List of bytes. Exception: The value -1 is used for EOP if not unwraped.
    • Error code from DecodeError if an invalid character is encountered or a
      verification check fails.

    The following checks are performed to ensure USB 2.0 complaince:
    • Verify bit stuffing is inserted after 6 consecutive 1s.
    • Verify that a multiple of 8 bits is recevied.

    The following checks are not perfomed as these are consessions by the
    standard for lower quality 1990s devices:
    • SE0 may be seen as a glitch briefly during differential transition.
      Max duration of this event (TFST) is 14ns.
    • Valid SE0 for transmission of EOP (TFEOPT) is 160-175ns.
    • Receiver must accept an SEO as short as 82ns (TFEOPR) as a valid EOP.
    • The last data bit before EOP can become stretched (dribble) into a 6th bit
      that does not require a bit stuff. The receiver must accept this as valid.

    >>> # Examples of proper usage:
    >>> nrzi2bytes('KJKJKJKKJJKJJKKK__J', wrapped=True)
    [210]
    >>> nrzi2bytes('JJKJJKKK', wrapped=False)
    [210]

    >>> # Verification of error handling:
    >>> nrzi2bytes('KJKJKJKKJJKJJKKK__J', wrapped=False)
    <DecodeError.FalseEOP: 'False EOP detected'>
    >>> nrzi2bytes('JJKJJKKK', wrapped=True)
    <DecodeError.InvalidSync: 'Packet does not start with Sync pattern'>
    """

    SYNC=128
    EOP=-1

    state=('J' if wrapped else 'K') # SOP from idle pattern vs end of Sync
    consecutive=0
    bits=""
    data=[]
    received.upper()
    for bit in received:
        if bit=='J' or bit=='K' or bit=='_':
            pass
        elif bit=='0':
            bit='_'
        else:
            logger.error(f"Unexpected character '{bit}' in NRZI bitstream")
            return DecodeError.InvalidToken
        if len(bits)==8:
            byte = int(bits[::-1], 2)
            #print("{} {:02x} {}".format(bits, byte, byte))
            data.append(byte)
            bits=""
        if bit==state:
            if bit=='J' or bit=='K':
                bits+='1'
            elif bit=='_':
                bits+='_'
            consecutive+=1
            if consecutive>6:
                logger.error("Bit stuffing violation")
                return DecodeError.BitStuffViolation
        else:
            if state == '_':
                # End of packet
                if bits!="__" or bit!='J' or not wrapped:
                    logger.error("Invalid EOP detected")
                    return DecodeError.FalseEOP
                data.append(EOP)
                bits=""
            else:
                if consecutive==6:
                    state=bit
                    consecutive=0
                    continue
                if bit=='J' or bit=='K':
                    bits+='0'
                elif bit=='_':
                    bits+='_'
                else:
                    logger.error(f"Invalid character '{bit}' in NRZI string")
                    return DecodeError.InvalidToken
                consecutive=0
        state=bit

    if bits!="":
        if len(bits)==8:
            byte = int(bits[::-1], 2)
            data.append(byte)
            bits=""
        else:
            logger.error(f"Incomplete byte '{bits}' received")
            return DecodeError.FalseEOP

    if not wrapped:
        return data
    if data[0]!=SYNC:
        logger.error("SYNC not detected")
        return DecodeError.InvalidSync
    elif data[-1]!=EOP:
        logger.error("EOP not detected")
        return DecodeError.InvalidEOP
    return data[1:-1]


def separate_packets(bitstream):
    ''' Break continuous JK bitstream in sequence of packets
    '''
    # Use EOF (00J or __J) as packet delimiter
    fields=re.split(r'([0_]+.)', bitstream)
    # Join EOF back onto packet
    pairs = iter(fields)
    return [c+next(pairs, '') for c in pairs]

def test_packet_decode():
    ''' Replay poor-man's USB tcpdump file. Useful for testing new decoders.
    '''
    bitstream=(fileinput.input())
    for line in bitstream:
        words=re.findall(r"\S+", line)
        # Default format is:
        #   [time] [direction] packet
        if len(words)>1:
            if len(words)>=3:
                time=words[0]
                direction=words[1]
            else:
                if re.search(r'^\d+$', words[0]):
                    time=words[0]
                    direction=""
                else:
                    time=""
                    direction=words[0]
        else:
            time=""
            direction=""
        packet=words[-1]
        if re.search(r'^[JKjk01_]+$', packet):
            print("------------", time, direction)
            captured=USBPacket(packet)

def test_stream_decode():
    ''' Read and display packet details from a Prety Printed dump.
    '''
    # Read packet details from a Prety Printed dump as continuous bitstream
    bitstream=unpp_packet((fileinput.input()))
    # Separate bitstream into packets
    packets=separate_packets(bitstream)
    # display details of each packet
    for packet in packets:
        # Ignore potential empty packets caused by artifacts of prety printing
        if len(packet)>0:
            packet=USBPacket(packet)
            print(packet)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
