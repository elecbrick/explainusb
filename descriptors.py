#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

'''
Copyright (c) 2020, Doug Eaton
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''


import logging
from array import array
from struct import unpack

try:
    from cocotb.log import SimLog
    logger = SimLog("cocotb.usb.descriptors")
    #logger.setLevel(logging.DEBUG)
except ImportError:
    logger = logging

class USBProtocolState():
    # A control pipe may have a variable-length data phase in which the host
    # requests more data than is contained in the specified data structure.
    # When all of the data structure is returned to the host, the function
    # should indicate that the Data stage is ended by returning a packet that
    # is shorter than the MaxPacketSize for the pipe. If the data structure
    # is an exact multiple of wMaxPacketSize for the pipe, the function will
    # return a zero-length packet to indicate the end of the Data stage.
    variable_length_data_remaining=0
    def set_variable_length_remaining(x):
        USBProtocolState.variable_length_data_remaining=x
    def get_variable_length_remaining():
        return USBProtocolState.variable_length_data_remaining
    def in_variable_length_data_stage():
        return USBProtocolState.variable_length_data_remaining>0


# Table 9-5. Descriptor Types
DescriptorType = {
    0x01: "DEVICE",
    0x02: "CONFIGURATION",
    0x03: "STRING",
    0x04: "INTERFACE",
    0x05: "ENDPOINT",
    0x06: "DEVICE_QUALIFIER",
    0x07: "OTHER_SPEED_CONFIGURATION",
    0x08: "INTERFACE_POWER",
    0x0F: "BOS",
    0x10: "DEVICE_CAPABILITY",
    0x21: "DFU",
    # 0x21: "HID",  # Class
    # 0x22: "REPORT",   # get_descriptor to INTERFACE with wValue HIGH 0x22
    # 0x23: "PHYSICAL", # get_descriptor to INTERFACE with wValue HIGH 0x23
    # 0x29: "HUB",
    # 0x2a: "SUPERSPEED_HUB",
    # 0x30: "SS_ENDPOINT_COMPANION",
    # 0x31: "SSP_ISOCHRONOUS_ENDPOINT_COMPANION",
}

# Table 9-6. Standard Feature Selectors
FeatureSelector = {             # Recipient
    0: "ENDPOINT_HALT",         # Endpoint
    1: "DEVICE_REMOTE_WAKEUP",  # Device
    2: "TEST_MODE",             # Device
    # Requests below this point are USB 3 specific
    #0 "FUNCTION_SUSPEND",      # Interface - USB 3 makes alternate use of 0
    3: "b_hnp_enable",          # Device
    4: "a_hnp_support",         # Device
    5: "a_alt_hnp_support",     # Device
    6: "WUSB_DEVICE",           # Device
    48: "U1_ENABLE",            # Device
    49: "U2_ENABLE",            # Device
    50: "LTM_ENABLE",           # Device
    51: "B3_NTF_HOST_REL",      # Device
    52: "B3_RSP_ENABLE",        # Device
    53: "LDM_ENABLE",           # Device
   }

# Table 9-7. Test Mode Selectors
TestModeSelectors = {
    0: "Reserved",
    1: "Test_J",
    2: "Test_K",
    3: "Test_SE0_NAK",
    4: "Test_Packet",
    5: "Test_Force_Enable",
}


def usbVer(w):
    # 0x0100 -> 1.0 and 0x0210 -> 2.1 (skip leading and trailing zero)
    ''' Convert BCD USB Version to official format. In particular, leading
    and trailing zeros are to be suppressed from the fixed point value:
    >>> usbVer(0x0200)
    '2.0'
    >>> usbVer(0x0201)
    '2.01'
    >>> usbVer(0x0210)
    '2.1'
    '''
    return f'{w>>8:x}.'+(f'{((w>>4)%16):x}' if w&15==0 else f'{(w%256):02x}')

def hex4(w):
    ''' Convert 16-bit word to 4-digit hex string with leading '0x'
    >>> hex4(0)
    '0x0000'
    >>> hex4(0xffff)
    '0xFFFF'
    '''
    return f'0x{w:04X}'

def bcd(w):
    ''' Convert 16-bit BCD word to 4-digit string
    >>> bcd(0)
    '0000'
    >>> bcd(0x1234)
    '1234'
    '''
    return f'{w:04X}'

def flag(b):
    ''' Turn a single bit value into True/False
    >>> flag(0)
    False
    >>> flag(1)
    True
    '''
    return True if b else False

def mA(s):
    return f'{s*2}mA'

def u16string(s, zero):
    # String descriptor zero returns a different value than all others
    # according to spec so assume first string returned will
    # be a language list
    logger.debug(f"String descriptor zero: {zero}")
    if zero:
        return list(map(lambda x: LangID[x], unpack(f"<{len(s)//2}H", s)))
    else:
        return str(s.decode(encoding="utf-16-le").encode(encoding="ascii",
                errors="backslashreplace"))


# Table 9-8. Standard Device Descriptor
DeviceDescriptor = (
    #&BBH4B3H4B"
    (1, "bLength", None),                   # Size of this descriptor
    (1, "bDescriptorType", DescriptorType), # DEVICE Descriptor Type
    (2, "bcdUSB", usbVer),                  # USB Specification Version
    (1, "bDeviceClass", None),              # Class code
    (1, "bDeviceSubClass", None),           # Subclass code
    (1, "bDeviceProtocol", None),           # Protocol code
    (1, "bMaxPacketSize0", None),           # Max packet size for endpoint zero
    (2, "idVendor", hex4),                  # Vendor ID
    (2, "idProduct", hex4),                 # Product ID
    (2, "bcdDevice", bcd),                  # Device release number
    (1, "iManufacturer", None),             # Index of manufacturer string desc
    (1, "iProduct", None),                  # Index product of string descriptor
    (1, "iSerialNumber", None),             # Index of serial number string desc
    (1, "bNumConfigurations", None),        # Number of configurations
)

# Table 9-9. Device_Qualifier Descriptor
Device_QualifierDescriptor = (
    #&BBH6B"
    (1, "bLength", None),                   # Size of this descriptor
    (1, "bDescriptorType", DescriptorType), # Device Qualifier Type
    (2, "bcdUSB", usbVer),                  # USB Specification Version
    (1, "bDeviceClass", None),              # Class code
    (1, "bDeviceSubClass", None),           # Subclass code
    (1, "bDeviceProtocol", None),           # Protocol code
    (1, "bMaxPacketSize0", None),           # Max packet size for endpoint zero
    (1, "bNumConfigurations", None),        # Number of Other-speed Configs
    (1, "bReserved", 0),                    # RFU, must be zero
)

# Table 9-10. Standard Configuration Descriptor
ConfigurationDescriptor = (
    #&BBH5B"
    (1, "bLength", None),                   # Size of this descriptor
    (1, "bDescriptorType", DescriptorType), # CONFIGURATION
    (2, "wTotalLength", None),              # Of all descriptors for this config
    (1, "bNumInterfaces", None),            # Num IF supported by this config
    (1, "bConfigurationValue", None),       # Value of arg to SetConfiguration
    (1, "iConfiguration", None),            # Index to string desc of config
    (1, "bmAttributes", (                   # Configuration characteristics
        (7, 8, "Reserved (set to one)", 1),
        (6, 7, "Self-powered", flag),
        (5, 6, "Remote Wakeup", flag),
        (0, 5, "Reserved (reset to zero)", 0))),
    (1, "bMaxPower", mA),                   # Max power Expressed in 2 mA units
)

# Table 9-11. Other_Speed_Configuration Descriptor
# The only difference is the value of bDescriptorType
Other_Speed_ConfigurationDescriptor = ConfigurationDescriptor

# Table 9-12. Standard Interface Descriptor
InterfaceDescriptor = (
    #&9B"
    (1, "bLength", None),                   # Size of this descriptor
    (1, "bDescriptorType", DescriptorType), # INTERFACE Descriptor Type
    (1, "bInterfaceNumber", None),          # Number of this IF.
    (1, "bAlternateSetting", None),         # Value to select this alt for IF
    (1, "bNumEndpoints", None),             # Number of endpoints used by IF
    (1, "bInterfaceClass", None),           # Class code
    (1, "bInterfaceSubClass", None),        # Subclass code
    (1, "bInterfaceProtocol", None),        # Protocol code
    (1, "iInterface", None),                # string desc describing this IF
)

# Table 9-13. Standard Endpoint Descriptor
EndpointDescriptor = (
    #&4BHB"
    (1, "bLength", None),                   # Size of this descriptor
    (1, "bDescriptorType", DescriptorType), # ENDPOINT Descriptor Type
    (1, "bEndpointAddress", (
        (0,4, "Endpoint number", None),
        (4,7, "Reserved, reset to zero", 0),
        (7,8, "Direction", ("OUT endpoint", "IN endpoint")))),
    (1, "bmAttributes", (                   # endpoint attributes
        (0,2, "Transfer Type", ("Control", "Isochronous", "Bulk", "Interrupt")),
        (2,4, "Synchronization Type", ("No Synchronization", "Asynchronous",
            "Adaptive", "Synchronous")),
        (4,6, "Usage Type", ("Data endpoint", "Feedback endpoint",
            "Implicit feedback Data endpoint", "Reserved")))),
    (2, "wMaxPacketSize", (                 # Max packet size using this config
        (0,11,  "maximum packet size", None),
        (11,13, "additional transaction opportunities per microframe",
            (0, 1, 2, "Reserved")),
        (13,16, "reserved", 0))),
    (1, "bInterval", None),                 # Interval for polling endpoint
)

# Table 9-14. Allowed wMaxPacketSize Values for Different Numbers of
#   Transactions per Microframe
# wMaxPacketSize bits 12..11	wMaxPacketSize bits 10..0 Values Allowed
MaxPacketSize = (
    (0b00, 1-1024),
    (0b01, 513-1024),
    (0b10, 683-1024),
    (0b11, "reserved"),
)

LangID = {
    0x0000: "no language specified",
    0x0401: "Arabic (Saudi Arabia)",
    0x0402: "Bulgarian",
    0x0403: "Catalan",
    0x0404: "Chinese (Taiwan)",
    0x0405: "Czech",
    0x0406: "Danish",
    0x0407: "German (Standard)",
    0x0408: "Greek",
    0x0409: "English (United States)",
    0x040a: "Spanish (Traditional Sort)",
    0x040b: "Finnish",
    0x040c: "French (Standard)",
    0x040d: "Hebrew",
    0x040e: "Hungarian",
    0x040f: "Icelandic",
    0x0410: "Italian (Standard)",
    0x0411: "Japanese",
    0x0412: "Korean",
    0x0413: "Dutch (Netherlands)",
    0x0414: "Norwegian (Bokmal)",
    0x0415: "Polish",
    0x0416: "Portuguese (Brazil)",
    0x0418: "Romanian",
    0x0419: "Russian",
    0x041a: "Croatian",
    0x041b: "Slovak",
    0x041c: "Albanian",
    0x041d: "Swedish",
    0x041e: "Thai",
    0x041f: "Turkish",
    0x0420: "Urdu (Pakistan)",
    0x0421: "Indonesian",
    0x0422: "Ukrainian",
    0x0423: "Belarussian",
    0x0424: "Slovenian",
    0x0425: "Estonian",
    0x0426: "Latvian",
    0x0427: "Lithuanian",
    0x0429: "Farsi",
    0x042a: "Vietnamese",
    0x042b: "Armenian",
    0x042c: "Azeri (Latin)",
    0x042d: "Basque",
    0x042f: "Macedonian",
    0x0430: "Sutu",
    0x0436: "Afrikaans",
    0x0437: "Georgian",
    0x0438: "Faeroese",
    0x0439: "Hindi",
    0x043e: "Malay (Malaysian)",
    0x043f: "Kazakh",
    0x0441: "Swahili (Kenya)",
    0x0443: "Uzbek (Latin)",
    0x0444: "Tatar (Tatarstan)",
    0x0445: "Bengali",
    0x0446: "Punjabi",
    0x0447: "Gujarati",
    0x0448: "Oriya",
    0x0449: "Tamil",
    0x044a: "Telugu",
    0x044b: "Kannada",
    0x044c: "Malayalam",
    0x044d: "Assamese",
    0x044e: "Marathi",
    0x044f: "Sanskrit",
    0x0455: "Burmese",
    0x0457: "Konkani",
    0x0458: "Manipuri",
    0x0459: "Sindhi",
    0x04ff: "HID (Usage Data Descriptor)",
    0x0801: "Arabic (Iraq)",
    0x0804: "Chinese (PRC)",
    0x0807: "German (Switzerland)",
    0x0809: "English (United Kingdom)",
    0x080a: "Spanish (Mexican)",
    0x080c: "French (Belgian)",
    0x0810: "Italian (Switzerland)",
    0x0812: "Korean (Johab)",
    0x0813: "Dutch (Belgium)",
    0x0814: "Norwegian (Nynorsk)",
    0x0816: "Portuguese (Standard)",
    0x081a: "Serbian (Latin)",
    0x081d: "Swedish (Finland)",
    0x0820: "Urdu (India)",
    0x0827: "Lithuanian (Classic)",
    0x082c: "Azeri (Cyrillic)",
    0x083e: "Malay (Brunei Darussalam)",
    0x0843: "Uzbek (Cyrillic)",
    0x0860: "Kashmiri (India)",
    0x0861: "Nepali (India)",
    0x0c01: "Arabic (Egypt)",
    0x0c04: "Chinese (Hong Kong SAR, PRC)",
    0x0c07: "German (Austria)",
    0x0c09: "English (Australian)",
    0x0c0a: "Spanish (Modern Sort)",
    0x0c0c: "French (Canadian)",
    0x0c1a: "Serbian (Cyrillic)",
    0x1001: "Arabic (Libya)",
    0x1004: "Chinese (Singapore)",
    0x1007: "German (Luxembourg)",
    0x1009: "English (Canadian)",
    0x100a: "Spanish (Guatemala)",
    0x100c: "French (Switzerland)",
    0x1401: "Arabic (Algeria)",
    0x1404: "Chinese (Macau SAR)",
    0x1407: "German (Liechtenstein)",
    0x1409: "English (New Zealand)",
    0x140a: "Spanish (Costa Rica)",
    0x140c: "French (Luxembourg)",
    0x1801: "Arabic (Morocco)",
    0x1809: "English (Ireland)",
    0x180a: "Spanish (Panama)",
    0x180c: "French (Monaco)",
    0x1c01: "Arabic (Tunisia)",
    0x1c09: "English (South Africa)",
    0x1c0a: "Spanish (Dominican Republic)",
    0x2001: "Arabic (Oman)",
    0x2009: "English (Jamaica)",
    0x200a: "Spanish (Venezuela)",
    0x2401: "Arabic (Yemen)",
    0x2409: "English (Caribbean)",
    0x240a: "Spanish (Colombia)",
    0x2801: "Arabic (Syria)",
    0x2809: "English (Belize)",
    0x280a: "Spanish (Peru)",
    0x2c01: "Arabic (Jordan)",
    0x2c09: "English (Trinidad)",
    0x2c0a: "Spanish (Argentina)",
    0x3001: "Arabic (Lebanon)",
    0x3009: "English (Zimbabwe)",
    0x300a: "Spanish (Ecuador)",
    0x3401: "Arabic (Kuwait)",
    0x3409: "English (Philippines)",
    0x340a: "Spanish (Chile)",
    0x3801: "Arabic (U.A.E.)",
    0x380a: "Spanish (Uruguay)",
    0x3c01: "Arabic (Bahrain)",
    0x3c0a: "Spanish (Paraguay)",
    0x4001: "Arabic (Qatar)",
    0x400a: "Spanish (Bolivia)",
    0x440a: "Spanish (El Salvador)",
    0x480a: "Spanish (Honduras)",
    0x4c0a: "Spanish (Nicaragua)",
    0x500a: "Spanish (Puerto Rico)",
    0xf0ff: "HID (Vendor Defined 1)",
    0xf4ff: "HID (Vendor Defined 2)",
    0xf8ff: "HID (Vendor Defined 3)",
    0xfcff: "HID (Vendor Defined 4)",
}

# Table 9-15. String Descriptor Zero, Specifying Languages Supported by the Dev
StringDescriptorZero = (
    #&2B{}H"
    (1, "bLength", None),                   # Size of this descriptor
    (1, "bDescriptorType", DescriptorType), # STRING Descriptor Type
    (0, "wLANGID", LangID),                 # LANGID code zero
    # Variable length with at least one language specified
)

# Table 9-16. UNICODE String Descriptor
StringDescriptor = (
    #&2B{}H"
    (1, "bLength", None),                   # Size of this descriptor
    (1, "bDescriptorType", DescriptorType), # STRING Descriptor Type
    (0, "bString", u16string),              # u16 encoded UNICODE string
    # Variable length with at least one character specified
)

# Table 4.2 DFU Functional Descriptor
DfuDescriptor = (
    (1, "bLength", None),                   # Size of this descriptor
    (1, "bDescriptorType", DescriptorType), # DFU FUNCTIONAL descriptor type 21h
    (1, "bmAttributes", (                   # Bit mask DFU attributes
        (4,8, "reserved", 0),
        (3,4, "bitWillDetach", flag),           # detach-attach on DFU_DETACH
        (2,3, "bitManifestationTolerant", flag),# must see bus reset if false
        (1,2, "bitCanUpload", flag),            # upload capable 
        (0,1, "bitCanDnload", flag))),          # download capable
    (2, "wDetachTimeOut", None),            # ms delay after DFU_DETACH
    (2, "wTransferSize", None),             # Max bytes per control-write
    (2, "bcdDFUVersion", bcd),              # version of DFU Specification
)

def descriptor_data(data, request):
    '''
    >>> # test vectors
    >>> descriptor_data([4, 3, 9, 4], {"Index": 0})
    {'bLength': 4, 'bDescriptorType': 'STRING', 'bString': ['English (United States)']}
    >>> descriptor_data([18,1, 16,1,0,0,0,0,0x34,0x12,0xcc,0xde,
    ...     0x34,0x12,0,1,2,1], None)
    {'bLength': 18, 'bDescriptorType': 'DEVICE', 'bcdUSB': '1.1', 'bDeviceClass': 0, 'bDeviceSubClass': 0, 'bDeviceProtocol': 0, 'bMaxPacketSize0': 0, 'idVendor': '0x1234', 'idProduct': '0xDECC', 'bcdDevice': '1234', 'iManufacturer': 0, 'iProduct': 1, 'iSerialNumber': 2, 'bNumConfigurations': 1}
    >>> descriptor_data([12, 3, 70, 0, 111, 0, 111, 0, 115, 0, 110, 0],
    ...     {"Index": 1})
    {'bLength': 12, 'bDescriptorType': 'STRING', 'bString': "b'Foosn'"}
    >>> descriptor_data([9, 2, 27, 0, 1, 1, 1, 128, 50, 9, 4, 0, 0, 0, 254,
    ...     1, 2, 2, 9, 33, 13, 16, 39, 0, 4, 1, 1], None)
    [{'bLength': 9, 'bDescriptorType': 'CONFIGURATION', 'wTotalLength': 27, 'bNumInterfaces': 1, 'bConfigurationValue': 1, 'iConfiguration': 1, 'Self-powered': 'False', 'Remote Wakeup': 'False', 'bMaxPower': '100mA'}, {'bLength': 9, 'bDescriptorType': 'INTERFACE', 'bInterfaceNumber': 0, 'bAlternateSetting': 0, 'bNumEndpoints': 0, 'bInterfaceClass': 254, 'bInterfaceSubClass': 1, 'bInterfaceProtocol': 2, 'iInterface': 2}, {'bLength': 9, 'bDescriptorType': 'DFU', 'bitWillDetach': True, 'bitManifestationTolerant': True, 'bitCanUpload': False, 'bitCanDnload': True, 'wDetachTimeOut': 10000, 'wTransferSize': 1024, 'bcdDFUVersion': '0101'}]
    '''

    descriptor={}
    logger.debug("Parsing descriptor")
    if USBProtocolState.in_variable_length_data_stage():
        logger.debug("Packet continuation")
        USBProtocolState.set_variable_length_remaining(
                USBProtocolState.get_variable_length_remaining()-len(data))
        return None
    ptr=0
    if data[0]>len(data):
        logger.debug("Shortened packet. Starting variable length transfer")
        USBProtocolState.set_variable_length_remaining(data[0]-len(data))
    variant=data[1]
    if variant in DescriptorType:
        variant=DescriptorType[variant].title()
    else:
        variant="RFU"+str(variant)
    # Avoid crashing due to unrecognized extenstions
    # TODO add more features
    try:
        fields=eval(variant+"Descriptor")
    except NameError as e:
        # TODO May want to downgrade this to info
        logger.warning(f"Unsupported descriptor {variant}")
        descriptor[variant]=data
        return descriptor
    for field in fields:
        if len(field)!=3:
            logger.critical(f"Decoder error: Invalid field descriptor in "
                    f"{variant}")
        size,name,template = field
        #name=field[1]
        #template=field[2]
        if size==1:
            # 8-bit parameter
            value=data[ptr]
            ptr+=1
        elif size==2:
            # 16-bit parameter
            value=data[ptr]+(data[ptr+1]<<8)
            ptr+=2
        elif size==0:
            # Variable length string or list - pack rest of packet
            value=array("B", data[ptr:]).tobytes()
            ptr=len(data)
        else:
            logger.critical(f"Decoder error: Invalid field size for {name}")
            return descriptor
        if template==None:
            #logger.debug(f"default: {name}={value}")
            descriptor[name]=value
        elif isinstance(template, int):
            if value!=template:
                logger.warning(f"Field {name} contains "
                        "{value} rather than expected {template}")
                descriptor[name]=value
            else:
                # Nothing to do - reserved fields are supressed
                #logger.debug(f"constant: {name}={value}")
                pass
        elif isinstance(template, (list, tuple)):
            if isinstance(template[0], (list, tuple)):
                # list of lists denotes bitfield
                #logger.debug(f"bitfield: {name}={value}")
                # move from bytes to bits
                for bf in template:
                    if len(bf)!=4:
                        logger.critical(f"Decoder error: Invalid field descriptor "
                                "in template of {name}")
                    bfvalue=((value>>(bf[0]))&((1<<(bf[1]-bf[0]))-1))
                        #logger.error(f"Invalid bitfield width "
                                #"{bf[0]} for {bf[1]}")
                    bfname=bf[2]
                    bftemplate=bf[3]
                    if bftemplate==None:
                        #logger.debug(f"bfdefault: {bfname}={bfvalue}")
                        descriptor[bfname]=bfvalue
                    elif isinstance(bftemplate, int):
                        if bfvalue!=bftemplate:
                            logger.warning(f"Bitfield {bfname} contains "
                                    "{bfvalue} rather than expected {bftemplate}")
                        else:
                            # Nothing to do - reserved fields are supressed
                            #logger.debug(f"constant: {bfname}={bfvalue}")
                            pass
                    elif isinstance(bftemplate, (list, tuple)):
                        #logger.debug(f"bflist: {bfname}={bftemplate[bfvalue]}")
                        descriptor[bfname]=bftemplate[bfvalue]
                    elif isinstance(bftemplate, (dict)):
                        #logger.debug(f"bfdict: {bfname}={bftemplate[bfvalue]}")
                        descriptor[bfname]=bftemplate[bfvalue]
                    elif callable(bftemplate):
                        #logger.debug(f"bffunc: {bfname}={bftemplate(bfvalue)}")
                        descriptor[bfname]=bftemplate(bfvalue)
                    else:
                        logger.error(f"No handling found for {bfname} "
                                "{type(bftemplate)}")
                    try:
                        logger.debug(f"{bfname}={descriptor[bfname]}")
                    except:
                        pass
            else:
                # Normal list so index it
                #logger.debug(f"list: {name}={template[value]}")
                descriptor[name]=template[value]
        elif isinstance(template, (dict)):
            #logger.debug(f"dict: {name}={template[value]}")
            descriptor[name]=template[value]
        elif callable(template):
            if template==u16string:
                descriptor[name]=template(value, request["Index"]==0)
            else:
                descriptor[name]=template(value)
        else:
            logger.error(f"Unhandled type '{type(template)}' for {name}")
        try:
            logger.debug(f"{name}={descriptor[name]}")
        except:
            pass

    if data[0]<len(data):
        # Recursion: the easy way to handle packets with multiple descriptors
        new=descriptor_data(data[data[0]:], request)
        #print("new: {new}\nold:{descriptor}")
        if isinstance(new, list):
            # Insert new at head of existing list
            new.insert(0, descriptor)
            return new
        else:
            # Create new list with 2 dict as entries
            return [descriptor, new]
    return descriptor

if __name__ == "__main__":
    import doctest
    doctest.testmod()
