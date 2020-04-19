#!/usr/bin/python3

from array import array

# Table 9-3. Standard Device Requests
'''
Format of SETUP packet that issues these requests is provided for reference
Handling of the SETUP packet is out of the scope of this module

bmRequestType bRequest          wValue      wIndex        wLength Data
000000xxB     CLEAR_FEATURE     FeatSelect  Zero If Ep    Zero    None
10000000B     GET_CONFIGURATION Zero        Zero          One     Config Value
10000000B     GET_DESCRIPTOR    Type+Index  Lang ID       Length  Descriptor
10000001B     GET_INTERFACE     Zero        Interface     One     Alt IF
100000xxB     GET_STATUS        Zero        Zero If Ep    Two     Dev If or Ep
00000000B     SET_ADDRESS       Device Addr Zero          Zero    None
00000000B     SET_CONFIGURATION Config Val  Zero          Zero    None
00000000B     SET_DESCRIPTOR    Type+Index  Lang ID       Length  Descriptor
000000xxB     SET_FEATURE       FeatSel     TestSel+0IfEp Zero    None
00000001B     SET_INTERFACE     Alt Setting Interface     Zero    None
10000010B     SYNCH_FRAME       Zero        Endpoint      Two     Frame Number
'''

# Table 9-4. Standard Request Codes
# bRequest Value
StandardRequest = {
    0: "GET_STATUS",            # 0  2-byte read, see Figure 9-4, 9-5, 9-6
    1: "CLEAR_FEATURE",         # 1  0-byte write, feature selected by wValue
    2: "RFU2",                  # 2  
    3: "SET_FEATURE",           # 3  0-byte write, feature selected by wValue
    4: "RFU4",                  # 4  
    5: "SET_ADDRESS",           # 5  0-byte write, address in wValue
    6: "GET_DESCRIPTOR",        # 6  wLength-byte read, type & index in wValue
    7: "SET_DESCRIPTOR",        # 7  wLength-byte write, type & index in wValue
    8: "GET_CONFIGURATION",     # 8  1-byte read, config selected by wValue
    9: "SET_CONFIGURATION",     # 9  0-byte write, config selected by wValue
    10: "GET_INTERFACE",        # 10 returns alternate setting for interface
    11: "SET_INTERFACE",        # 11 0-byte write - select alternate setting
    12: "SYNCH_FRAME",          # 12 2-byte frame number in data
    # Requests below this point are USB 3 specific
    13: "SET_ENCRYPTION"
    14: "GET_ENCRYPTION"
    15: "SET_HANDSHAKE"
    16: "GET_HANDSHAKE"
    17: "SET_CONNECTION"
    18: "SET_SECURITY_DATA"
    19: "GET_SECURITY_DATA"
    20: "SET_WUSB_DATA"
    21: "LOOPBACK_DATA_WRITE"
    22: "LOOPBACK_DATA_READ"
    23: "SET_INTERFACE_DS"
    48: "SET_SEL"
    49: "SET_ISOCH_DELAY"
}

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
    0x0F: "BOS"
    0x10: "DEVICE_CAPABILITY"
    # HID = 0x21, REPORT = 0x22, PHYSICAL = 0x23, HUB = 0x29
    # SUPERSPEED_HUB = 0x2a
    0x30: "SS_ENDPOINT_COMPANION"
    0x31: "SSP_ISOCHRONOUS_ENDPOINT_COMPANION"
}

# Table 9-6. Standard Feature Selectors
FeatureSelector = {             # Recipient
    0: "ENDPOINT_HALT",         # Endpoint
    1: "DEVICE_REMOTE_WAKEUP",  # Device
    2: "TEST_MODE",             # Device
    # Requests below this point are USB 3 specific
    #0 "FUNCTION_SUSPEND",      # Interface - USB 3 makes alternate use of 0
    3: "b_hnp_enable"           # Device
    4: "a_hnp_support"          # Device
    5: "a_alt_hnp_support"      # Device
    6: "WUSB_DEVICE"            # Device
    48: "U1_ENABLE"             # Device
    49: "U2_ENABLE"             # Device
    50: "LTM_ENABLE"            # Device
    51: "B3_NTF_HOST_REL"       # Device
    52: "B3_RSP_ENABLE"         # Device
    53: "LDM_ENABLE"            # Device
   }

# Figure 9-4. Information Returned by a GetStatus() Request to a Device
GetStatusDevice = {
    # D15-D2 Reserved
    1: "Remote Wakeup",
    0: "Self Powered",
}

# Figure 9-5. Information Returned by a GetStatus() Request to an Interface
GetStatusInterface = {
    # D15-D0 Reserved
}

# Figure 9-6. Information Returned by a GetStatus() Request to an Endpoint
GetStatusEndpoint = {
    # D15-D1 Reserved
    0: "Halt",
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
    return f'{w>>8:x}.'+(f'{((w>>4)%16):x}' if w&15==0 else f'{(w%256):02x}')

def hex4(w):
    return f'0x{w:04X}'

def bcd(w):
    return f'{w:04X}'

def flag(b):
    return str(b!=0)

def mA(s):
    return f'{s*2}mA'

def u16string(s):
    pass


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

# Table 9-15. String Descriptor Zero, Specifying Languages Supported by the Dev
StringDescriptorZero = (
    #&2B{}H"
    (1, "bLength", None),                   # Size of this descriptor
    (1, "bDescriptorType", DescriptorType), # STRING Descriptor Type
    (0, "wLANGID", None),                   # LANGID code zero
    # Variable length with at least one language specified
)

# Table 9-16. UNICODE String Descriptor
StringDescriptor = (
    #&2B{}H"
    (1, "bLength", None),                   # Size of this descriptor
    (1, "bDescriptorType", DescriptorType), # STRING Descriptor Type
    (0, "bString", "utf-16-le"),            # u16 encoded UNICODE string
    # Variable length with at least one character specified
)

def string_descriptor(bytes):
    bytes.decode(encoding="utf-16-le")

def descriptor_data(data):
    print(data)
    ptr=0
    if data[0]==len(data):
        print("Length is", data[0])
    else:
        print(f"Length is claiming to be {data[0]} but is actually {len(data)}")
        if data[0]>len(data):
            print("Warning: Actual length is less than expected")
    variant=data[1]
    if variant in DescriptorType:
        variant=DescriptorType[variant].title()
    else:
        variant="RFU"+str(variant)
    # Avoid crashing due to lack of a decoder
    try:
        for field in eval(variant+"Descriptor"):
            name=field[1]
            template=field[2]
            if field[0]==1:
                value=data[ptr]
                ptr+=1
            elif field[0]==2:
                value=data[ptr]+(data[ptr+1]<<8)
                ptr+=2
            elif field[0]==0 and isinstance(field[2], str):
                # Variable length string or list
                value=0
                ptr=999
            else:
                print(f"Error: Invalid field width {field[0]} for {name}")
            if template==None:
                print("None: ", end="")
                print(field[1], value)
            elif isinstance(template, int):
                if value!=template:
                    print("Warning: field does not contain expected value {}".
                            format(template))
                    print("int:  ", end="")
                    print(name, value)
                else:
                    print("int:  ", name)
            elif isinstance(template, (list, tuple)):
                print("list: ", end="")
                if isinstance(template[0], (list, tuple)):
                    print(name, value)
                    # move from bytes to bits
                    for bf in template:
                        bfvalue=((value>>(bf[0]))&((1<<(bf[1]-bf[0]))-1))
                            #print(f"Error: Invalid bitfield width "
                                    #"{bf[0]} for {bf[1]}")
                        bfname=bf[2]
                        bftemplate=bf[3]
                        if bftemplate==None:
                            print("bfNone: ", end="")
                            print(bf[1], bfvalue)
                        elif isinstance(bftemplate, int):
                            if bfvalue!=bftemplate:
                                print("Warning: bitfield does not contain "
                                    "expected bfvalue {}".format(bftemplate))
                                print("bfint:  ", end="")
                                print(bfname, bfvalue)
                            else:
                                # Nothing to do as reserved fields are supressed
                                #print("bfint:  ", bfname)
                                pass
                        elif isinstance(bftemplate, (list, tuple)):
                            print("bflist: ", end="")
                            print(bfname, bftemplate[bfvalue])
                        elif isinstance(bftemplate, (dict)):
                            print("bfdict: ", end="")
                            print(bfname, bftemplate[bfvalue])
                        elif callable(bftemplate):
                            print("bffunc: ", end="")
                            print(bfname, bftemplate(bfvalue))
                        else:
                            print("Error: No handling defined for",
                                    type(bftemplate))
                            print(bfname, bfvalue, bftemplate)
                else:
                    print(name, template[value])
            elif isinstance(template, (dict)):
                print("dict: ", end="")
                print(name, template[value])
            elif callable(template):
                print("func: ", end="")
                print(name, template(value))
            elif isinstance(template, str):
                if template=="utf-16-le":
                    print("str:  ", end="")
                    s=array("B", data[2:]).tobytes().decode(template)
                    print(name, s)
                else:
                    print("Error: Unrecognized string encoding '{template}'")
            else:
                print(type(template))
                print(name, value)
    except NameError as e:
        print(f"Error: Template {e} does not exist")
    except TypeError:
        print(f"Error: Incorrect type {e}")
    except Exception as e:
        print(f"Error: Unhandled exception {e} caught")
    if data[0]<len(data):
        # Recursion: the easy way to handle packets with multiple descriptors
        descriptor_data(data[data[0]:])

if __name__ == "__main__":
    # test vectors
    descriptor_data([18,1, 16,1,0,0,0,0,0x34,0x12,0xcc,0xde,0x34,0x12,0,1,2,1])
    descriptor_data([14, 3, 70, 0, 111, 0, 111, 0, 115, 0, 110, 0, 0, 0])
    descriptor_data([9, 2, 27, 0, 1, 1, 1, 128, 50, 9, 4, 0, 0, 0, 254, 1, 2, 2, 9, 33, 13, 16, 39, 0, 4, 1, 1])