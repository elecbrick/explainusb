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

#-----------------------------------------------------------------------------

'''
USB Protocol Analyzer that decodes, compares, and clarifies USB packet contents
to simplify testing and verification.
Routines are provided to show details of what was received and to show
differences in packet fields from what was expected.

Environment:
-----------
Designed to work as a stand-alone application or as an enhansement to
cocotb_usb. The default  the only 

Design Philosophy:
-----------------

Packet: May be initialized by passing:
    1. a string of JK characters starting with SYNC and ending with EOP pattern
    2. a pair of strings of 01 characters for D+/D-
    3. a list of bytes, the content between but excluding SYNC and EOP

Mismatch handling can give a warning, an error or be fatal.
Simulation should be allowed to proceed and not aborted just because
the client gave a different response than expected.
------------------------------------------------------------------- '''

from explainusb.explain import USBPacket, logger
#import explainusb.packets
#import explainusb.descriptors

class Analyze:
    # USB State: Last packet sent, Expected response remaining
    current_request=None
    data_remaining=0

    def sent(sentpp):
        # Record side effects and display summary of packet
        sent=USBPacket(sentpp, Analyze.current_request)
        logger.info(f"Sent: {sent.summarize()}")
        if sent.pid=="SETUP" and sent.fields['Endpoint']==0:
            Analyze.current_request="SETUP"
        elif Analyze.current_request=="SETUP":
            Analyze.current_request=sent
        elif sent.pid=="DATA1" and len(sent.byte)==3:
            # Zero-length data packet indicates status stage
            Analyze.current_request=None

    def received(receivedpp):
        # Record side effects and display summary of packet
        received=USBPacket(receivedpp, Analyze.current_request)
        logger.info(f"Received: {received.summarize()}")
        if received.pid=="DATA1" and len(received.byte)==3:
            # Zero-length data packet indicates status stage
            Analyze.current_request=None

    def explain(receivedpp, expectedpp=None, transfer=None):
        received=USBPacket(receivedpp, Analyze.current_request)
        logger.info(f"Received: {received.summarize()}")
        if expectedpp!=None:
            expected=USBPacket(expectedpp, Analyze.current_request)
            logger.info(f"Expected: {expected.summarize()}")
            received.compare(expected)
