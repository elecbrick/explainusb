#!/usr/bin/env python3

'''
Copyright © 2020 Doug Eaton

USBDecode is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as
published by the Free Software Foundation, either version 2 of
the License, or (at your option) any later version.

usb_decode is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
'''

from enum import Enum
import fileinput
import re

wanted=["usb_d_n", "usb_d_p", "usb_tx_en", "usb_pullup"]
signals=[]
line=None

if __name__ == "__main__":
    tb="tb"
    # Expect test bench a "module tb"
    # Process headers first. Break and move to next phase after definitions
    with fileinput.input() as vcd:
        for line in vcd:
            if line[0:6]=='$scope':
                break
            print(line, end='')
        print("$scope module", tb, "$end")
        for line in vcd:
            word=re.findall("\S+", line)
            if word[4] in wanted:
                print(line, end='')
                signals.append(word[3])
                wanted.remove(word[4])
                if len(wanted)==0:
                    break
        if len(wanted)>0:
            print("Not all signals found:", wanted, file=sys.stderr)
        print("$upscope $end")
        print("$enddefinitions $end")
        for line in vcd:
            line=line.rstrip()
            if line[0]=='#':
                # Avoid printing time if none of the signals cared about toggle
                time=line
                next
            if line[0]=='b':
                if line[line.find(' ')+1:] in signals:
                    if time:
                        print(time)
                        time=None
                    print(line)
            elif line[1:] in signals:
                if time:
                    print(time)
                    time=None
                print(line)
        if time:
            print(time)
