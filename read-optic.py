#!/usr/bin/python3

# XXX FIXME: Need to implement SFF-8636 to read 4-lane optics
#
# XXX FIXME: Need to read all user-pages on 0xa0 with page-select-byte (?)


# (c) 2015-2023 Jared Mauch jared@puck.nether.net
# (c) 2015 WhiteBoxOptical LLC
#
# Unauthorized copying Prohibited
#
# Raspberry PI 2 setup details:
# % # echo dtparam=i2c_arm=on >> /boot/config.txt
# % # echo dtparam=i2c_vc=on >> /boot/config.txt
# % # apt-get install python-smbus2
# % # modprobe i2c_dev ; echo i2c_dev >> /etc/modules
# % ** append  bcm2708.vc_i2c_override=1 to /boot/cmdline.txt
#
# INF-8074 version: 1.0
# INF-8077 version: 4.5
# SFF-8024 version: 4.12
# SFF-8419 version: 1.3
# SFF-8436 version: FIXME (needs to be 4.8)
# SFF-8472 version: 12.4.3
# SFF-8636 version: 2.11 (needs to be x)
# SFF-8679 version: 1.8 (needs to be x)
# SFF-8690 version: 1.4.2
# OIF-CMIS version: 5.3
#
#
#
from __future__ import division
from __future__ import print_function

# some optics (eg: GLC-T) come soft-disabled for some reason
# added code to soft-enable them

from builtins import chr
from builtins import range
import argparse
import re
import sys
import struct

real_hardware = True
if real_hardware:
   try:
       import smbus2
   except:
       real_hardware = False
       print("If we are in real hardware you are missing the python3-smbus2 library, disabled real hardware code paths")
import time
import json
import math
from curses.ascii import isprint
usleep = lambda x: time.sleep(x/1000000.0)

# globals
address_one = 0x50 # A0
address_two = 0x51 # A2 DDM and SFF-8690 Tunable support

tmp102_address = 0x48
#tmp102_address = 0x4e

# lower page
optic_lower_page = bytearray.fromhex("18400407000000000000000000002fb8811f000000003486000020000000000000000000000100030400000000000000000000000000000000000000000000000000000000000000000000000000000000000000030402111e840111438401ff00000000000000000000000000000000000000000000000000000000000000001118434947202020202020202020202020000b4054524435483230454e462d4c4630303030315332324a423035525220202020202020323230393236202020202020202020202020a0300007000000000000f00006000000000000000000d6000000000000000000000000000000000000000000000000000000000000000000")

# page 0
optic_sff = bytearray.fromhex("18400407000000000000000000002fb8811f0000000034860000200000000000000000000001000304000000000000000000000000000000000000000000000000000000000000000000000000000000000000030402111e840111438401ff000000000000000000000000000000000000000000000000000000000000000011030402004a000000000065a4051424f017c2460000009c1a00fa773b03070613075d3d77ff00003822000000000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000099")

optic_sff_read = len(optic_sff)

upper_page = { }
#upper_page{1} = bytearray.fromhex("030402004a000000000065a4051424f017c2460000009c1a00fa773b03070613075d3d77ff00003822000000000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000099")

#upper_page{2}=bytearray.fromhex("4b00fb00460000008dcc7404875a7a76000000000000000000000000000000003f8029803c802c8000000000000000009f220a847e6714fac35030d4afc8445c9f2202777e6704eb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007c")

#upper_page{0x10}=bytearray.fromhex("00000000000000000000000000000000001010101010101010ff000000000000ffff2222222200000000333333330000000000002121212121212121ff000000000000ffff2222222200000000333333330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

#upper_page{0x11}=bytearray.fromhex("44444444000000000000000000000000000000000000000000005552564c549b561b00000000000000007417687461a861a80000000000000000481a4bbf432546810000000000000000111111111010101010101010ff000000000000ffff222222220000000033333333000000000011213141000000001121314100000000")

# page 1
optic_ddm = bytearray.fromhex("5000f6004b00fb0088b8785087f07918d6d82710c3503a986e181ba7621f1f070c5a002809d000320000000000000000000000000000000000000000000000000000000003f8000000000000001000000010000000100000001000000000000b116a980d700000000000000000000000005400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

optic_sff_read = len(optic_sff)
optic_ddm_read = len(optic_ddm)

optic_dwdm = []
optic_dwdm_read = -1

def parse_hex_dump_line(line):
    """Parse a hex dump line and return the hex bytes"""
    hex_bytes = re.findall(r'([0-9a-fA-F]{2})', line)
    if len(hex_bytes) > 1:
        data_bytes = [int(b, 16) for b in hex_bytes[1:]]
        return data_bytes
    return []

def parse_optic_file(filename):
    """Parse optic data from a file and populate the global page dictionary"""
    global optic_pages, optic_ddm_pages, optic_dwdm_pages, optic_sff_read, optic_ddm_read, optic_dwdm_read
    try:
        with open(filename, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return False
    except Exception as e:
        print(f"Error reading file '{filename}': {e}")
        return False
    lines = content.split('\n')
    # Use dicts to store each page
    optic_pages = {}
    optic_ddm_pages = {}
    optic_dwdm_pages = {}
    current_device = None
    current_address = None
    current_page = 0x00
    is_juniper_qsfp = False
    page_map = {
        'Lower Page': 0x00,
        'Upper Page 00h': 0x80,
        'Upper Page 01h': 0x100,
        'Upper Page 02h': 0x180,
        'Upper Page 03h': 0x200,
        'Upper Page 04h': 0x280,
        'Upper Page 10h': 0x400,
        'Upper Page 11h': 0x480,
        'Upper Page 12h': 0x500,
        'Upper Page 13h': 0x580,
        'Upper Page 25h': 0x1280,
    }
    for idx, orig_line in enumerate(lines):
        line = orig_line.strip()
        if not line:
            continue
        lstripped = orig_line.lstrip()
        # Device address detection (SFP/SFP+)
        if "2-wire device address" in line:
            addr_match = re.search(r'0x([0-9a-fA-F]+)', line)
            if addr_match:
                current_address = int(addr_match.group(1), 16)
                if current_address == 0x50:
                    current_device = 'sff'
                elif current_address == 0x51:
                    current_device = 'ddm'
                else:
                    current_device = None
                continue
        # SFP hex dump lines (indented, after device address)
        if current_device and lstripped.startswith('0x') and ':' in lstripped and not is_juniper_qsfp:
            hex_bytes = parse_hex_dump_line(lstripped)
            if hex_bytes:
                try:
                    base_addr = int(lstripped.split(':')[0], 16)
                    page = optic_pages if current_device == 'sff' else optic_ddm_pages
                    if 0x00 not in page:
                        page[0x00] = [0]*256
                    for i, val in enumerate(hex_bytes):
                        addr = base_addr + i
                        if addr < 256:
                            page[0x00][addr] = val
                except (ValueError, IndexError):
                    continue
            continue
        # Handle hex dump format with 0x00= and 0x01= prefixes
        if line.startswith('0x00='):
            hex_data = line[5:]
            hex_bytes = [int(hex_data[i:i+2], 16) for i in range(0, len(hex_data), 2)]
            if 0x00 not in optic_pages:
                optic_pages[0x00] = [0]*256
            for i, val in enumerate(hex_bytes):
                if i < 256:
                    optic_pages[0x00][i] = val
            continue
        if line.startswith('0x01='):
            hex_data = line[5:]
            hex_bytes = [int(hex_data[i:i+2], 16) for i in range(0, len(hex_data), 2)]
            if 0x00 not in optic_ddm_pages:
                optic_ddm_pages[0x00] = [0]*256
            for i, val in enumerate(hex_bytes):
                if i < 256:
                    optic_ddm_pages[0x00][i] = val
            continue
        # Handle formatted hex dumps with headers
        for page_name, page_offset in page_map.items():
            if lstripped.startswith(f'QSFP-DD {page_name}') or lstripped.startswith(page_name):
                current_device = 'sff'
                current_page = page_offset
                if current_page not in optic_pages:
                    optic_pages[current_page] = [0]*256
                break
        # Parse hex dump lines in formatted output
        if line.startswith('0x') and current_device and 'Addr' not in line and '----' not in line:
            parts = line.split()
            if len(parts) >= 17:
                try:
                    base_addr = int(parts[0], 16)
                    for i in range(1, 17):
                        if i < len(parts):
                            val = int(parts[i], 16)
                            addr = base_addr + (i - 1)
                            if current_page not in optic_pages:
                                optic_pages[current_page] = [0]*256
                            if addr < 256:
                                optic_pages[current_page][addr] = val
                except ValueError:
                    continue
            continue
        # Juniper QSFP format detection
        if line.startswith('QSFP IDEEPROM (Low Page 00h'):
            is_juniper_qsfp = True
            current_device = 'sff'
            current_page = 0x00
            if current_page not in optic_pages:
                optic_pages[current_page] = [0]*256
            continue
        if line.startswith('QSFP IDEEPROM (Upper Page 00h'):
            is_juniper_qsfp = True
            current_device = 'sff'
            current_page = 0x80
            if current_page not in optic_pages:
                optic_pages[current_page] = [0]*256
            continue
        if line.startswith('QSFP IDEEPROM (Upper Page 03h'):
            is_juniper_qsfp = True
            current_device = 'ddm'
            current_page = 0x00
            if current_page not in optic_ddm_pages:
                optic_ddm_pages[current_page] = [0]*256
            continue
        # Generic QSFP IDEEPROM format (like qsfp-40g-dac)
        if line.startswith('QSFP IDEEPROM:'):
            current_device = 'sff'
            current_page = 0x00
            if current_page not in optic_pages:
                optic_pages[current_page] = [0]*256
            continue
        if line.startswith('QSFP IDEEPROM (diagnostics):'):
            current_device = 'ddm'
            current_page = 0x00
            if current_page not in optic_ddm_pages:
                optic_ddm_pages[current_page] = [0]*256
            continue
        # Address lines (both Juniper and generic formats)
        if line.startswith('Address 0x'):
            addr_match = re.match(r'Address 0x([0-9a-fA-F]+):\s+(.+)', line)
            if addr_match:
                base_addr = int(addr_match.group(1), 16)
                hex_bytes = [int(b, 16) for b in addr_match.group(2).split() if len(b) == 2]
                page = optic_pages if current_device == 'sff' else optic_ddm_pages
                if current_page not in page:
                    page[current_page] = [0]*256
                for i, val in enumerate(hex_bytes):
                    addr = base_addr + i
                    if addr < 256:
                        page[current_page][addr] = val
            continue
        # Always parse lines that look like hex dumps if current_device is set
        if current_device and re.match(r'^0x[0-9a-fA-F]{2}:', lstripped):
            hex_bytes = parse_hex_dump_line(lstripped)
            if hex_bytes:
                try:
                    base_addr = int(lstripped.split(':')[0], 16)
                    page = optic_pages if current_device == 'sff' else optic_ddm_pages
                    if current_page not in page:
                        page[current_page] = [0]*256
                    for i, val in enumerate(hex_bytes):
                        addr = base_addr + i
                        if addr < 256:
                            page[current_page][addr] = val
                except (ValueError, IndexError):
                    continue
            continue
    # Set global arrays to zero length if not present
    optic_sff_read = sum(len(v) for v in optic_pages.values())
    optic_ddm_read = sum(len(v) for v in optic_ddm_pages.values())
    optic_dwdm_read = sum(len(v) for v in optic_dwdm_pages.values())
    if optic_sff_read == 0:
        print("Warning: No SFF data parsed from file.")
    if optic_ddm_read == 0:
        print("Warning: No DDM data parsed from file.")
    return True

def reset_muxes(busno):
    mcp23017_bus = smbus2.SMBus(busno)
    for mcp23017 in [0x20, 0x21, 0x22, 0x23]:
        try:
            optic_bus.write_byte_data(mcp23017, 0, 0)
            usleep(20)
            optic_bus.write_byte_data(mcp23017, 0, 0xff)
        except IOError:
            usleep(0)

def fetch_psu_data(busno):
    try:
        with smbus2.SMBus(busno) as psu_bus:
            for psu_address in [0x40, 0x47]:
                psu=[]
                psu_read = -1
                while psu_read < 128:
                    try:
                        if (psu_read == -1):
                            psu_tmp = psu_bus.read_i2c_block_data(psu_address, 0, 32)
                        else:
                            psu_tmp = psu_bus.read_i2c_block_data(psu_address, psu_read, 32)
                        for member in psu_tmp:
                            psu.append(member)
                        psu_read = len(psu)
                    except IOError:
                        break

                if psu_read >= 128:
                    psu_model=""
                    psu_sn=""
                    psu_rev=""
                    psu_mfg=""
                    for byte in range (1, 16):
                        if (isprint(chr(psu[byte]))):
                            psu_model += "%c" % psu[byte]
                    for byte in range (17, 26):
                        if (isprint(chr(psu[byte]))):
                            psu_sn += "%c" % psu[byte]
                    for byte in range (27, 29):
                        if (isprint(chr(psu[byte]))):
                            psu_rev += "%c" % psu[byte]
                    for byte in range (33, 42):
                        if (isprint(chr(psu[byte]))):
                            psu_mfg += "%c" % psu[byte]

                    psu_date = "%4.4d-%-2.2d-%2.2d" % (psu[29]+2000, psu[30], psu[31])
                    print("PSU_MODEL: %s" % psu_model)
                    print("PSU_SN: %s" % psu_sn)
                    print("PSU_DATE: %s" % psu_date)
                    print("PSU_MFG: %s" % psu_mfg)
                    print("PSU_MFG_LOC: %d" % psu[42])
                    print("PSU_SPEC_VOLTAGE: %d" % ((psu[43]*256)+psu[44]))
                    print("PSU_SPEC_CURRENT: %d" % ((psu[46]*256)+psu[47]))
                    print("PSU_SPEC_POWER: %d" % ((psu[49]*256)+psu[50]))
                    print("PSU_SPEC_MIN_AC: %d" % ((psu[51]*256)+psu[52]))
                    print("PSU_SPEC_MAX_AC: %d" % ((psu[53]*256)+psu[54]))
                    print("PSU_CHECKSUM: %d" % psu[55])
                    print("PSU_FAULT: 0x%x" % psu[56])
                    if (psu[56] & 0x10): # 0b00010000
                        print("PSU_FAULT: OVER_TEMP")
                    if (psu[56] & 0x08): #
                        print("PSU_FAULT: FAN_FAIL")
                    if (psu[56] & 0x04): #
                        print("PSU_FAULT: DC_OUTPUT_FAIL")
                    if (psu[56] & 0x02): #
                        print("PSU_FAULT: AC_INPUT_FAIL")
                    if (psu[56] & 0x01): #
                        print("PSU_FAULT: SEATED_IMPROPERLY")
                    print("PSU_FAN_SPEED: %d RPM" % (psu[57]*100))
                    if (psu[58] & 0x80):
                        print("PSU_TEMP: OUT_OF_RANGE")
                    else:
                        psu_temp = (psu[58] & 0b01111111)-34
                        print("PSU_TEMP: %d C" % psu_temp)
                    print("PSU_ROHS_BYTE: %c" % psu[59])
    except IOError as e:
        print(f"Error accessing PSU on bus {busno}: {str(e)}")
        return
    except Exception as e:
        print(f"Unexpected error accessing PSU on bus {busno}: {str(e)}")
        return

def fetch_optic_data(optic_bus):
    # import as globals
    global optic_sff
    global optic_sff_read
    global optic_ddm
    global optic_ddm_read
    global optic_dwdm
    global optic_dwdm_read

    # initalize them
    optic_sff = []
    optic_sff_read = 0
    optic_ddm = []
    optic_ddm_read = -1
    optic_dwdm = []
    optic_dwdm_read = -1

    fast_read = 0
    # read SFF data
    while optic_sff_read < 256:
        try:
            if fast_read == 1:
                optic_sff_tmp = optic_bus.read_i2c_block_data(address_one, optic_sff_read, 32, force=True)
                for member in optic_sff_tmp:
                    optic_sff.append(member)
                optic_sff_read = len(optic_sff)
            else:
                value = optic_bus.read_byte_data(address_one, optic_sff_read)
                optic_sff.append(value)
                optic_sff_read = len(optic_sff)
        except IOError as e:
            print(f"Error reading SFF data: {str(e)}")
            break
        except Exception as e:
            print(f"Unexpected error reading SFF data: {str(e)}")
            break

    # regular page
    try:
        # write data to set to default page
        optic_bus.write_byte_data(address_two, 127, 0x0)
    except IOError as e:
        print(f"Error switching optic page: {str(e)}")
    except Exception as e:
        print(f"Unexpected error switching optic page: {str(e)}")

    # read DDM data
    while optic_ddm_read < 256:
        try:
            if fast_read == 1:
                if (optic_ddm_read == -1):
                    optic_ddm_tmp = optic_bus.read_i2c_block_data(address_two, 0, 32)
                else:
                    optic_ddm_tmp = optic_bus.read_i2c_block_data(address_two, optic_ddm_read, 32)
                for member in optic_ddm_tmp:
                    optic_ddm.append(member)
                optic_ddm_read = len(optic_ddm)
            else:
                value = optic_bus.read_byte_data(address_two, optic_ddm_read)
                optic_ddm.append(value)
                optic_ddm_read = len(optic_ddm)
        except IOError:
            break

    # if dwdm optic value
    if (optic_sff_read > 65):
        if (get_byte(optic_pages, 0x00, 65) & 0x40):
            # switch to page with DWDM dwdm data
            try:
                # write data
                optic_bus.write_byte_data(address_two, 127, 0x2)
            except IOError:
                # error switching to dwdm data page
                a=0

    # read DWDM-DDM data
    while optic_dwdm_read < 256:
        try:
            if (optic_dwdm_read == -1):
                optic_dwdm_tmp = optic_bus.read_i2c_block_data(address_two, 0, 32)
            else:
                optic_dwdm_tmp = optic_bus.read_i2c_block_data(address_two, optic_dwdm_read, 32)
            for member in optic_dwdm_tmp:
                optic_dwdm.append(member)
            optic_dwdm_read = len(optic_dwdm)
        except IOError:
            break

def read_optic_type():
    # defined in SFF-8024 4.11
    # updated 2023-12-05

    # Get the optic type from the page dictionary
    optic_type = get_byte(optic_pages, 0x00, 0)

    if optic_type == 0x00:
        sff_type_text = "Unknown or unspecified"
    elif optic_type == 0x01:
        sff_type_text = "GBIC"
    elif optic_type == 0x02:
        sff_type_text = "Module soldered to motherboard" # SFF-8472
    elif optic_type == 0x03:
        sff_type_text = "SFP/SFP+/SFP28" # SFF-8472
    elif optic_type == 0x04:
        sff_type_text = "300 pin XBI"
    elif optic_type == 0x05:
        sff_type_text = "XENPAK"
    elif optic_type == 0x06:
        sff_type_text = "XFP" # INF-8077i, SFF-8477
    elif optic_type == 0x07:
        sff_type_text = "XFF"
    elif optic_type == 0x08:
        sff_type_text = "XFP-E"
    elif optic_type == 0x09:
        sff_type_text = "XPAK"
    elif optic_type == 0x0A:
        sff_type_text = "X2"
    elif optic_type == 0x0B:
        sff_type_text = "DWDM-SFP/SFP+" # DOES NOT USE SFF-8472
    elif optic_type == 0x0C:
        sff_type_text = "QSFP"
    elif optic_type == 0x0D:
        sff_type_text = "QSFP+" # SFF-8436 SFF-8635 SFF-8665 SFF-8685
    elif optic_type == 0x0E:
        sff_type_text = "CXP"
    elif optic_type == 0x0F:
        sff_type_text = "Shielded Mini Multilane HD 4X"
    elif optic_type == 0x10:
        sff_type_text = "Shielded Mini Multilane HD 8X"
    elif optic_type == 0x11:
        sff_type_text = "QSFP28" # SFF-8636/SFF-8665
    elif optic_type == 0x12:
        sff_type_text = "CXP2/CFP28"
    elif optic_type == 0x13:
        sff_type_text = "CDFP" # INF-TA-1003 style 1/2
    elif optic_type == 0x14:
        sff_type_text = "Shielded Mini Multilane HD 4X Fanout"
    elif optic_type == 0x15:
        sff_type_text = "Shielded Mini Multilane HD 8X Fanout"
    elif optic_type == 0x16:
        sff_type_text = "CDFP Style 3" # INF-TA-1003
    elif optic_type == 0x17:
        sff_type_text = "microQSFP"
    elif optic_type == 0x18:
        sff_type_text = "QSFP-DD" # CMIS 5.0
    elif optic_type == 0x19:
        sff_type_text = "OSPF 8X Pluggable Transceiver"
    elif optic_type == 0x1a:
        sff_type_text = "SFP-DD Double Density 2X Pluggable Transceiver"
    elif optic_type == 0x1b:
        sff_type_text = "DSFP Dual Small Form Factor Pluggable Transceiver"
    elif optic_type == 0x1c:
        sff_type_text = "x4 MiniLink/OcuLink"
    elif optic_type == 0x1d:
        sff_type_text = "x4 MiniLink"
    elif optic_type == 0x1f:
        sff_type_text = "QSFP+ or later with Common Management Interface Specification (CMIS)"
    elif optic_type == 0x20:
        sff_type_text = "SFP+ CMIS"
    elif optic_type == 0x21:
        sff_type_text = "OSFP-XD CMIS"
    elif optic_type == 0x22:
        sff_type_text = "OIF-ELSFP CMIS"
    elif optic_type == 0x23:
        sff_type_text = "CDFP (x4 PCIe) SFF-TA-1032 CMIS"
    elif optic_type == 0x24:
        sff_type_text = "CDFP (x8 PCIe) SFF-TA-1032 CMIS"
    elif optic_type == 0x25:
        sff_type_text = "CDFP (x16 PCIe) SFF-TA-1032 CMIS"
    elif optic_type >= 0x80:
        sff_type_text = "Vendor Specific"
    else:
        sff_type_text = "Not yet specified value (%d) check SFF-8024" % optic_type
    print("SFF Type:", sff_type_text)

    return int(optic_type)


def read_optic_mod_def():
    # SFF-8472 Physical Device Extended Identifer Values
    # Byte 1 Table 5-2

    val = get_byte(optic_pages, 0x00, 1)
    if val == 0x00:
        mod_def_text = ("Not Specified")
    elif val == 0x01:
        mod_def_text = ("MOD_DEF 1")
    elif val == 0x02:
        mod_def_text = ("MOD_DEF 2")
    elif val == 0x03:
        mod_def_text = ("MOD_DEF 3")
    elif val == 0x04:
        mod_def_text = ("function defined by i2c ID only")
    elif val == 0x05:
        mod_def_text = ("MOD_DEF 5")
    elif val == 0x06:
        mod_def_text = ("MOD_DEF 6")
    elif val == 0x07:
        mod_def_text = ("MOD_DEF 7")
    else:
        mod_def_text = ("Unallocated (%d)" % val)
    print("Extended Identifier Value:", mod_def_text)


def read_optic_connector_type(connector_type):
    # defined in SFF-8024 4-3, INF-8077 Table 48

    if connector_type == 0x00:
        connector_type_text = "Unknown or unspecified"
    elif connector_type == 0x01:
       connector_type_text = "SC"
    elif connector_type == 0x02:
        connector_type_text ="Fibre Channel Style 1 copper connector"
    elif connector_type == 0x03:
        connector_type_text ="Fibre Channel Style 2 copper connector"
    elif connector_type == 0x04:
        connector_type_text ="BNC/TNC"
    elif connector_type == 0x05:
        connector_type_text ="Fiber Channel coax headers"
    elif connector_type == 0x06:
        connector_type_text ="Fiber Jack"
    elif connector_type == 0x07:
        connector_type_text ="LC"
    elif connector_type == 0x08:
        connector_type_text ="MT-RJ"
    elif connector_type == 0x09:
        connector_type_text ="MU"
    elif connector_type == 0x0A:
        connector_type_text ="SG"
    elif connector_type == 0x0B:
        connector_type_text ="Optical Pigtail"
    elif connector_type == 0x0C:
        connector_type_text ="MPO 1x12"
    elif connector_type == 0x0D:
        connector_type_text ="MPO 2x16"
    elif connector_type == 0x20:
        connector_type_text ="HSSDC II"
    elif connector_type == 0x21:
        connector_type_text = "Copper Pigtail"
    elif connector_type == 0x22:
        connector_type_text = "RJ45"
    elif connector_type == 0x23:
        connector_type_text = "No separable connector"
    elif connector_type == 0x24:
        connector_type_text = "MXC 2x16"
    elif connector_type == 0x25:
        connector_type_text = "CS optical connector"
    elif connector_type == 0x26:
        connector_type_text = "SN optical connector (Mini CS)"
    elif connector_type == 0x27:
        connector_type_text = "MPO 2x12"
    elif connector_type == 0x28:
        connector_type_text = "MPO 1x16"
    elif connector_type >= 0x80:
        connector_type_text = "Vendor Specific" # sff-8024 4.3
    else:
        connector_type_text = "Not yet specified value (%d) check SFF-8024" % connector_type
    print("Connector Type:", connector_type_text)


def read_sff_optic_encoding():
    # SFF 8472 11
    # SFF 8024 4-2
    # SFF-8436 & SFF-8636

    val = get_byte(optic_pages, 0x00, 11)
    if val == 0x00:
        encoding_type_text = ("Unspecified")
    elif val == 0x01:
        encoding_type_text = ("8B/10B")
    elif val == 0x02:
        encoding_type_text = ("4B/5B")
    elif val == 0x03:
        encoding_type_text = ("NRZ")
    # 0x4-0x6 only valid for SFF-8472, SFF-8436 and SFF-8636 has other encodings
    elif val == 0x04:
        encoding_type_text = ("Manchester")
    elif val == 0x05:
        encoding_type_text = ("SONET Scrambled")
    elif val == 0x06:
        encoding_type_text = ("64B/66B")
    elif val == 0x07:
        encoding_type_text = ("256B/257B")
    elif val == 0x08:
        encoding_type_text = ("PAM-4")
    else:
        encoding_type_text = ("Not yet specified value (%d) check SFF-8024" % val)
    print("Encoding Type:", encoding_type_text)


def read_xfp_encoding():
    # INF-8077 Table 50 Byte 139
    xfp_encoding= []
    if (get_byte(optic_pages, 0x00, 139) & 0x80): # bit 7
        xfp_encoding.append('64B/66B')
    if (get_byte(optic_pages, 0x00, 139) & 0x40): # bit 6
        xfp_encoding.append('8B10B')
    if (get_byte(optic_pages, 0x00, 139) & 0x20): # bit 5
        xfp_encoding.append('SONET Scrambled')
    if (get_byte(optic_pages, 0x00, 139) & 0x10): # bit 4
        xfp_encoding.append('NRZ')
    if (get_byte(optic_pages, 0x00, 139) & 0x8):  # bit 3
        xfp_encoding.append('RZ')
    if (get_byte(optic_pages, 0x00, 139) & 0x4):  # bit 2
        xfp_encoding.append('139-2-Reserved')
    if (get_byte(optic_pages, 0x00, 139) & 0x2):  # bit 1
        xfp_encoding.append('139-1-Reserved')
    if (get_byte(optic_pages, 0x00, 139) & 0x1):  # bit 0
        xfp_encoding.append('139-0-Reserved')

    comma=","
    print("XFP Encoding:", comma.join(xfp_encoding))

def read_xfp_br():
    xfp_min_br = get_byte(optic_pages, 0x00, 140) * 100
    xfp_max_br = get_byte(optic_pages, 0x00, 141) * 100
    print("XFP Min-Bitrate = %d Mbps" % xfp_min_br)
    print("XFP Max-Bitrate = %d Mbps" % xfp_max_br)

def read_xfp_lengths():
    xfp_len_km_smf = get_byte(optic_pages, 0x00, 142)
    xfp_len_om2_mmf = get_byte(optic_pages, 0x00, 143) *2 # convert to meters
    xfp_len_mmf = get_byte(optic_pages, 0x00, 144)
    xfp_len_om1_mmf = get_byte(optic_pages, 0x00, 145)
    xfp_len_copper = get_byte(optic_pages, 0x00, 146) # meters

    print("XFP Distances:")
    print("\tSMF %d KM" % xfp_len_km_smf)
    print("\tOM2 MMF %d meters" % xfp_len_om2_mmf)
    print("\tOM2 MMF %d meters" % xfp_len_mmf)
    print("\tOM1 MMF %d meters" % xfp_len_om1_mmf)
    print("\tCopper %d meters" % xfp_len_copper)

def read_xfp_technology():
    xfp_device_technology = []
    if (get_byte(optic_pages, 0x00, 147) & 0x8): # bit 3
        xfp_device_technology.append('Active Wavelength Control')
    else:
        xfp_device_technology.append('No Wavelength Control')
    if (get_byte(optic_pages, 0x00, 147) & 0x4): # bit 2
        xfp_device_technology.append('Cooled transmitter')
    else:
        xfp_device_technology.append('Uncooled transmitter')
    if (get_byte(optic_pages, 0x00, 147) & 0x2): # bit 1
        xfp_device_technology.append('APD Detector')
    else:
        xfp_device_technology.append('PIN detector')
    if (get_byte(optic_pages, 0x00, 147) & 0x1): # bit 0
        xfp_device_technology.append('Transmitter Tunable')
    else:
        xfp_device_technology.append('Transmitter not Tunable')
    comma=","
    print("XFP Technology:", comma.join(xfp_device_technology))

    xfp_technology_bits = get_byte(optic_pages, 0x00, 147) >> 4
    print("XFP Transmitter Technology:")
    if (xfp_technology_bits == 0x0):
        print("\t850 nm VCSEL")
    elif (xfp_technology_bits == 0x1):
        print("\t1310 nm VCSEL")
    elif (xfp_technology_bits == 0x2):
        print("\t1550 nm VCSEL")
    elif (xfp_technology_bits == 0x3):
        print("\t1310 nm FP")
    elif (xfp_technology_bits == 0x4):
        print("\t1310 nm DFB")
    elif (xfp_technology_bits == 0x5):
        print("\t1550 nm DFB")
    elif (xfp_technology_bits == 0x6):
        print("\t1310 nm EML")
    elif (xfp_technology_bits == 0x7):
        print("\t1550 nm EML")
    elif (xfp_technology_bits == 0x8):
        print("\tCopper")
    else:
        print("\tReserved (%x)" % xfp_technology_bits)


def read_qsfpdd_vendor():
    """Read and print the vendor name for QSFP-DD/CMIS modules using page dict."""
    try:
        # Debug: print available pages
        print(f"Debug: Available pages: {list(optic_pages.keys())}")
        
        # Vendor name is at Upper Page 00h (0x80), bytes 0x10-0x1F
        vendor = ''.join(chr(get_byte(optic_pages, 0x80, i)) for i in range(0x10, 0x20))
        print("Vendor:", vendor.strip())
    except Exception as e:
        print(f"Error reading vendor name: {e}")

def read_xfp_vendor():
    # INF-8077 5.XX
    # 16 bytes ASCII at bytes 148-163
    vendor = get_bytes(optic_pages, 0x00, 148, 164).decode('ascii', errors='ignore').strip()
    print("Vendor:", vendor)

def read_xfp_vendor_pn():
    # INF-8077 5.31
    vendor_pn = get_bytes(optic_pages, 0x00, 168, 184).decode('ascii', errors='ignore').strip()
    print("Vendor PN:", vendor_pn)

def read_qsfpdd_vendor_pn():
    # QSFP-DD-CMIS rev4p0 8.3
    # For CMIS modules, part number is in Upper Page 01h (offset 0x100)
    # Part number is at bytes 0x110-0x11F (272-287)
    vendor_pn = get_bytes(optic_pages, 0x01, 272, 288).decode('ascii', errors='ignore').strip()
    print("Vendor PN:", vendor_pn)

def read_qsfpdd_vendor_rev():
    # QSFP-DD-CMIS rev4p0 8.3
    # For CMIS modules, revision is in Upper Page 01h (offset 0x100)
    # Revision is at bytes 0x120-0x121 (288-289)
    vendor_rev = get_bytes(optic_pages, 0x01, 288, 290).decode('ascii', errors='ignore').strip()
    print("Vendor rev:", vendor_rev)

def read_xfp_vendor_rev():
    # INF-8077 5.32 (184-185)
    vendor_rev = get_bytes(optic_pages, 0x00, 184, 186).decode('ascii', errors='ignore').strip()
    print("Vendor REV:", vendor_rev)

def read_xfp_wavelength():
    # INF-8077 5.33 (186,187)
    xfp_wavelength = ((get_byte(optic_pages, 0x00, 186)*256)+get_byte(optic_pages, 0x00, 187))*.05

    print("XFP Wavelength: %d nm" % xfp_wavelength)
    # INF-8077 5.34
    print("XFP Wavelength Tolerance: %d nm" % (((get_byte(optic_pages, 0x00, 188)*256)+get_byte(optic_pages, 0x00, 189)) *.005))

def read_xfp_max_temp():
    # INF-8077 5.35
    xfp_max_temp_c = get_byte(optic_pages, 0x00, 190)
    print("XFP Max Temp: %d C" % xfp_max_temp_c)

def read_xfp_cc_base():
    # INF-8077 5.36
    # checksum of bytes 128-190
    calc_cc_base = 0
    for byte in range (128, 191):
        calc_cc_base = calc_cc_base + get_byte(optic_pages, 0x00, byte)
    print("XFP CC Base = %x, Calc = %x" % (get_byte(optic_pages, 0x00, 191), calc_cc_base & 0xff))

def read_xfp_power_supply():
    # INF-8077 5.37
    # 192-195
    xfp_max_power_disp = get_byte(optic_pages, 0x00, 192) * 20
    xfp_total_power_disp = get_byte(optic_pages, 0x00, 193) * 10
    xfp_max_current_5v = (get_byte(optic_pages, 0x00, 194) >> 4) * 50
    xfp_max_current_3v = (get_byte(optic_pages, 0x00, 194) & 0xf) * 100
    xfp_max_current_1v = (get_byte(optic_pages, 0x00, 195) >> 4) * 100
    xfp_max_current_neg5v = (get_byte(optic_pages, 0x00, 195) & 0xf) * 50
    print("Maximum Power Dissipation: %d mW" % xfp_max_power_disp)
    print("Maximum Total Power Dissipation (P_Down): %d mW" % xfp_total_power_disp)
    print("Maximum current required 5V: %d mA" % xfp_max_current_5v)
    print("Maximum current required 3V3: %d mA" % xfp_max_current_3v)
    print("Maximum current required 1V8: %d mA" % xfp_max_current_1v)
    print("Maximum current required -5.2V: %d mA" % xfp_max_current_neg5v)

def read_xfp_ext_ddm_type():
    # INF-8077 5.40 Byte 220
    xfp_ddm_type=[]

    if (get_byte(optic_pages, 0x00, 220) & 0x10): # bit 4
        xfp_ddm_type.append('BER Support')
    else:
        xfp_ddm_type.append('No BER Support')
    if (get_byte(optic_pages, 0x00, 220) & 0x8): # bit 3
        xfp_ddm_type.append('OMA')
    else:
        xfp_ddm_type.append('Average Power')
    comma=','
    print("XFP DDM Type:", comma.join(xfp_ddm_type))

def read_xfp_ext_enh_monitoring():
    # INF-8077 5.41 Table 57 Byte 221
    xfp_enh_options=[]
    if (get_byte(optic_pages, 0x00, 221) & 0x80): # bit 7
        xfp_enh_options.append('VPS supported')
    if (get_byte(optic_pages, 0x00, 221) & 0x40): # bit 6
        xfp_enh_options.append('Soft TX_DISABLE supported')
    if (get_byte(optic_pages, 0x00, 221) & 0x20): # bit 5
        xfp_enh_options.append('Soft P_Down supported')
    if (get_byte(optic_pages, 0x00, 221) & 0x10): # bit 4
        xfp_enh_options.append('VPS LV regulator supported')
    if (get_byte(optic_pages, 0x00, 221) & 0x8): # bit 3
        xfp_enh_options.append('VPS bypassed regulator modes supported')
    if (get_byte(optic_pages, 0x00, 221) & 0x4): # bit 2
        xfp_enh_options.append('Active FEC control functions supported')
    if (get_byte(optic_pages, 0x00, 221) & 0x2): # bit 1
        xfp_enh_options.append('Wavelength tunable supported')
    if (get_byte(optic_pages, 0x00, 221) & 0x1): # bit 0
        xfp_enh_options.append('CMU Support Mode Supported')
    comma=','
    print("XFP Enhanced Options:", comma.join(xfp_enh_options))


def read_xfp_cdr():
    xfp_cdr_support=[]
    if (get_byte(optic_pages, 0x00, 164) & 0x80): # bit 7
        xfp_cdr_support.append('9.95Gb/s')
    if (get_byte(optic_pages, 0x00, 164) & 0x40): # bit 6
        xfp_cdr_support.append('10.3Gb/s')
    if (get_byte(optic_pages, 0x00, 164) & 0x20): # bit 5
        xfp_cdr_support.append('10.5Gb/s')
    if (get_byte(optic_pages, 0x00, 164) & 0x10): # bit 4
        xfp_cdr_support.append('10.7Gb/s')
    if (get_byte(optic_pages, 0x00, 164) & 0x8): # bit 3
        xfp_cdr_support.append('11.1Gb/s')
    if (get_byte(optic_pages, 0x00, 164) & 0x4): # bit 2
        xfp_cdr_support.append('Reserved')
    if (get_byte(optic_pages, 0x00, 164) & 0x2): # bit 1
        xfp_cdr_support.append('Lineside Loopback Mode Supported')
    if (get_byte(optic_pages, 0x00, 164) & 0x1): # bit 0
        xfp_cdr_support.append('XFP Loopback Mode Supported')
    comma=','
    print("XFP CDR Support:", comma.join(xfp_cdr_support))

def read_optic_signaling_rate():
    # SFF-8472 12
    print("Optic Sigaling Rate: %d Mbit" % (get_byte(optic_pages, 0x00, 12) *100))

def read_optic_rate_identifier():
    # SFF-8472 13

    print("Optic Rate Identifier: %d" % get_byte(optic_pages, 0x00, 13))

def read_optic_vendor():
    # SFF-8472
    # 16 bytes ASCII at bytes 20-35
    vendor = get_bytes(optic_pages, 0x00, 20, 36).decode('ascii', errors='ignore').strip()
    print("Vendor:", vendor)

def read_optic_transciever():
    # SFF-8472 Table 5-3
    # Bytes 3-9
    # Extended 1 byte 36
    #
    # XXX This code is a hack
    # XXX

    # Decode Table 5-3
    if (get_byte(optic_pages, 0x00, 3) & 0x80):
        print("10G-Base-ER")
    if (get_byte(optic_pages, 0x00, 3) & 0x40):
        print("10G-Base-LRM")
    if (get_byte(optic_pages, 0x00, 3) & 0x20):
        print("10G-Base-LR")
    if (get_byte(optic_pages, 0x00, 3) & 0x10):
        print("10G-Base-SR")
    if (get_byte(optic_pages, 0x00, 3) & 0x08):
        print("Infiniband 1X SX")
    if (get_byte(optic_pages, 0x00, 3) & 0x04):
        print("Infiniband 1X LX")
    if (get_byte(optic_pages, 0x00, 3) & 0x02):
        print("infiniband 1X Copper Active")
    if (get_byte(optic_pages, 0x00, 3) & 0x01):
        print("Infiniband 1X Copper Passive")

    if (get_byte(optic_pages, 0x00, 6) & 0x80):
        print("Base-PX")
    if (get_byte(optic_pages, 0x00, 6) & 0x40):
        print("Base-BX10")
    if (get_byte(optic_pages, 0x00, 6) & 0x20):
        print("100Base-FX")
    if (get_byte(optic_pages, 0x00, 6) & 0x10):
        print("100Base-LX/LX10")
    if (get_byte(optic_pages, 0x00, 6) & 0x08):
        print("1000Base-T")
    if (get_byte(optic_pages, 0x00, 6) & 0x04):
        print("1000Base-CX")
    if (get_byte(optic_pages, 0x00, 6) & 0x02):
        print("1000Base-LX")
    if (get_byte(optic_pages, 0x00, 6) & 0x01):
        print("1000Base-SX")


    print("extended compliance_code %d" % get_byte(optic_pages, 0x00, 36))

def read_qsfpdd_vendor_oui():
    """Read and print the vendor OUI for QSFP-DD/CMIS modules."""
    try:
        # For CMIS, OUI is at 0x100 + 0x25 = 293, length 3 bytes
        oui = get_bytes(optic_pages, 0x01, 293, 296)
        print("Vendor OUI: %02x%02x%02x" % (oui[0], oui[1], oui[2]))
    except Exception as e:
        print(f"Error reading vendor OUI: {e}")


def read_optic_vendor_oui():
    # SFF-8472 4-1
    # 3 bytes 37-39

    vendor_oui=""
    for byte in range (37, 40):
        vendor_oui = vendor_oui + ("%2.2x" % get_byte(optic_pages, 0x00, byte))
    print("vendor_oui: %s" % vendor_oui)

def read_xfp_vendor_oui():
    # INF-8077 5.30
    # 3 bytes 165-167

    vendor_oui=""
    for byte in range (165, 168):
        vendor_oui = vendor_oui + ("%2.2x" % get_byte(optic_pages, 0x00, byte))
    print("vendor_oui: %s" % vendor_oui)

def read_optic_vendor_partnum():
    # QSFP-DD-CMIS-rev4p0
    # 16 bytes ASCII at bytes 148-163
    vendor_partnum = get_bytes(optic_pages, 0x00, 148, 164).decode('ascii', errors='ignore').strip()
    print("PN:", vendor_partnum)


def read_optic_vendor_partnum():
    # SFF-8472
    # 16 bytes ASCII at bytes 40-55
    vendor_partnum = get_bytes(optic_pages, 0x00, 40, 56).decode('ascii', errors='ignore').strip()
    print("PN:", vendor_partnum)

def read_qsfpdd_vendor_sn():
    """Read and print the vendor serial number for QSFP-DD/CMIS modules."""
    try:
        vendor_sn = ""
        # For CMIS modules, serial number is in Upper Page 01h (offset 0x100)
        for byte in range(290, 306):
            if get_byte(optic_pages, 0x01, byte) == 0 or get_byte(optic_pages, 0x01, byte) == 0xFF:
                break
            vendor_sn += chr(get_byte(optic_pages, 0x01, byte))
        print("SN:", vendor_sn.strip())
    except Exception as e:
        print(f"Error reading vendor serial number: {e}")


def read_optic_vendor_serialnum():
    # SFF-8472
    # 16 bytes ASCII at bytes 68-83
    vendor_serialnum = ""

    for byte in range (68, 84):
        if (get_byte(optic_pages, 0x00, byte) == 0 or get_byte(optic_pages, 0x00, byte) == 0xff):
            break
        vendor_serialnum=vendor_serialnum +('%c' % get_byte(optic_pages, 0x00, byte))
    print("SN:", vendor_serialnum)

def read_xfp_ext_vendor_sn():
    # INF-8077 5.38 196-211
    vendor_serialnum = ""

    for byte in range (196, 212):
        if (get_byte(optic_pages, 0x00, byte) == 0 or get_byte(optic_pages, 0x00, byte) == 0xff):
            break
        vendor_serialnum=vendor_serialnum +('%c' % get_byte(optic_pages, 0x00, byte))
    print("Vendor SN:", vendor_serialnum)

def read_qsfpdd_date():
    """Read and print the date code for QSFP-DD/CMIS modules."""
    try:
        date_code = ""
        # For CMIS, date code is at 0x100 + 0x52 = 338, length 8 bytes
        # Try Upper Page 01h first (standard CMIS location)
        for byte in range(338, 346):
            if get_byte(optic_pages, 0x01, byte) == 0 or get_byte(optic_pages, 0x01, byte) == 0xFF:
                break
            date_code += chr(get_byte(optic_pages, 0x01, byte))
        
        if not date_code.strip():
            # Try Upper Page 00h as fallback
            for byte in range(200, 208):
                if get_byte(optic_pages, 0x00, byte) == 0 or get_byte(optic_pages, 0x00, byte) == 0xFF:
                    break
                date_code += chr(get_byte(optic_pages, 0x00, byte))
        
        print("Date Code:", date_code.strip())
    except Exception as e:
        print(f"Error reading date code: {e}")

def read_qsfpdd_clei_code():
    """Read and print the CLEI code for QSFP-DD/CMIS modules."""
    try:
        clei_code = ""
        for byte in range(190, 200):
            if get_byte(optic_pages, 0x00, byte) == 0 or get_byte(optic_pages, 0x00, byte) == 0xFF:
                break
            clei_code += chr(get_byte(optic_pages, 0x00, byte))
        print("CLEI Code:", clei_code.strip())
    except Exception as e:
        print(f"Error reading CLEI code: {e}")

def read_qsfpdd_mod_power():
    # QSFP-DD-CMIS-rev4p0
    # 2 bytes at 200-201
    # According to CMIS 5.0, power class is in byte 200 bits 7-5
    # Max power is in byte 201, units of 0.25W
    # For some modules, this data might be in Upper Page 00h instead of Lower Page
    
    # Try Lower Page first (standard CMIS location)
    power_class_lower = (get_byte(optic_pages, 0x00, 200) >> 5) & 0x07
    max_power_lower = get_byte(optic_pages, 0x00, 201) * 0.25
    
    # Try Upper Page 00h (some modules use this location)
    power_class_upper = (get_byte(optic_pages, 0x00, 200) >> 5) & 0x07
    max_power_upper = get_byte(optic_pages, 0x00, 201) * 0.25
    
    # Use the non-zero values, preferring Lower Page if both are non-zero
    if power_class_lower > 0 or max_power_lower > 0:
        power_class = power_class_lower
        max_power = max_power_lower
        source = "Lower Page"
    elif power_class_upper > 0 or max_power_upper > 0:
        power_class = power_class_upper
        max_power = max_power_upper
        source = "Upper Page 00h"
    else:
        power_class = 0
        max_power = 0
        source = "Not specified"
    
    print(f"Module Card power Class: {power_class} (Class {power_class}) [{source}]")
    print(f"Module Max Power : {max_power:.2f} W [{source}]")

# read_qsfpdd_cable_len
def read_qsfpdd_cable_len():
    # QSFP-DD-CMIS-rev4p0
    print("read_qsfpdd_length_multiplier:", bin(get_byte(optic_pages, 0x00, 202)>>6))
    print("read_qsfpdd_length_baselength:", get_byte(optic_pages, 0x00, 202) & 0x1f)

# read_qsfpdd_connector_type
def read_qsfpdd_connector_type():
    # QSFP-DD-CMIS-rev4p0
    # Connector type is in byte 203 (0xCB) in Lower Page
    # For CMIS modules, this should be read from the correct offset
    # Try Lower Page first, then Upper Page 00h
    connector_type_lower = get_byte(optic_pages, 0x00, 203)
    connector_type_upper = get_byte(optic_pages, 0x00, 203)
    
    # Use the non-zero value, preferring Lower Page
    if connector_type_lower != 0:
        connector_type = connector_type_lower
        source = "Lower Page"
    elif connector_type_upper != 0:
        connector_type = connector_type_upper
        source = "Upper Page 00h"
    else:
        connector_type = 0
        source = "Not specified"
    
    print(f"Connector Type Raw Value: 0x{connector_type:02x} [{source}]")
    read_optic_connector_type(connector_type)

# read_qsfpdd_copper_attenuation
def read_qsfpdd_copper_attenuation():
    # QSFP-DD-CMIS-rev5p0
    # bytes 204-209
    # 204 - AttenuationAt 5GHz - 1 dB increments
    # 205 - AttenuationAt 7GHz - 1 dB increments
    # 206 - AttenuationAt 12.9GHz - 1dB increments
    # 207 - AttenuationAt 25.8GHz - 1dB increments
    # 208-209 reserved

    print("read_qsfpdd_copper_attenuation not implemented yet")

# read_qsfpdd_cable_lane_info
def read_qsfpdd_media_lane_info():
    # QSFP-DD-CMIS-rev5p0
    # 1 byte at 210 bit set for lanes 8-1 in order
    # The module indicates which Media Lanes are not supported
    # Try Lower Page first, then Upper Page 00h
    lane_info_lower = get_byte(optic_pages, 0x00, 210)
    lane_info_upper = get_byte(optic_pages, 0x00, 210)
    
    # Use the non-zero value, preferring Lower Page
    if lane_info_lower != 0:
        lane_info = lane_info_lower
        source = "Lower Page"
    elif lane_info_upper != 0:
        lane_info = lane_info_upper
        source = "Upper Page 00h"
    else:
        lane_info = 0
        source = "Not specified"
    
    print(f"Media Lane Info Raw Value: 0x{lane_info:02x} ({bin(lane_info)}) [{source}]")
    print("Media Lane Support:")
    for lane in range(8):
        supported = (lane_info & (1 << lane)) != 0
        print(f"  Lane {lane + 1}: {'Supported' if supported else 'Not Supported'}")


# read_qsfpdd_media_interface_tech
def read_qsfpdd_media_interface_tech():
    """Read and print the media interface technology for QSFP-DD/CMIS modules.
    See OIF-CMIS 5.3 Table 8-6 for full mapping.
    """
    try:
        # Media Interface Technology is in Upper Page 01h, byte 135 (0x187)
        # For CMIS modules, this is at offset 0x187 in the extended array
        tech = get_byte(optic_pages, 0x100, 0x87)  # 0x100 + 0x87 = 0x187
        MEDIA_TECH_MAP = {
            0x00: "Not specified",
            0x01: "850 nm VCSEL",
            0x02: "1310 nm VCSEL",
            0x03: "1550 nm VCSEL",
            0x04: "1310 nm FP",
            0x05: "1310 nm DFB",
            0x06: "1550 nm DFB",
            0x07: "1310 nm EML",
            0x08: "1550 nm EML",
            0x09: "Copper cable (passive)",
            0x0A: "Copper cable (active)",
            0x0B: "Copper cable (active, retimed)",
            0x0C: "Copper cable (active, linear)",
            0x0D: "Copper cable (active, limiting)",
            0x0E: "AOC (Active Optical Cable)",
            0x0F: "AOC (Active Optical Cable, limiting)",
            0x10: "AOC (Active Optical Cable, linear)",
            0x11: "AOC (Active Optical Cable, retimed)",
            0x12: "1490 nm DFB",
            0x13: "1625 nm DFB",
            0x14: "1270 nm DFB",
            0x15: "1330 nm DFB",
            0x16: "Cooled EML",
            0x17: "Uncooled EML",
            0x18: "Cooled DFB",
            0x19: "Uncooled DFB",
            0x1A: "Cooled FP",
            0x1B: "Uncooled FP",
            0x1C: "Cooled VCSEL",
            0x1D: "Uncooled VCSEL",
            0x1E: "Cooled DML",
            0x1F: "Uncooled DML",
            0x20: "BiDi (WDM) 1270 nm Tx/1330 nm Rx",
            0x21: "BiDi (WDM) 1330 nm Tx/1270 nm Rx",
            0x22: "BiDi (WDM) 1490 nm Tx/1550 nm Rx",
            0x23: "BiDi (WDM) 1550 nm Tx/1490 nm Rx",
            0x24: "BiDi (WDM) 1271 nm Tx/1331 nm Rx",
            0x25: "BiDi (WDM) 1331 nm Tx/1271 nm Rx",
            0x26: "BiDi (WDM) 1291 nm Tx/1311 nm Rx",
            0x27: "BiDi (WDM) 1311 nm Tx/1291 nm Rx",
            0x28: "BiDi (WDM) 1273.54 nm Tx/1336.41 nm Rx",
            0x29: "BiDi (WDM) 1336.41 nm Tx/1273.54 nm Rx",
            0x2A: "DWDM Tunable",
            0x2B: "CWDM Tunable",
            0x2C: "LWDM",
            0x2D: "MWDM",
            0x2E: "SWDM",
            0x2F: "LWDM (extended)",
            0x30: "Copper cable (passive, SFF-8636)",
            0x31: "Copper cable (active, SFF-8636)",
            0x32: "Copper cable (active, retimed, SFF-8636)",
            0x33: "Copper cable (active, linear, SFF-8636)",
            0x34: "Copper cable (active, limiting, SFF-8636)",
            0x35: "AOC (Active Optical Cable, SFF-8636)",
            0x36: "AOC (Active Optical Cable, limiting, SFF-8636)",
            0x37: "AOC (Active Optical Cable, linear, SFF-8636)",
            0x38: "AOC (Active Optical Cable, retimed, SFF-8636)",
            0x39: "Reserved",
            0x3A: "Reserved",
            0x3B: "Reserved",
            0x3C: "Reserved",
            0x3D: "Reserved",
            0x3E: "Reserved",
            0x3F: "Reserved",
            # 0x40-0xFF Reserved
        }
        desc = MEDIA_TECH_MAP.get(tech, "Reserved" if 0x40 <= tech <= 0xFF else f"Unknown (0x{tech:02x})")
        print("Media Interface Technology:")
        print("  ", desc)
    except Exception as e:
        print(f"Error reading media interface technology: {e}")

def read_optic_datecode():
    # SFF-8472
    # 8 bytes ASCII at bytes 84-91
    vendor_datecode = ""

    for byte in range (84, 92):
        if (get_byte(optic_pages, 0x00, byte) == 0 or get_byte(optic_pages, 0x00, byte) == 0xff):
            break
        vendor_datecode = vendor_datecode + ('%c' % get_byte(optic_pages, 0x00, byte))

    print("Date Code:", vendor_datecode)

def read_xfp_datecode():
    # INF-8077
    # 8 Bytes ASCII at 212-219
    vendor_datecode = ""

    for byte in range (212, 220):
        if (get_byte(optic_pages, 0x00, byte) == 0 or get_byte(optic_pages, 0x00, byte) == 0xff):
            break
        vendor_datecode = vendor_datecode + ('%c' % get_byte(optic_pages, 0x00, byte))

    print("Date Code:", vendor_datecode)

def read_qsfpdd_datecode():
    # CMIS rev4p0
    # 8 Bytes ASCII at 182-189
    vendor_datecode = ""

    for byte in range (182, 190):
        if (get_byte(optic_pages, 0x00, byte) == 0 or get_byte(optic_pages, 0x00, byte) == 0xff):
            break
        vendor_datecode = vendor_datecode + ('%c' % get_byte(optic_pages, 0x00, byte))

    print("Date Code:", vendor_datecode)

def read_cmis_global_status():
    # CMIS rev5p0
    # byte 3
    print("cmis_global_status_module_state:", bin((get_byte(optic_pages, 0x00, 3) & 0xf) >> 1))
    print("cmis_global_status_interrupt_deasserted:", bin(get_byte(optic_pages, 0x00, 3)&1))

def write_optic_power_control(bus, power_override=False, power_high=False, low_power=False):
    """Write power control settings to QSFP+ module (SFF-8636)"""
    try:
        power_ctrl = 0
        if power_override:
            power_ctrl |= 0x04
        if power_high:
            power_ctrl |= 0x02
        if low_power:
            power_ctrl |= 0x01

        bus.write_byte_data(0x50, 93, power_ctrl)
        print("Power control settings updated successfully")
    except IOError as e:
        print(f"Error writing power control: {str(e)}")

def write_optic_cdr_control(bus, tx_cdr=True, rx_cdr=True):
    """Write CDR control settings to QSFP+ module (SFF-8636)"""
    try:
        cdr_ctrl = 0
        if tx_cdr:
            cdr_ctrl |= 0xF0
        if rx_cdr:
            cdr_ctrl |= 0x0F

        bus.write_byte_data(0x50, 98, cdr_ctrl)
        print("CDR control settings updated successfully")
    except IOError as e:
        print(f"Error writing CDR control: {str(e)}")

def write_optic_rate_select(bus, rate_select):
    """Write rate selection to SFP module (SFF-8472)"""
    try:
        bus.write_byte_data(0x50, 87, rate_select)
        print("Rate selection updated successfully")
    except IOError as e:
        print(f"Error writing rate selection: {str(e)}")

def write_optic_tx_disable(bus, disable):
    """Write TX disable control to SFP module (SFF-8472)"""
    try:
        bus.write_byte_data(0x50, 86, 0x01 if disable else 0x00)
        print("TX disable control updated successfully")
    except IOError as e:
        print(f"Error writing TX disable: {str(e)}")

def write_optic_page_select(bus, page):
    """Write page selection for QSFP+ module (SFF-8636)"""
    try:
        bus.write_byte_data(0x50, 127, page)
        time.sleep(0.1)  # Allow time for page switch
        print("Page selection updated successfully")
    except IOError as e:
        print(f"Error writing page selection: {str(e)}")

def read_optic_rev():
    # SFF-8472
    # 4 bytes ASCII at bytes 56-59
    vendor_hwrev = ""

    for byte in range (56, 60):
        vendor_hwrev=vendor_hwrev +('%c' % get_byte(optic_pages, 0x00, byte))
    print("HW Revision:", vendor_hwrev)

def read_optic_distances():
    # SFF-8472
    # bytes 14, 15, 16, 17, 18, 19
    # 14 = SMF in KM
    # 15 = SMF in 100 meter units
    # 16 = 50um OM2 fiber, 10 meter units
    # 17 = 62.5um OM1, 10 meter units
    # 18 = OM4 or DAC cable, units meter
    # 19 = 50um OM4 , 10 meter units

    try:
        smf_km      = get_byte(optic_pages, 0x00, 14)
        smf_100m    = get_byte(optic_pages, 0x00, 15)
        mmf_om2_10m = get_byte(optic_pages, 0x00, 16)
        mmf_om1_10m = get_byte(optic_pages, 0x00, 17)
        mmf_om4_m   = get_byte(optic_pages, 0x00, 18)
        mmf_om4_10m = get_byte(optic_pages, 0x00, 19)
    except IOError:
        return

    print("Distances:")
    if smf_km:
        print("\tSMF - %d km" % smf_km)
    if smf_100m:
        print("\tSMF - %d meters" % (smf_100m *100))
    if mmf_om2_10m:
        print("\tOM2 - %d meters" % (mmf_om2_10m * 10))
    if mmf_om1_10m:
        print("\tOM1 - %d meters" % (mmf_om1_10m * 10))
    if mmf_om4_m:
        print("\tOM4/DAC - %d meter(s)" % (mmf_om4_m))
    if mmf_om4_10m:
        print("\tOM4 - %d meters" % (mmf_om4_10m * 10))


def read_optic_monitoring_type():
    # SFF-8472
    # byte 92 - Diagnostic Monitoring Type Table 8-5

    print("Monitoring Types:")
    if (get_byte(optic_pages, 0x00, 92) & 0x80):
        print("\tReserved for legacy diagnostic implementations")
    if (get_byte(optic_pages, 0x00, 92) & 0x40):
        print("\tDDM Supported")
    if (get_byte(optic_pages, 0x00, 92) & 0x20):
        print("\tInternally calibrated")
    if (get_byte(optic_pages, 0x00, 92) & 0x10):
        print("\tExternally calibrated")
    if (get_byte(optic_pages, 0x00, 92) & 0x08):
        print("\tReceived power measurement type: average") # unset this is OMA
    if (get_byte(optic_pages, 0x00, 92) & 0x04):
        print("\tAddress Change Required")


def read_option_values():
    # SFF-8472, SFF-8431 and SFF-8690 for some undefined bits
    # bytes 64-65

    print("Option Values")

    if (get_byte(optic_pages, 0x00, 64) & 0x80):
        print("\tUndefined bit 7 set")
    if (get_byte(optic_pages, 0x00, 64) & 0x40):
        print("\tUndefined bit 6 set")
    if (get_byte(optic_pages, 0x00, 64) & 0x20):
        print("\tHigh Power Level Required - Level3")
    if (get_byte(optic_pages, 0x00, 64) & 0x10):
        print("\tPaging Implemented")
    if (get_byte(optic_pages, 0x00, 64) & 0x08):
        print("\tInternal Retimer")
    if (get_byte(optic_pages, 0x00, 64) & 0x04):
        print("\tCooled Transciever")
    if (get_byte(optic_pages, 0x00, 64) & 0x02):
        print("\tPower Level 2")
    if (get_byte(optic_pages, 0x00, 64) & 0x01):
        print("\tLinear Receiver Output")

    if (get_byte(optic_pages, 0x00, 65) & 0x80):
        print("\tReceiver decision threshold supported")
    if (get_byte(optic_pages, 0x00, 65) & 0x40):
        print("\tTunable Optic")
    if (get_byte(optic_pages, 0x00, 65) & 0x20):
        print("\tRATE_SELECT supported")
    if (get_byte(optic_pages, 0x00, 65) & 0x10):
        print("\tTX_DISABLE supported")
    if (get_byte(optic_pages, 0x00, 65) & 0x08):
        print("\tTX_FAULT implemented")
    if (get_byte(optic_pages, 0x00, 65) & 0x04):
        print("\tSignal Detect implemented")
    if (get_byte(optic_pages, 0x00, 65) & 0x02):
        print("\tRx_LOS implemented")
    if (get_byte(optic_pages, 0x00, 65) & 0x01):
        print("\tUnallocated")


def read_enhanced_options():
    """Read enhanced options and diagnostic information as defined in SFF-8472"""
    try:
        print("\nEnhanced Options:")

        # Check if enhanced options are supported
        options = get_byte(optic_ddm_pages, 0x00, 92)
        if not options & 0x04:  # Check if diagnostic monitoring is implemented
            print("Enhanced options not supported")
            return

        # Print supported options
        print("Supported Features:")
        if options & 0x80:
            print("- External Calibration")
        if options & 0x40:
            print("- Rate Select")
        if options & 0x20:
            print("- Application Select")
        if options & 0x10:
            print("- Soft Rate Select")
        if options & 0x08:
            print("- Soft Rate Select Monitoring")

        # Read optional measurements
        print("\nOptional Measurements:")

        # Check for optional measurement support
        opt_diag = get_byte(optic_ddm_pages, 0x00, 93)

        if opt_diag & 0x80:
            # Read and display received power measurement type
            rx_pwr_type = "Average" if opt_diag & 0x08 else "OMA"
            print(f"- Received Power Measurement Type: {rx_pwr_type}")

        if opt_diag & 0x40:
            # Read and display address change sequence
            addr_chg = get_byte(optic_ddm_pages, 0x00, 94)
            print(f"- Address Change Sequence: 0x{addr_chg:02x}")

        if opt_diag & 0x20:
            print("- Supports Power Supply Measurements")

        # Read auxiliary monitoring
        if opt_diag & 0x10:
            print("\nAuxiliary Monitoring:")
            try:
                with smbus2.SMBus(busno) as bus:
                    # Read auxiliary channel monitoring data
                    aux_data = []
                    for i in range(0, 8):  # Read 8 bytes of auxiliary monitoring
                        aux_data.append(bus.read_byte_data(address_two, 104 + i))

                    # Display auxiliary monitoring values
                    aux1 = (aux_data[0] << 8 | aux_data[1]) / 256.0
                    aux2 = (aux_data[2] << 8 | aux_data[3]) / 256.0
                    aux3 = (aux_data[4] << 8 | aux_data[5]) / 256.0

                    print(f"- Auxiliary 1: {aux1:.2f}V")
                    print(f"- Auxiliary 2: {aux2:.2f}V")
                    print(f"- Auxiliary 3: {aux3:.2f}V")

            except IOError as e:
                print(f"Error reading auxiliary monitoring: {str(e)}")

    except Exception as e:
        print(f"Error reading enhanced options: {str(e)}")

def read_sff_8472_compliance():
    # SFF-8472
    # byte 94 Table 8-8

    if get_byte(optic_pages, 0x00, 94) == 0x00:
        sff_8472_compliance_text = ("Unsupported")
    elif get_byte(optic_pages, 0x00, 94) == 0x01:
        sff_8472_compliance_text = ("SFF-8472 9.3")
    elif get_byte(optic_pages, 0x00, 94) == 0x02:
        sff_8472_compliance_text = ("SFF-8472 9.5")
    elif get_byte(optic_pages, 0x00, 94) == 0x03:
        sff_8472_compliance_text = ("SFF-8472 10.2")
    elif get_byte(optic_pages, 0x00, 94) == 0x04:
        sff_8472_compliance_text = ("SFF-8472 10.4")
    elif get_byte(optic_pages, 0x00, 94) == 0x05:
        sff_8472_compliance_text = ("SFF-8472 11.0")
    elif get_byte(optic_pages, 0x00, 94) == 0x06:
        sff_8472_compliance_text = ("SFF-8472 11.3")
    elif get_byte(optic_pages, 0x00, 94) == 0x07:
        sff_8472_compliance_text = ("SFF-8472 11.4")
    elif get_byte(optic_pages, 0x00, 94) == 0x08:
        sff_8472_compliance_text = ("SFF-8472 12.3")
    elif get_byte(optic_pages, 0x00, 94) == 0x09:
        sff_8472_compliance_text = ("SFF-8472 12.4")
    else:
        sff_8472_compliance_text =("Unallocated")
    print("SFF 8472 Compliance:", sff_8472_compliance_text)


def read_optic_frequency():
    # SFF-8472
    # Byte 60-61

    wave_msb = get_byte(optic_pages, 0x00, 60)
    wave_lsb = get_byte(optic_pages, 0x00, 61)
    wave_dec = get_byte(optic_pages, 0x00, 62)

    wavelength = (wave_msb*256)+wave_lsb
    print("Wavelength: %d.%02dnm" % (wavelength, wave_dec))

def read_xfp_status_bits():
    # XFP MSA INF-8077
    # byte 110 Table 42

    try:
        print("Status Bits:")

        if (get_byte(optic_pages, 0x00, 110) & 0x80): # bit 7
            print("\tTX_Disable Set")
        if (get_byte(optic_pages, 0x00, 110) & 0x40): # bit 6
            print("\tSoft TX Disable Selected")
        if (get_byte(optic_pages, 0x00, 110) & 0x20): # bit 5
            print("\tMOD_NR State set")
        if (get_byte(optic_pages, 0x00, 110) & 0x10): # bit 4
            print("\tP_Down Set")
        if (get_byte(optic_pages, 0x00, 110) & 0x08): # bit 3
            print("\tSoft P_Down set")
        if (get_byte(optic_pages, 0x00, 110) & 0x04): # bit 2
            print("\tInterrupt")
        if (get_byte(optic_pages, 0x00, 110) & 0x02): # bit 1
            print("\tRX_LOS")
        if (get_byte(optic_pages, 0x00, 110) & 0x01): # bit 0
            print("\tData NOT Ready")

    except IndexError:
        print("got IndexError on optic_sff byte 110")


def read_sfp_status_bits():
    # SFF-8472
    # byte 110 Table 9-11

    try:
        status_byte = get_byte(optic_pages, 0x00, 110)
        print("Status Bits:")

        if (status_byte & 0x80): # bit 7
            print("\tTX_Disable Set")
        if (status_byte & 0x40): # bit 6
            print("\tSoft TX Disable Selected")
        if (status_byte & 0x20): # bit 5
            print("\tRS(1) State set")
        if (status_byte & 0x10): # bit 4
            print("\tRate_Select State")
        if (status_byte & 0x08): # bit 3
            print("\tSoft Rate_Select selected")
        if (status_byte & 0x04): # bit 2
            print("\tTX_Fault")
        if (status_byte & 0x02): # bit 1
            print("\tRX_LOS")
        if (status_byte & 0x01): # bit 0
            print("\tData Ready")

    except IndexError:
        print("got IndexError on optic_sff byte 110")




def read_optic_temperature():
    # SFF-8472
    # bytes 96-97 Table 9-2

    temp_msb = get_byte(optic_pages, 0x00, 96)
    temp_lsb = get_byte(optic_pages, 0x00, 97)

    print("Optic Temperature: %4.2fC" % (temp_msb + (temp_lsb/256)))

def read_optic_vcc():
    # SFF-8472
    # bytes 98-99 Table 9-11

    vcc_msb = get_byte(optic_pages, 0x00, 98)
    vcc_lsb = get_byte(optic_pages, 0x00, 99)

    vcc = (vcc_msb<<8 | vcc_lsb) *0.0001
    print("Optic VCC: %4.2fV msb = %d, lsb = %d" % (vcc, vcc_msb, vcc_lsb))

def read_laser_temperature():
    # SFF-8472
    # bytes 106-107 Table 9-2

    temp_msb = get_byte(optic_pages, 0x00, 106)
    temp_lsb = get_byte(optic_pages, 0x00, 107)

    print("Laser Temperature: msb = %d, lsb = %d" % (temp_msb, temp_lsb))


def read_optic_rxpower():
    # SFF-8472
    # bytes 104, 105

    rx_pwr_msb = get_byte(optic_pages, 0x00, 104)
    rx_pwr_lsb = get_byte(optic_pages, 0x00, 105)

    # need to convert this from mW to dBm, eg:
    # 10 * math.log10(rx_power)
    # 0 = -40 dBm
    temp_pwr = (rx_pwr_msb<<8|rx_pwr_lsb) *0.0001
    if (temp_pwr > 0):
        rx_pwr = 10 * math.log10((rx_pwr_msb<<8|rx_pwr_lsb) *0.0001)
    else:
        rx_pwr = 0
    print("Rx Power: (%4.2f) dBm  vs mW %f" % (rx_pwr, ((rx_pwr_msb<<8|rx_pwr_lsb) *0.0001)))

def read_optic_txpower():
    # SFF-8472
    # bytes 102, 103

    tx_pwr_msb = get_byte(optic_pages, 0x00, 102)
    tx_pwr_lsb = get_byte(optic_pages, 0x00, 103)

    # need to convert this from mW to dBm, eg:
    # 10 * math.log10(rx_power)
    # 0 = -40 dBm
    temp_pwr = (tx_pwr_msb<<8|tx_pwr_lsb) *0.0001
    if (temp_pwr > 0):
        tx_pwr = 10 * math.log10((tx_pwr_msb<<8|tx_pwr_lsb) *0.0001)
    else:
        tx_pwr = 0
    print("Tx Power: (%4.2f) mW vs mW = %f" % (tx_pwr, ((tx_pwr_msb<<8|tx_pwr_lsb) *0.0001)))

def read_measured_current():
    # SFF-8472
    # bytes 108-109

    current_msb = get_byte(optic_pages, 0x00, 108)
    current_lsb = get_byte(optic_pages, 0x00, 109)
    bias = (current_msb<<8 | current_lsb) * 0.002

    print("Current Draw: %4.2fmA msb = %d, lsb = %d mA" % (bias, current_msb, current_lsb))



def dump_vendor():
    # SFF-8472 Table 4-1
    # bytes 96-127

    vendor_hex = ""
    vendor_isprint = ""

    for byte in range (96, 128):
        vendor_byte = get_byte(optic_pages, 0x00, byte)
        vendor_hex=vendor_hex +('%-2.2x' % vendor_byte)

        v_char = '%c' % vendor_byte

        if (isprint(v_char)):
            vendor_isprint= vendor_isprint + v_char
        else:
            vendor_isprint= vendor_isprint + ' '
    print(vendor_hex)
    print(vendor_isprint)

def decode_dwdm_data():

    if (get_byte(optic_pages, 0x00, 128) & 0x4):
        print("\tTx Dither Supported")
    if (get_byte(optic_pages, 0x00, 128) & 0x2):
        print("\tTunable DWDM selection by channel number")
    if (get_byte(optic_pages, 0x00, 128) & 0x1):
        print("\tTunable DWDM selection by 50pm steps")

    laser_first_freq_thz = (get_byte(optic_pages, 0x00, 132)*256)+get_byte(optic_pages, 0x00, 133)
    print("\tLaser First Frequency %d THz, (%d, %d)" % (laser_first_freq_thz, get_byte(optic_pages, 0x00, 132), get_byte(optic_pages, 0x00, 133)))

    laser_first_freq_ghz = (get_byte(optic_pages, 0x00, 134)*256)+get_byte(optic_pages, 0x00, 135)
    print("\tLaser First Frequency %d GHz, (%d, %d)" % (laser_first_freq_ghz, get_byte(optic_pages, 0x00, 134), get_byte(optic_pages, 0x00, 135)))

    laser_last_freq_thz = (get_byte(optic_pages, 0x00, 136)*256)+get_byte(optic_pages, 0x00, 137)
    print("\tLaser Last Frequency %d THz, (%d, %d)" % (laser_last_freq_thz, get_byte(optic_pages, 0x00, 136), get_byte(optic_pages, 0x00, 137)))

    laser_last_freq_ghz = (get_byte(optic_pages, 0x00, 138)*256)+get_byte(optic_pages, 0x00, 139)
    print("\tLaser Last Frequency %d GHz, (%d, %d)" % (laser_last_freq_ghz, get_byte(optic_pages, 0x00, 138), get_byte(optic_pages, 0x00, 139)))

    laser_min_grid = (get_byte(optic_pages, 0x00, 140)*256)+get_byte(optic_pages, 0x00, 141)
    print("\tLasers minimum grid: %d Ghz, (%d, %d)" % (laser_min_grid, get_byte(optic_pages, 0x00, 140), get_byte(optic_pages, 0x00, 141)))

    channel_set = (get_byte(optic_pages, 0x00, 144)*256)+get_byte(optic_pages, 0x00, 145)
    print("\tDWDM Channel set: %d (%d, %d)" % (channel_set, get_byte(optic_pages, 0x00, 144), get_byte(optic_pages, 0x00, 145)))

    wavelength_set = (get_byte(optic_pages, 0x00, 146)*256)+get_byte(optic_pages, 0x00, 147)
    print("\tDWDM wavelength set: %2.02f nm (%d, %d)" % (wavelength_set, get_byte(optic_pages, 0x00, 146), get_byte(optic_pages, 0x00, 147)))

    # SFF 8690 Table 4-5
    print("\tDWDM frequency error (152, 153) = %d (%d, %d)" % ((get_byte(optic_pages, 0x00, 152)*256)+get_byte(optic_pages, 0x00, 153), get_byte(optic_pages, 0x00, 152), get_byte(optic_pages, 0x00, 153)))

    print("\tDWDM wavelength error (154, 155) = %d (%d, %d)" % ((get_byte(optic_pages, 0x00, 154)*256)+get_byte(optic_pages, 0x00, 155), get_byte(optic_pages, 0x00, 154), get_byte(optic_pages, 0x00, 155)))

    # SFF 8690 Table 4-6
    if (get_byte(optic_pages, 0x00, 168) & 0x80):
        print("\tDWDM Reserved bit set")
    if (get_byte(optic_pages, 0x00, 168) & 0x40):
        print("\tTEC Fault")
    if (get_byte(optic_pages, 0x00, 168) & 0x20):
        print("\tWavelength Unlocked")
    if (get_byte(optic_pages, 0x00, 168) & 0x10):
        print("\tTxTune - Transmit not ready due to tuning")

    # SFF 8690 Table 4-7
    if (get_byte(optic_pages, 0x00, 172) & 0x40):
        print("\tL-TEC Fault")
    if (get_byte(optic_pages, 0x00, 172) & 0x20):
        print("\tL-Wavelength-Unlocked")
    if (get_byte(optic_pages, 0x00, 172) & 0x10):
        print("\tL-Bad Channel")
    if (get_byte(optic_pages, 0x00, 172) & 0x8):
        print("\tL-New Channel")
    if (get_byte(optic_pages, 0x00, 172) & 0x4):
        print("\tL-Unsupported TX Dither")


# read the board type
# 0x00-0f = Board Name
# 0x10-1f = Board Sub-type
# 0x20-2f = Mfg date
# 0x30-3f = Board Test Time
# 0x40-4f = Board port types
#  0x40 = SFP ports
#  0x41 = QSFP ports
#  0x42 = XFP ports
#  0x43 = CFP ports
#  0x44 = CFP2 ports
#  0x45 = CFP4 ports
#  0x46 = microQSFP ports
# 0x50-5f = board serial number
#      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f    0123456789abcdef
# 00: 57 42 4f 2d 53 49 58 76 31 ff ff ff ff ff ff ff    WBO-SIXv1.......
# 10: 48 57 52 45 56 2d 30 2e 31 41 ff ff ff ff ff ff    HWREV-0.1A......
# 20: 32 30 31 35 31 31 31 37 ff ff ff ff ff ff ff ff    20151117........
# 30: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
# 40: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
# 50: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
# 60: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
# 70: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................

def read_board_id(bus, i2cbus, mux, mux_val):
#	print("Should read 0x57 to ID the board type")
    board_type=[]
    board_type_read = -1

    while board_type_read < 128:
        try:
            if (board_type_read == -1):
                board_type_tmp = bus.read_i2c_block_data(0x57, 0, 32)
            else:
                board_type_tmp = bus.read_i2c_block_data(0x57, board_type_read, 32)
            for member in board_type_tmp:
                board_type.append(member)
            board_type_read = len(board_type)
#		      print("board_type_read=%d, %d" % (board_type_read, len(board_type)))
        except IOError:
#			print("Error reading board ID")
            break

#	print("Read %d bytes checking board_type" % board_type_read)
    if (board_type_read >= 128):
        board_name =""
        board_sub_type =""
        board_mfg_date=""
        board_test_time=""
        board_sn=""
        for byte in range (0, 0x10):
            if (isprint(chr(board_type[byte]))):
                board_name += "%c" % board_type[byte]
        for byte in range (0x10, 0x20):
            if (isprint(chr(board_type[byte]))):
                board_sub_type += "%c" % board_type[byte]
        for byte in range (0x20, 0x30):
            if (isprint(chr(board_type[byte]))):
                board_mfg_date += "%c" % board_type[byte]
        for byte in range (0x30, 0x40):
            if (isprint(chr(board_type[byte]))):
                board_test_time += "%c" % board_type[byte]
        for byte in range (0x50, 0x60):
            if (isprint(chr(board_type[byte]))):
                board_sn += "%c" % board_type[byte]

        print("--> BOARD INFO <--")
        print("NAME: %s" % board_name)
        print("SUB_TYPE: %s" % board_sub_type)
        print("MFG_DATE: %s" % board_mfg_date)
        print("TEST_TIME: %s" % board_test_time)
        print("SERIAL: %s" % board_sn)


def read_optic_xfp_signal_conditioner_control():
    # FIXME check bitwise operator
    xfp_speed = get_byte(optic_pages, 0x00, 1)
    if (xfp_speed > 0):
        xfp_speed = get_byte(optic_pages, 0x00, 1) >> 4
        print("XFP Speed = %d, %x" % (xfp_speed, get_byte(optic_pages, 0x00, 1)))

def read_optic_xfp_thresholds():
    # INF-8077
    print("FIXME: read_optic_xfp_thresholds Unimplemented")

def read_optic_xfp_vps_control_registers():
    # INF-8077 Table 33 Bytes 58-59
    print("XFP: Lowest Voltage Supported: %d" % (get_byte(optic_pages, 0x00, 58)>>4))
    print("XFP: Voltage Supplied on VCC2: %d" % (get_byte(optic_pages, 0x00, 58) & 0xf))
    print("XFP: Voltage Supported with Bypasss regulator: %d" % (get_byte(optic_pages, 0x00, 59)<<4))
    print("XFP: Regulator bypass mode: %d" % (get_byte(optic_pages, 0x00, 59) & 0x1))

def read_xfp_transciever():
    # INF-8077 Table 49
    #

    transciever_type=[]
    if (get_byte(optic_pages, 0x00, 131) & 0x80): # bit 7
        transciever_type.append('10Gbase-SR')
    if (get_byte(optic_pages, 0x00, 131) & 0x40): # bit 6
        transciever_type.append('10GBase-LR')
    if (get_byte(optic_pages, 0x00, 131) & 0x20): # bit 5
        transciever_type.append('10Gbase-ER')
    if (get_byte(optic_pages, 0x00, 131) & 0x10): # bit 4
        transciever_type.append('10Gbase-LRM')
    if (get_byte(optic_pages, 0x00, 131) & 0x8): # bit 3
        transciever_type.append('10Gbase-SW')
    if (get_byte(optic_pages, 0x00, 131) & 0x4): # bit 2
        transciever_type.append('10Gbase-LW')
    if (get_byte(optic_pages, 0x00, 131) & 0x2): # bit 1
        transciever_type.append('10Gbase-EW')
    if (get_byte(optic_pages, 0x00, 131) & 0x1): # bit 0
        transciever_type.append('131-0-Reserved')

    if (get_byte(optic_pages, 0x00, 132) & 0x80): # bit 7
        transciever_type.append('1200-MX-SN-I')
    if (get_byte(optic_pages, 0x00, 132) & 0x40): # bit 6
        transciever_type.append('1200-SM-LL-L')
    if (get_byte(optic_pages, 0x00, 132) & 0x20): # bit 5
        transciever_type.append('132-5-Reserved')
    if (get_byte(optic_pages, 0x00, 132) & 0x10): # bit 4
        transciever_type.append('132-4-Reserved')
    if (get_byte(optic_pages, 0x00, 132) & 0x8):  # bit 3
        transciever_type.append('132-3-Reserved')
    if (get_byte(optic_pages, 0x00, 132) & 0x4):  # bit 2
        transciever_type.append('132-2-Reserved')
    if (get_byte(optic_pages, 0x00, 132) & 0x2):  # bit 1
        transciever_type.append('132-1-Reserved')
    if (get_byte(optic_pages, 0x00, 132) & 0x1):  # bit 0
        transciever_type.append('132-0-Reserved')

    if (get_byte(optic_pages, 0x00, 133) & 0x80): # bit 7
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, 0x00, 133) & 0x40): # bit 6
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, 0x00, 133) & 0x20): # bit 5
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, 0x00, 133) & 0x10): # bit 4
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, 0x00, 133) & 0x8):  # bit 3
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, 0x00, 133) & 0x4):  # bit 2
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, 0x00, 133) & 0x2):  # bit 1
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, 0x00, 133) & 0x1):  # bit 0
        transciever_type.append('133-Reserved')

    if (get_byte(optic_pages, 0x00, 134) & 0x80): # bit 7
        transciever_type.append('1000Base-SX/1xFC MMF')
    if (get_byte(optic_pages, 0x00, 134) & 0x40): # bit 6
        transciever_type.append('1000Base-LX/1xFC SMF')
    if (get_byte(optic_pages, 0x00, 134) & 0x20): # bit 5
        transciever_type.append('2xFC MMF')
    if (get_byte(optic_pages, 0x00, 134) & 0x10): # bit 4
        transciever_type.append('2xFC SMF')
    if (get_byte(optic_pages, 0x00, 134) & 0x8):  # bit 3
        transciever_type.append('OC-48-SR')
    if (get_byte(optic_pages, 0x00, 134) & 0x4):  # bit 2
        transciever_type.append('OC-48-IR')
    if (get_byte(optic_pages, 0x00, 134) & 0x2):  # bit 1
        transciever_type.append('OC-48-LR')
    if (get_byte(optic_pages, 0x00, 134) & 0x1):  # bit 0
        transciever_type.append('134-Reserved')

    if (get_byte(optic_pages, 0x00, 135) & 0x80): # bit 7
        transciever_type.append('I-64.1r')
    if (get_byte(optic_pages, 0x00, 135) & 0x40): # bit 6
        transciever_type.append('I-64.1')
    if (get_byte(optic_pages, 0x00, 135) & 0x20): # bit 5
        transciever_type.append('I-64.2r')
    if (get_byte(optic_pages, 0x00, 135) & 0x10): # bit 4
        transciever_type.append('I-64.2')
    if (get_byte(optic_pages, 0x00, 135) & 0x8):  # bit 3
        transciever_type.append('I-64.3')
    if (get_byte(optic_pages, 0x00, 135) & 0x4):  # bit 2
        transciever_type.append('I-64.5')
    if (get_byte(optic_pages, 0x00, 135) & 0x2):  # bit 1
        transciever_type.append('135-1-Reserved')
    if (get_byte(optic_pages, 0x00, 135) & 0x1):  # bit 0
        transciever_type.append('135-0-Reserved')

    if (get_byte(optic_pages, 0x00, 136) & 0x80): # bit 7
        transciever_type.append('S-64.1')
    if (get_byte(optic_pages, 0x00, 136) & 0x40): # bit 6
        transciever_type.append('S-64.2a')
    if (get_byte(optic_pages, 0x00, 136) & 0x20): # bit 5
        transciever_type.append('S-64.2b')
    if (get_byte(optic_pages, 0x00, 136) & 0x10): # bit 4
        transciever_type.append('S-64.3a')
    if (get_byte(optic_pages, 0x00, 136) & 0x8):  # bit 3
        transciever_type.append('S-64.3b')
    if (get_byte(optic_pages, 0x00, 136) & 0x4):  # bit 2
        transciever_type.append('S-64.5a')
    if (get_byte(optic_pages, 0x00, 136) & 0x2):  # bit 1
        transciever_type.append('S-64.5b')
    if (get_byte(optic_pages, 0x00, 136) & 0x1):  # bit 0
        transciever_type.append('136-0-Reserved')

    if (get_byte(optic_pages, 0x00, 137) & 0x80): # bit 7
        transciever_type.append('L-64.1')
    if (get_byte(optic_pages, 0x00, 137) & 0x40): # bit 6
        transciever_type.append('L-64.2a')
    if (get_byte(optic_pages, 0x00, 137) & 0x20): # bit 5
        transciever_type.append('L-64.2b')
    if (get_byte(optic_pages, 0x00, 137) & 0x10): # bit 4
        transciever_type.append('L-64.2c')
    if (get_byte(optic_pages, 0x00, 137) & 0x8):  # bit 3
        transciever_type.append('L-64.3')
    if (get_byte(optic_pages, 0x00, 137) & 0x4):  # bit 2
        transciever_type.append('G.959.1 P1L1-2D2')
    if (get_byte(optic_pages, 0x00, 137) & 0x2):  # bit 1
        transciever_type.append('137-1-Reserved')
    if (get_byte(optic_pages, 0x00, 137) & 0x1):  # bit 0
        transciever_type.append('137-0-Reserved')

    if (get_byte(optic_pages, 0x00, 138) & 0x80): # bit 7
        transciever_type.append('V-64.2a')
    if (get_byte(optic_pages, 0x00, 138) & 0x40): # bit 6
        transciever_type.append('V-64-2b')
    if (get_byte(optic_pages, 0x00, 138) & 0x20): # bit 5
        transciever_type.append('V-64-3')
    if (get_byte(optic_pages, 0x00, 138) & 0x10): # bit 4
        transciever_type.append('138-Reserved')
    if (get_byte(optic_pages, 0x00, 138) & 0x8):  # bit 3
        transciever_type.append('138-Reserved')
    if (get_byte(optic_pages, 0x00, 138) & 0x4):  # bit 2
        transciever_type.append('138-Reserved')
    if (get_byte(optic_pages, 0x00, 138) & 0x2):  # bit 1
        transciever_type.append('138-Reserved')
    if (get_byte(optic_pages, 0x00, 138) & 0x1):  # bit 0
        transciever_type.append('138-Reserved')

    comma=','
    print("Transciever Type:", comma.join(transciever_type))

def read_optic_xfp_fec_control_registers():
    # INF-8077 I Table 38
    xfp_amplitude_adustment = get_byte(optic_pages, 0x00, 76)
    xfp_phase_adjustment = get_byte(optic_pages, 0x00, 77)
    print("XFP Amplitude Adustment: %d" % xfp_amplitude_adustment)
    print("XFP Phase Adjustment: %d" % xfp_phase_adjustment)

def read_optic_xfp_flags():
    # INF-8077 I Table 39 Bytes 80-95
    xfp_flags =[]

    if (get_byte(optic_pages, 0x00, 80) & 0x80): # bit 7
        xfp_flags.append('L-Temp High Alarm')
    if (get_byte(optic_pages, 0x00, 80) & 0x40): # bit 6
        xfp_flags.append('L-Temp Low Alarm')
    if (get_byte(optic_pages, 0x00, 80) & 0x20): # bit 5
        xfp_flags.append('80-5-Reserved')
    if (get_byte(optic_pages, 0x00, 80) & 0x10): # bit 4
        xfp_flags.append('80-4-Reserved')
    if (get_byte(optic_pages, 0x00, 80) & 0x8):  # bit 3
        xfp_flags.append('L-TX Bias High Alarm')
    if (get_byte(optic_pages, 0x00, 80) & 0x4):  # bit 2
        xfp_flags.append('L-TX Biase Low Alarm')
    if (get_byte(optic_pages, 0x00, 80) & 0x2):  # bit 1
        xfp_flags.append('L-TX Power High Alarm')
    if (get_byte(optic_pages, 0x00, 80) & 0x1):  # bit 0
        xfp_flags.append('L-TX Power Low Alarm')

    if (get_byte(optic_pages, 0x00, 81) & 0x80): # bit 7
        xfp_flags.append('L-RX Power High Alarm')
    if (get_byte(optic_pages, 0x00, 81) & 0x40): # bit 6
        xfp_flags.append('L-RX Power Low Alarm')
    if (get_byte(optic_pages, 0x00, 81) & 0x20): # bit 5
        xfp_flags.append('L-AUX-1 High Alarm')
    if (get_byte(optic_pages, 0x00, 81) & 0x10): # bit 4
        xfp_flags.append('L-AUX-1 Low Alarm')
    if (get_byte(optic_pages, 0x00, 81) & 0x8):  # bit 3
        xfp_flags.append('L-AUX-2 High Alarm')
    if (get_byte(optic_pages, 0x00, 81) & 0x4):  # bit 2
        xfp_flags.append('L-AUX-2 Low Alarm')
    if (get_byte(optic_pages, 0x00, 81) & 0x2):  # bit 1
        xfp_flags.append('81-1-Reserved')
    if (get_byte(optic_pages, 0x00, 81) & 0x1):  # bit 0
        xfp_flags.append('81-0-Reserved')

    if (get_byte(optic_pages, 0x00, 82) & 0x80): # bit 7
        xfp_flags.append('L-Temp High Warning')
    if (get_byte(optic_pages, 0x00, 82) & 0x40): # bit 6
        xfp_flags.append('L-Temp Low Warning')
    if (get_byte(optic_pages, 0x00, 82) & 0x20): # bit 5
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 82) & 0x10): # bit 4
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 82) & 0x8):  # bit 3
        xfp_flags.append('L-TX Bias High Warning')
    if (get_byte(optic_pages, 0x00, 82) & 0x4):  # bit 2
        xfp_flags.append('L-TX Bias Low Warning')
    if (get_byte(optic_pages, 0x00, 82) & 0x2):  # bit 1
        xfp_flags.append('L-TX Power High Warning')
    if (get_byte(optic_pages, 0x00, 82) & 0x1):  # bit 0
        xfp_flags.append('L-TX Power Low Warning')

    if (get_byte(optic_pages, 0x00, 83) & 0x80): # bit 7
        xfp_flags.append('L-RX Power High Warning')
    if (get_byte(optic_pages, 0x00, 83) & 0x40): # bit 6
        xfp_flags.append('L-RX Power Low Warning')
    if (get_byte(optic_pages, 0x00, 83) & 0x20): # bit 5
        xfp_flags.append('L-AUX-1 High Warning')
    if (get_byte(optic_pages, 0x00, 83) & 0x10): # bit 4
        xfp_flags.append('L-AUX-1 Low Warning')
    if (get_byte(optic_pages, 0x00, 83) & 0x8):  # bit 3
        xfp_flags.append('L-AUX-2 High Warning')
    if (get_byte(optic_pages, 0x00, 83) & 0x4):  # bit 2
        xfp_flags.append('L-AUX-2 Low Warning')
    if (get_byte(optic_pages, 0x00, 83) & 0x2):  # bit 1
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 83) & 0x1):  # bit 0
        xfp_flags.append('Reserved')

    if (get_byte(optic_pages, 0x00, 84) & 0x80): # bit 7
        xfp_flags.append('L-TX Not Ready')
    if (get_byte(optic_pages, 0x00, 84) & 0x40): # bit 6
        xfp_flags.append('L-TX Fault')
    if (get_byte(optic_pages, 0x00, 84) & 0x20): # bit 5
        xfp_flags.append('L-TX CDR not Locked')
    if (get_byte(optic_pages, 0x00, 84) & 0x10): # bit 4
        xfp_flags.append('L-RX Not Ready')
    if (get_byte(optic_pages, 0x00, 84) & 0x8):  # bit 3
        xfp_flags.append('L-RX LOS')
    if (get_byte(optic_pages, 0x00, 84) & 0x4):  # bit 2
        xfp_flags.append('L-RX CDR not Locked')
    if (get_byte(optic_pages, 0x00, 84) & 0x2):  # bit 1
        xfp_flags.append('L-Module Not Ready')
    if (get_byte(optic_pages, 0x00, 84) & 0x1):  # bit 0
        xfp_flags.append('L-Reset Complete')

    if (get_byte(optic_pages, 0x00, 85) & 0x80): # bit 7
        xfp_flags.append('L-APD Supply Fault')
    if (get_byte(optic_pages, 0x00, 85) & 0x40): # bit 6
        xfp_flags.append('L-TEC Fault')
    if (get_byte(optic_pages, 0x00, 85) & 0x20): # bit 5
        xfp_flags.append('L-Wavelength Unlocked')
    if (get_byte(optic_pages, 0x00, 85) & 0x10): # bit 4
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 85) & 0x8):  # bit 3
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 85) & 0x4):  # bit 2
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 85) & 0x2):  # bit 1
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 85) & 0x1):  # bit 0
        xfp_flags.append('Reserved')

    if (get_byte(optic_pages, 0x00, 86) & 0x80): # bit 7
        xfp_flags.append('L-VCC5 High Alarm')
    if (get_byte(optic_pages, 0x00, 86) & 0x40): # bit 6
        xfp_flags.append('L-VCC5 Low Alarm')
    if (get_byte(optic_pages, 0x00, 86) & 0x20): # bit 5
        xfp_flags.append('L-VCC3 High Alarm')
    if (get_byte(optic_pages, 0x00, 86) & 0x10): # bit 4
        xfp_flags.append('L-VCC3 Low Alarm')
    if (get_byte(optic_pages, 0x00, 86) & 0x8):  # bit 3
        xfp_flags.append('L-VCC2 High Alarm')
    if (get_byte(optic_pages, 0x00, 86) & 0x4):  # bit 2
        xfp_flags.append('L-VCC2 Low Alarm')
    if (get_byte(optic_pages, 0x00, 86) & 0x2):  # bit 1
        xfp_flags.append('L-Vee5 High Alarm')
    if (get_byte(optic_pages, 0x00, 86) & 0x1):  # bit 0
        xfp_flags.append('L-Vee5 Low Alarm')

    if (get_byte(optic_pages, 0x00, 87) & 0x80): # bit 7
        xfp_flags.append('L-VCC5 High Warning')
    if (get_byte(optic_pages, 0x00, 87) & 0x40): # bit 6
        xfp_flags.append('L-VCC5 Low Warning')
    if (get_byte(optic_pages, 0x00, 87) & 0x20): # bit 5
        xfp_flags.append('L-VCC3 High Warning')
    if (get_byte(optic_pages, 0x00, 87) & 0x10): # bit 4
        xfp_flags.append('L-VCC3 Low Warning')
    if (get_byte(optic_pages, 0x00, 87) & 0x8):  # bit 3
        xfp_flags.append('L-VCC2 High Warning')
    if (get_byte(optic_pages, 0x00, 87) & 0x4):  # bit 2
        xfp_flags.append('L-VCC2 Low Warning')
    if (get_byte(optic_pages, 0x00, 87) & 0x2):  # bit 1
        xfp_flags.append('L-Vee5 High Warning')
    if (get_byte(optic_pages, 0x00, 87) & 0x1):  # bit 0
        xfp_flags.append('L-Vee5 Low Warning')

    if (get_byte(optic_pages, 0x00, 88) & 0x80): # bit 7
        xfp_flags.append('M-Temp High Alarm')
    if (get_byte(optic_pages, 0x00, 88) & 0x40): # bit 6
        xfp_flags.append('M-Temp Low Alarm')
    if (get_byte(optic_pages, 0x00, 88) & 0x20): # bit 5
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 88) & 0x10): # bit 4
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 88) & 0x8):  # bit 3
        xfp_flags.append('M-TX Bias High Alarm')
    if (get_byte(optic_pages, 0x00, 88) & 0x4):  # bit 2
        xfp_flags.append('M-TX Bias Low Alarm')
    if (get_byte(optic_pages, 0x00, 88) & 0x2):  # bit 1
        xfp_flags.append('M-TX Power High Alarm')
    if (get_byte(optic_pages, 0x00, 88) & 0x1):  # bit 0
        xfp_flags.append('M-TX Power Low Alarm')

    if (get_byte(optic_pages, 0x00, 89) & 0x80): # bit 7
        xfp_flags.append('M-RX Power High Alarm')
    if (get_byte(optic_pages, 0x00, 89) & 0x40): # bit 6
        xfp_flags.append('M-RX Power Low Alarm')
    if (get_byte(optic_pages, 0x00, 89) & 0x20): # bit 5
        xfp_flags.append('M-AUX-1 High Alarm')
    if (get_byte(optic_pages, 0x00, 89) & 0x10): # bit 4
        xfp_flags.append('M-AUX-1 Low Alarm')
    if (get_byte(optic_pages, 0x00, 89) & 0x8):  # bit 3
        xfp_flags.append('M-AUX-2 High Alarm')
    if (get_byte(optic_pages, 0x00, 89) & 0x4):  # bit 2
        xfp_flags.append('M-AUX-2 Low Alarm')
    if (get_byte(optic_pages, 0x00, 89) & 0x2):  # bit 1
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 89) & 0x1):  # bit 0
        xfp_flags.append('Reserved')

    if (get_byte(optic_pages, 0x00, 90) & 0x80): # bit 7
        xfp_flags.append('M-Temp High Warning')
    if (get_byte(optic_pages, 0x00, 90) & 0x40): # bit 6
        xfp_flags.append('M-Temp Low Warning')
    if (get_byte(optic_pages, 0x00, 90) & 0x20): # bit 5
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 90) & 0x10): # bit 4
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 90) & 0x8):  # bit 3
        xfp_flags.append('M-TX Bias High Warning')
    if (get_byte(optic_pages, 0x00, 90) & 0x4):  # bit 2
        xfp_flags.append('M-TX Bias Low Warning')
    if (get_byte(optic_pages, 0x00, 90) & 0x2):  # bit 1
        xfp_flags.append('M-Tx Power High Warning')
    if (get_byte(optic_pages, 0x00, 90) & 0x1):  # bit 0
        xfp_flags.append('M-Tx Power Low Warning')

    if (get_byte(optic_pages, 0x00, 91) & 0x80): # bit 7
        xfp_flags.append('M-Rx Power High Warning')
    if (get_byte(optic_pages, 0x00, 91) & 0x40): # bit 6
        xfp_flags.append('M-Rx Power Low Warning')
    if (get_byte(optic_pages, 0x00, 91) & 0x20): # bit 5
        xfp_flags.append('M-AUX-1 High Warning')
    if (get_byte(optic_pages, 0x00, 91) & 0x10): # bit 4
        xfp_flags.append('M-AUX-1 Low Warning')
    if (get_byte(optic_pages, 0x00, 91) & 0x8):  # bit 3
        xfp_flags.append('M-AUX-2 High Warning')
    if (get_byte(optic_pages, 0x00, 91) & 0x4):  # bit 2
        xfp_flags.append('M-AUX-2 Low Warning')
    if (get_byte(optic_pages, 0x00, 91) & 0x2):  # bit 1
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 91) & 0x1):  # bit 0
        xfp_flags.append('Reserved')

    if (get_byte(optic_pages, 0x00, 92) & 0x80): # bit 7
        xfp_flags.append('M-TX Not Ready')
    if (get_byte(optic_pages, 0x00, 92) & 0x40): # bit 6
        xfp_flags.append('M-TX Fault')
    if (get_byte(optic_pages, 0x00, 92) & 0x20): # bit 5
        xfp_flags.append('M-TX CDR not Locked')
    if (get_byte(optic_pages, 0x00, 92) & 0x10): # bit 4
        xfp_flags.append('M-RX not Ready')
    if (get_byte(optic_pages, 0x00, 92) & 0x8):  # bit 3
        xfp_flags.append('M-RX LOS')
    if (get_byte(optic_pages, 0x00, 92) & 0x4):  # bit 2
        xfp_flags.append('M-RX CDR not Locked')
    if (get_byte(optic_pages, 0x00, 92) & 0x2):  # bit 1
        xfp_flags.append('M-Module not Ready')
    if (get_byte(optic_pages, 0x00, 92) & 0x1):  # bit 0
        xfp_flags.append('M-Reset Complete')

    if (get_byte(optic_pages, 0x00, 93) & 0x80): # bit 7
        xfp_flags.append('M-APD Supply Fault')
    if (get_byte(optic_pages, 0x00, 93) & 0x40): # bit 6
        xfp_flags.append('M-TEC Fault')
    if (get_byte(optic_pages, 0x00, 93) & 0x20): # bit 5
        xfp_flags.append('M-Wavelength Unlocked')
    if (get_byte(optic_pages, 0x00, 93) & 0x10): # bit 4
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 93) & 0x8):  # bit 3
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 93) & 0x4):  # bit 2
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 93) & 0x2):  # bit 1
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, 0x00, 93) & 0x1):  # bit 0
        xfp_flags.append('Reserved')

    if (get_byte(optic_pages, 0x00, 94) & 0x80): # bit 7
        xfp_flags.append('M-VCC5 High Alarm')
    if (get_byte(optic_pages, 0x00, 94) & 0x40): # bit 6
        xfp_flags.append('M-VCC5 Low Alarm')
    if (get_byte(optic_pages, 0x00, 94) & 0x20): # bit 5
        xfp_flags.append('M-VCC3 High Alarm')
    if (get_byte(optic_pages, 0x00, 94) & 0x10): # bit 4
        xfp_flags.append('M-VCC3 Low Alarm')
    if (get_byte(optic_pages, 0x00, 94) & 0x8):  # bit 3
        xfp_flags.append('M-VCC2 High Alarm')
    if (get_byte(optic_pages, 0x00, 94) & 0x4):  # bit 2
        xfp_flags.append('M-VCC2 Low Alarm')
    if (get_byte(optic_pages, 0x00, 94) & 0x2):  # bit 1
        xfp_flags.append('M-Vee5 High Alarm')
    if (get_byte(optic_pages, 0x00, 94) & 0x1):  # bit 0
        xfp_flags.append('M-Vee5 Low Alarm')

    if (get_byte(optic_pages, 0x00, 95) & 0x80): # bit 7
        xfp_flags.append('M-VCC5 High Warning')
    if (get_byte(optic_pages, 0x00, 95) & 0x40): # bit 6
        xfp_flags.append('M-VCC5 Low Warning')
    if (get_byte(optic_pages, 0x00, 95) & 0x20): # bit 5
        xfp_flags.append('M-VCC3 High Warning')
    if (get_byte(optic_pages, 0x00, 95) & 0x10): # bit 4
        xfp_flags.append('M-VCC3 Low Warning')
    if (get_byte(optic_pages, 0x00, 95) & 0x8):  # bit 3
        xfp_flags.append('M-VCC2 High Warning')
    if (get_byte(optic_pages, 0x00, 95) & 0x4):  # bit 2
        xfp_flags.append('M-VCC2 Low Warning')
    if (get_byte(optic_pages, 0x00, 95) & 0x2):  # bit 1
        xfp_flags.append('M-Vee5 High Warning')
    if (get_byte(optic_pages, 0x00, 95) & 0x1):  # bit 0
        xfp_flags.append('M-Vee5 Low Warning')

    comma=','
    print("XFP Flags:", comma.join(xfp_flags))

def read_optic_xfp_ad_readout():
    # INF-8077 I Table 41
    xfp_temp = (get_byte(optic_pages, 0x00, 96)<<8)+get_byte(optic_pages, 0x00, 97)
    xfp_tx_bias = (get_byte(optic_pages, 0x00, 100)<<8)+get_byte(optic_pages, 0x00, 101)
    xfp_tx_power = (get_byte(optic_pages, 0x00, 102)<<8)+get_byte(optic_pages, 0x00, 103)
    xfp_rx_power = (get_byte(optic_pages, 0x00, 104)<<8)+get_byte(optic_pages, 0x00, 105)
    xfp_aux1 = (get_byte(optic_pages, 0x00, 106)<<8)+get_byte(optic_pages, 0x00, 107)
    xfp_aux2 = (get_byte(optic_pages, 0x00, 108)<<8)+get_byte(optic_pages, 0x00, 109)
    print("XFP Temp: %d" % xfp_temp)
    print("XFP TX Bias: %d" % xfp_tx_bias)
    print("XFP TX Power: %d" % xfp_tx_power)
    print("XFP RX Power: %d" % xfp_rx_power)
    print("XFP Aux1: %d" % xfp_aux1)
    print("XFP Aux2: %d" % xfp_aux2)

# actually read data from the optic at this location
def process_optic_data(bus, i2cbus, mux, mux_val, hash_key):
    # read SFF and DDM data
    if real_hardware:
        fetch_optic_data(bus)

    if (optic_sff_read == -1):
        print("Error: Failed to read optic SFF data")
        return
    if (optic_sff_read < 128):
        print("Error reading optic bus %d mux_val %d, read %d bytes and %d bytes" % (i2cbus, mux_val, optic_sff_read, optic_ddm_read))
        return

    if (optic_sff_read >=128):
        optic_type = read_optic_type() # SFF
        print(f"read_optic_type = {optic_type}")
        print(f"optic_ddm_read = {optic_ddm_read}")
        cmis_ver_major = 0
        if optic_type > 0x18:
            cmis_ver_major = get_byte(optic_pages, 0x00, 1) >> 4
            cmis_ver_minor = get_byte(optic_pages, 0x00, 1) & 0xf
            print(f"CMIS Version: {cmis_ver_major}.{cmis_ver_minor}")
        elif optic_type == 0x18:
            cmis_ver_major = get_byte(optic_pages, 0x00, 1) >> 4
            cmis_ver_minor = get_byte(optic_pages, 0x00, 1) & 0xf
            print(f"CMIS Version: {cmis_ver_major}.{cmis_ver_minor}")
        if (optic_type == 0x06):
            read_optic_xfp_signal_conditioner_control()
            read_optic_xfp_thresholds()
            read_optic_xfp_vps_control_registers()
            #read_optic_xfp_ber_reporting()
            #read_optic_xfp_wavelength_control_registers()
            read_optic_xfp_fec_control_registers()
            read_optic_xfp_flags()
            read_optic_xfp_ad_readout()
            read_xfp_status_bits()
            if (get_byte(optic_pages, 0x00, 127) == 0x01):
                read_optic_connector_type(get_byte(optic_pages, 0x00, 130))
                read_xfp_transciever()
                read_xfp_encoding()
                read_xfp_br()
                read_xfp_lengths()
                read_xfp_technology()
                read_xfp_vendor()
                read_xfp_cdr()
                read_xfp_vendor_oui()
                read_xfp_vendor_pn()
                read_xfp_vendor_rev()
                read_xfp_wavelength()
                read_xfp_max_temp()
                read_xfp_cc_base()
                read_xfp_power_supply()
                read_xfp_ext_vendor_sn() #
                read_xfp_datecode() # table 55
                read_xfp_ext_ddm_type() # table 56
                read_xfp_ext_enh_monitoring() # Table 57
                #
                # FIXME do this
                #read_xfp_aux_types()
            #
        elif optic_type == 0x18 or cmis_ver_major > 3:
            print("Reading QSFP-DD/CMIS module data...")
            read_cmis_global_status()
            read_qsfpdd_vendor()
            read_qsfpdd_vendor_oui()
            read_qsfpdd_vendor_pn()
            read_qsfpdd_vendor_rev()
            read_qsfpdd_vendor_sn()
            read_qsfpdd_date()
            read_qsfpdd_clei_code()
            read_qsfpdd_mod_power()
            read_qsfpdd_cable_len()
            read_qsfpdd_connector_type()
            read_qsfpdd_media_interface_tech()
            
            # Only read copper attenuation if this is a copper module
            # Check media interface technology to determine if it's copper
            tech = get_byte(optic_pages, 0x100, 0x87) if 0x100 in optic_pages else 0  # Media Interface Technology
            copper_techs = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x30, 0x31, 0x32, 0x33, 0x34]  # Copper technologies
            if tech in copper_techs:
                read_qsfpdd_copper_attenuation()
                read_cmis_copper_attenuation()
            else:
                print("Copper attenuation: Not applicable (optical module)")
            read_cmis_media_lane_info()
            read_qsfpdd_media_interface_tech()
            read_cmis_module_power()
            
            # Read CMIS monitoring data instead of SFF-8472 DDM
            if (optic_sff_read >= 128):
                print("Reading CMIS monitoring data...")
                read_cmis_monitoring_data()
                print("Reading CMIS thresholds...")
                read_cmis_thresholds()
                
                # Read advanced monitoring data
                print("Reading advanced CMIS monitoring...")
                read_cmis_advanced_monitoring()
                read_cmis_performance_monitoring()
                read_cmis_coherent_monitoring()
        elif optic_type in [0x0B, 0x0C, 0x0D, 0x11]:  # QSFP/QSFP+/QSFP28
            print("Reading QSFP module data...")
            read_qsfp_data()
            read_qsfp_power_control()
            read_qsfp_page_support()
            read_qsfp_thresholds()
            read_qsfp_extended_status()
            read_qsfp_control_status()
            read_qsfp_application()
        else:
            print("Reading standard SFF module data...")
            read_optic_mod_def()
            read_optic_connector_type(get_byte(optic_pages, 0x00, 2))
            read_sff_optic_encoding()
            read_optic_signaling_rate()
            read_optic_rate_identifier()
            read_optic_vendor()
            read_optic_vendor_oui()
            read_optic_vendor_partnum()
            read_optic_vendor_serialnum()
            read_optic_rev()
            read_optic_datecode()
            read_optic_transciever()
            read_optic_distances()
            read_optic_frequency()

            read_optic_monitoring_type()
            read_option_values()

            read_enhanced_options()
            read_sff_8472_compliance()
            read_sfp_status_bits()

            # if optic is disabled re-enable it
            if (real_hardware and (get_byte(optic_pages, 0x00, 110) & 0x40) | (get_byte(optic_pages, 0x00, 110) & 0x80)):
                print("%x would be %x" % (get_byte(optic_pages, 0x00, 110), (get_byte(optic_pages, 0x00, 110)&~(0x80 + 0x40))))
                try:
                    bus.write_byte_data(address_one, 110, get_byte(optic_pages, 0x00, 110)&~(0x80 + 0x40))
                except IOError:
                    print("Unable to set optic to Soft-TX-Enable")

            if (optic_ddm_read >=128):
                print("Reading DDM data...")
                read_optic_temperature()
                read_optic_rxpower()
                read_optic_txpower()

                read_laser_temperature()
                read_optic_vcc()
                read_measured_current()
                read_alarm_warning_thresholds()  # Add this line
                check_alarm_status()  # Add this line
                read_ext_cal_constants()  # Add this line
                read_vendor_specific()  # Add this line
                read_enhanced_options()  # Add this line
                # if the optic is dwdm
                if (get_byte(optic_pages, 0x00, 65) & 0x40): # bit 6 - SFF-8690 4.1
                    print("Reading/decoding dwdm")
                    if (optic_dwdm_read >= 128):
                        decode_dwdm_data()
            else:
                print(f"Warning: DDM data not available (read {optic_ddm_read} bytes)")

    return optic_sff_read
## end process_optic_data




def poll_busses():

    optics_exist = { }
    temps = { }
    retval = -1

    # iterate through i2c busses
    for busno in range (0, 2):

        print("Optic(s) on slot(Bus) number %d:" % busno)
        try:
            with smbus2.SMBus(busno) as bus:
                for mux_loc in range (0x70, 0x77):
                    mux_exist = 0
                    any_mux_exist = 0
                    ## detect if PCA9547 is there by reading 0x70-0x77
                    # perhaps also 0x70 - 0x77
                    try:
                        mux = bus.read_byte_data(mux_loc, 0x4)
                        mux_exist = 1
                        any_mux_exist = 1
    #				print("Found pca954x at i2c %d at %-2x" % (busno, mux_loc))
                    except IOError:
                        mux_exist=0

                    if (mux_exist == 1):
                        for i2csel in range (8, 16):
    #					print("---- > Switching i2c(%d) to %d-0x%-2x" % (busno, (mux_loc-0x70), i2csel))
                            key = "%d-%d-%d" % (busno, mux_loc-0x70, i2csel - 0x9)
    #					print("HASH KEY = %s" % key)
                            try:
                                bus.write_byte_data(mux_loc,0x04,i2csel)
                            except IOError:
                                print("i2c switch failed for bus %d location 0x%-2x" % (busno, i2csel))

                            retval = process_optic_data(bus, busno, mux_loc, i2csel, key)
                            if (retval > 0):
                                optics_exist[key] = 1
                            if ((i2csel == 15) or (i2csel == 9)):
                                try:
                                    # read the flash chip that says what board it is
    #							print("Should read 0x57")
                                    read_board_id(bus, busno, mux_loc, i2csel)
                                except IOError:
                                    # Error reading flash chip
                                    print("Error reading board ID via i2c, reseat board?")

                                try:
                                    # try to read TMP102 sensor

                                    msb = bus.read_byte_data(tmp102_address, 0x0)
                                    lsb = bus.read_byte_data(tmp102_address, 0x1)

                                    temp = ((msb << 8) | lsb)
                                    temp >>=4
                                    if(temp & (1<<11)):
                                        temp |= 0xf800

                                    tempC = temp*0.0625
                                    tempF = (1.8* tempC) + 32
                                    print("PCB Temperature appears to be %2.2fC or %2.2fF msb %d lsb %d" % (tempC, tempF, msb, lsb))
                                    temps[key] = tempF

                                except IOError:
                                    temp = -1
                                # end try TMP102

                        # end i2csel

                        # reset the i2c mux back to the first channel to avoid address conflicts
                        try:
                            bus.write_byte_data(mux_loc, 0x04, 8)
                        except IOError:
                            print("Unable to set mux back to first channel")
                # end for mux_loc

                if (any_mux_exist == 0):
                    try:
                        msb = bus.read_byte_data(tmp102_address, 0x0)
                        lsb = bus.read_byte_data(tmp102_address, 0x1)

                        temp = ((msb << 8) | lsb)
                        temp >>=4
                        if(temp & (1<<11)):
                            temp |= 0xf800

                        tempC = temp*0.0625
                        tempF = (1.8* tempC) + 32
                        print("PCB Temperature appears to be %2.2fC or %2.2fF msb %d lsb %d" % (tempC, tempF, msb, lsb))
                        temps["0"] = tempF
                    except IOError:
                        temp = -1


                # handle any optics not on a mux
                process_optic_data(bus, busno, 0, 0, "nomux")

        except IOError:
            continue

    # end for busno
    print("Optics exist in these slots:")
    for k in sorted(optics_exist.keys()):
        print(k)

    print("Board Temps:")
    for k in sorted(temps.keys()):
        print("%s %s" % (k, temps[k]))

def read_alarm_warning_thresholds():
    """Read alarm and warning thresholds as defined in SFF-8472 Table 9-5"""
    # Temperature thresholds
    temp_high_alarm = (optic_ddm[0] << 8 | optic_ddm[1]) / 256.0
    temp_low_alarm = (optic_ddm[2] << 8 | optic_ddm[3]) / 256.0
    temp_high_warning = (optic_ddm[4] << 8 | optic_ddm[5]) / 256.0
    temp_low_warning = (optic_ddm[6] << 8 | optic_ddm[7]) / 256.0

    # Voltage thresholds
    voltage_high_alarm = (optic_ddm[8] << 8 | optic_ddm[9]) / 10000.0
    voltage_low_alarm = (optic_ddm[10] << 8 | optic_ddm[11]) / 10000.0
    voltage_high_warning = (optic_ddm[12] << 8 | optic_ddm[13]) / 10000.0
    voltage_low_warning = (optic_ddm[14] << 8 | optic_ddm[15]) / 10000.0

    # Bias current thresholds
    bias_high_alarm = (optic_ddm[16] << 8 | optic_ddm[17]) * 2.0
    bias_low_alarm = (optic_ddm[18] << 8 | optic_ddm[19]) * 2.0
    bias_high_warning = (optic_ddm[20] << 8 | optic_ddm[21]) * 2.0
    bias_low_warning = (optic_ddm[22] << 8 | optic_ddm[23]) * 2.0

    def safe_log10(val, label):
        try:
            if val <= 0:
                print(f"Warning: {label} value is zero or negative ({val}), cannot compute log10.")
                return float('nan')
            return 10 * math.log10(val)
        except Exception as e:
            print(f"Warning: math error for {label}: {e}")
            return float('nan')

    # TX power thresholds
    tx_power_high_alarm = safe_log10((optic_ddm[24] << 8 | optic_ddm[25]) / 10000.0, 'TX Power High Alarm')
    tx_power_low_alarm = safe_log10((optic_ddm[26] << 8 | optic_ddm[27]) / 10000.0, 'TX Power Low Alarm')
    tx_power_high_warning = safe_log10((optic_ddm[28] << 8 | optic_ddm[29]) / 10000.0, 'TX Power High Warning')
    tx_power_low_warning = safe_log10((optic_ddm[30] << 8 | optic_ddm[31]) / 10000.0, 'TX Power Low Warning')

    # RX power thresholds
    rx_power_high_alarm = safe_log10((optic_ddm[32] << 8 | optic_ddm[33]) / 10000.0, 'RX Power High Alarm')
    rx_power_low_alarm = safe_log10((optic_ddm[34] << 8 | optic_ddm[35]) / 10000.0, 'RX Power Low Alarm')
    rx_power_high_warning = safe_log10((optic_ddm[36] << 8 | optic_ddm[37]) / 10000.0, 'RX Power High Warning')
    rx_power_low_warning = safe_log10((optic_ddm[38] << 8 | optic_ddm[39]) / 10000.0, 'RX Power Low Warning')

    print("Temperature Thresholds (°C):")
    print(f"  High Alarm:  {temp_high_alarm:.2f}")
    print(f"  Low Alarm:   {temp_low_alarm:.2f}")
    print(f"  High Warning:{temp_high_warning:.2f}")
    print(f"  Low Warning: {temp_low_warning:.2f}")

    print("\nVoltage Thresholds (V):")
    print(f"  High Alarm:  {voltage_high_alarm:.3f}")
    print(f"  Low Alarm:   {voltage_low_alarm:.3f}")
    print(f"  High Warning:{voltage_high_warning:.3f}")
    print(f"  Low Warning: {voltage_low_warning:.3f}")

    print("\nBias Current Thresholds (mA):")
    print(f"  High Alarm:  {bias_high_alarm:.2f}")
    print(f"  Low Alarm:   {bias_low_alarm:.2f}")
    print(f"  High Warning:{bias_high_warning:.2f}")
    print(f"  Low Warning: {bias_low_warning:.2f}")

    print("\nTX Power Thresholds (dBm):")
    print(f"  High Alarm:  {tx_power_high_alarm:.2f}")
    print(f"  Low Alarm:   {tx_power_low_alarm:.2f}")
    print(f"  High Warning:{tx_power_high_warning:.2f}")
    print(f"  Low Warning: {tx_power_low_warning:.2f}")

    print("\nRX Power Thresholds (dBm):")
    print(f"  High Alarm:  {rx_power_high_alarm:.2f}")
    print(f"  Low Alarm:   {rx_power_low_alarm:.2f}")
    print(f"  High Warning:{rx_power_high_warning:.2f}")
    print(f"  Low Warning: {rx_power_low_warning:.2f}")

def check_alarm_status():
    """Check current values against thresholds and report alarms/warnings"""
    try:
        temp = read_optic_temperature()
        vcc = read_optic_vcc()
        bias = read_measured_current()
        tx_power = read_optic_txpower()
        rx_power = read_optic_rxpower()

        # Read alarm flags from bytes 112-115
        alarm_flags = (optic_ddm[112] << 24) | (optic_ddm[113] << 16) | (optic_ddm[114] << 8) | optic_ddm[115]

        print("\nAlarm Status:")
        if alarm_flags & 0x80000000:
            print("  Temperature High Alarm")
        if alarm_flags & 0x40000000:
            print("  Temperature Low Alarm")
        if alarm_flags & 0x20000000:
            print("  Voltage High Alarm")
        if alarm_flags & 0x10000000:
            print("  Voltage Low Alarm")
        if alarm_flags & 0x08000000:
            print("  TX Bias High Alarm")
        if alarm_flags & 0x04000000:
            print("  TX Bias Low Alarm")
        if alarm_flags & 0x02000000:
            print("  TX Power High Alarm")
        if alarm_flags & 0x01000000:
            print("  TX Power Low Alarm")
        if alarm_flags & 0x00800000:
            print("  RX Power High Alarm")
        if alarm_flags & 0x00400000:
            print("  RX Power Low Alarm")

        # Warning flags
        if alarm_flags & 0x00200000:
            print("  Temperature High Warning")
        if alarm_flags & 0x00100000:
            print("  Temperature Low Warning")
        if alarm_flags & 0x00080000:
            print("  Voltage High Warning")
        if alarm_flags & 0x00040000:
            print("  Voltage Low Warning")
        if alarm_flags & 0x00020000:
            print("  TX Bias High Warning")
        if alarm_flags & 0x00010000:
            print("  TX Bias Low Warning")
        if alarm_flags & 0x00008000:
            print("  TX Power High Warning")
        if alarm_flags & 0x00004000:
            print("  TX Power Low Warning")
        if alarm_flags & 0x00002000:
            print("  RX Power High Warning")
        if alarm_flags & 0x00001000:
            print("  RX Power Low Warning")

    except Exception as e:
        print(f"Error checking alarm status: {str(e)}")

def read_ext_cal_constants():
    """Read extended calibration constants as defined in SFF-8472"""
    try:
        # Check if calibration is internal or external
        if not (optic_ddm[92] & 0x80):
            print("Module uses internal calibration")
            return

        print("\nExtended Calibration Constants:")

        # Rx Power Calibration
        rx_pwr_slope = (optic_ddm[56] << 8 | optic_ddm[57])
        rx_pwr_offset = (optic_ddm[58] << 8 | optic_ddm[59])
        print(f"RX Power Slope: {rx_pwr_slope}")
        print(f"RX Power Offset: {rx_pwr_offset}")

        # Tx Power Calibration
        tx_pwr_slope = (optic_ddm[60] << 8 | optic_ddm[61])
        tx_pwr_offset = (optic_ddm[62] << 8 | optic_ddm[63])
        print(f"TX Power Slope: {tx_pwr_slope}")
        print(f"TX Power Offset: {tx_pwr_offset}")

        # Temperature Calibration
        temp_slope = (optic_ddm[64] << 8 | optic_ddm[65])
        temp_offset = (optic_ddm[66] << 8 | optic_ddm[67])
        print(f"Temperature Slope: {temp_slope}")
        print(f"Temperature Offset: {temp_offset}")

        # Voltage Calibration
        voltage_slope = (optic_ddm[68] << 8 | optic_ddm[69])
        voltage_offset = (optic_ddm[70] << 8 | optic_ddm[71])
        print(f"Voltage Slope: {voltage_slope}")
        print(f"Voltage Offset: {voltage_offset}")

        # Bias Calibration
        bias_slope = (optic_ddm[72] << 8 | optic_ddm[73])
        bias_offset = (optic_ddm[74] << 8 | optic_ddm[75])
        print(f"Bias Slope: {bias_slope}")
        print(f"Bias Offset: {bias_offset}")

        # TX/RX Power Calibration for high power/current
        tx_i_slope = (optic_ddm[76] << 8 | optic_ddm[77])
        tx_i_offset = (optic_ddm[78] << 8 | optic_ddm[79])
        tx_pwr_slope_hi = (optic_ddm[80] << 8 | optic_ddm[81])
        tx_pwr_offset_hi = (optic_ddm[82] << 8 | optic_ddm[83])
        print(f"TX I Slope: {tx_i_slope}")
        print(f"TX I Offset: {tx_i_offset}")
        print(f"TX Power Slope (High): {tx_pwr_slope_hi}")
        print(f"TX Power Offset (High): {tx_pwr_offset_hi}")

        # Optional checksum
        if optic_ddm_read >= 95:
            checksum = optic_ddm[95]
            calc_checksum = 0
            for i in range(56, 95):
                calc_checksum = (calc_checksum + optic_ddm[i]) & 0xFF
            print(f"Calibration Checksum: 0x{checksum:02x} (Calculated: 0x{calc_checksum:02x})")
            if checksum != calc_checksum:
                print("Warning: Calibration checksum mismatch!")

    except Exception as e:
        print(f"Error reading extended calibration constants: {str(e)}")

def read_vendor_specific():
    """Read vendor specific information as defined in SFF-8472"""
    try:
        print("\nVendor Specific Information:")

        # Check if vendor specific page is supported
        if optic_ddm_read < 256:
            print("Vendor specific page not available")
            return

        # Read vendor specific data (Page 3)
        vendor_data = []
        if real_hardware:
            try:
                with smbus2.SMBus(busno) as bus:
                    # Select page 3
                    bus.write_byte_data(address_two, 127, 3)
                    time.sleep(0.01)  # Allow page switch

                    # Read vendor specific data
                    for i in range(128, 256):
                        vendor_data.append(bus.read_byte_data(address_two, i))

                    # Return to page 0
                    bus.write_byte_data(address_two, 127, 0)
                    time.sleep(0.01)

            except IOError as e:
                print(f"I/O error reading vendor page: {str(e)}")
                return
        else:
            # When reading from file, we don't have vendor page data
            print("Vendor specific page data not available when reading from file")
            return

        # Print vendor specific data
        print("\nVendor Page Data (Page 3):")
        for i in range(0, len(vendor_data), 16):
            hex_data = ' '.join([f"{x:02x}" for x in vendor_data[i:i+16]])
            ascii_data = ''.join([chr(x) if 32 <= x <= 126 else '.' for x in vendor_data[i:i+16]])
            print(f"{i:04x}: {hex_data:<48} {ascii_data}")

    except Exception as e:
        print(f"Error reading vendor specific information: {str(e)}")

def read_qsfp_data():
    """Read QSFP+ specific data according to SFF-8636"""
    try:
        print("\nQSFP+ Module Information:")

        # Read identifier byte
        identifier = get_byte(optic_pages, 0x00, 0)
        if identifier not in [0x0B, 0x0C, 0x0D, 0x11]:
            print("Not a QSFP/QSFP+/QSFP28 module")
            return False

        # Read page support
        pages = get_byte(optic_pages, 0x00, 2)
        print("\nPage Support:")
        print(f"- Number of virtual pages: {pages & 0x0F}")
        if pages & 0x80:
            print("- Flat memory implemented")
        if pages & 0x40:
            print("- Page-2 implemented")

        # Read power control
        power_ctrl = get_byte(optic_pages, 0x00, 93)
        print("\nPower Control:")
        if power_ctrl & 0x04:
            print("- Power override enabled")
        if power_ctrl & 0x02:
            print("- Power set high")
        if power_ctrl & 0x01:
            print("- Low power mode")

        # Read CDR control
        cdr_control = get_byte(optic_pages, 0x00, 98)
        print("\nCDR Control:")
        print(f"TX CDR Control: {'Enabled' if cdr_control & 0xF0 else 'Disabled'}")
        print(f"RX CDR Control: {'Enabled' if cdr_control & 0x0F else 'Disabled'}")

        # Read vendor information (SFF-8636 Table 6-1)
        print("\nVendor Information:")
        # For QSFP-DD/CMIS, use upper page 0x80
        if identifier == 0x18 or identifier > 0x18:
            vendor_name = get_bytes(optic_pages, 0x80, 0x10, 0x20).decode(errors='ignore').strip()
            print(f"Vendor: {vendor_name}")
            vendor_oui = f"{get_byte(optic_pages, 0x80, 0x0D):02x}{get_byte(optic_pages, 0x80, 0x0E):02x}{get_byte(optic_pages, 0x80, 0x0F):02x}"
            print(f"Vendor OUI: {vendor_oui}")
            part_number = get_bytes(optic_pages, 0x80, 0x20, 0x30).decode(errors='ignore').strip()
            print(f"Vendor PN: {part_number}")
            revision = get_bytes(optic_pages, 0x80, 0x30, 0x32).decode(errors='ignore').strip()
            print(f"Vendor rev: {revision}")
            serial_number = get_bytes(optic_pages, 0x80, 0x44, 0x54).decode(errors='ignore').strip()
            print(f"SN: {serial_number}")
            date_code = get_bytes(optic_pages, 0x80, 0x54, 0x5C).decode(errors='ignore').strip()
            print(f"Date Code: {date_code}")
        elif identifier in [0x0B, 0x0C, 0x0D, 0x11]:
            vendor_name = get_bytes(optic_pages, 0x80, 0x10, 0x20).decode(errors='ignore').strip()
            print(f"Vendor: {vendor_name}")
            vendor_oui = f"{get_byte(optic_pages, 0x80, 0x0D):02x}{get_byte(optic_pages, 0x80, 0x0E):02x}{get_byte(optic_pages, 0x80, 0x0F):02x}"
            print(f"Vendor OUI: {vendor_oui}")
            part_number = get_bytes(optic_pages, 0x80, 0x20, 0x30).decode(errors='ignore').strip()
            print(f"Part Number: {part_number}")
            revision = get_bytes(optic_pages, 0x80, 0x30, 0x32).decode(errors='ignore').strip()
            print(f"Revision: {revision}")
            serial_number = get_bytes(optic_pages, 0x80, 0x44, 0x54).decode(errors='ignore').strip()
            print(f"Serial Number: {serial_number}")
            date_code = get_bytes(optic_pages, 0x80, 0x54, 0x5C).decode(errors='ignore').strip()
            print(f"Date Code: {date_code}")
        else:
            vendor_name = get_bytes(optic_pages, 0x00, 20, 36).decode(errors='ignore').strip()
            print(f"Vendor: {vendor_name}")
            vendor_oui = f"{get_byte(optic_pages, 0x00, 37):02x}{get_byte(optic_pages, 0x00, 38):02x}{get_byte(optic_pages, 0x00, 39):02x}"
            print(f"Vendor OUI: {vendor_oui}")
            part_number = get_bytes(optic_pages, 0x00, 40, 56).decode(errors='ignore').strip()
            print(f"Part Number: {part_number}")
            serial_number = get_bytes(optic_pages, 0x00, 68, 84).decode(errors='ignore').strip()
            print(f"Serial Number: {serial_number}")
            date_code = get_bytes(optic_pages, 0x00, 84, 92).decode(errors='ignore').strip()
            print(f"Date Code: {date_code}")
            revision = get_bytes(optic_pages, 0x00, 56, 60).decode(errors='ignore').strip()
            print(f"Revision: {revision}")

        # Read monitoring data if available
        if optic_ddm_read >= 128:
            print("\nMonitoring Data:")
            # Temperature (bytes 22-23)
            temp = struct.unpack_from('>h', bytes(optic_ddm[22:24]))[0] / 256.0
            print(f"Temperature: {temp:.2f}°C")

            # Supply voltage (bytes 26-27)
            vcc = struct.unpack_from('>H', bytes(optic_ddm[26:28]))[0] / 10000.0
            print(f"Supply Voltage: {vcc:.3f}V")

            # Per channel monitoring
            for i in range(4):
                print(f"\nChannel {i+1}:")
                # Rx Power (bytes 34-41)
                rx_power = struct.unpack_from('>H', bytes(optic_ddm[34+i*2:36+i*2]))[0] / 10000.0
                print(f"Rx Power: {rx_power:.2f}mW")

                # Tx Bias (bytes 42-49)
                tx_bias = struct.unpack_from('>H', bytes(optic_ddm[42+i*2:44+i*2]))[0] / 500.0
                print(f"Tx Bias: {tx_bias:.2f}mA")

                # Tx Power (bytes 50-57)
                tx_power = struct.unpack_from('>H', bytes(optic_ddm[50+i*2:52+i*2]))[0] / 10000.0
                print(f"Tx Power: {tx_power:.2f}mW")

            # Read thresholds
            print("\nMonitoring Thresholds:")
            temp_high_alarm = struct.unpack_from('>h', bytes(optic_ddm[128:130]))[0] / 256.0
            temp_low_alarm = struct.unpack_from('>h', bytes(optic_ddm[130:132]))[0] / 256.0
            print(f"Temperature Alarm Thresholds: High={temp_high_alarm:.2f}°C, Low={temp_low_alarm:.2f}°C")

            vcc_high_alarm = struct.unpack_from('>H', bytes(optic_ddm[144:146]))[0] / 10000.0
            vcc_low_alarm = struct.unpack_from('>H', bytes(optic_ddm[146:148]))[0] / 10000.0
            print(f"Voltage Alarm Thresholds: High={vcc_high_alarm:.3f}V, Low={vcc_low_alarm:.3f}V")

        return True

    except Exception as e:
        print(f"Error reading QSFP+ data: {str(e)}")
        return False

# Add to process_optic_data() after optic type check:
#                # ... existing code ...
#                if optic_type in [0x0B, 0x0C, 0x0D]:  # QSFP/QSFP+/QSFP28
#                    if read_qsfp_data():
#                        return
#                # ... existing code ...

def read_qsfp_power_control():
    """Read QSFP+ power control as defined in SFF-8636"""
    try:
        power_ctrl = get_byte(optic_pages, 0x00, 93)
        print("\nPower Control:")
        if power_ctrl & 0x04:
            print("- Power override enabled")
        if power_ctrl & 0x02:
            print("- Power set high")
        if power_ctrl & 0x01:
            print("- Low power mode")
    except Exception as e:
        print(f"Error reading power control: {str(e)}")

def read_qsfp_page_support():
    """Read QSFP+ page support as defined in SFF-8636"""
    try:
        pages = get_byte(optic_pages, 0x00, 2)
        print("\nPage Support:")
        print(f"- Number of virtual pages: {pages & 0x0F}")
        if pages & 0x80:
            print("- Flat memory implemented")
        if pages & 0x40:
            print("- Page-2 implemented")
        if pages & 0x10:
            print("- Bank-0 implemented")
    except Exception as e:
        print(f"Error reading page support: {str(e)}")

def read_qsfp_thresholds():
    """Read QSFP+ monitoring thresholds as defined in SFF-8636"""
    try:
        print("\nMonitoring Thresholds:")

        # Temperature thresholds
        temp_high_alarm = struct.unpack_from('>h', bytes(optic_ddm[128:130]))[0] / 256.0
        temp_low_alarm = struct.unpack_from('>h', bytes(optic_ddm[130:132]))[0] / 256.0
        temp_high_warn = struct.unpack_from('>h', bytes(optic_ddm[132:134]))[0] / 256.0
        temp_low_warn = struct.unpack_from('>h', bytes(optic_ddm[134:136]))[0] / 256.0

        print(f"Temperature Thresholds (°C):")
        print(f"  High Alarm: {temp_high_alarm:.2f}")
        print(f"  Low Alarm:  {temp_low_alarm:.2f}")
        print(f"  High Warn:  {temp_high_warn:.2f}")
        print(f"  Low Warn:   {temp_low_warn:.2f}")

        # Voltage thresholds
        vcc_high_alarm = struct.unpack_from('>H', bytes(optic_ddm[144:146]))[0] / 10000.0
        vcc_low_alarm = struct.unpack_from('>H', bytes(optic_ddm[146:148]))[0] / 10000.0
        vcc_high_warn = struct.unpack_from('>H', bytes(optic_ddm[148:150]))[0] / 10000.0
        vcc_low_warn = struct.unpack_from('>H', bytes(optic_ddm[150:152]))[0] / 10000.0

        print(f"\nVoltage Thresholds (V):")
        print(f"  High Alarm: {vcc_high_alarm:.3f}")
        print(f"  Low Alarm:  {vcc_low_alarm:.3f}")
        print(f"  High Warn:  {vcc_high_warn:.3f}")
        print(f"  Low Warn:   {vcc_low_warn:.3f}")

        # Per channel thresholds
        for i in range(4):
            print(f"\nChannel {i+1} Thresholds:")

            # RX Power thresholds
            rx_pwr_high_alarm = struct.unpack_from('>H', bytes(optic_ddm[176+i*8:178+i*8]))[0] / 10000.0
            rx_pwr_low_alarm = struct.unpack_from('>H', bytes(optic_ddm[178+i*8:180+i*8]))[0] / 10000.0
            rx_pwr_high_warn = struct.unpack_from('>H', bytes(optic_ddm[180+i*8:182+i*8]))[0] / 10000.0
            rx_pwr_low_warn = struct.unpack_from('>H', bytes(optic_ddm[182+i*8:184+i*8]))[0] / 10000.0

            print(f"  RX Power (mW):")
            print(f"    High Alarm: {rx_pwr_high_alarm:.3f}")
            print(f"    Low Alarm:  {rx_pwr_low_alarm:.3f}")
            print(f"    High Warn:  {rx_pwr_high_warn:.3f}")
            print(f"    Low Warn:   {rx_pwr_low_warn:.3f}")

            # TX Bias thresholds
            tx_bias_high_alarm = struct.unpack_from('>H', bytes(optic_ddm[184+i*8:186+i*8]))[0] / 500.0
            tx_bias_low_alarm = struct.unpack_from('>H', bytes(optic_ddm[186+i*8:188+i*8]))[0] / 500.0
            tx_bias_high_warn = struct.unpack_from('>H', bytes(optic_ddm[188+i*8:190+i*8]))[0] / 500.0
            tx_bias_low_warn = struct.unpack_from('>H', bytes(optic_ddm[190+i*8:192+i*8]))[0] / 500.0

            print(f"  TX Bias (mA):")
            print(f"    High Alarm: {tx_bias_high_alarm:.2f}")
            print(f"    Low Alarm:  {tx_bias_low_alarm:.2f}")
            print(f"    High Warn:  {tx_bias_high_warn:.2f}")
            print(f"    Low Warn:   {tx_bias_low_warn:.2f}")

    except Exception as e:
        print(f"Error reading monitoring thresholds: {str(e)}")

def read_qsfp_extended_status():
    """Read QSFP+ extended status as defined in SFF-8636"""
    try:
        print("\nExtended Status:")

        # Read extended identifier
        ext_id = get_byte(optic_pages, 0x00, 129)
        print(f"Extended Identifier: 0x{ext_id:02x}")

        # Read connector type
        connector = get_byte(optic_pages, 0x00, 130)
        connector_types = {
            0x00: "Unknown",
            0x01: "SC",
            0x02: "Fibre Channel Style 1",
            0x03: "Fibre Channel Style 2",
            0x04: "BNC/TNC",
            0x05: "Fibre Channel Coax",
            0x06: "Fiber Jack",
            0x07: "LC",
            0x08: "MT-RJ",
            0x09: "MU",
            0x0A: "SG",
            0x0B: "Optical Pigtail",
            0x0C: "MPO 1x12",
            0x0D: "MPO 2x16",
            0x20: "HSSDC II",
            0x21: "Copper Pigtail",
            0x23: "RJ45",
            0x24: "No Separable Connector"
        }
        print(f"Connector: {connector_types.get(connector, f'Unknown (0x{connector:02x})')}")

        # Read specification compliance
        spec_compliance = list(get_bytes(optic_pages, 0x00, 131, 139))
        print("\nSpecification Compliance:")

        # 10G Ethernet Compliance (byte 131)
        if spec_compliance[0] & 0x80:
            print("- 10G Base-SR")
        if spec_compliance[0] & 0x40:
            print("- 10G Base-LR")
        if spec_compliance[0] & 0x20:
            print("- 10G Base-ER")

        # SONET Compliance (byte 132)
        if spec_compliance[1] & 0x80:
            print("- OC 48 Short")
        if spec_compliance[1] & 0x40:
            print("- OC 48 Intermediate")
        if spec_compliance[1] & 0x20:
            print("- OC 48 Long")

        # SAS/SATA Compliance (byte 133)
        if spec_compliance[2] & 0x80:
            print("- SAS 6.0G")
        if spec_compliance[2] & 0x40:
            print("- SAS 3.0G")

        # Ethernet Compliance (byte 134)
        if spec_compliance[3] & 0x80:
            print("- 40G Base-SR4")
        if spec_compliance[3] & 0x40:
            print("- 40G Base-LR4")
        if spec_compliance[3] & 0x20:
            print("- 40G Base-CR4")

        # Fibre Channel Link Length (byte 135)
        if spec_compliance[4] & 0x80:
            print("- Very Long Distance")
        if spec_compliance[4] & 0x40:
            print("- Short Distance")
        if spec_compliance[4] & 0x20:
            print("- Intermediate Distance")
        if spec_compliance[4] & 0x10:
            print("- Long Distance")

        # Fibre Channel Technology (byte 136)
        if spec_compliance[5] & 0x80:
            print("- Electrical Inter-Enclosure")
        if spec_compliance[5] & 0x40:
            print("- Longwave Laser (LC)")
        if spec_compliance[5] & 0x20:
            print("- Shortwave Laser w/OFC (SN)")
        if spec_compliance[5] & 0x10:
            print("- Shortwave Laser w/OFL (SL)")

        # Cable Technology (byte 137)
        if spec_compliance[6] & 0x80:
            print("- Active Cable")
        if spec_compliance[6] & 0x40:
            print("- Passive Cable")

    except Exception as e:
        print(f"Error reading extended status: {str(e)}")

def read_qsfp_control_status():
    """Read QSFP+ control and status bytes as defined in SFF-8636"""
    try:
        print("\nControl/Status:")

        # Low Power Mode Status
        lpmode = get_byte(optic_pages, 0x00, 93) & 0x01
        print(f"Low Power Mode: {'Enabled' if lpmode else 'Disabled'}")

        # CDR Control/Status
        cdr_control = get_byte(optic_pages, 0x00, 98)
        print("\nCDR Control:")
        print(f"TX CDR Control: {'Enabled' if cdr_control & 0xF0 else 'Disabled'}")
        print(f"RX CDR Control: {'Enabled' if cdr_control & 0x0F else 'Disabled'}")

        # Rate Select Status
        rate_select = list(get_bytes(optic_pages, 0x00, 87, 89))
        print("\nRate Select Status:")
        print(f"TX Rate Select: 0x{rate_select[0]:02x}")
        print(f"RX Rate Select: 0x{rate_select[1]:02x}")

        # Module Status
        status = get_byte(optic_pages, 0x00, 85)
        print("\nModule Status:")
        if status & 0x80:
            print("- Module Ready")
        if status & 0x40:
            print("- IntL Asserted")
        if status & 0x20:
            print("- Module Fault")

    except Exception as e:
        print(f"Error reading control/status: {str(e)}")

def read_qsfp_application():
    """Read QSFP+ application advertisement as defined in SFF-8636"""
    try:
        print("\nApplication Advertisement:")

        # Read application advertisement fields
        for i in range(0, 32, 4):  # Read 8 application entries
            app_code = get_bytes(optic_pages, 0x00, 139 + i, 143 + i)
            if app_code is None:
                continue
            host_speed = app_code[0]
            media_type = app_code[1]
            media_speed = app_code[2]
            link_length = app_code[3]

            if host_speed == 0 and media_type == 0:
                continue  # Skip empty entries

            print(f"\nApplication {i//4 + 1}:")

            # Decode host interface speed
            speeds = {
                0x00: "Undefined",
                0x01: "1000BASE-CX",
                0x02: "XAUI/10GBASE-CX4",
                0x03: "XFI/SFI",
                0x04: "25GAUI/25GBASE-CR CA-L",
                0x05: "CAUI-4/40GBASE-CR4",
                0x06: "50GAUI-2/50GBASE-CR2",
                0x07: "100GAUI-4/100GBASE-CR4"
            }
            print(f"Host Interface: {speeds.get(host_speed, f'Unknown (0x{host_speed:02x})')}")

            # Decode media type
            media_types = {
                0x00: "Undefined",
                0x01: "MMF",
                0x02: "SMF",
                0x03: "Passive Copper",
                0x04: "Active Copper"
            }
            print(f"Media Type: {media_types.get(media_type, f'Unknown (0x{media_type:02x})')}")

            # Print media speed
            print(f"Media Speed: {media_speed} Gb/s")

            # Decode link length
            if media_type == 0x01:  # MMF
                print(f"Link Length: {link_length*10}m OM4")
            elif media_type == 0x02:  # SMF
                print(f"Link Length: {link_length}km")
            elif media_type in [0x03, 0x04]:  # Copper
                print(f"Link Length: {link_length}m")

    except Exception as e:
        print(f"Error reading application advertisement: {str(e)}")




def read_cmis_application_codes():
    """Read and print CMIS Application Codes"""
    print("CMIS Application Codes:")
    for i in range(8):
        app_code = get_bytes(optic_pages, 0x00, 139 + i, 143 + i)
        if app_code and any(b != 0 for b in app_code):
            print(f"  Lane {i}: {app_code.hex().upper()}")

def read_cmis_lane_status():
    """Read and print CMIS Lane Status"""
    print("CMIS Lane Status:")
    for lane in range(8):
        app_code = get_byte(optic_pages, 0x00, 12 + lane)
        if app_code and app_code != 0:
            print(f"  Lane {lane}: {app_code:02x}")

def read_cmis_module_state():
    """Read and print CMIS Module State (Table 8-5)"""
    try:
        state = get_byte(optic_pages, 0x00, 3) & 0x0F
        state_map = {
            0x00: "ModuleLowPwr",
            0x01: "ModulePwrUp",
            0x02: "ModuleReady",
            0x03: "ModulePwrDn",
            0x04: "ModuleFault",
            0x05: "ModuleTxOff",
            0x06: "ModuleTxTuning",
            0x07: "ModuleRxTuning",
            0x08: "ModuleLoopback",
            0x09: "ModuleTest",
            0x0A: "ModuleFaultPwrDn",
            0x0B: "ModuleTxFault",
            0x0C: "ModuleRxFault",
            0x0D: "ModuleTxRxFault",
            0x0E: "ModuleTxRxFaultPwrDn",
            0x0F: "ModuleFaultPwrDn"
        }
        print(f"Module State: {state_map.get(state, f'Unknown({state:02x})')}")
    except Exception as e:
        print(f"Error reading module state: {e}")

def read_cmis_module_power():
    """Read CMIS module power control (CMIS 5.0)"""
    try:
        print("\nPower Control:")
        # Power control is in byte 93 (0x5D)
        power_ctrl = get_byte(optic_pages, 0x00, 93)
        print(f"Power Override: {'Enabled' if power_ctrl & 0x04 else 'Disabled'}")
        print(f"Power Set High: {'Yes' if power_ctrl & 0x02 else 'No'}")
        print(f"Low Power Mode: {'Enabled' if power_ctrl & 0x01 else 'Disabled'}")
        
        # Power consumption is in bytes 18-19 (0x12-0x13) for current consumption
        # Max power is in byte 201 (0xC9) for maximum power
        if get_byte(optic_pages, 0x00, 19) is not None:
            power = (get_byte(optic_pages, 0x00, 18) << 8) | get_byte(optic_pages, 0x00, 19)
            power = power / 10000.0  # Convert to watts (units of 0.0001W)
            print(f"Current Power Consumption: {power:.3f}W")
        
        # Read max power from byte 201
        if get_byte(optic_pages, 0x00, 201) is not None:
            max_power = get_byte(optic_pages, 0x00, 201) * 0.25  # Units of 0.25W
            print(f"Maximum Power: {max_power:.2f}W")
            
        return power_ctrl
    except Exception as e:
        print(f"Error reading power control: {str(e)}")
        return None

def read_cmis_module_config():
    """Read CMIS module configuration (CMIS 5.0)"""
    try:
        print("\nModule Configuration:")
        
        # Module type and capabilities
        module_type = get_byte(optic_pages, 0x00, 4)
        print(f"Module Type: 0x{module_type:02x}")
        
        # Features
        features = get_byte(optic_pages, 0x00, 5)
        print("\nFeatures:")
        print(f"Power Control: {'Supported' if features & 0x80 else 'Not Supported'}")
        print(f"CDR Control: {'Supported' if features & 0x40 else 'Not Supported'}")
        print(f"Application Select: {'Supported' if features & 0x20 else 'Not Supported'}")
        print(f"Rate Select: {'Supported' if features & 0x10 else 'Not Supported'}")
        
        # Status
        status = get_byte(optic_pages, 0x00, 6)
        print("\nStatus:")
        print(f"Module Ready: {'Yes' if status & 0x80 else 'No'}")
        print(f"Module Fault: {'Yes' if status & 0x40 else 'No'}")
        print(f"Module PwrDn: {'Yes' if status & 0x20 else 'No'}")
        print(f"Module TxOff: {'Yes' if status & 0x10 else 'No'}")
        
        return module_type
    except Exception as e:
        print(f"Error reading module configuration: {str(e)}")
        return None

def read_cmis_copper_attenuation():
    """Read CMIS copper attenuation data (CMIS 5.0)"""
    try:
        print("\nCopper Attenuation:")
        print(f"5GHz: {get_byte(optic_pages, 0x00, 204)} dB")
        print(f"7GHz: {get_byte(optic_pages, 0x00, 205)} dB")
        print(f"12.9GHz: {get_byte(optic_pages, 0x00, 206)} dB")
        print(f"25.8GHz: {get_byte(optic_pages, 0x00, 207)} dB")
    except Exception as e:
        print(f"Error reading copper attenuation: {str(e)}")

def read_cmis_media_lane_info():
    """Read CMIS media lane information (CMIS 5.0)"""
    try:
        # Use the same fallback logic as other functions
        lane_info_lower = get_byte(optic_pages, 0x00, 210) if get_byte(optic_pages, 0x00, 210) is not None else 0
        lane_info_upper = get_byte(optic_pages, 0x80, 210) if get_byte(optic_pages, 0x80, 210) is not None else 0
        
        # Use the non-zero value, preferring Lower Page
        if lane_info_lower != 0:
            lane_info = lane_info_lower
            source = "Lower Page"
        elif lane_info_upper != 0:
            lane_info = lane_info_upper
            source = "Upper Page 00h"
        else:
            lane_info = 0
            source = "Not specified"
        
        print(f"\nMedia Lane Support [{source}]:")
        for lane in range(8):
            print(f"Lane {lane + 1}: {'Supported' if lane_info & (1 << lane) else 'Not Supported'}")
    except Exception as e:
        print(f"Error reading media lane info: {str(e)}")

def get_cmis_supported_lanes():
    """Return a list of supported lane indices (0-based) according to the Media Lane Support bitmap."""
    lane_info_lower = get_byte(optic_pages, 0x00, 210) if get_byte(optic_pages, 0x00, 210) is not None else 0
    lane_info_upper = get_byte(optic_pages, 0x80, 210) if get_byte(optic_pages, 0x80, 210) is not None else 0
    if lane_info_lower != 0:
        lane_info = lane_info_lower
    elif lane_info_upper != 0:
        lane_info = lane_info_upper
    else:
        lane_info = 0
    return [lane for lane in range(8) if lane_info & (1 << lane)]

def read_cmis_monitoring_data():
    """Read CMIS monitoring data for QSFP-DD modules"""
    try:
        # Read module temperature (bytes 14-15)
        temp = (get_byte(optic_pages, 0x00, 14) << 8) | get_byte(optic_pages, 0x00, 15)
        temp = temp / 256.0  # Convert to Celsius
        print(f"Module Temperature: {temp:.1f}°C")

        # Read module voltage (bytes 16-17)
        voltage = (get_byte(optic_pages, 0x00, 16) << 8) | get_byte(optic_pages, 0x00, 17)
        voltage = voltage / 10000.0  # Convert to V
        print(f"Module Voltage: {voltage:.3f}V")

        # Read module power consumption (bytes 18-19)
        power = (get_byte(optic_pages, 0x00, 18) << 8) | get_byte(optic_pages, 0x00, 19)
        power = power / 10000.0  # Convert to W
        print(f"Module Power: {power:.3f}W")

        # Only print for supported lanes
        supported_lanes = get_cmis_supported_lanes()
        if not supported_lanes:
            print("No supported lanes found for monitoring data.")
            return
        # Read lane-specific data (bytes 20-31)
        for lane in supported_lanes:
            # Read RX power (bytes 20+2*lane, 21+2*lane)
            rx_power = (get_byte(optic_pages, 0x00, 20+2*lane) << 8) | get_byte(optic_pages, 0x00, 21+2*lane)
            rx_power = rx_power / 10000.0  # Convert to mW
            if rx_power > 0:
                print(f"Lane {lane+1} RX Power: {rx_power:.3f}mW")

            # Read TX power (bytes 36+2*lane, 37+2*lane)
            tx_power = (get_byte(optic_pages, 0x00, 36+2*lane) << 8) | get_byte(optic_pages, 0x00, 37+2*lane)
            tx_power = tx_power / 10000.0  # Convert to mW
            if tx_power > 0:
                print(f"Lane {lane+1} TX Power: {tx_power:.3f}mW")

            # Read bias current (bytes 52+2*lane, 53+2*lane)
            bias = (get_byte(optic_pages, 0x00, 52+2*lane) << 8) | get_byte(optic_pages, 0x00, 53+2*lane)
            bias = bias / 500.0  # Convert to mA
            if bias > 0:
                print(f"Lane {lane+1} Bias Current: {bias:.2f}mA")

    except Exception as e:
        print(f"Error reading CMIS monitoring data: {e}")

def read_cmis_thresholds():
    """Read CMIS threshold values for QSFP-DD modules"""
    try:
        # Read temperature thresholds (bytes 128-131)
        temp_high_alarm = (get_byte(optic_pages, 0x00, 128) << 8) | get_byte(optic_pages, 0x00, 129)
        temp_high_alarm = temp_high_alarm / 256.0  # Convert to Celsius
        temp_low_alarm = (get_byte(optic_pages, 0x00, 130) << 8) | get_byte(optic_pages, 0x00, 131)
        temp_low_alarm = temp_low_alarm / 256.0
        print(f"Temperature Thresholds - High Alarm: {temp_high_alarm:.1f}°C, Low Alarm: {temp_low_alarm:.1f}°C")

        # Read voltage thresholds (bytes 132-135)
        voltage_high_alarm = (get_byte(optic_pages, 0x00, 132) << 8) | get_byte(optic_pages, 0x00, 133)
        voltage_high_alarm = voltage_high_alarm / 10000.0  # Convert to V
        voltage_low_alarm = (get_byte(optic_pages, 0x00, 134) << 8) | get_byte(optic_pages, 0x00, 135)
        voltage_low_alarm = voltage_low_alarm / 10000.0
        print(f"Voltage Thresholds - High Alarm: {voltage_high_alarm:.3f}V, Low Alarm: {voltage_low_alarm:.3f}V")

        # Read power thresholds (bytes 136-139)
        power_high_alarm = (get_byte(optic_pages, 0x00, 136) << 8) | get_byte(optic_pages, 0x00, 137)
        power_high_alarm = power_high_alarm / 10000.0  # Convert to W
        power_low_alarm = (get_byte(optic_pages, 0x00, 138) << 8) | get_byte(optic_pages, 0x00, 139)
        power_low_alarm = power_low_alarm / 10000.0
        print(f"Power Thresholds - High Alarm: {power_high_alarm:.3f}W, Low Alarm: {power_low_alarm:.3f}W")

        # Only print for supported lanes
        supported_lanes = get_cmis_supported_lanes()
        if not supported_lanes:
            print("No supported lanes found for threshold data.")
            return
        # Read lane-specific thresholds (bytes 140-191)
        for lane in supported_lanes:
            # RX power thresholds
            rx_power_high_alarm = (get_byte(optic_pages, 0x00, 140+6*lane) << 8) | get_byte(optic_pages, 0x00, 141+6*lane)
            rx_power_high_alarm = rx_power_high_alarm / 10000.0  # Convert to mW
            rx_power_low_alarm = (get_byte(optic_pages, 0x00, 142+6*lane) << 8) | get_byte(optic_pages, 0x00, 143+6*lane)
            rx_power_low_alarm = rx_power_low_alarm / 10000.0
            print(f"Lane {lane+1} RX Power Thresholds - High Alarm: {rx_power_high_alarm:.3f}mW, Low Alarm: {rx_power_low_alarm:.3f}mW")

            # TX power thresholds
            tx_power_high_alarm = (get_byte(optic_pages, 0x00, 144+6*lane) << 8) | get_byte(optic_pages, 0x00, 145+6*lane)
            tx_power_high_alarm = tx_power_high_alarm / 10000.0  # Convert to mW
            tx_power_low_alarm = (get_byte(optic_pages, 0x00, 146+6*lane) << 8) | get_byte(optic_pages, 0x00, 147+6*lane)
            tx_power_low_alarm = tx_power_low_alarm / 10000.0
            print(f"Lane {lane+1} TX Power Thresholds - High Alarm: {tx_power_high_alarm:.3f}mW, Low Alarm: {tx_power_low_alarm:.3f}mW")

    except Exception as e:
        print(f"Error reading CMIS thresholds: {e}")

def read_cmis_application_advertisement():
    """Read and print CMIS Application Advertisement (Tables 8-7, 8-8, 8-9)"""
    try:
        print("\nApplication Advertisement:")
        # Application codes are in Upper Page 0x01, bytes 128-191 (0x180-0x1BF)
        for app in range(8):
            base = 0x180 + app * 8
            code = get_byte(optic_pages, 0x01, base - 0x180)  # Convert to Upper Page 01h offset
            if code == 0:
                continue
            host_lane_count = get_byte(optic_pages, 0x01, base - 0x180 + 1)
            media_lane_count = get_byte(optic_pages, 0x01, base - 0x180 + 2)
            host_lane_assignment = get_byte(optic_pages, 0x01, base - 0x180 + 3)
            media_lane_assignment = get_byte(optic_pages, 0x01, base - 0x180 + 4)
            # Table 8-8: Application Code meanings (partial, expand as needed)
            app_map = {
                0x01: "100GAUI-4 C2M (NRZ)",
                0x02: "100GAUI-4 C2M (PAM4)",
                0x03: "200GAUI-8 C2M (NRZ)",
                0x04: "200GAUI-8 C2M (PAM4)",
                0x05: "400GAUI-8 C2M (PAM4)",
                0x06: "400GAUI-4 C2M (PAM4)",
                0x07: "50GAUI-2 C2M (PAM4)",
                0x08: "50GAUI-1 C2M (PAM4)",
                0x09: "25GAUI-1 C2M (NRZ)",
                0x0A: "10GAUI-1 C2M (NRZ)",
                0x0B: "25GAUI-1 C2M (PAM4)",
                0x0C: "50GAUI-2 C2M (NRZ)",
                0x0D: "100GAUI-2 C2M (PAM4)",
                0x0E: "200GAUI-4 C2M (PAM4)",
                0x0F: "400GAUI-8 C2M (PAM4)",
                # ... add more as needed ...
            }
            print(f"  App {app}: Code 0x{code:02x} ({app_map.get(code, 'Unknown')}) | Host Lanes: {host_lane_count} | Media Lanes: {media_lane_count} | Host Lane Assignment: 0x{host_lane_assignment:02x} | Media Lane Assignment: 0x{media_lane_assignment:02x}")
    except Exception as e:
        print(f"Error reading application advertisement: {e}")

def read_cmis_module_state():
    """Read and print CMIS Module State (Table 8-5)"""
    try:
        state = get_byte(optic_pages, 0x00, 3) & 0x0F
        state_map = {
            0x00: "ModuleLowPwr",
            0x01: "ModulePwrUp",
            0x02: "ModuleReady",
            0x03: "ModulePwrDn",
            0x04: "ModuleFault",
            0x05: "ModuleTxOff",
            0x06: "ModuleTxTuning",
            0x07: "ModuleRxTuning",
            0x08: "ModuleLoopback",
            0x09: "ModuleTest",
            0x0A: "ModuleFaultPwrDn",
            0x0B: "ModuleTxFault",
            0x0C: "ModuleRxFault",
            0x0D: "ModuleTxRxFault",
            0x0E: "ModuleTxRxFaultPwrDn",
            0x0F: "ModuleFaultPwrDn"
        }
        print(f"Module State: {state_map.get(state, f'Unknown({state:02x})')}")
    except Exception as e:
        print(f"Error reading module state: {e}")

def read_cmis_global_status():
    """Read and print CMIS Global Status/Interrupts (Table 8-4)"""
    try:
        status = get_byte(optic_pages, 0x00, 2)
        print("Global Status/Interrupts:")
        print(f"  Module State Changed: {'Yes' if status & 0x80 else 'No'}")
        print(f"  Module Interrupt: {'Yes' if status & 0x40 else 'No'}")
        print(f"  Data Path State Changed: {'Yes' if status & 0x20 else 'No'}")
        print(f"  Data Path Interrupt: {'Yes' if status & 0x10 else 'No'}")
        print(f"  Module Fault: {'Yes' if status & 0x08 else 'No'}")
        print(f"  Module Warning: {'Yes' if status & 0x04 else 'No'}")
        print(f"  Reserved: {status & 0x03:02b}")
    except Exception as e:
        print(f"Error reading global status: {e}")

def read_cmis_advanced_monitoring():
    """Read advanced CMIS monitoring data including OSNR, CD, BER, etc."""
    try:
        print("\nAdvanced CMIS Monitoring:")
        
        # Get media lane support information
        # Try both Lower Page and Upper Page 00h for lane info
        lane_info_lower = get_byte(optic_pages, 0x00, 210) if get_byte(optic_pages, 0x00, 210) is not None else 0
        lane_info_upper = get_byte(optic_pages, 0x80, 210) if get_byte(optic_pages, 0x80, 210) is not None else 0
        
        # Use the non-zero value, preferring Lower Page
        if lane_info_lower != 0:
            lane_info = lane_info_lower
        elif lane_info_upper != 0:
            lane_info = lane_info_upper
        else:
            lane_info = 0
        
        supported_lanes = []
        for lane in range(8):
            if lane_info & (1 << lane):
                supported_lanes.append(lane)
        
        if not supported_lanes:
            print("No supported lanes found, skipping advanced monitoring")
            return
        
        # Check if advanced monitoring is supported
        # This would typically be indicated in the module capabilities
        # For now, we'll try to read the data and see what's available
        
        # OSNR monitoring (if supported)
        # OSNR is typically only available in coherent modules (400G ZR, etc.)
        # Check if this is a coherent module based on Media Interface Technology
        media_tech = get_byte(optic_pages, 0x80, 0x87) if get_byte(optic_pages, 0x80, 0x87) is not None else 0  # Upper Page 00h byte 135
        coherent_techs = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27]  # Coherent technologies
        
        # --- OSNR ---
        osnr_pages = []
        if media_tech in coherent_techs:
            if get_byte(optic_pages, 0x20, 0) is not None:
                osnr_pages.append((0x20, "Upper Page 20h"))
            if get_byte(optic_pages, 0x1280, 0) is not None:
                osnr_pages.append((0x1280, "Upper Page 25h"))
        if osnr_pages:
            for page, label in osnr_pages:
                print(f"\nOSNR Data ({label}):")
                for lane in supported_lanes:
                    osnr_offset = lane * 4
                    osnr_raw = (get_byte(optic_pages, page, osnr_offset) << 8) | get_byte(optic_pages, page, osnr_offset + 1)
                    if osnr_raw > 0:
                        osnr_db = osnr_raw / 100.0  # Convert to dB
                        print(f"Lane {lane+1} OSNR: {osnr_db:.2f} dB")
        else:
            print("\nOSNR Data: Not supported (non-coherent module or no OSNR page present)")

        # --- Chromatic Dispersion ---
        cd_pages = []
        if media_tech in coherent_techs:
            if get_byte(optic_pages, 0x20, 0x40) is not None:
                cd_pages.append((0x20, "Upper Page 20h"))
            if get_byte(optic_pages, 0x1280, 0x40) is not None:
                cd_pages.append((0x1280, "Upper Page 25h"))
        if cd_pages:
            for page, label in cd_pages:
                print(f"\nChromatic Dispersion Data ({label}):")
                for lane in supported_lanes:
                    cd_offset = 0x40 + lane * 4
                    cd_bytes = get_bytes(optic_pages, page, cd_offset, cd_offset + 4)
                    if cd_bytes:
                        cd_raw = struct.unpack_from('>i', bytes(cd_bytes))[0]
                        if cd_raw != 0:
                            cd_ps_nm = cd_raw / 1000.0  # Convert to ps/nm
                            print(f"Lane {lane+1} CD: {cd_ps_nm:.3f} ps/nm")
        else:
            print("\nChromatic Dispersion Data: Not supported (non-coherent module or no CD page present)")

        # --- BER ---
        ber_pages = []
        if media_tech in coherent_techs:
            if get_byte(optic_pages, 0x20, 0x80) is not None:
                ber_pages.append((0x20, "Upper Page 20h"))
            if get_byte(optic_pages, 0x1280, 0x80) is not None:
                ber_pages.append((0x1280, "Upper Page 25h"))
        if ber_pages:
            for page, label in ber_pages:
                print(f"\nBER Data ({label}):")
                for lane in supported_lanes:
                    ber_offset = 0x80 + lane * 8
                    pre_fec_bytes = get_bytes(optic_pages, page, ber_offset, ber_offset + 8)
                    if pre_fec_bytes:
                        pre_fec_ber_raw = struct.unpack_from('>Q', bytes(pre_fec_bytes))[0]
                        if pre_fec_ber_raw > 0:
                            pre_fec_ber = pre_fec_ber_raw / 1e15
                            print(f"Lane {lane+1} Pre-FEC BER: {pre_fec_ber:.2e}")
                    post_fec_offset = ber_offset + 8
                    post_fec_bytes = get_bytes(optic_pages, page, post_fec_offset, post_fec_offset + 8)
                    if post_fec_bytes:
                        post_fec_ber_raw = struct.unpack_from('>Q', bytes(post_fec_bytes))[0]
                        if post_fec_ber_raw > 0:
                            post_fec_ber = post_fec_ber_raw / 1e15
                            print(f"Lane {lane+1} Post-FEC BER: {post_fec_ber:.2e}")
        else:
            print("\nBER Data: Not supported (non-coherent module or no BER page present)")

        # --- Q-Factor ---
        q_pages = []
        if media_tech in coherent_techs:
            if get_byte(optic_pages, 0x20, 0x100) is not None:
                q_pages.append((0x20, "Upper Page 20h"))
            if get_byte(optic_pages, 0x1280, 0x100) is not None:
                q_pages.append((0x1280, "Upper Page 25h"))
        if q_pages:
            for page, label in q_pages:
                print(f"\nQ-Factor Data ({label}):")
                for lane in supported_lanes:
                    q_offset = 0x100 + lane * 2
                    q_raw = (get_byte(optic_pages, page, q_offset) << 8) | get_byte(optic_pages, page, q_offset + 1)
                    if q_raw > 0:
                        q_factor = q_raw / 100.0  # Convert to dB
                        print(f"Lane {lane+1} Q-Factor: {q_factor:.2f} dB")
        else:
            print("\nQ-Factor Data: Not supported (non-coherent module or no Q-Factor page present)")
        
        # Laser wavelength (for tunable modules)
        # According to CMIS 5.0, wavelength info is in Upper Page 01h at specific offsets
        # For tunable modules, this is typically in the Media Interface Technology section
        if get_byte(optic_pages, 0x01, 0) is not None:
            print("\nLaser Wavelength Data (if supported):")
            for lane in supported_lanes:
                # Try different wavelength locations based on CMIS specification
                # Primary wavelength location for tunable modules
                wavelength_offset = 0x88 + lane * 2  # Upper Page 01h, byte 136+ (0x188+)
                wavelength_raw = (get_byte(optic_pages, 0x01, wavelength_offset) << 8) | get_byte(optic_pages, 0x01, wavelength_offset + 1)
                if wavelength_raw > 0:
                    wavelength_nm = wavelength_raw * 0.05  # Convert to nm (CMIS spec)
                    print(f"Lane {lane+1} Wavelength: {wavelength_nm:.2f} nm")
                
                # Alternative wavelength location for coherent modules
                alt_wavelength_offset = 0x90 + lane * 4  # Upper Page 01h, byte 144+ (0x190+)
                alt_wavelength_bytes = get_bytes(optic_pages, 0x01, alt_wavelength_offset, alt_wavelength_offset + 4)
                if alt_wavelength_bytes:
                    alt_wavelength_raw = struct.unpack_from('>I', bytes(alt_wavelength_bytes))[0]
                    if alt_wavelength_raw > 0 and alt_wavelength_raw != wavelength_raw:
                        alt_wavelength_nm = alt_wavelength_raw / 1000.0  # Convert to nm
                        print(f"Lane {lane+1} Alt Wavelength: {alt_wavelength_nm:.3f} nm")
        
        # Laser temperature (for wavelength stability)
        if get_byte(optic_pages, 0x01, 0x60) is not None:
            print("\nLaser Temperature Data (if supported):")
            for lane in supported_lanes:
                laser_temp_offset = 0x60 + lane * 2
                laser_temp_bytes = get_bytes(optic_pages, 0x01, laser_temp_offset, laser_temp_offset + 2)
                if laser_temp_bytes:
                    laser_temp_raw = struct.unpack_from('>h', bytes(laser_temp_bytes))[0]
                    if laser_temp_raw != 0:
                        laser_temp_c = laser_temp_raw / 256.0  # Convert to Celsius
                        print(f"Lane {lane+1} Laser Temperature: {laser_temp_c:.2f}°C")
        
        # Check for data in higher pages (10h, 11h, 12h, 13h, 25h)
        # These pages contain advanced monitoring data for coherent modules
        if get_byte(optic_pages, 0x10, 0) is not None:
            print("\nAdvanced Monitoring Data from Higher Pages:")
            # Check for data in Upper Page 10h (0x400-0x4FF)
            for lane in supported_lanes:
                # Look for coherent monitoring data
                coherent_offset = lane * 16
                coherent_bytes = get_bytes(optic_pages, 0x10, coherent_offset, coherent_offset + 16)
                if coherent_bytes:
                    # Check for non-zero data
                    data_sum = sum(coherent_bytes)
                    if data_sum > 0:
                        print(f"Lane {lane+1} has coherent monitoring data at offset 0x{coherent_offset:04x}")
            
            # Check for data in Upper Page 11h (0x480-0x4FF)
            for lane in supported_lanes:
                coherent_offset = lane * 16
                coherent_bytes = get_bytes(optic_pages, 0x11, coherent_offset, coherent_offset + 16)
                if coherent_bytes:
                    data_sum = sum(coherent_bytes)
                    if data_sum > 0:
                        print(f"Lane {lane+1} has additional monitoring data at offset 0x{coherent_offset:04x}")
            
            # Check for data in Upper Page 25h (0x1280-0x12FF) - this is where coherent data often is
            if get_byte(optic_pages, 0x25, 0) is not None:
                print("\nCoherent Module Data (Upper Page 25h):")
                for lane in supported_lanes:
                    coherent_offset = lane * 32
                    coherent_bytes = get_bytes(optic_pages, 0x25, coherent_offset, coherent_offset + 32)
                    if coherent_bytes:
                        data_sum = sum(coherent_bytes)
                        if data_sum > 0:
                            print(f"Lane {lane+1} has coherent data at offset 0x{coherent_offset:04x}")
                            # Try to decode some coherent-specific fields
                            # EVM (Error Vector Magnitude)
                            evm_raw = (coherent_bytes[0] << 8) | coherent_bytes[1]
                            if evm_raw > 0:
                                evm_percent = evm_raw / 100.0
                                print(f"  EVM: {evm_percent:.2f}%")
                            
                            # MER (Modulation Error Ratio)
                            mer_raw = (coherent_bytes[2] << 8) | coherent_bytes[3]
                            if mer_raw > 0:
                                mer_db = mer_raw / 100.0
                                print(f"  MER: {mer_db:.2f} dB")
                            
                            # Carrier frequency offset
                            freq_offset_raw = struct.unpack_from('>i', bytes(coherent_bytes[4:8]))[0]
                            if freq_offset_raw != 0:
                                freq_offset_mhz = freq_offset_raw / 1000.0
                                print(f"  Frequency Offset: {freq_offset_mhz:.3f} MHz")
        
        # Advanced lane status
        print("\nAdvanced Lane Status:")
        for lane in supported_lanes:
            lane_status_offset = 0x10 + lane
            status = get_byte(optic_pages, 0x00, lane_status_offset)
            if status is not None:
                print(f"\nLane {lane+1} Advanced Status:")
                print(f"  Data Path State: {'Enabled' if status & 0x80 else 'Disabled'}")
                print(f"  TX Fault: {'Yes' if status & 0x40 else 'No'}")
                print(f"  TX LOS: {'Yes' if status & 0x20 else 'No'}")
                print(f"  TX CDR Lock: {'Locked' if status & 0x10 else 'Unlocked'}")
                print(f"  RX LOS: {'Yes' if status & 0x08 else 'No'}")
                print(f"  RX CDR Lock: {'Locked' if status & 0x04 else 'Unlocked'}")
                print(f"  Signal Detect: {'Yes' if status & 0x02 else 'No'}")
                print(f"  Configuration Valid: {'Yes' if status & 0x01 else 'No'}")
                
                # Additional advanced status bits (if available)
                adv_status = get_byte(optic_pages, 0x00, 0x20 + lane)
                if adv_status is not None:
                    print(f"  Adaptive EQ: {'Enabled' if adv_status & 0x80 else 'Disabled'}")
                    print(f"  TX Adaptive EQ: {'Enabled' if adv_status & 0x40 else 'Disabled'}")
                    print(f"  RX Adaptive EQ: {'Enabled' if adv_status & 0x20 else 'Disabled'}")
                    print(f"  TX Tuning: {'In Progress' if adv_status & 0x10 else 'Complete'}")
                    print(f"  RX Tuning: {'In Progress' if adv_status & 0x08 else 'Complete'}")
                    print(f"  TX Power Control: {'Enabled' if adv_status & 0x04 else 'Disabled'}")
                    print(f"  RX Power Control: {'Enabled' if adv_status & 0x02 else 'Disabled'}")
                    print(f"  Module Ready: {'Yes' if adv_status & 0x01 else 'No'}")
        
    except Exception as e:
        print(f"Error reading advanced CMIS monitoring: {e}")

def read_cmis_performance_monitoring():
    """Read CMIS performance monitoring data including error counts and statistics"""
    try:
        print("\nPerformance Monitoring:")
        
        # Error counters
        if get_byte(optic_pages, 0x10, 0) is not None:
            print("\nError Counters:")
            for lane in range(8):
                error_offset = lane * 16
                error_bytes = get_bytes(optic_pages, 0x10, error_offset, error_offset + 16)
                if error_bytes:
                    # FEC corrected errors
                    fec_corrected = struct.unpack_from('>Q', bytes(error_bytes[0:8]))[0]
                    # FEC uncorrected errors
                    fec_uncorrected = struct.unpack_from('>Q', bytes(error_bytes[8:16]))[0]
                    
                    if fec_corrected > 0 or fec_uncorrected > 0:
                        print(f"Lane {lane+1}:")
                        print(f"  FEC Corrected Errors: {fec_corrected}")
                        print(f"  FEC Uncorrected Errors: {fec_uncorrected}")
        
        # Performance statistics
        if get_byte(optic_pages, 0x10, 0x100) is not None:
            print("\nPerformance Statistics:")
            for lane in range(8):
                stats_offset = 0x100 + lane * 12
                stats_bytes = get_bytes(optic_pages, 0x10, stats_offset, stats_offset + 12)
                if stats_bytes:
                    # Average power
                    avg_power = struct.unpack_from('>H', bytes(stats_bytes[0:2]))[0] / 10000.0
                    # Peak power
                    peak_power = struct.unpack_from('>H', bytes(stats_bytes[2:4]))[0] / 10000.0
                    # Min power
                    min_power = struct.unpack_from('>H', bytes(stats_bytes[4:6]))[0] / 10000.0
                    
                    if avg_power > 0 or peak_power > 0 or min_power > 0:
                        print(f"Lane {lane+1} Power Statistics:")
                        print(f"  Average: {avg_power:.3f} mW")
                        print(f"  Peak: {peak_power:.3f} mW")
                        print(f"  Minimum: {min_power:.3f} mW")
                    
                    # Timing statistics
                    timing_bytes = stats_bytes[6:12]
                    if timing_bytes:
                        # Jitter
                        jitter = struct.unpack_from('>H', bytes(timing_bytes[0:2]))[0] / 1000.0
                        # Skew
                        skew = struct.unpack_from('>H', bytes(timing_bytes[2:4]))[0] / 1000.0
                        # Wander
                        wander = struct.unpack_from('>H', bytes(timing_bytes[4:6]))[0] / 1000.0
                        
                        if jitter > 0 or skew > 0 or wander > 0:
                            print(f"Lane {lane+1} Timing Statistics:")
                            print(f"  Jitter: {jitter:.3f} ps")
                            print(f"  Skew: {skew:.3f} ps")
                            print(f"  Wander: {wander:.3f} ps")
        
    except Exception as e:
        print(f"Error reading performance monitoring: {e}")

def read_cmis_coherent_monitoring():
    """Read CMIS coherent-specific monitoring data"""
    try:
        print("\nCoherent Monitoring (if supported):")
        
        # Check if coherent monitoring is available
        # This would typically be indicated in module capabilities
        if get_byte(optic_pages, 0x10, 0x200) is not None:
            print("\nCoherent Performance Data:")
            
            # Constellation diagram data
            for lane in range(8):
                const_offset = 0x200 + lane * 32
                const_bytes = get_bytes(optic_pages, 0x10, const_offset, const_offset + 32)
                if const_bytes:
                    # EVM (Error Vector Magnitude)
                    evm_raw = struct.unpack_from('>H', bytes(const_bytes[0:2]))[0]
                    if evm_raw > 0:
                        evm_percent = evm_raw / 100.0
                        print(f"Lane {lane+1} EVM: {evm_percent:.2f}%")
                    
                    # MER (Modulation Error Ratio)
                    mer_raw = struct.unpack_from('>H', bytes(const_bytes[2:4]))[0]
                    if mer_raw > 0:
                        mer_db = mer_raw / 100.0
                        print(f"Lane {lane+1} MER: {mer_db:.2f} dB")
                    
                    # Carrier frequency offset
                    freq_offset_raw = struct.unpack_from('>i', bytes(const_bytes[4:8]))[0]
                    if freq_offset_raw != 0:
                        freq_offset_mhz = freq_offset_raw / 1000.0
                        print(f"Lane {lane+1} Frequency Offset: {freq_offset_mhz:.3f} MHz")
                    
                    # Phase noise
                    phase_noise_raw = struct.unpack_from('>H', bytes(const_bytes[8:10]))[0]
                    if phase_noise_raw > 0:
                        phase_noise_db = phase_noise_raw / 100.0
                        print(f"Lane {lane+1} Phase Noise: {phase_noise_db:.2f} dBc/Hz")
            
            # Polarization monitoring
            if get_byte(optic_pages, 0x10, 0x400) is not None:
                print("\nPolarization Data:")
                for lane in range(8):
                    pol_offset = 0x400 + lane * 16
                    pol_bytes = get_bytes(optic_pages, 0x10, pol_offset, pol_offset + 16)
                    if pol_bytes:
                        # SOP (State of Polarization) rate
                        sop_rate = struct.unpack_from('>H', bytes(pol_bytes[0:2]))[0] / 1000.0
                        # PDL (Polarization Dependent Loss)
                        pdl = struct.unpack_from('>H', bytes(pol_bytes[2:4]))[0] / 100.0
                        # PMD (Polarization Mode Dispersion)
                        pmd = struct.unpack_from('>H', bytes(pol_bytes[4:6]))[0] / 1000.0
                        
                        if sop_rate > 0 or pdl > 0 or pmd > 0:
                            print(f"Lane {lane+1} Polarization:")
                            print(f"  SOP Rate: {sop_rate:.3f} rad/s")
                            print(f"  PDL: {pdl:.2f} dB")
                            print(f"  PMD: {pmd:.3f} ps")
        
    except Exception as e:
        print(f"Error reading coherent monitoring: {e}")

def get_byte(page_dict, page, offset):
    return page_dict.get(page, [0]*256)[offset]

def get_bytes(page_dict, page, start, end):
    """Get a range of bytes from a specific page."""
    if page not in page_dict:
        return bytes([0] * (end - start))
    
    page_data = page_dict[page]
    result = []
    for i in range(start, end):
        if i < len(page_data):
            result.append(page_data[i])
        else:
            result.append(0)
    return bytes(result)

## main

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Read and decode optic module data')
    parser.add_argument('-f', '--file', help='Parse optic data from file instead of hardware')
    parser.add_argument('--no-hardware', action='store_true', help='Disable hardware access (for testing)')
    args = parser.parse_args()
    
    # If file is specified, parse it and disable hardware
    if args.file:
        print(f"Parsing optic data from file: {args.file}")
        if not parse_optic_file(args.file):
            sys.exit(1)
        real_hardware = False
        print("File parsing complete, processing data...")
        process_optic_data(0, 0, 0, 0, 0)
    else:
        # Original hardware polling behavior
        while True:
            if real_hardware and not args.no_hardware:
                # poll the busses
                poll_busses()
                # fetch power supply data
                fetch_psu_data(0)
            else:
                process_optic_data(0, 0, 0, 0, 0)
            if real_hardware and not args.no_hardware:
                time.sleep(2)
            else:
                break
