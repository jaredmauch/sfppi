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

# Import specification-specific modules
try:
    import oif_cmis
    import sff_8472
    import sff_8636
    SPEC_MODULES_AVAILABLE = True
except ImportError as e:
    SPEC_MODULES_AVAILABLE = False
    print(f"Warning: Specification modules not available ({e}), using legacy functions")

# globals
address_one = 0x50 # A0
address_two = 0x51 # A2 DDM and SFF-8690 Tunable support

# Global page dictionaries
optic_pages = {}
optic_ddm_pages = {}
optic_dwdm_pages = {}
optic_sff_read = 0
optic_ddm_read = 0
optic_dwdm_read = 0

tmp102_address = 0x48
#tmp102_address = 0x4e

# lower page
#optic_lower_page = bytearray.fromhex("18400407000000000000000000002fb8811f000000003486000020000000000000000000000100030400000000000000000000000000000000000000000000000000000000000000000000000000000000000000030402111e840111438401ff00000000000000000000000000000000000000000000000000000000000000001118434947202020202020202020202020000b405452443554483230454e462d4c4630303030315332324a423035525220202020202020323230393236202020202020202020202020a0300007000000000000f00006000000000000000000d6000000000000000000000000000000000000000000000000000000000000000000")

# page 0
#optic_sff = bytearray.fromhex("18400407000000000000000000002fb8811f0000000034860000200000000000000000000001000304000000000000000000000000000000000000000000000000000000000000000000000000000000000000030402111e840111438401ff000000000000000000000000000000000000000000000000000000000000000011030402004a000000000065a4051424f017c2460000009c1a00fa773b03070613075d3d77ff00003822000000000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000099")

#optic_sff_read = len(optic_sff)

upper_page = { }
#upper_page{1} = bytearray.fromhex("030402004a000000000065a4051424f017c2460000009c1a00fa773b03070613075d3d77ff00003822000000000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000099")

#upper_page{2}=bytearray.fromhex("4b00fb00460000008dcc7404875a7a76000000000000000000000000000000003f8029803c802c8000000000000000009f220a847e6714fac35030d4afc8445c9f2202777e6704eb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007c")

#upper_page{0x10}=bytearray.fromhex("00000000000000000000000000000000001010101010101010ff000000000000ffff2222222200000000333333330000000000002121212121212121ff000000000000ffff2222222200000000333333330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

#upper_page{0x11}=bytearray.fromhex("44444444000000000000000000000000000000000000000000005552564c549b561b00000000000000007417687461a861a80000000000000000481a4bbf432546810000000000000000111111111010101010101010ff000000000000ffff222222220000000033333333000000000011213141000000001121314100000000")

# page 1
#optic_ddm = bytearray.fromhex("5000f6004b00fb0088b8785087f07918d6d82710c3503a986e181ba7621f1f070c5a002809d000320000000000000000000000000000000000000000000000000000000003f8000000000000001000000010000000100000001000000000000b116a980d700000000000000000000000005400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

#optic_sff_read = len(optic_sff)
#optic_ddm_read = len(optic_ddm)

optic_dwdm = []
optic_dwdm_read = -1

def get_byte(page_dict, page, offset):
    """Get a single byte from a specific page."""
    if page not in page_dict:
        return None
    page_data = page_dict[page]
    if offset < len(page_data):
        return page_data[offset]
    return None

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
        'Upper Page 02h': 0x200,
        'Upper Page 03h': 0x300,
        'Upper Page 04h': 0x400,
        'Upper Page 10h': 0x1000,
        'Upper Page 11h': 0x1100,
        'Upper Page 12h': 0x1200,
        'Upper Page 13h': 0x1300,
        'Upper Page 25h': 0x2500,
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
        # Parse hex dump lines in formatted output (QSFP-DD format)
        if line.startswith('0x') and current_device and 'Addr' not in line and '----' not in line:
            parts = line.split()
            if len(parts) >= 17:
                try:
                    base_addr = int(parts[0], 16)
                    for i in range(1, 17):
                        if i < len(parts):
                            val = int(parts[i], 16)
                            # Map to offset within the page
                            addr = base_addr - current_page + (i - 1)
                            if 0 <= addr < 256:
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
                    # Map to offset within the page
                    addr = base_addr - current_page + i
                    if 0 <= addr < 256:
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

def validate_optic_type(optic_type):
    """Validate optic type against SFF-8024 specification and return detailed information"""
    optic_type_info = {
        0x00: {"name": "Unknown or unspecified", "spec": "SFF-8024", "status": "supported"},
        0x01: {"name": "GBIC", "spec": "SFF-8053", "status": "supported"},
        0x02: {"name": "Module/connector soldered to motherboard", "spec": "SFF-8472", "status": "supported"},
        0x03: {"name": "SFP/SFP+/SFP28", "spec": "SFF-8472", "status": "supported"},
        0x04: {"name": "300 pin XBI", "spec": "Legacy", "status": "supported"},
        0x05: {"name": "XENPAK", "spec": "Legacy", "status": "supported"},
        0x06: {"name": "XFP", "spec": "INF-8077", "status": "supported"},
        0x07: {"name": "XFF", "spec": "Legacy", "status": "supported"},
        0x08: {"name": "XFP-E", "spec": "Legacy", "status": "supported"},
        0x09: {"name": "XPAK", "spec": "Legacy", "status": "supported"},
        0x0A: {"name": "X2", "spec": "Legacy", "status": "supported"},
        0x0B: {"name": "DWDM-SFP/SFP+", "spec": "Legacy", "status": "supported"},
        0x0C: {"name": "QSFP", "spec": "INF-8438", "status": "supported"},
        0x0D: {"name": "QSFP+", "spec": "SFF-8636", "status": "supported"},
        0x0E: {"name": "CXP", "spec": "SFF-8643", "status": "supported"},
        0x0F: {"name": "Shielded Mini Multilane HD 4X", "spec": "Legacy", "status": "supported"},
        0x10: {"name": "Shielded Mini Multilane HD 8X", "spec": "Legacy", "status": "supported"},
        0x11: {"name": "QSFP28", "spec": "SFF-8636", "status": "supported"},
        0x12: {"name": "CXP2 (CXP28)", "spec": "SFF-8643", "status": "supported"},
        0x13: {"name": "CDFP (Style 1/Style2)", "spec": "INF-TA-1003", "status": "supported"},
        0x14: {"name": "Shielded Mini Multilane HD 4X Fanout Cable", "spec": "Legacy", "status": "supported"},
        0x15: {"name": "Shielded Mini Multilane HD 8X Fanout Cable", "spec": "Legacy", "status": "supported"},
        0x16: {"name": "CDFP (Style 3)", "spec": "INF-TA-1003", "status": "supported"},
        0x17: {"name": "microQSFP", "spec": "Legacy", "status": "supported"},
        0x18: {"name": "QSFP-DD", "spec": "SFF-8663", "status": "supported"},
        0x19: {"name": "OSFP", "spec": "OSFP MSA", "status": "supported"},
        0x1A: {"name": "SFP-DD", "spec": "SFP-DD MSA", "status": "supported"},
        0x1B: {"name": "DSFP", "spec": "DSFP MSA", "status": "supported"},
        0x1C: {"name": "x4 MiniLink/OcuLink", "spec": "Legacy", "status": "supported"},
        0x1D: {"name": "x8 MiniLink", "spec": "Legacy", "status": "supported"},
        0x1E: {"name": "QSFP+ with CMIS", "spec": "OIF-CMIS", "status": "supported"},
        0x1F: {"name": "SFP-DD with CMIS", "spec": "OIF-CMIS", "status": "supported"},
        0x20: {"name": "SFP+ with CMIS", "spec": "OIF-CMIS", "status": "supported"},
        0x21: {"name": "OSFP-XD with CMIS", "spec": "OIF-CMIS", "status": "supported"},
        0x22: {"name": "OIF-ELSFP with CMIS", "spec": "OIF-CMIS", "status": "supported"},
        0x23: {"name": "CDFP (x4 PCIe) with CMIS", "spec": "OIF-CMIS", "status": "supported"},
        0x24: {"name": "CDFP (x8 PCIe) with CMIS", "spec": "OIF-CMIS", "status": "supported"},
        0x25: {"name": "CDFP (x16 PCIe) with CMIS", "spec": "OIF-CMIS", "status": "supported"}
    }
    
    if optic_type in optic_type_info:
        info = optic_type_info[optic_type]
        return {
            "valid": True,
            "name": info["name"],
            "spec": info["spec"],
            "status": info["status"],
            "type": optic_type
        }
    elif 0x26 <= optic_type <= 0x7F:
        return {
            "valid": False,
            "name": "Reserved",
            "spec": "SFF-8024",
            "status": "reserved",
            "type": optic_type
        }
    elif 0x80 <= optic_type <= 0xFF:
        return {
            "valid": True,
            "name": "Vendor Specific",
            "spec": "Vendor Defined",
            "status": "vendor_specific",
            "type": optic_type
        }
    else:
        return {
            "valid": False,
            "name": "Invalid",
            "spec": "Unknown",
            "status": "invalid",
            "type": optic_type
        }

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
        sff_type_text = "OSFP 8X Pluggable Transceiver"
    elif optic_type == 0x1a:
        sff_type_text = "SFP-DD Double Density 2X Pluggable Transceiver"
    elif optic_type == 0x1b:
        sff_type_text = "DSFP Dual Small Form Factor Pluggable Transceiver"
    elif optic_type == 0x1c:
        sff_type_text = "x4 MiniLink/OcuLink"
    elif optic_type == 0x1d:
        sff_type_text = "x8 MiniLink"
    elif optic_type == 0x1e:
        sff_type_text = "QSFP+ or later with Common Management Interface Specification (CMIS)"
    elif optic_type == 0x1f:
        sff_type_text = "SFP-DD Double Density 2X Pluggable Transceiver with Common Management Interface Specification (CMIS)"
    elif optic_type == 0x20:
        sff_type_text = "SFP+ and later with Common Management Interface Specification (CMIS)"
    elif optic_type == 0x21:
        sff_type_text = "OSFP-XD with Common Management interface Specification (CMIS)"
    elif optic_type == 0x22:
        sff_type_text = "OIF-ELSFP with Common Management interface Specification (CMIS)"
    elif optic_type == 0x23:
        sff_type_text = "CDFP (x4 PCIe) SFF-TA-1032 with Common Management interface Specification (CMIS)"
    elif optic_type == 0x24:
        sff_type_text = "CDFP (x8 PCIe) SFF-TA-1032 with Common Management interface Specification (CMIS)"
    elif optic_type == 0x25:
        sff_type_text = "CDFP (x16 PCIe) SFF-TA-1032 with Common Management interface Specification (CMIS)"
    elif optic_type >= 0x80:
        sff_type_text = "Vendor Specific"
    else:
        sff_type_text = "Not yet specified value (%d) check SFF-8024" % optic_type
    print("SFF Type:", sff_type_text)

    return optic_type


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
    """Read QSFP-DD vendor information according to OIF-CMIS 5.3 Table 8-28"""
    try:
        # Vendor name is in bytes 129-144 (16 bytes) according to Table 8-28
        vendor_bytes = get_bytes(optic_pages, 0x00, 129, 144)
        if vendor_bytes:
            vendor_name = vendor_bytes.decode('ascii', errors='ignore').rstrip()
            if vendor_name and not vendor_name.isspace():
                print(f"Vendor: {vendor_name}")
                return vendor_name
        return None
    except Exception as e:
        print(f"Error reading vendor name: {e}")
        return None

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
    # For CMIS modules, part number is in Upper Page 00h (0x80), bytes 0x10-0x1F (16 bytes)
    vendor_pn = get_bytes(optic_pages, 0x80, 0x10, 0x20).decode('ascii', errors='ignore').strip()
    print("Vendor PN:", vendor_pn)

def read_qsfpdd_vendor_rev():
    """Read QSFP-DD vendor revision according to OIF-CMIS 5.3 Table 8-28"""
    try:
        # Vendor revision is in bytes 164-165 (2 bytes) according to Table 8-28
        vendor_rev_bytes = get_bytes(optic_pages, 0x00, 164, 165)
        if vendor_rev_bytes:
            vendor_rev = vendor_rev_bytes.decode('ascii', errors='ignore').rstrip()
            if vendor_rev and not vendor_rev.isspace():
                print(f"Vendor Rev: {vendor_rev}")
                return vendor_rev
        return None
    except Exception as e:
        print(f"Error reading vendor revision: {e}")
        return None

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

# Helper function to check if a page is empty
def is_page_empty(page_id):
    page = optic_pages.get(page_id)
    if not page:
        return True
    return all(b == 0 for b in page)

# Add comprehensive SFP parsing functions according to INF-8074_1.0 specification

def read_sfp_identifier():
    """Read SFP Identifier according to INF-8074_1.0 Table 3.2"""
    try:
        identifier = get_byte(optic_pages, 0x00, 0)
        if identifier is not None:
            print(f"SFP Identifier: 0x{identifier:02x}")
            if identifier == 0x00:
                print("  Description: Unknown or unspecified")
            elif identifier == 0x01:
                print("  Description: GBIC")
            elif identifier == 0x02:
                print("  Description: Module/connector soldered to motherboard")
            elif identifier == 0x03:
                print("  Description: SFP transceiver")
            elif 0x04 <= identifier <= 0x7F:
                print("  Description: Reserved")
            elif 0x80 <= identifier <= 0xFF:
                print("  Description: Vendor specific")
        else:
            print("SFP Identifier: Not available")
    except Exception as e:
        print(f"Error reading SFP Identifier: {e}")

def read_sfp_extended_identifier():
    """Read SFP Extended Identifier according to INF-8074_1.0"""
    try:
        ext_id = get_byte(optic_pages, 0x00, 1)
        if ext_id is not None:
            print(f"SFP Extended Identifier: 0x{ext_id:02x}")
            if ext_id == 0x04:
                print("  Description: Serial ID module definition")
            else:
                print("  Description: Other value")
        else:
            print("SFP Extended Identifier: Not available")
    except Exception as e:
        print(f"Error reading SFP Extended Identifier: {e}")

def read_sfp_connector():
    """Read SFP Connector according to INF-8074_1.0 Table 3.3"""
    try:
        connector = get_byte(optic_pages, 0x00, 2)
        if connector is not None:
            print(f"SFP Connector: 0x{connector:02x}")
            connector_names = {
                0x00: "Unknown or unspecified",
                0x01: "SC",
                0x02: "Fibre Channel Style 1 copper connector",
                0x03: "Fibre Channel Style 2 copper connector",
                0x04: "BNC/TNC",
                0x05: "Fibre Channel coaxial headers",
                0x06: "FiberJack",
                0x07: "LC",
                0x08: "MT-RJ",
                0x09: "MU",
                0x0A: "SG",
                0x0B: "Optical pigtail",
                0x20: "HSSDC II",
                0x21: "Copper Pigtail"
            }
            if connector in connector_names:
                print(f"  Description: {connector_names[connector]}")
            elif 0x0C <= connector <= 0x1F:
                print("  Description: Reserved")
            elif 0x22 <= connector <= 0x7F:
                print("  Description: Reserved")
            elif 0x80 <= connector <= 0xFF:
                print("  Description: Vendor specific")
        else:
            print("SFP Connector: Not available")
    except Exception as e:
        print(f"Error reading SFP Connector: {e}")

def read_sfp_transceiver_codes():
    """Read SFP Transceiver codes according to INF-8074_1.0 Table 3.4"""
    try:
        print("\n--- SFP Transceiver Codes ---")
        
        # Read bytes 3-10 (8 bytes total)
        transceiver_bytes = get_bytes(optic_pages, 0x00, 3, 11)
        if transceiver_bytes:
            print(f"Transceiver Codes: {transceiver_bytes}")
            
            # Parse each byte according to the specification
            for i, byte_val in enumerate(transceiver_bytes):
                if byte_val != 0:  # Only show non-zero bytes
                    print(f"  Byte {3+i}: 0x{byte_val:02x}")
                    
                    # Parse specific bits based on the specification
                    if i == 4:  # SONET Compliance Codes
                        if byte_val & 0x04:
                            print("    - OC 48, long reach")
                        if byte_val & 0x02:
                            print("    - OC 48, intermediate reach")
                        if byte_val & 0x01:
                            print("    - OC 48 short reach")
                    
                    elif i == 5:  # SONET Compliance Codes (continued)
                        if byte_val & 0x40:
                            print("    - OC 12, single mode long reach")
                        if byte_val & 0x20:
                            print("    - OC 12, single mode inter. reach")
                        if byte_val & 0x10:
                            print("    - OC 12 multi-mode short reach")
                        if byte_val & 0x04:
                            print("    - OC 3, single mode long reach")
                        if byte_val & 0x02:
                            print("    - OC 3, single mode inter. reach")
                        if byte_val & 0x01:
                            print("    - OC 3, multi-mode short reach")
                    
                    elif i == 6:  # Gigabit Ethernet Compliance Codes
                        if byte_val & 0x08:
                            print("    - 1000BASE-T")
                        if byte_val & 0x04:
                            print("    - 1000BASE-CX")
                        if byte_val & 0x02:
                            print("    - 1000BASE-LX")
                        if byte_val & 0x01:
                            print("    - 1000BASE-SX")
                    
                    elif i == 7:  # Fibre Channel codes
                        if byte_val & 0x80:
                            print("    - Very long distance (V)")
                        if byte_val & 0x40:
                            print("    - Short distance (S)")
                        if byte_val & 0x20:
                            print("    - Intermediate distance (I)")
                        if byte_val & 0x10:
                            print("    - Long distance (L)")
                        if byte_val & 0x08:
                            print("    - Longwave laser (LC)")
                        if byte_val & 0x01:
                            print("    - Electrical inter-enclosure (EL)")
                    
                    elif i == 8:  # Fibre Channel transmitter technology
                        if byte_val & 0x80:
                            print("    - Electrical intra-enclosure (EL)")
                        if byte_val & 0x40:
                            print("    - Shortwave laser w/o OFC (SN)")
                        if byte_val & 0x20:
                            print("    - Shortwave laser w/ OFC (SL)")
                        if byte_val & 0x10:
                            print("    - Longwave laser (LL)")
                    
                    elif i == 9:  # Fibre Channel transmission media
                        if byte_val & 0x80:
                            print("    - Twin Axial Pair (TW)")
                        if byte_val & 0x40:
                            print("    - Shielded Twisted Pair (TP)")
                        if byte_val & 0x20:
                            print("    - Miniature Coax (MI)")
                        if byte_val & 0x10:
                            print("    - Video Coax (TV)")
                        if byte_val & 0x08:
                            print("    - Multi-mode, 62.5m (M6)")
                        if byte_val & 0x04:
                            print("    - Multi-mode, 50 m (M5)")
                        if byte_val & 0x01:
                            print("    - Single Mode (SM)")
        else:
            print("SFP Transceiver Codes: Not available")
    except Exception as e:
        print(f"Error reading SFP Transceiver Codes: {e}")

def read_sfp_encoding():
    """Read SFP Encoding according to INF-8074_1.0 Table 3.5"""
    try:
        encoding = get_byte(optic_pages, 0x00, 11)
        if encoding is not None:
            print(f"SFP Encoding: 0x{encoding:02x}")
            encoding_names = {
                0x00: "Unspecified",
                0x01: "8B10B",
                0x02: "4B5B",
                0x03: "NRZ",
                0x04: "Manchester"
            }
            if encoding in encoding_names:
                print(f"  Description: {encoding_names[encoding]}")
            elif 0x05 <= encoding <= 0xFF:
                print("  Description: Reserved")
        else:
            print("SFP Encoding: Not available")
    except Exception as e:
        print(f"Error reading SFP Encoding: {e}")

def read_sfp_bit_rate():
    """Read SFP Bit Rate according to INF-8074_1.0"""
    try:
        br_nominal = get_byte(optic_pages, 0x00, 12)
        if br_nominal is not None:
            print(f"SFP Nominal Bit Rate: {br_nominal} (units of 100 MBits/sec)")
            if br_nominal > 0:
                actual_rate = br_nominal * 100
                print(f"  Actual Rate: {actual_rate} MBits/sec")
            else:
                print("  Description: Bit rate not specified")
        else:
            print("SFP Nominal Bit Rate: Not available")
    except Exception as e:
        print(f"Error reading SFP Bit Rate: {e}")

def read_sfp_lengths():
    """Read SFP Length fields according to INF-8074_1.0"""
    try:
        print("\n--- SFP Length Information ---")
        
        # Length (9m) - km
        length_9m_km = get_byte(optic_pages, 0x00, 14)
        if length_9m_km is not None:
            print(f"Length (9m) - km: {length_9m_km}")
            if length_9m_km == 0:
                print("  Description: Does not support single mode fiber")
            elif length_9m_km == 255:
                print("  Description: Supports link length > 254 km")
            else:
                print(f"  Description: Supports {length_9m_km} km on single mode fiber")
        
        # Length (9m)
        length_9m = get_byte(optic_pages, 0x00, 15)
        if length_9m is not None:
            print(f"Length (9m): {length_9m}")
            if length_9m == 0:
                print("  Description: Does not support single mode fiber")
            elif length_9m == 255:
                print("  Description: Supports link length > 25.4 km")
            else:
                print(f"  Description: Supports {length_9m * 100} m on single mode fiber")
        
        # Length (50m)
        length_50m = get_byte(optic_pages, 0x00, 16)
        if length_50m is not None:
            print(f"Length (50m): {length_50m}")
            if length_50m == 0:
                print("  Description: Does not support 50 micron multi-mode fiber")
            elif length_50m == 255:
                print("  Description: Supports link length > 2.54 km")
            else:
                print(f"  Description: Supports {length_50m * 10} m on 50 micron multi-mode fiber")
        
        # Length (62.5m)
        length_62_5m = get_byte(optic_pages, 0x00, 17)
        if length_62_5m is not None:
            print(f"Length (62.5m): {length_62_5m}")
            if length_62_5m == 0:
                print("  Description: Does not support 62.5 micron multi-mode fiber")
            elif length_62_5m == 255:
                print("  Description: Supports link length > 2.54 km")
            else:
                print(f"  Description: Supports {length_62_5m * 10} m on 62.5 micron multi-mode fiber")
        
        # Length (Copper)
        length_copper = get_byte(optic_pages, 0x00, 18)
        if length_copper is not None:
            print(f"Length (Copper): {length_copper}")
            if length_copper == 0:
                print("  Description: Does not support copper cables")
            elif length_copper == 255:
                print("  Description: Supports link length > 254 meters")
            else:
                print(f"  Description: Supports {length_copper} m on copper cable")
        
    except Exception as e:
        print(f"Error reading SFP Lengths: {e}")

def read_sfp_vendor_info():
    """Read SFP Vendor information according to INF-8074_1.0"""
    try:
        print("\n--- SFP Vendor Information ---")
        
        # Vendor name (bytes 20-35, 16 bytes)
        vendor_name = get_bytes(optic_pages, 0x00, 20, 36).decode('ascii', errors='ignore').strip()
        print(f"Vendor Name: {vendor_name}")
        
        # Vendor OUI (bytes 37-39, 3 bytes)
        vendor_oui = get_bytes(optic_pages, 0x00, 37, 40)
        if vendor_oui and any(b != 0 for b in vendor_oui):
            oui_str = ''.join([f"{b:02x}" for b in vendor_oui])
            print(f"Vendor OUI: {oui_str}")
        else:
            print("Vendor OUI: Unspecified")
        
        # Vendor Part Number (bytes 40-55, 16 bytes)
        vendor_pn = get_bytes(optic_pages, 0x00, 40, 56).decode('ascii', errors='ignore').strip()
        print(f"Vendor Part Number: {vendor_pn}")
        
        # Vendor Revision (bytes 56-59, 4 bytes)
        vendor_rev = get_bytes(optic_pages, 0x00, 56, 60).decode('ascii', errors='ignore').strip()
        print(f"Vendor Revision: {vendor_rev}")
        
    except Exception as e:
        print(f"Error reading SFP Vendor Info: {e}")

def read_sfp_extended_info():
    """Read SFP Extended information according to INF-8074_1.0"""
    try:
        print("\n--- SFP Extended Information ---")
        
        # Options (bytes 64-65, 2 bytes)
        options_bytes = get_bytes(optic_pages, 0x00, 64, 66)
        if options_bytes:
            print(f"Options: {options_bytes}")
            options_byte = options_bytes[1] if len(options_bytes) > 1 else 0
            
            if options_byte & 0x20:
                print("  - RATE_SELECT is implemented")
            if options_byte & 0x10:
                print("  - TX_DISABLE is implemented and disables the serial output")
            if options_byte & 0x08:
                print("  - TX_FAULT signal implemented")
            if options_byte & 0x04:
                print("  - Loss of Signal implemented, signal inverted")
            if options_byte & 0x02:
                print("  - Loss of Signal implemented, signal as defined")
        
        # BR, max (byte 66)
        br_max = get_byte(optic_pages, 0x00, 66)
        if br_max is not None:
            print(f"BR, max: {br_max}% above nominal bit rate")
        
        # BR, min (byte 67)
        br_min = get_byte(optic_pages, 0x00, 67)
        if br_min is not None:
            print(f"BR, min: {br_min}% below nominal bit rate")
        
        # Vendor Serial Number (bytes 68-83, 16 bytes)
        vendor_sn = get_bytes(optic_pages, 0x00, 68, 84).decode('ascii', errors='ignore').strip()
        print(f"Vendor Serial Number: {vendor_sn}")
        
        # Date Code (bytes 84-91, 8 bytes)
        date_code = get_bytes(optic_pages, 0x00, 84, 92).decode('ascii', errors='ignore').strip()
        print(f"Date Code: {date_code}")
        
    except Exception as e:
        print(f"Error reading SFP Extended Info: {e}")

def read_sfp_check_codes():
    """Read SFP Check codes according to INF-8074_1.0"""
    try:
        print("\n--- SFP Check Codes ---")
        
        # CC_BASE (byte 63)
        cc_base = get_byte(optic_pages, 0x00, 63)
        if cc_base is not None:
            print(f"CC_BASE: 0x{cc_base:02x}")
        
        # CC_EXT (byte 95)
        cc_ext = get_byte(optic_pages, 0x00, 95)
        if cc_ext is not None:
            print(f"CC_EXT: 0x{cc_ext:02x}")
        
    except Exception as e:
        print(f"Error reading SFP Check Codes: {e}")

def read_sfp_vendor_specific():
    """Read SFP Vendor specific data according to INF-8074_1.0"""
    try:
        print("\n--- SFP Vendor Specific Data ---")
        
        # Read-only vendor specific data (bytes 96-127, 32 bytes)
        vendor_specific = get_bytes(optic_pages, 0x00, 96, 128)
        if vendor_specific and any(b != 0 for b in vendor_specific):
            print(f"Vendor Specific Data: {vendor_specific}")
            # Try to decode as ASCII if possible
            try:
                ascii_data = vendor_specific.decode('ascii', errors='ignore').strip()
                if ascii_data:
                    print(f"  ASCII: {ascii_data}")
            except:
                pass
        else:
            print("Vendor Specific Data: Not available or all zeros")
        
    except Exception as e:
        print(f"Error reading SFP Vendor Specific Data: {e}")

# Comprehensive SFP parsing function
def read_sfp_comprehensive():
    """Read all SFP data according to INF-8074_1.0 specification"""
    try:
        print("\n=== SFP Comprehensive Data (INF-8074_1.0) ===")
        
        read_sfp_identifier()
        read_sfp_extended_identifier()
        # Note: read_sfp_connector() removed to avoid duplication with read_optic_connector_type()
        read_sfp_transceiver_codes()
        read_sfp_encoding()
        read_sfp_bit_rate()
        read_sfp_lengths()
        read_sfp_vendor_info()
        read_sfp_extended_info()
        read_sfp_check_codes()
        read_sfp_vendor_specific()
        
    except Exception as e:
        print(f"Error in comprehensive SFP parsing: {e}")

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
    """Read QSFP-DD vendor OUI according to OIF-CMIS 5.3 Table 8-28"""
    try:
        # Vendor OUI is in bytes 145-147 (3 bytes) according to Table 8-28
        oui_bytes = get_bytes(optic_pages, 0x00, 145, 147)
        if oui_bytes and len(oui_bytes) >= 3:
            print(f"Vendor OUI: {oui_bytes[0]:02x}{oui_bytes[1]:02x}{oui_bytes[2]:02x}")
            return oui_bytes
        else:
            print("Vendor OUI: Not available")
            return None
    except Exception as e:
        print(f"Error reading vendor OUI: {e}")
        return None


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

def read_qsfpdd_vendor_partnum():
    """Read QSFP-DD vendor part number according to OIF-CMIS 5.3 Table 8-28"""
    try:
        # Vendor part number is in bytes 148-163 (16 bytes) according to Table 8-28
        vendor_pn_bytes = get_bytes(optic_pages, 0x00, 148, 163)
        if vendor_pn_bytes:
            vendor_pn = vendor_pn_bytes.decode('ascii', errors='ignore').rstrip()
            if vendor_pn and not vendor_pn.isspace():
                print(f"Vendor PN: {vendor_pn}")
                return vendor_pn
        return None
    except Exception as e:
        print(f"Error reading vendor part number: {e}")
        return None


def read_sff8472_vendor_partnum():
    # SFF-8472
    # 16 bytes ASCII at bytes 40-55
    vendor_partnum = get_bytes(optic_pages, 0x00, 40, 56).decode('ascii', errors='ignore').strip()
    print("PN:", vendor_partnum)

def read_qsfpdd_vendor_sn():
    """Read QSFP-DD vendor serial number according to OIF-CMIS 5.3 Table 8-28"""
    try:
        # Vendor serial number is in bytes 166-181 (16 bytes) according to Table 8-28
        vendor_sn_bytes = get_bytes(optic_pages, 0x00, 166, 181)
        if vendor_sn_bytes:
            vendor_sn = vendor_sn_bytes.decode('ascii', errors='ignore').rstrip()
            if vendor_sn and not vendor_sn.isspace():
                print(f"Vendor SN: {vendor_sn}")
                return vendor_sn
        return None
    except Exception as e:
        print(f"Error reading vendor serial number: {e}")
        return None


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
    """Read QSFP-DD date code according to OIF-CMIS 5.3 Table 8-29"""
    try:
        # Date code is in bytes 182-189 (8 bytes) according to Table 8-29
        date_code_bytes = get_bytes(optic_pages, 0x00, 182, 189)
        if date_code_bytes:
            date_code = date_code_bytes.decode('ascii', errors='ignore').rstrip()
            if date_code and not date_code.isspace():
                print(f"Date Code: {date_code}")
                return date_code
        return None
    except Exception as e:
        print(f"Error reading date code: {e}")
        return None

def read_qsfpdd_clei_code():
    """Read QSFP-DD CLEI code according to OIF-CMIS 5.3 Table 8-30"""
    try:
        # CLEI code is in bytes 190-199 (10 bytes) according to Table 8-30
        clei_code_bytes = get_bytes(optic_pages, 0x00, 190, 199)
        if clei_code_bytes:
            clei_code = clei_code_bytes.decode('ascii', errors='ignore').rstrip()
            if clei_code and not clei_code.isspace():
                print(f"CLEI Code: {clei_code}")
                return clei_code
        return None
    except Exception as e:
        print(f"Error reading CLEI code: {e}")
        return None

def read_qsfpdd_mod_power():
    """Read QSFP-DD module power according to OIF-CMIS 5.3 Table 8-31"""
    try:
        # Power class is in byte 200 bits 7-5, max power is in byte 201 according to Table 8-31
        power_class_byte = get_byte(optic_pages, 0x00, 200)
        max_power_byte = get_byte(optic_pages, 0x00, 201)
        
        if power_class_byte is not None:
            power_class = (power_class_byte >> 5) & 0x07
            print(f"Module Power Class: {power_class}")
        else:
            power_class = None
            print("Module Power Class: Not available")
            
        if max_power_byte is not None:
            max_power = max_power_byte * 0.25  # Units of 0.25W
            print(f"Module Max Power: {max_power:.2f} W")
        else:
            max_power = None
            print("Module Max Power: Not available")
            
        return power_class, max_power
    except Exception as e:
        print(f"Error reading module power: {e}")
        return None, None

def read_qsfpdd_cable_len():
    """Read QSFP-DD cable length according to OIF-CMIS 5.3 Table 8-32"""
    try:
        # Cable assembly link length is in byte 202 according to Table 8-32
        length_byte = get_byte(optic_pages, 0x00, 202)
        if length_byte is not None:
            length_multiplier = (length_byte >> 6) & 0x03
            base_length = length_byte & 0x1F
            
            multiplier_map = {
                0: 0.1,
                1: 1.0,
                2: 10.0,
                3: 100.0
            }
            
            if length_multiplier in multiplier_map:
                actual_length = base_length * multiplier_map[length_multiplier]
                print(f"Cable Length: {actual_length} m (multiplier: {multiplier_map[length_multiplier]}, base: {base_length})")
                return actual_length
            else:
                print(f"Cable Length: Invalid multiplier {length_multiplier}")
                return None
        else:
            print("Cable Length: Not available")
            return None
    except Exception as e:
        print(f"Error reading cable length: {e}")
        return None

def read_qsfpdd_connector_type():
    """Read QSFP-DD connector type according to OIF-CMIS 5.3 Table 8-33"""
    try:
        # Connector type is in byte 203 according to Table 8-33
        connector_type = get_byte(optic_pages, 0x00, 203)
        if connector_type is not None:
            print(f"Connector Type: 0x{connector_type:02x}")
            read_optic_connector_type(connector_type)
            return connector_type
        else:
            print("Connector Type: Not available")
            return None
    except Exception as e:
        print(f"Error reading connector type: {e}")
        return None

def read_qsfpdd_copper_attenuation():
    """Read QSFP-DD copper attenuation according to OIF-CMIS 5.3 Table 8-34"""
    try:
        # Copper cable attenuation is in bytes 204-209 according to Table 8-34
        attenuation = get_bytes(optic_pages, 0x00, 204, 209)
        if attenuation and len(attenuation) >= 6:
            att_5ghz = attenuation[0]
            att_7ghz = attenuation[1]
            att_12_9ghz = attenuation[2]
            att_25_8ghz = attenuation[3]
            att_53_1ghz = attenuation[4]
            
            print(f"Copper Attenuation at 5GHz: {att_5ghz} dB")
            print(f"Copper Attenuation at 7GHz: {att_7ghz} dB")
            print(f"Copper Attenuation at 12.9GHz: {att_12_9ghz} dB")
            print(f"Copper Attenuation at 25.8GHz: {att_25_8ghz} dB")
            print(f"Copper Attenuation at 53.125GHz: {att_53_1ghz} dB")
            
            return {
                '5GHz': att_5ghz,
                '7GHz': att_7ghz,
                '12.9GHz': att_12_9ghz,
                '25.8GHz': att_25_8ghz,
                '53.125GHz': att_53_1ghz
            }
        else:
            print("Copper Attenuation: Not available")
            return None
    except Exception as e:
        print(f"Error reading copper attenuation: {e}")
        return None

def read_qsfpdd_media_lane_info():
    """Read QSFP-DD media lane information according to OIF-CMIS 5.3 Table 8-35"""
    try:
        # Media lane information is in byte 210 according to Table 8-35
        lane_info = get_byte(optic_pages, 0x00, 210)
        if lane_info is not None:
            print(f"Media Lane Info: 0x{lane_info:02x}")
            print("Media Lane Support:")
            supported_lanes = []
            for lane in range(8):
                supported = (lane_info & (1 << lane)) != 0
                status = "Supported" if supported else "Not Supported"
                print(f"  Lane {lane + 1}: {status}")
                if supported:
                    supported_lanes.append(lane)
            return supported_lanes
        else:
            print("Media Lane Info: Not available")
            return []
    except Exception as e:
        print(f"Error reading media lane info: {e}")
        return []


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


def read_extended_compliance_codes():
    """Read extended specification compliance codes (Byte 36) - SFF-8472"""
    # SFF-8472 Table 5-4 Extended Specification Compliance Codes
    # Byte 36 - Extended Specification Compliance Codes
    compliance_byte = get_byte(optic_pages, 0x00, 36)
    
    compliance_codes = []
    
    if compliance_byte & 0x01:
        compliance_codes.append("Fibre Channel Link Length (V/S/I/L/M)")
    if compliance_byte & 0x02:
        compliance_codes.append("Fibre Channel Technology (SA/LC/EL/SN/SL/LL)")
    if compliance_byte & 0x04:
        compliance_codes.append("SFP+ Cable Technology (Active/Passive)")
    if compliance_byte & 0x08:
        compliance_codes.append("Fibre Channel Transmission Media")
    if compliance_byte & 0x10:
        compliance_codes.append("Fibre Channel Speed")
    if compliance_byte & 0x20:
        compliance_codes.append("Fibre Channel Encoding")
    if compliance_byte & 0x40:
        compliance_codes.append("Fibre Channel Application")
    if compliance_byte & 0x80:
        compliance_codes.append("Fibre Channel Distance")
    
    print("Extended Compliance Codes:", compliance_codes)
    return compliance_codes


def read_rate_identifier():
    """Read rate identifier (Byte 13) - SFF-8472"""
    # SFF-8472 Table 5-1 Rate Identifier
    # Byte 13 - Rate Identifier
    rate_byte = get_byte(optic_pages, 0x00, 13)
    
    rate_codes = []
    
    if rate_byte & 0x01:
        rate_codes.append("SFF-8079")
    if rate_byte & 0x02:
        rate_codes.append("SFF-8431")
    if rate_byte & 0x04:
        rate_codes.append("SFF-8436")
    if rate_byte & 0x08:
        rate_codes.append("SFF-8636")
    if rate_byte & 0x10:
        rate_codes.append("SFF-8679")
    if rate_byte & 0x20:
        rate_codes.append("SFF-8690")
    if rate_byte & 0x40:
        rate_codes.append("SFF-8024")
    if rate_byte & 0x80:
        rate_codes.append("SFF-8024 Extended")
    
    print("Rate Identifier:", rate_codes)
    return rate_codes


def read_application_select():
    """Read application select codes - SFF-8472"""
    # SFF-8472 Application Select
    # Multiple application support for different operating rates
    # This is typically vendor-specific and may be in vendor-specific area
    
    # Check if application select is supported in extended area
    # Byte 92 - Diagnostic Monitoring Type
    monitoring_type = get_byte(optic_pages, 0x00, 92)
    
    if monitoring_type & 0x01:  # Enhanced monitoring supported
        # Application select may be in upper pages
        # This is typically vendor-specific implementation
        result = "Enhanced monitoring supported - application select vendor-specific"
    else:
        result = "Standard monitoring - no application select"
    
    print("Application Select:", result)
    return result


def read_fibre_channel_link_length():
    """Read Fibre Channel Link Length specifications - SFF-8472"""
    # SFF-8472 Fibre Channel Link Length
    # V/S/I/L/M specifications
    # This information is typically in the extended compliance codes
    
    # Check extended compliance byte 36
    compliance_byte = get_byte(optic_pages, 0x00, 36)
    
    if compliance_byte & 0x01:  # Fibre Channel Link Length supported
        # Additional bytes may contain specific length information
        # This is typically vendor-specific
        result = "Fibre Channel Link Length supported (V/S/I/L/M)"
    else:
        result = "Fibre Channel Link Length not specified"
    
    print("Fibre Channel Link Length:", result)
    return result


def read_fibre_channel_technology():
    """Read Fibre Channel Technology specifications - SFF-8472"""
    # SFF-8472 Fibre Channel Technology
    # SA/LC/EL/SN/SL/LL laser types
    # This information is typically in the extended compliance codes
    
    # Check extended compliance byte 36
    compliance_byte = get_byte(optic_pages, 0x00, 36)
    
    if compliance_byte & 0x02:  # Fibre Channel Technology supported
        # Additional bytes may contain specific technology information
        # This is typically vendor-specific
        result = "Fibre Channel Technology supported (SA/LC/EL/SN/SL/LL)"
    else:
        result = "Fibre Channel Technology not specified"
    
    print("Fibre Channel Technology:", result)
    return result


def read_sfp_cable_technology():
    """Read SFP+ Cable Technology specifications - SFF-8472"""
    # SFF-8472 SFP+ Cable Technology
    # Active/Passive cable indicators
    # This information is typically in the extended compliance codes
    
    # Check extended compliance byte 36
    compliance_byte = get_byte(optic_pages, 0x00, 36)
    
    if compliance_byte & 0x04:  # SFP+ Cable Technology supported
        # Additional bytes may contain specific cable technology information
        # This is typically vendor-specific
        result = "SFP+ Cable Technology supported (Active/Passive)"
    else:
        result = "SFP+ Cable Technology not specified"
    
    print("SFP+ Cable Technology:", result)
    return result


def read_fibre_channel_transmission_media():
    """Read Fibre Channel Transmission Media specifications - SFF-8472"""
    # SFF-8472 Fibre Channel Transmission Media
    # Media type specifications
    # This information is typically in the extended compliance codes
    
    # Check extended compliance byte 36
    compliance_byte = get_byte(optic_pages, 0x00, 36)
    
    if compliance_byte & 0x08:  # Fibre Channel Transmission Media supported
        # Additional bytes may contain specific media information
        # This is typically vendor-specific
        result = "Fibre Channel Transmission Media supported"
    else:
        result = "Fibre Channel Transmission Media not specified"
    
    print("Fibre Channel Transmission Media:", result)
    return result


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
    """
    Decode DWDM data according to SFF-8690 specification.
    Implements Tables 5-3 through 5-8 for tunable SFP+ modules.
    """
    print("\n=== DWDM Tunable Module Data (SFF-8690) ===")
    
    # Table 5-3: Features Advertisement for Tunability (Byte 128)
    byte_128 = get_byte(optic_pages, 0x00, 128)
    print("\n--- Feature Advertisement (Byte 128) ---")
    
    if (byte_128 & 0x10):  # Bit 4
        print("\tVendor defined tunability supported")
    if (byte_128 & 0x08):  # Bit 3
        print("\tSelf Tuning via Smart Tunable MSA Supported")
    if (byte_128 & 0x04):  # Bit 2
        print("\tTx Dither Supported")
    if (byte_128 & 0x02):  # Bit 1
        print("\tTunable DWDM selection by channel number")
    if (byte_128 & 0x01):  # Bit 0
        print("\tTunable DWDM selection by 50pm steps")
    
    # Table 5-4: Module Capabilities (Bytes 132-141)
    print("\n--- Module Capabilities (Bytes 132-141) ---")
    
    laser_first_freq_thz = (get_byte(optic_pages, 0x00, 132) * 256) + get_byte(optic_pages, 0x00, 133)
    print("\tLaser First Frequency: %d THz" % laser_first_freq_thz)
    
    laser_first_freq_ghz = (get_byte(optic_pages, 0x00, 134) * 256) + get_byte(optic_pages, 0x00, 135)
    print("\tLaser First Frequency: %.1f GHz (units of 0.1 GHz)" % (laser_first_freq_ghz / 10.0))
    
    laser_last_freq_thz = (get_byte(optic_pages, 0x00, 136) * 256) + get_byte(optic_pages, 0x00, 137)
    print("\tLaser Last Frequency: %d THz" % laser_last_freq_thz)
    
    laser_last_freq_ghz = (get_byte(optic_pages, 0x00, 138) * 256) + get_byte(optic_pages, 0x00, 139)
    print("\tLaser Last Frequency: %.1f GHz (units of 0.1 GHz)" % (laser_last_freq_ghz / 10.0))
    
    laser_min_grid = (get_byte(optic_pages, 0x00, 140) * 256) + get_byte(optic_pages, 0x00, 141)
    # Handle signed value (2's complement)
    if laser_min_grid > 32767:
        laser_min_grid = laser_min_grid - 65536
    print("\tLaser minimum grid spacing: %.1f GHz (units of 0.1 GHz)" % (laser_min_grid / 10.0))
    
    # Table 5-5: Module Capabilities - Control and Status
    print("\n--- Control and Status (Bytes 144-151) ---")
    
    channel_set = (get_byte(optic_pages, 0x00, 144) * 256) + get_byte(optic_pages, 0x00, 145)
    print("\tChannel Number Set: %d" % channel_set)
    
    wavelength_set = (get_byte(optic_pages, 0x00, 146) * 256) + get_byte(optic_pages, 0x00, 147)
    wavelength_nm = wavelength_set * 0.05  # Units of 0.05 nm
    print("\tWavelength Set: %.2f nm (units of 0.05 nm)" % wavelength_nm)
    
    # Byte 151 Control Bits
    byte_151 = get_byte(optic_pages, 0x00, 151)
    print("\n--- Control Register (Byte 151) ---")
    
    if (byte_151 & 0x04):  # Bit 2
        print("\tSelf Tuning Restart on LOS Timer: Disabled")
    else:
        print("\tSelf Tuning Restart on LOS Timer: Enabled")
    
    if (byte_151 & 0x02):  # Bit 1
        print("\tSelf Tuning: Enabled")
    else:
        print("\tSelf Tuning: Disabled")
    
    if (byte_151 & 0x01):  # Bit 0
        print("\tTx Dither: Disabled")
    else:
        print("\tTx Dither: Enabled")
    
    # Table 5-6: Frequency and Wavelength Errors (Bytes 152-155)
    print("\n--- Error Reporting (Bytes 152-155) ---")
    
    freq_error_raw = (get_byte(optic_pages, 0x00, 152) * 256) + get_byte(optic_pages, 0x00, 153)
    # Handle signed value (2's complement)
    if freq_error_raw > 32767:
        freq_error_raw = freq_error_raw - 65536
    freq_error_ghz = freq_error_raw * 0.1  # Units of 0.1 GHz
    print("\tFrequency Error: %.1f GHz (units of 0.1 GHz)" % freq_error_ghz)
    
    wavelength_error_raw = (get_byte(optic_pages, 0x00, 154) * 256) + get_byte(optic_pages, 0x00, 155)
    # Handle signed value (2's complement)
    if wavelength_error_raw > 32767:
        wavelength_error_raw = wavelength_error_raw - 65536
    wavelength_error_nm = wavelength_error_raw * 0.005  # Units of 0.005 nm
    print("\tWavelength Error: %.3f nm (units of 0.005 nm)" % wavelength_error_nm)
    
    # Table 5-7: Current Status (Byte 168)
    print("\n--- Current Status (Byte 168) ---")
    
    byte_168 = get_byte(optic_pages, 0x00, 168)
    
    if (byte_168 & 0x80):  # Bit 7
        print("\tSelf Tuning: In Progress")
    else:
        print("\tSelf Tuning: Idle or Locked")
    
    if (byte_168 & 0x40):  # Bit 6
        print("\tTEC (Temperature Control) Fault")
    
    if (byte_168 & 0x20):  # Bit 5
        print("\tWavelength Unlocked")
    
    if (byte_168 & 0x10):  # Bit 4
        print("\tTxTune - Transmit not ready due to tuning")
    
    # Table 5-8: Latched Status (Byte 172)
    print("\n--- Latched Status (Byte 172) ---")
    
    byte_172 = get_byte(optic_pages, 0x00, 172)
    
    if (byte_172 & 0x80):  # Bit 7
        print("\tL-Self Tune: Self tuning in progress or completed")
    
    if (byte_172 & 0x40):  # Bit 6
        print("\tL-TEC Fault: Latched TEC Fault")
    
    if (byte_172 & 0x20):  # Bit 5
        print("\tL-Wavelength-Unlocked: Latched Wavelength Unlocked Condition")
    
    if (byte_172 & 0x10):  # Bit 4
        print("\tL-Bad Channel: Latched Bad Channel Requested")
    
    if (byte_172 & 0x08):  # Bit 3
        print("\tL-New Channel: Latched New Channel Acquired")
    
    if (byte_172 & 0x04):  # Bit 2
        print("\tL-Unsupported TX Dither: Latched Unsupported TX Dither Request")


def write_dwdm_control(bus, channel_number=None, wavelength_nm=None, enable_self_tuning=False, 
                      disable_self_tuning_restart=False, disable_tx_dither=False):
    """
    Write DWDM control values according to SFF-8690 specification.
    
    Args:
        bus: I2C bus object
        channel_number: Channel number to set (bytes 144-145)
        wavelength_nm: Wavelength in nm to set (bytes 146-147, units of 0.05 nm)
        enable_self_tuning: Enable self-tuning (byte 151 bit 1)
        disable_self_tuning_restart: Disable self-tuning restart on LOS timer (byte 151 bit 2)
        disable_tx_dither: Disable TX dither (byte 151 bit 0)
    """
    try:
        # Write channel number (bytes 144-145)
        if channel_number is not None:
            if 1 <= channel_number <= 65535:
                msb = (channel_number >> 8) & 0xFF
                lsb = channel_number & 0xFF
                bus.write_i2c_block_data(0x51, 144, [msb, lsb])
                print(f"Set channel number to: {channel_number}")
            else:
                print(f"Error: Channel number must be between 1 and 65535")
        
        # Write wavelength (bytes 146-147)
        if wavelength_nm is not None:
            if 1525.0 <= wavelength_nm <= 1625.0:  # Typical DWDM range
                wavelength_units = int(wavelength_nm / 0.05)  # Convert to units of 0.05 nm
                msb = (wavelength_units >> 8) & 0xFF
                lsb = wavelength_units & 0xFF
                bus.write_i2c_block_data(0x51, 146, [msb, lsb])
                print(f"Set wavelength to: {wavelength_nm:.2f} nm")
            else:
                print(f"Error: Wavelength must be between 1525.0 and 1625.0 nm")
        
        # Write control register (byte 151)
        control_byte = 0x00
        if disable_self_tuning_restart:
            control_byte |= 0x04  # Bit 2
        if enable_self_tuning:
            control_byte |= 0x02  # Bit 1
        if disable_tx_dither:
            control_byte |= 0x01  # Bit 0
        
        bus.write_i2c_block_data(0x51, 151, [control_byte])
        print(f"Set control register to: 0x{control_byte:02X}")
        
    except Exception as e:
        print(f"Error writing DWDM control values: {e}")


def read_dwdm_status():
    """
    Read current DWDM status and return as structured data.
    Returns a dictionary with current status information.
    """
    status = {}
    
    # Read feature advertisement
    byte_128 = get_byte(optic_pages, 0x00, 128)
    status['features'] = {
        'vendor_defined_tunability': bool(byte_128 & 0x10),
        'self_tuning_supported': bool(byte_128 & 0x08),
        'tx_dither_supported': bool(byte_128 & 0x04),
        'channel_number_selection': bool(byte_128 & 0x02),
        'wavelength_selection': bool(byte_128 & 0x01)
    }
    
    # Read current control state
    byte_151 = get_byte(optic_pages, 0x00, 151)
    status['control'] = {
        'self_tuning_restart_disabled': bool(byte_151 & 0x04),
        'self_tuning_enabled': bool(byte_151 & 0x02),
        'tx_dither_disabled': bool(byte_151 & 0x01)
    }
    
    # Read current status
    byte_168 = get_byte(optic_pages, 0x00, 168)
    status['current_status'] = {
        'self_tuning_in_progress': bool(byte_168 & 0x80),
        'tec_fault': bool(byte_168 & 0x40),
        'wavelength_unlocked': bool(byte_168 & 0x20),
        'txtune_not_ready': bool(byte_168 & 0x10)
    }
    
    # Read latched status
    byte_172 = get_byte(optic_pages, 0x00, 172)
    status['latched_status'] = {
        'self_tune_latched': bool(byte_172 & 0x80),
        'tec_fault_latched': bool(byte_172 & 0x40),
        'wavelength_unlocked_latched': bool(byte_172 & 0x20),
        'bad_channel_latched': bool(byte_172 & 0x10),
        'new_channel_latched': bool(byte_172 & 0x08),
        'unsupported_dither_latched': bool(byte_172 & 0x04)
    }
    
    return status


# read the board type
# 0x00-0f = Board Name
# 0x10-1f = Board Sub-type
# 0x20-2f = Mfg date
# 0x30-3f = Board port types
# 0x40-4f = Board serial number
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
def process_optic_data_unified(page_dict, optic_type):
    """
    Unified optic data processing using specification-specific modules.
    This eliminates duplication and ensures consistency.
    
    Args:
        page_dict: Dictionary containing page data
        optic_type: Type of optic module
    """
    if not SPEC_MODULES_AVAILABLE:
        print("Warning: Specification modules not available, falling back to legacy processing")
        return
    
    print(f"\n=== Processing {optic_type} Module ===")
    
    # Determine optic type and use appropriate parser
    if optic_type in ['QSFP-DD', 'CMIS']:
        try:
            cmis_data = oif_cmis.parse_cmis_data_centralized(page_dict)
            oif_cmis.output_cmis_data_unified(cmis_data)
        except Exception as e:
            print(f"Error processing CMIS data: {e}")
            print("Falling back to legacy processing...")
            return
    
    elif optic_type in ['SFP+', 'SFP']:
        try:
            sff8472_data = sff_8472.parse_sff8472_data_centralized(page_dict)
            sff_8472.output_sff8472_data_unified(sff8472_data)
        except Exception as e:
            print(f"Error processing SFF-8472 data: {e}")
            print("Falling back to legacy processing...")
            return
    
    elif optic_type in ['QSFP+', 'QSFP28']:
        try:
            sff8636_data = sff_8636.parse_sff8636_data_centralized(page_dict)
            sff_8636.output_sff8636_data_unified(sff8636_data)
        except Exception as e:
            print(f"Error processing SFF-8636 data: {e}")
            print("Falling back to legacy processing...")
            return
    
    else:
        print(f"Unknown optic type: {optic_type}")
        print("Falling back to legacy processing...")
        return

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
        
        # Try unified processing first
        if SPEC_MODULES_AVAILABLE:
            try:
                optic_type_name = {
                    0x03: 'SFP+',
                    0x0C: 'QSFP',
                    0x0D: 'QSFP+',
                    0x11: 'QSFP28',
                    0x18: 'QSFP-DD'
                }.get(optic_type, f'Unknown({optic_type})')
                
                process_optic_data_unified(optic_pages, optic_type_name)
                return  # Exit early if unified processing succeeds
            except Exception as e:
                print(f"Unified processing failed: {e}")
                print("Falling back to legacy processing...")
        
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
            
            # Read comprehensive CMIS data using oif_cmis module
            oif_cmis.read_cmis_lower_memory(optic_pages)  # Page 00h (Lower Memory)
            oif_cmis.read_cmis_page_00h(optic_pages)      # Page 00h (Upper Memory)
            oif_cmis.read_cmis_page_01h(optic_pages)      # Page 01h (Module Capabilities)
            oif_cmis.read_cmis_page_02h(optic_pages)      # Page 02h (Monitor Thresholds)
            oif_cmis.read_cmis_wavelength_info(optic_pages)  # Wavelength information from Page 01h
            
            # Read advanced pages if available
            if 0x1000 in optic_pages:
                oif_cmis.read_cmis_page_10h(optic_pages)  # Page 10h (Lane Control)
            if 0x1100 in optic_pages:
                oif_cmis.read_cmis_page_11h(optic_pages)  # Page 11h (Lane Status)
            if 0x400 in optic_pages:
                oif_cmis.read_cmis_page_04h(optic_pages)  # Page 04h (Vendor-specific)
            if 0x1200 in optic_pages:
                oif_cmis.read_cmis_page_12h(optic_pages)  # Page 12h (Tunable Laser)
            if 0x1300 in optic_pages:
                oif_cmis.read_cmis_page_13h(optic_pages)  # Page 13h (Diagnostics)
            if 0x2500 in optic_pages:
                oif_cmis.read_cmis_page_25h(optic_pages)  # Page 25h (Vendor-specific)
            
            # Legacy functions for backward compatibility
            oif_cmis.read_cmis_global_status_detailed(optic_pages)
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
                oif_cmis.read_cmis_copper_attenuation(optic_pages)
            # Suppress copper attenuation message for optical modules
            oif_cmis.read_cmis_media_lane_info(optic_pages)
            read_qsfpdd_media_interface_tech()
            oif_cmis.read_cmis_module_power(optic_pages)
            
            # Read CMIS monitoring data instead of SFF-8472 DDM
            if (optic_sff_read >= 128):
                print("Reading CMIS monitoring data...")
                oif_cmis.read_cmis_monitoring_data(optic_pages)
                print("Reading CMIS thresholds...")
                oif_cmis.read_cmis_thresholds(optic_pages)
                
                # Read advanced monitoring data
                print("Reading advanced CMIS monitoring...")
                oif_cmis.read_cmis_advanced_monitoring(optic_pages)
                oif_cmis.read_cmis_performance_monitoring(optic_pages)
                oif_cmis.read_cmis_coherent_monitoring(optic_pages)
        elif optic_type in [0x0B, 0x0C, 0x0D, 0x11]:  # QSFP/QSFP+/QSFP28
            print("Reading QSFP module data...")
            # Use unified processing for QSFP modules
            try:
                print("Parsing SFF-8636 data...")
                sff8636_data = sff_8636.parse_sff8636_data_centralized(optic_pages)
                print("Outputting unified data...")
                sff_8636.output_sff8636_data_unified(sff8636_data)
            except Exception as e:
                print(f"Error in unified QSFP processing: {e}")
                print("Falling back to individual function calls...")
                # Fallback to individual function calls
                print(sff_8636.read_qsfp_data(optic_pages))
                print(sff_8636.read_qsfp_power_control(optic_pages))
                print(sff_8636.read_qsfp_page_support(optic_pages))
                print(sff_8636.read_qsfp_thresholds(optic_pages))
                print(sff_8636.read_qsfp_extended_status(optic_pages))
                print(sff_8636.read_qsfp_control_status(optic_pages))
                print(sff_8636.read_qsfp_application(optic_pages))
                print(sff_8636.read_qsfp_per_channel_monitoring(optic_pages))
                print(sff_8636.read_qsfp_channel_thresholds(optic_pages))
                print(sff_8636.read_qsfp_advanced_controls(optic_pages))
                print(sff_8636.read_qsfp_enhanced_status(optic_pages))
        elif optic_type == 0x01:  # GBIC
            read_gbic_data()
        elif optic_type in [0x0E, 0x12]:  # CXP/CXP2
            read_cxp_data()
        elif optic_type == 0x19:  # OSFP
            read_osfp_data()
        elif optic_type == 0x1A:  # SFP-DD
            read_sfpdd_data()
        elif optic_type == 0x1B:  # DSFP
            read_dsfp_data()
        elif optic_type in [0x1C, 0x1D]:  # MiniLink/OcuLink
            read_minilink_data()
        elif optic_type == 0x00:  # Unknown or unspecified
            read_unknown_optic_data()
        elif optic_type in [0x04, 0x05, 0x07, 0x08, 0x09, 0x0A, 0x0F, 0x10, 0x13, 0x14, 0x15, 0x16, 0x17]:  # Legacy types
            read_legacy_optic_data()
        else:
            print("Reading standard SFF module data...")
            read_optic_mod_def()
            read_optic_connector_type(get_byte(optic_pages, 0x00, 2))
            read_sff_optic_encoding()
            read_optic_signaling_rate()
            read_optic_rate_identifier()
            read_optic_vendor()
            read_optic_vendor_oui()
            read_sff8472_vendor_partnum()
            read_optic_vendor_serialnum()
            read_optic_rev()
            read_optic_datecode()
            read_optic_transciever()
            read_optic_distances()
            read_optic_frequency()
            
            # Add comprehensive SFP parsing according to INF-8074_1.0
            if optic_type == 0x03:  # SFP transceiver
                read_sfp_comprehensive()

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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Read and decode optic module data')
    parser.add_argument('-f', '--file', help='Parse optic data from file instead of hardware')
    parser.add_argument('--no-hardware', action='store_true', help='Disable hardware access (for testing)')
    args = parser.parse_args()
    
    if args.no_hardware:
        real_hardware = False
    
    if args.file:
        # Parse from file
        if parse_optic_file(args.file):
            process_optic_data(None, 0, 0, 0, "file")
    else:
        # Poll hardware
        poll_busses()

def read_qsfp_channel_thresholds():
    """Read per-channel thresholds for QSFP+ modules using sff_8636.py implementation"""
    try:
        result = sff_8636.read_qsfp_channel_thresholds(optic_pages)
        if result and result.get('thresholds_raw'):
            print("\nChannel Thresholds:")
            thresholds = result['thresholds_raw']
            
            # Parse per-channel thresholds (bytes 16-95)
            for i in range(4):
                if len(thresholds) >= 96 + i*20:
                    base = 16 + i*20
                    # RX Power thresholds
                    rx_high_alarm = struct.unpack_from('>H', bytes(thresholds[base:base+2]))[0] / 10000.0
                    rx_low_alarm = struct.unpack_from('>H', bytes(thresholds[base+2:base+4]))[0] / 10000.0
                    rx_high_warn = struct.unpack_from('>H', bytes(thresholds[base+4:base+6]))[0] / 10000.0
                    rx_low_warn = struct.unpack_from('>H', bytes(thresholds[base+6:base+8]))[0] / 10000.0
                    
                    # TX Bias thresholds
                    tx_bias_high_alarm = struct.unpack_from('>H', bytes(thresholds[base+8:base+10]))[0] / 500.0
                    tx_bias_low_alarm = struct.unpack_from('>H', bytes(thresholds[base+10:base+12]))[0] / 500.0
                    tx_bias_high_warn = struct.unpack_from('>H', bytes(thresholds[base+12:base+14]))[0] / 500.0
                    tx_bias_low_warn = struct.unpack_from('>H', bytes(thresholds[base+14:base+16]))[0] / 500.0
                    
                    print(f"\nChannel {i+1} Thresholds:")
                    print(f"  RX Power (mW):")
                    print(f"    High Alarm: {rx_high_alarm:.3f}")
                    print(f"    Low Alarm:  {rx_low_alarm:.3f}")
                    print(f"    High Warn:  {rx_high_warn:.3f}")
                    print(f"    Low Warn:   {rx_low_warn:.3f}")
                    print(f"  TX Bias (mA):")
                    print(f"    High Alarm: {tx_bias_high_alarm:.2f}")
                    print(f"    Low Alarm:  {tx_bias_low_alarm:.2f}")
                    print(f"    High Warn:  {tx_bias_high_warn:.2f}")
                    print(f"    Low Warn:   {tx_bias_low_warn:.2f}")
    except Exception as e:
        print(f"Error reading QSFP+ channel thresholds: {str(e)}")

def read_qsfp_advanced_controls():
    """Read advanced control functions for QSFP+ modules (SFF-8636)"""
    try:
        print("\n--- QSFP+ Advanced Controls ---")
        
        # CDR (Clock Data Recovery) Controls (Byte 98)
        cdr_control = get_byte(optic_ddm_pages, 0x00, 98)
        if cdr_control is not None:
            print("\nCDR Controls:")
            for lane in range(4):
                lane_mask = 1 << lane
                tx_cdr = "Enabled" if cdr_control & (lane_mask << 4) else "Disabled"
                rx_cdr = "Enabled" if cdr_control & lane_mask else "Disabled"
                print(f"  Lane {lane}: TX CDR: {tx_cdr}, RX CDR: {rx_cdr}")
            
        # Rate Select Controls (Bytes 87-88)
        rate_select_1 = get_byte(optic_ddm_pages, 0x00, 87)
        rate_select_2 = get_byte(optic_ddm_pages, 0x00, 88)
        if rate_select_1 is not None and rate_select_2 is not None:
            print("\nRate Select Controls:")
            for lane in range(4):
                lane_mask = 1 << lane
                rate1 = "High" if rate_select_1 & lane_mask else "Low"
                rate2 = "High" if rate_select_2 & lane_mask else "Low"
                print(f"  Lane {lane}: Rate1: {rate1}, Rate2: {rate2}")
            
        # Power Class Controls (Byte 93)
        power_class = get_byte(optic_ddm_pages, 0x00, 93)
        if power_class is not None:
            print(f"\nPower Class: {power_class}")
            print(f"Power Override: {'Enabled' if power_class & 0x04 else 'Disabled'}")
            print(f"Power Set High: {'Yes' if power_class & 0x02 else 'No'}")
            print(f"Low Power Mode: {'Enabled' if power_class & 0x01 else 'Disabled'}")
        
        # Software Reset (Byte 94)
        sw_reset = get_byte(optic_ddm_pages, 0x00, 94)
        if sw_reset is not None:
            print(f"\nSoftware Reset: {'Active' if sw_reset & 0x01 else 'Inactive'}")
            
    except Exception as e:
        print(f"Error reading advanced controls: {str(e)}")

def read_qsfp_enhanced_status():
    """Read enhanced status indicators for QSFP+ modules (SFF-8636)"""
    try:
        print("\n--- QSFP+ Enhanced Status ---")
        
        # Status Indicators (Byte 6)
        status = get_byte(optic_ddm_pages, 0x00, 6)
        if status is not None:
            print("\nStatus Indicators:")
            print(f"Initialization Complete: {'Yes' if status & 0x80 else 'No'}")
            print(f"TC Readiness: {'Yes' if status & 0x40 else 'No'}")
            print(f"Data Not Ready: {'Yes' if status & 0x20 else 'No'}")
            print(f"Interrupt: {'Yes' if status & 0x10 else 'No'}")
            print(f"Module Fault: {'Yes' if status & 0x08 else 'No'}")
            print(f"Module Ready: {'Yes' if status & 0x04 else 'No'}")
            print(f"TX Fault: {'Yes' if status & 0x02 else 'No'}")
            print(f"RX LOS: {'Yes' if status & 0x01 else 'No'}")
        
        # Extended Identifier Values (Byte 129)
        ext_id = get_byte(optic_ddm_pages, 0x00, 129)
        if ext_id is not None:
            print(f"\nExtended Identifier: 0x{ext_id:02x}")
            print("Extended Features:")
            print(f"  Rate Select: {'Supported' if ext_id & 0x80 else 'Not Supported'}")
            print(f"  Application Select: {'Supported' if ext_id & 0x40 else 'Not Supported'}")
            print(f"  Power Control: {'Supported' if ext_id & 0x20 else 'Not Supported'}")
            print(f"  CDR Control: {'Supported' if ext_id & 0x10 else 'Not Supported'}")
        
        # Device Technology (Byte 147)
        device_tech = get_byte(optic_ddm_pages, 0x00, 147)
        if device_tech is not None:
            print(f"\nDevice Technology: 0x{device_tech:02x}")
            tx_tech = (device_tech >> 4) & 0x0F
            rx_tech = device_tech & 0x0F
            
            tx_technologies = {
                0x00: "Undefined",
                0x01: "850nm VCSEL",
                0x02: "1310nm FP",
                0x03: "1550nm FP",
                0x04: "1310nm DFB",
                0x05: "1550nm DFB",
                0x06: "1310nm EML",
                0x07: "1550nm EML",
                0x08: "1490nm DFB",
                0x09: "Copper",
                0x0A: "1490nm EML",
                0x0B: "Undefined",
                0x0C: "Undefined",
                0x0D: "Undefined",
                0x0E: "Undefined",
                0x0F: "Undefined"
            }
            
            rx_technologies = {
                0x00: "Undefined",
                0x01: "PIN",
                0x02: "APD",
                0x03: "PIN-TIA",
                0x04: "APD-TIA",
                0x05: "PIN-EDFA",
                0x06: "APD-EDFA",
                0x07: "Copper",
                0x08: "Undefined",
                0x09: "Undefined",
                0x0A: "Undefined",
                0x0B: "Undefined",
                0x0C: "Undefined",
                0x0D: "Undefined",
                0x0E: "Undefined",
                0x0F: "Undefined"
            }
            
            print(f"  TX Technology: {tx_technologies.get(tx_tech, f'Unknown (0x{tx_tech:02x})')}")
            print(f"  RX Technology: {rx_technologies.get(rx_tech, f'Unknown (0x{rx_tech:02x})')}")
            
    except Exception as e:
        print(f"Error reading enhanced status: {str(e)}")

def read_vdm_instance_descriptors():
    """Read VDM Instance Descriptors - CMIS VDM support"""
    try:
        print("\n=== VDM Instance Descriptors ===")
        
        # VDM instance descriptors define observable types
        # This is typically in CMIS modules that support VDM
        print("VDM Instance Descriptors: VDM support not yet implemented")
        
    except Exception as e:
        print(f"Error reading VDM Instance Descriptors: {e}")


def read_vdm_real_time_values():
    """Read VDM Real-Time Values - CMIS VDM support"""
    try:
        print("\n=== VDM Real-Time Values ===")
        
        # VDM real-time monitoring data
        # This is typically in CMIS modules that support VDM
        print("VDM Real-Time Values: VDM support not yet implemented")
        
    except Exception as e:
        print(f"Error reading VDM Real-Time Values: {e}")


def read_vdm_thresholds():
    """Read VDM Alarm/Warning Thresholds - CMIS VDM support"""
    try:
        print("\n=== VDM Alarm/Warning Thresholds ===")
        
        # VDM dynamic threshold management
        # This is typically in CMIS modules that support VDM
        print("VDM Thresholds: VDM support not yet implemented")
        
    except Exception as e:
        print(f"Error reading VDM Thresholds: {e}")


def read_vdm_threshold_crossing_flags():
    """Read VDM Threshold Crossing Flags - CMIS VDM support"""
    try:
        print("\n=== VDM Threshold Crossing Flags ===")
        
        # VDM threshold violation indicators
        # This is typically in CMIS modules that support VDM
        print("VDM Threshold Crossing Flags: VDM support not yet implemented")
        
    except Exception as e:
        print(f"Error reading VDM Threshold Crossing Flags: {e}")


def read_vdm_configuration():
    """Read VDM Configuration - CMIS VDM support"""
    try:
        print("\n=== VDM Configuration ===")
        
        # VDM feature configuration
        # This is typically in CMIS modules that support VDM
        print("VDM Configuration: VDM support not yet implemented")
        
    except Exception as e:
        print(f"Error reading VDM Configuration: {e}")


def read_vdm_power_saving_mode():
    """Read VDM Power Saving Mode - CMIS VDM support"""
    try:
        print("\n=== VDM Power Saving Mode ===")
        
        # VDM optional power saving features
        # This is typically in CMIS modules that support VDM
        print("VDM Power Saving Mode: VDM support not yet implemented")
        
    except Exception as e:
        print(f"Error reading VDM Power Saving Mode: {e}")


def read_cdb_message_communication():
    """Read CDB Message Communication - CMIS CDB support"""
    try:
        print("\n=== CDB Message Communication ===")
        
        # CDB command/reply messaging system
        # This is typically in CMIS modules that support CDB
        print("CDB Message Communication: CDB support not yet implemented")
        
    except Exception as e:
        print(f"Error reading CDB Message Communication: {e}")


def read_cdb_firmware_management():
    """Read CDB Firmware Management - CMIS CDB support"""
    try:
        print("\n=== CDB Firmware Management ===")
        
        # CDB firmware download/upload via CDB
        # This is typically in CMIS modules that support CDB
        print("CDB Firmware Management: CDB support not yet implemented")
        
    except Exception as e:
        print(f"Error reading CDB Firmware Management: {e}")


def read_cdb_performance_monitoring():
    """Read CDB Performance Monitoring - CMIS CDB support"""
    try:
        print("\n=== CDB Performance Monitoring ===")
        
        # CDB performance monitoring using CDB commands
        # This is typically in CMIS modules that support CDB
        print("CDB Performance Monitoring: CDB support not yet implemented")
        
    except Exception as e:
        print(f"Error reading CDB Performance Monitoring: {e}")


def read_cdb_security_features():
    """Read CDB Security Features - CMIS CDB support"""
    try:
        print("\n=== CDB Security Features ===")
        
        # CDB module authentication and security
        # This is typically in CMIS modules that support CDB
        print("CDB Security Features: CDB support not yet implemented")
        
    except Exception as e:
        print(f"Error reading CDB Security Features: {e}")


def read_cdb_bulk_commands():
    """Read CDB Bulk Read/Write Commands - CMIS CDB support"""
    try:
        print("\n=== CDB Bulk Read/Write Commands ===")
        
        # CDB large data transfer operations
        # This is typically in CMIS modules that support CDB
        print("CDB Bulk Commands: CDB support not yet implemented")
        
    except Exception as e:
        print(f"Error reading CDB Bulk Commands: {e}")


def read_cdb_bert_commands():
    """Read CDB BERT Commands - CMIS CDB support"""
    try:
        print("\n=== CDB BERT Commands ===")
        
        # CDB Bit Error Rate Testing
        # This is typically in CMIS modules that support CDB
        print("CDB BERT Commands: CDB support not yet implemented")
        
    except Exception as e:
        print(f"Error reading CDB BERT Commands: {e}")


def read_cdb_diagnostics_commands():
    """Read CDB Diagnostics Commands - CMIS CDB support"""
    try:
        print("\n=== CDB Diagnostics Commands ===")
        
        # CDB advanced diagnostic capabilities
        # This is typically in CMIS modules that support CDB
        print("CDB Diagnostics Commands: CDB support not yet implemented")
        
    except Exception as e:
        print(f"Error reading CDB Diagnostics Commands: {e}")


def read_pattern_generation():
    """Read Pattern Generation - CMIS diagnostic features"""
    try:
        print("\n=== Pattern Generation ===")
        
        # PRBS and user-defined pattern generation
        # This is typically in CMIS modules that support pattern generation
        print("Pattern Generation: Pattern generation support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Pattern Generation: {e}")


def read_pattern_checking():
    """Read Pattern Checking - CMIS diagnostic features"""
    try:
        print("\n=== Pattern Checking ===")
        
        # Bit error rate measurement
        # This is typically in CMIS modules that support pattern checking
        print("Pattern Checking: Pattern checking support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Pattern Checking: {e}")


def read_loopback_controls():
    """Read Loopback Controls - CMIS diagnostic features"""
    try:
        print("\n=== Loopback Controls ===")
        
        # Host and media side loopback
        # This is typically in CMIS modules that support loopback
        print("Loopback Controls: Loopback support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Loopback Controls: {e}")


def read_diagnostic_masks():
    """Read Diagnostic Masks - CMIS diagnostic features"""
    try:
        print("\n=== Diagnostic Masks ===")
        
        # Configurable diagnostic monitoring
        # This is typically in CMIS modules that support diagnostic masks
        print("Diagnostic Masks: Diagnostic masks support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Diagnostic Masks: {e}")


def read_user_patterns():
    """Read User Patterns - CMIS diagnostic features"""
    try:
        print("\n=== User Patterns ===")
        
        # Custom pattern definition
        # This is typically in CMIS modules that support user patterns
        print("User Patterns: User patterns support not yet implemented")
        
    except Exception as e:
        print(f"Error reading User Patterns: {e}")


def read_diagnostic_selection():
    """Read Diagnostic Selection - CMIS diagnostic features"""
    try:
        print("\n=== Diagnostic Selection ===")
        
        # Configurable diagnostic measurements
        # This is typically in CMIS modules that support diagnostic selection
        print("Diagnostic Selection: Diagnostic selection support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Diagnostic Selection: {e}")


def read_diagnostic_reporting():
    """Read Diagnostic Reporting - CMIS diagnostic features"""
    try:
        print("\n=== Diagnostic Reporting ===")
        
        # Advanced reporting capabilities
        # This is typically in CMIS modules that support diagnostic reporting
        print("Diagnostic Reporting: Diagnostic reporting support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Diagnostic Reporting: {e}")


def read_module_performance_monitoring():
    """Read Module Performance Monitoring - CMIS performance monitoring"""
    try:
        print("\n=== Module Performance Monitoring ===")
        
        # Module-level performance monitoring
        # This is typically in CMIS modules that support performance monitoring
        print("Module Performance Monitoring: Performance monitoring support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Module Performance Monitoring: {e}")


def read_host_side_performance_monitoring():
    """Read Host Side Performance Monitoring - CMIS performance monitoring"""
    try:
        print("\n=== Host Side Performance Monitoring ===")
        
        # Host interface performance monitoring
        # This is typically in CMIS modules that support performance monitoring
        print("Host Side Performance Monitoring: Performance monitoring support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Host Side Performance Monitoring: {e}")


def read_media_side_performance_monitoring():
    """Read Media Side Performance Monitoring - CMIS performance monitoring"""
    try:
        print("\n=== Media Side Performance Monitoring ===")
        
        # Media interface performance monitoring
        # This is typically in CMIS modules that support performance monitoring
        print("Media Side Performance Monitoring: Performance monitoring support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Media Side Performance Monitoring: {e}")


def read_data_path_performance_monitoring():
    """Read Data Path Performance Monitoring - CMIS performance monitoring"""
    try:
        print("\n=== Data Path Performance Monitoring ===")
        
        # Data path performance monitoring
        # This is typically in CMIS modules that support performance monitoring
        print("Data Path Performance Monitoring: Performance monitoring support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Data Path Performance Monitoring: {e}")


def read_rmon_statistics():
    """Read RMON Statistics - CMIS performance monitoring"""
    try:
        print("\n=== RMON Statistics ===")
        
        # Remote monitoring statistics
        # This is typically in CMIS modules that support RMON
        print("RMON Statistics: RMON support not yet implemented")
        
    except Exception as e:
        print(f"Error reading RMON Statistics: {e}")


def read_fec_statistics():
    """Read FEC Statistics - CMIS performance monitoring"""
    try:
        print("\n=== FEC Statistics ===")
        
        # Forward Error Correction statistics
        # This is typically in CMIS modules that support FEC
        print("FEC Statistics: FEC support not yet implemented")
        
    except Exception as e:
        print(f"Error reading FEC Statistics: {e}")


def read_temperature_histograms():
    """Read Temperature Histograms - CMIS performance monitoring"""
    try:
        print("\n=== Temperature Histograms ===")
        
        # Temperature distribution data
        # This is typically in CMIS modules that support temperature histograms
        print("Temperature Histograms: Temperature histogram support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Temperature Histograms: {e}")


def read_staged_control_sets():
    """Read Staged Control Sets - CMIS advanced control features"""
    try:
        print("\n=== Staged Control Sets ===")
        
        # Multi-stage configuration control
        # This is typically in CMIS modules that support staged control sets
        print("Staged Control Sets: Staged control sets support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Staged Control Sets: {e}")


def read_data_path_configuration():
    """Read Data Path Configuration - CMIS advanced control features"""
    try:
        print("\n=== Data Path Configuration ===")
        
        # Per-lane data path setup
        # This is typically in CMIS modules that support data path configuration
        print("Data Path Configuration: Data path configuration support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Data Path Configuration: {e}")


def read_network_path_configuration():
    """Read Network Path Configuration - CMIS advanced control features"""
    try:
        print("\n=== Network Path Configuration ===")
        
        # Network path provisioning
        # This is typically in CMIS modules that support network path configuration
        print("Network Path Configuration: Network path configuration support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Network Path Configuration: {e}")


def read_lane_specific_masks():
    """Read Lane-Specific Masks - CMIS advanced control features"""
    try:
        print("\n=== Lane-Specific Masks ===")
        
        # Per-lane control masks
        # This is typically in CMIS modules that support lane-specific masks
        print("Lane-Specific Masks: Lane-specific masks support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Lane-Specific Masks: {e}")


def read_configuration_commands():
    """Read Configuration Commands - CMIS advanced control features"""
    try:
        print("\n=== Configuration Commands ===")
        
        # Advanced configuration management
        # This is typically in CMIS modules that support configuration commands
        print("Configuration Commands: Configuration commands support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Configuration Commands: {e}")


def read_state_management():
    """Read State Management - CMIS advanced control features"""
    try:
        print("\n=== State Management ===")
        
        # Module and lane state management
        # This is typically in CMIS modules that support state management
        print("State Management: State management support not yet implemented")
        
    except Exception as e:
        print(f"Error reading State Management: {e}")


def read_lane_associated_data_path_states():
    """Read Lane-associated Data Path States - CMIS enhanced status monitoring"""
    try:
        print("\n=== Lane-associated Data Path States ===")
        
        # Per-lane state information
        # This is typically in CMIS modules that support lane-associated states
        print("Lane-associated Data Path States: Lane-associated states support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Lane-associated Data Path States: {e}")


def read_lane_specific_output_status():
    """Read Lane-Specific Output Status - CMIS enhanced status monitoring"""
    try:
        print("\n=== Lane-Specific Output Status ===")
        
        # Detailed lane status
        # This is typically in CMIS modules that support lane-specific output status
        print("Lane-Specific Output Status: Lane-specific output status support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Lane-Specific Output Status: {e}")


def read_state_changed_flags():
    """Read State Changed Flags - CMIS enhanced status monitoring"""
    try:
        print("\n=== State Changed Flags ===")
        
        # State change indicators
        # This is typically in CMIS modules that support state changed flags
        print("State Changed Flags: State changed flags support not yet implemented")
        
    except Exception as e:
        print(f"Error reading State Changed Flags: {e}")


def read_configuration_status():
    """Read Configuration Status - CMIS enhanced status monitoring"""
    try:
        print("\n=== Configuration Status ===")
        
        # Configuration command status
        # This is typically in CMIS modules that support configuration status
        print("Configuration Status: Configuration status support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Configuration Status: {e}")


def read_active_control_set():
    """Read Active Control Set - CMIS enhanced status monitoring"""
    try:
        print("\n=== Active Control Set ===")
        
        # Currently active configurations
        # This is typically in CMIS modules that support active control set
        print("Active Control Set: Active control set support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Active Control Set: {e}")


def read_data_path_conditions():
    """Read Data Path Conditions - CMIS enhanced status monitoring"""
    try:
        print("\n=== Data Path Conditions ===")
        
        # Data path operational conditions
        # This is typically in CMIS modules that support data path conditions
        print("Data Path Conditions: Data path conditions support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Data Path Conditions: {e}")


def read_laser_tuning_controls():
    """Read Laser Tuning Controls - CMIS tunable laser support"""
    try:
        print("\n=== Laser Tuning Controls ===")
        
        # Wavelength tuning capabilities
        # This is typically in CMIS modules that support tunable lasers
        print("Laser Tuning Controls: Tunable laser support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Laser Tuning Controls: {e}")


def read_laser_status_monitoring():
    """Read Laser Status Monitoring - CMIS tunable laser support"""
    try:
        print("\n=== Laser Status Monitoring ===")
        
        # Tunable laser status
        # This is typically in CMIS modules that support tunable lasers
        print("Laser Status Monitoring: Tunable laser support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Laser Status Monitoring: {e}")


def read_laser_flags():
    """Read Laser Flags - CMIS tunable laser support"""
    try:
        print("\n=== Laser Flags ===")
        
        # Tunable laser operational flags
        # This is typically in CMIS modules that support tunable lasers
        print("Laser Flags: Tunable laser support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Laser Flags: {e}")


def read_wavelength_information():
    """Read Wavelength Information - CMIS tunable laser support"""
    try:
        print("\n=== Wavelength Information ===")
        
        # Current wavelength data
        # This is typically in CMIS modules that support tunable lasers
        print("Wavelength Information: Tunable laser support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Wavelength Information: {e}")


def read_tuning_capabilities():
    """Read Tuning Capabilities - CMIS tunable laser support"""
    try:
        print("\n=== Tuning Capabilities ===")
        
        # Laser tuning feature support
        # This is typically in CMIS modules that support tunable lasers
        print("Tuning Capabilities: Tunable laser support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Tuning Capabilities: {e}")


def read_network_path_provisioning():
    """Read Network Path Provisioning - CMIS network path features"""
    try:
        print("\n=== Network Path Provisioning ===")
        
        # Network path configuration
        # This is typically in CMIS modules that support network paths
        print("Network Path Provisioning: Network path support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Network Path Provisioning: {e}")


def read_network_path_states():
    """Read Network Path States - CMIS network path features"""
    try:
        print("\n=== Network Path States ===")
        
        # Network path operational states
        # This is typically in CMIS modules that support network paths
        print("Network Path States: Network path support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Network Path States: {e}")


def read_network_path_conditions():
    """Read Network Path Conditions - CMIS network path features"""
    try:
        print("\n=== Network Path Conditions ===")
        
        # Network path conditions
        # This is typically in CMIS modules that support network paths
        print("Network Path Conditions: Network path support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Network Path Conditions: {e}")


def read_multiplex_lane_grouping():
    """Read Multiplex Lane Grouping - CMIS network path features"""
    try:
        print("\n=== Multiplex Lane Grouping ===")
        
        # Lane grouping capabilities
        # This is typically in CMIS modules that support multiplexing
        print("Multiplex Lane Grouping: Multiplexing support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Multiplex Lane Grouping: {e}")


def read_multiplex_granularities():
    """Read Multiplex Granularities - CMIS network path features"""
    try:
        print("\n=== Multiplex Granularities ===")
        
        # Multiplexing granularity support
        # This is typically in CMIS modules that support multiplexing
        print("Multiplex Granularities: Multiplexing support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Multiplex Granularities: {e}")


def read_global_multiplex_structures():
    """Read Global Multiplex Structures - CMIS network path features"""
    try:
        print("\n=== Global Multiplex Structures ===")
        
        # Advanced multiplexing features
        # This is typically in CMIS modules that support advanced multiplexing
        print("Global Multiplex Structures: Advanced multiplexing support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Global Multiplex Structures: {e}")


def read_enhanced_laser_temperature_monitoring():
    """Read Enhanced Laser Temperature Monitoring - SFF-8472 enhanced monitoring"""
    try:
        print("\n=== Enhanced Laser Temperature Monitoring ===")
        
        # Enhanced laser temperature monitoring with thresholds
        # This is an enhancement to the existing laser temperature monitoring
        print("Enhanced Laser Temperature Monitoring: Enhanced monitoring support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Enhanced Laser Temperature Monitoring: {e}")


def read_tec_current_monitoring():
    """Read TEC Current Monitoring - SFF-8472 enhanced monitoring"""
    try:
        print("\n=== TEC Current Monitoring ===")
        
        # TEC (Thermoelectric Cooler) current monitoring
        # This is typically in modules that support TEC monitoring
        print("TEC Current Monitoring: TEC monitoring support not yet implemented")
        
    except Exception as e:
        print(f"Error reading TEC Current Monitoring: {e}")


def read_tec_current_thresholds():
    """Read TEC Current Thresholds - SFF-8472 enhanced monitoring"""
    try:
        print("\n=== TEC Current Thresholds ===")
        
        # TEC current thresholds (alarm/warning levels)
        # This is typically in modules that support TEC monitoring
        print("TEC Current Thresholds: TEC monitoring support not yet implemented")
        
    except Exception as e:
        print(f"Error reading TEC Current Thresholds: {e}")


def read_laser_temperature_thresholds():
    """Read Laser Temperature Thresholds - SFF-8472 enhanced monitoring"""
    try:
        print("\n=== Laser Temperature Thresholds ===")
        
        # Laser temperature thresholds (alarm/warning levels)
        # This is typically in modules that support enhanced temperature monitoring
        print("Laser Temperature Thresholds: Enhanced temperature monitoring support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Laser Temperature Thresholds: {e}")


def read_enhanced_diagnostic_monitoring():
    """Read Enhanced Diagnostic Monitoring - SFF-8472 enhanced monitoring"""
    try:
        print("\n=== Enhanced Diagnostic Monitoring ===")
        
        # Enhanced diagnostic monitoring capabilities
        # This is typically in modules that support enhanced diagnostic monitoring
        print("Enhanced Diagnostic Monitoring: Enhanced diagnostic monitoring support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Enhanced Diagnostic Monitoring: {e}")


def read_advanced_control_functions():
    """Read Advanced Control Functions - SFF-8472 enhanced monitoring"""
    try:
        print("\n=== Advanced Control Functions ===")
        
        # CDR, rate select, power management controls
        # This is typically in modules that support advanced control functions
        print("Advanced Control Functions: Advanced control functions support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Advanced Control Functions: {e}")


def read_extended_module_information():
    """Read Extended Module Information - SFF-8472 enhanced monitoring"""
    try:
        print("\n=== Extended Module Information ===")
        
        # Device technology, transmitter details
        # This is typically in modules that support extended module information
        print("Extended Module Information: Extended module information support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Extended Module Information: {e}")


def read_validation_functions():
    """Read Validation Functions - Data integrity and compliance checking"""
    try:
        print("\n=== Validation Functions ===")
        
        # Data integrity and compliance checking
        # This includes checksum validation, range validation, consistency checks
        print("Validation Functions: Validation functions support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Validation Functions: {e}")


def read_checksum_validation():
    """Read Checksum Validation - Data integrity checking"""
    try:
        print("\n=== Checksum Validation ===")
        
        # Verify data integrity using CC_BASE/CC_EXT
        # This is typically used to validate data integrity
        print("Checksum Validation: Checksum validation support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Checksum Validation: {e}")


def read_range_validation():
    """Read Range Validation - Data integrity checking"""
    try:
        print("\n=== Range Validation ===")
        
        # Validate monitoring values against reasonable ranges
        # This is typically used to validate data ranges
        print("Range Validation: Range validation support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Range Validation: {e}")


def read_consistency_checks():
    """Read Consistency Checks - Data integrity checking"""
    try:
        print("\n=== Consistency Checks ===")
        
        # Cross-validate related fields
        # This is typically used to validate data consistency
        print("Consistency Checks: Consistency checks support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Consistency Checks: {e}")


def read_optic_type_validation():
    """Read Optic Type Validation - Specification compliance"""
    try:
        print("\n=== Optic Type Validation ===")
        
        # Validate against SFF-8024 definitions
        # This is typically used to validate optic types
        print("Optic Type Validation: Optic type validation support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Optic Type Validation: {e}")


def read_compliance_code_validation():
    """Read Compliance Code Validation - Specification compliance"""
    try:
        print("\n=== Compliance Code Validation ===")
        
        # Verify compliance codes against specifications
        # This is typically used to validate compliance codes
        print("Compliance Code Validation: Compliance code validation support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Compliance Code Validation: {e}")


def read_encoding_validation():
    """Read Encoding Validation - Specification compliance"""
    try:
        print("\n=== Encoding Validation ===")
        
        # Validate encoding values against standards
        # This is typically used to validate encoding values
        print("Encoding Validation: Encoding validation support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Encoding Validation: {e}")


def read_power_class_8_support():
    """Read Power Class 8 Support - SFF-8679 advanced power management"""
    try:
        print("\n=== Power Class 8 Support ===")
        
        # Higher power class modules
        # This is typically in QSFP-DD modules that support power class 8
        print("Power Class 8 Support: Power class 8 support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Power Class 8 Support: {e}")


def read_dynamic_power_management():
    """Read Dynamic Power Management - SFF-8679 advanced power management"""
    try:
        print("\n=== Dynamic Power Management ===")
        
        # Runtime power adjustments
        # This is typically in QSFP-DD modules that support dynamic power management
        print("Dynamic Power Management: Dynamic power management support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Dynamic Power Management: {e}")


def read_power_override_controls():
    """Read Power Override Controls - SFF-8679 advanced power management"""
    try:
        print("\n=== Power Override Controls ===")
        
        # Software power control
        # This is typically in QSFP-DD modules that support power override controls
        print("Power Override Controls: Power override controls support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Power Override Controls: {e}")


def read_advanced_temperature_monitoring():
    """Read Advanced Temperature Monitoring - SFF-8679 enhanced monitoring"""
    try:
        print("\n=== Advanced Temperature Monitoring ===")
        
        # Multiple temperature sensors
        # This is typically in QSFP-DD modules that support advanced temperature monitoring
        print("Advanced Temperature Monitoring: Advanced temperature monitoring support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Advanced Temperature Monitoring: {e}")


def read_voltage_monitoring():
    """Read Voltage Monitoring - SFF-8679 enhanced monitoring"""
    try:
        print("\n=== Voltage Monitoring ===")
        
        # Multiple voltage rails
        # This is typically in QSFP-DD modules that support voltage monitoring
        print("Voltage Monitoring: Voltage monitoring support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Voltage Monitoring: {e}")


def read_power_consumption_monitoring():
    """Read Power Consumption Monitoring - SFF-8679 enhanced monitoring"""
    try:
        print("\n=== Power Consumption Monitoring ===")
        
        # Real-time power usage
        # This is typically in QSFP-DD modules that support power consumption monitoring
        print("Power Consumption Monitoring: Power consumption monitoring support not yet implemented")
        
    except Exception as e:
        print(f"Error reading Power Consumption Monitoring: {e}")

def read_gbic_data():
    """Read GBIC (Gigabit Interface Converter) module data"""
    try:
        print("\n--- GBIC Module Data ---")
        print("GBIC modules follow SFF-8472 specification")
        
        # Read basic GBIC information
        read_optic_mod_def()
        read_optic_connector_type(get_byte(optic_pages, 0x00, 2))
        read_sff_optic_encoding()
        read_optic_signaling_rate()
        read_optic_rate_identifier()
        read_optic_vendor()
        read_optic_vendor_oui()
        read_sff8472_vendor_partnum()
        read_optic_vendor_serialnum()
        read_optic_rev()
        read_optic_datecode()
        read_optic_transciever()
        read_optic_distances()
        read_optic_frequency()
        
        # Read monitoring data if available
        if optic_ddm_read >= 128:
            read_optic_temperature()
            read_optic_rxpower()
            read_optic_txpower()
            read_laser_temperature()
            read_optic_vcc()
            read_measured_current()
            read_alarm_warning_thresholds()
            check_alarm_status()
            read_ext_cal_constants()
            read_vendor_specific()
            
    except Exception as e:
        print(f"Error reading GBIC data: {str(e)}")

def read_cxp_data():
    """Read CXP/CXP2 (High-speed parallel optics) module data"""
    try:
        print("\n--- CXP/CXP2 Module Data ---")
        print("CXP modules follow SFF-8472 specification with extended capabilities")
        
        # Read basic CXP information
        read_optic_mod_def()
        read_optic_connector_type(get_byte(optic_pages, 0x00, 2))
        read_sff_optic_encoding()
        read_optic_signaling_rate()
        read_optic_rate_identifier()
        read_optic_vendor()
        read_optic_vendor_oui()
        read_sff8472_vendor_partnum()
        read_optic_vendor_serialnum()
        read_optic_rev()
        read_optic_datecode()
        read_optic_transciever()
        read_optic_distances()
        read_optic_frequency()
        
        # CXP-specific features
        print("\nCXP-specific features:")
        print("- High-speed parallel optics")
        print("- Multiple lane support")
        print("- Enhanced monitoring capabilities")
        
        # Read monitoring data if available
        if optic_ddm_read >= 128:
            read_optic_temperature()
            read_optic_rxpower()
            read_optic_txpower()
            read_laser_temperature()
            read_optic_vcc()
            read_measured_current()
            read_alarm_warning_thresholds()
            check_alarm_status()
            read_ext_cal_constants()
            read_vendor_specific()
            
    except Exception as e:
        print(f"Error reading CXP data: {str(e)}")

def read_osfp_data():
    """Read OSFP (Octal Small Form Factor Pluggable) module data"""
    try:
        print("\n--- OSFP Module Data ---")
        print("OSFP modules follow CMIS specification")
        
        # OSFP uses CMIS specification
        print("OSFP modules use CMIS (Common Management Interface Specification)")
        print("- 8-lane electrical interface")
        print("- Enhanced thermal management")
        print("- Advanced monitoring capabilities")
        
        # Read CMIS data for OSFP
        read_cmis_lower_memory()
        read_cmis_page_00h()
        read_cmis_page_01h()
        oif_cmis.read_cmis_page_02h(optic_pages)
        oif_cmis.read_cmis_wavelength_info(optic_pages)
        
        # Read advanced pages if available
        if 0x1000 in optic_pages:
            oif_cmis.read_cmis_page_10h(optic_pages)
        if 0x1100 in optic_pages:
            oif_cmis.read_cmis_page_11h(optic_pages)
        if 0x400 in optic_pages:
            oif_cmis.read_cmis_page_04h(optic_pages)
        if 0x1200 in optic_pages:
            oif_cmis.read_cmis_page_12h(optic_pages)
        if 0x1300 in optic_pages:
            oif_cmis.read_cmis_page_13h(optic_pages)
        if 0x2500 in optic_pages:
            oif_cmis.read_cmis_page_25h(optic_pages)
            
        # Read monitoring data
        if optic_sff_read >= 128:
            oif_cmis.read_cmis_monitoring_data(optic_pages)
            oif_cmis.read_cmis_thresholds(optic_pages)
            oif_cmis.read_cmis_advanced_monitoring(optic_pages)
            oif_cmis.read_cmis_performance_monitoring(optic_pages)
            oif_cmis.read_cmis_coherent_monitoring(optic_pages)
            
    except Exception as e:
        print(f"Error reading OSFP data: {str(e)}")

def read_sfpdd_data():
    """Read SFP-DD (SFP Double Density) module data"""
    try:
        print("\n--- SFP-DD Module Data ---")
        print("SFP-DD modules follow SFF-8472 specification with enhanced features")
        
        # Read basic SFP-DD information
        read_optic_mod_def()
        read_optic_connector_type(get_byte(optic_pages, 0x00, 2))
        read_sff_optic_encoding()
        read_optic_signaling_rate()
        read_optic_rate_identifier()
        read_optic_vendor()
        read_optic_vendor_oui()
        read_sff8472_vendor_partnum()
        read_optic_vendor_serialnum()
        read_optic_rev()
        read_optic_datecode()
        read_optic_transciever()
        read_optic_distances()
        read_optic_frequency()
        
        # SFP-DD specific features
        print("\nSFP-DD-specific features:")
        print("- Double density electrical interface")
        print("- Enhanced thermal management")
        print("- Advanced monitoring capabilities")
        
        # Read monitoring data if available
        if optic_ddm_read >= 128:
            read_optic_temperature()
            read_optic_rxpower()
            read_optic_txpower()
            read_laser_temperature()
            read_optic_vcc()
            read_measured_current()
            read_alarm_warning_thresholds()
            check_alarm_status()
            read_ext_cal_constants()
            read_vendor_specific()
            
    except Exception as e:
        print(f"Error reading SFP-DD data: {str(e)}")

def read_dsfp_data():
    """Read DSFP (Dual SFP) module data"""
    try:
        print("\n--- DSFP Module Data ---")
        print("DSFP modules contain two SFP interfaces in one module")
        
        # Read basic DSFP information
        read_optic_mod_def()
        read_optic_connector_type(get_byte(optic_pages, 0x00, 2))
        read_sff_optic_encoding()
        read_optic_signaling_rate()
        read_optic_rate_identifier()
        read_optic_vendor()
        read_optic_vendor_oui()
        read_sff8472_vendor_partnum()
        read_optic_vendor_serialnum()
        read_optic_rev()
        read_optic_datecode()
        read_optic_transciever()
        read_optic_distances()
        read_optic_frequency()
        
        # DSFP specific features
        print("\nDSFP-specific features:")
        print("- Dual SFP interfaces")
        print("- Independent monitoring per interface")
        print("- Enhanced thermal management")
        
        # Read monitoring data if available
        if optic_ddm_read >= 128:
            read_optic_temperature()
            read_optic_rxpower()
            read_optic_txpower()
            read_laser_temperature()
            read_optic_vcc()
            read_measured_current()
            read_alarm_warning_thresholds()
            check_alarm_status()
            read_ext_cal_constants()
            read_vendor_specific()
            
    except Exception as e:
        print(f"Error reading DSFP data: {str(e)}")

def read_minilink_data():
    """Read MiniLink/OcuLink module data"""
    try:
        print("\n--- MiniLink/OcuLink Module Data ---")
        print("MiniLink/OcuLink modules are high-speed interconnect solutions")
        
        # Read basic MiniLink/OcuLink information
        read_optic_mod_def()
        read_optic_connector_type(get_byte(optic_pages, 0x00, 2))
        read_sff_optic_encoding()
        read_optic_signaling_rate()
        read_optic_rate_identifier()
        read_optic_vendor()
        read_optic_vendor_oui()
        read_sff8472_vendor_partnum()
        read_optic_vendor_serialnum()
        read_optic_rev()
        read_optic_datecode()
        read_optic_transciever()
        read_optic_distances()
        read_optic_frequency()
        
        # MiniLink/OcuLink specific features
        print("\nMiniLink/OcuLink-specific features:")
        print("- High-speed interconnect")
        print("- Enhanced thermal management")
        print("- Advanced monitoring capabilities")
        
        # Read monitoring data if available
        if optic_ddm_read >= 128:
            read_optic_temperature()
            read_optic_rxpower()
            read_optic_txpower()
            read_laser_temperature()
            read_optic_vcc()
            read_measured_current()
            read_alarm_warning_thresholds()
            check_alarm_status()
            read_ext_cal_constants()
            read_vendor_specific()
            
    except Exception as e:
        print(f"Error reading MiniLink/OcuLink data: {str(e)}")

def read_unknown_optic_data():
    """Read unknown/unspecified optic module data"""
    try:
        print("\n--- Unknown/Unspecified Optic Module Data ---")
        print("Attempting to read data from unknown optic type")
        
        # Try to read basic information that might be available
        optic_type = read_optic_type()
        print(f"Detected optic type: 0x{optic_type:02x}")
        
        # Try to read vendor information
        try:
            read_optic_vendor()
        except:
            print("Vendor information not available")
            
        try:
            read_optic_vendor_oui()
        except:
            print("Vendor OUI not available")
            
        try:
            read_sff8472_vendor_partnum()
        except:
            print("Part number not available")
            
        try:
            read_optic_vendor_serialnum()
        except:
            print("Serial number not available")
            
        # Try to read basic monitoring if available
        if optic_ddm_read >= 128:
            try:
                read_optic_temperature()
            except:
                print("Temperature monitoring not available")
                
            try:
                read_optic_rxpower()
            except:
                print("RX power monitoring not available")
                
            try:
                read_optic_txpower()
            except:
                print("TX power monitoring not available")
                
        print("\nNote: This optic type is not fully supported.")
        print("Consider updating the parser to support this optic type.")
            
    except Exception as e:
        print(f"Error reading unknown optic data: {str(e)}")

def read_legacy_optic_data():
    """Read legacy optic module data"""
    try:
        print("\n--- Legacy Optic Module Data ---")
        print("Reading data from legacy optic type")
        
        optic_type = read_optic_type()
        print(f"Legacy optic type: 0x{optic_type:02x}")
        
        # Try to read basic information
        try:
            read_optic_mod_def()
        except:
            print("Module definition not available")
            
        try:
            read_optic_connector_type(get_byte(optic_pages, 0x00, 2))
        except:
            print("Connector type not available")
            
        try:
            read_sff_optic_encoding()
        except:
            print("Encoding information not available")
            
        try:
            read_optic_vendor()
        except:
            print("Vendor information not available")
            
        try:
            read_optic_vendor_oui()
        except:
            print("Vendor OUI not available")
            
        try:
            read_sff8472_vendor_partnum()
        except:
            print("Part number not available")
            
        try:
            read_optic_vendor_serialnum()
        except:
            print("Serial number not available")
            
        try:
            read_optic_rev()
        except:
            print("Revision not available")
            
        try:
            read_optic_datecode()
        except:
            print("Date code not available")
            
        # Try to read monitoring data if available
        if optic_ddm_read >= 128:
            try:
                read_optic_temperature()
            except:
                print("Temperature monitoring not available")
                
            try:
                read_optic_rxpower()
            except:
                print("RX power monitoring not available")
                
            try:
                read_optic_txpower()
            except:
                print("TX power monitoring not available")
                
            try:
                read_laser_temperature()
            except:
                print("Laser temperature monitoring not available")
                
            try:
                read_optic_vcc()
            except:
                print("VCC monitoring not available")
                
            try:
                read_measured_current()
            except:
                print("Current monitoring not available")
                
        print("\nNote: This is a legacy optic type with limited support.")
        print("Consider using a more recent optic type for full functionality.")
            
    except Exception as e:
        print(f"Error reading legacy optic data: {str(e)}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Read and decode optic module data')
    parser.add_argument('-f', '--file', help='Parse optic data from file instead of hardware')
    parser.add_argument('--no-hardware', action='store_true', help='Disable hardware access (for testing)')
    args = parser.parse_args()
    
    if args.no_hardware:
        real_hardware = False
    
    if args.file:
        # Parse from file
        if parse_optic_file(args.file):
            process_optic_data(None, 0, 0, 0, "file")
    else:
        # Poll hardware
        poll_busses()
