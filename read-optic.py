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
#optic_lower_page = bytearray.fromhex("18400407000000000000000000002fb8811f00000000348600002000000000000000000000010003040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030402111e840111438401ff00000000000000000000000000000000000000000000000000000000000000001118434947202020202020202020202020000b405452443554483230454e462d4c4630303030315332324a423035525220202020202020323230393236202020202020202020202020a0300007000000000000f00006000000000000000000d6000000000000000000000000000000000000000000000000000000000000000000")

# page 0
#optic_sff = bytearray.fromhex("18400407000000000000000000002fb8811f000000003486000020000000000000000000000100030400000000000000000000000000000000000000000000000000000000000000000000000000000000000000030402111e840111438401ff000000000000000000000000000000000000000000000000000000000000000011030402004a000000000065a4051424f017c2460000009c1a00fa773b03070613075d3d77ff00003822000000000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000099")

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
        'Lower Page': '00h',
        'Upper Page 00h': '80h',
        'Upper Page 01h': '01h',
        'Upper Page 02h': '02h',
        'Upper Page 03h': '03h',
        'Upper Page 04h': '04h',
        'Upper Page 10h': '10h',
        'Upper Page 11h': '11h',
        'Upper Page 12h': '12h',
        'Upper Page 13h': '13h',
        'Upper Page 25h': '25h',
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
                # For CMIS modules, ensure lower page data is included in each upper page
                if current_page != '00h' and '00h' in optic_pages:
                    # Copy lower page data (bytes 0-127) to the upper page
                    for i in range(128):
                        optic_pages[current_page][i] = optic_pages['00h'][i]
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
                            if current_page != '00h' and base_addr >= 0x80:
                                # For upper pages, map 0x80-0xFF to 128-255
                                addr = base_addr + (i - 1)
                                if 0x80 <= addr <= 0xFF:
                                    page_offset = addr - 0x80 + 128
                                    if 128 <= page_offset < 256:
                                        optic_pages[current_page][page_offset] = val
                            else:
                                # Lower page or lower half of upper page
                                addr = base_addr + (i - 1)
                                if 0 <= addr < 128:
                                    optic_pages[current_page][addr] = val
                except ValueError:
                    continue
            continue
        # Juniper QSFP format detection
        if line.startswith('QSFP IDEEPROM (Low Page 00h'):
            is_juniper_qsfp = True
            current_device = 'sff'
            current_page = '00h'
            if current_page not in optic_pages:
                optic_pages[current_page] = [0]*256
            continue
        if line.startswith('QSFP IDEEPROM (Upper Page 00h'):
            is_juniper_qsfp = True
            current_device = 'sff'
            current_page = '80h'
            if current_page not in optic_pages:
                optic_pages[current_page] = [0]*256
            continue
        if line.startswith('QSFP IDEEPROM (Upper Page 03h'):
            is_juniper_qsfp = True
            current_device = 'ddm'
            current_page = '00h'
            if current_page not in optic_ddm_pages:
                optic_ddm_pages[current_page] = [0]*256
            continue
        # Generic QSFP IDEEPROM format (like qsfp-40g-dac)
        if line.startswith('QSFP IDEEPROM:'):
            current_device = 'sff'
            current_page = '00h'
            if current_page not in optic_pages:
                optic_pages[current_page] = [0]*256
            continue
        if line.startswith('QSFP IDEEPROM (diagnostics):'):
            current_device = 'ddm'
            current_page = '00h'
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
                    # Convert current_page string to integer offset
                    page_offset = 0
                    if current_page == '00h':
                        page_offset = 0
                    elif current_page == '80h':
                        page_offset = 0x80
                    elif current_page == '01h':
                        page_offset = 0x01
                    elif current_page == '02h':
                        page_offset = 0x02
                    elif current_page == '03h':
                        page_offset = 0x03
                    elif current_page == '04h':
                        page_offset = 0x04
                    elif current_page == '06h':
                        page_offset = 0x06
                    elif current_page == '10h':
                        page_offset = 0x10
                    elif current_page == '11h':
                        page_offset = 0x11
                    elif current_page == '12h':
                        page_offset = 0x12
                    elif current_page == '13h':
                        page_offset = 0x13
                    elif current_page == '25h':
                        page_offset = 0x25
                    else:
                        # Try to parse as hex if it's a different format
                        try:
                            page_offset = int(current_page.replace('h', ''), 16)
                        except ValueError:
                            page_offset = 0
                    
                    addr = base_addr - page_offset + i
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
   
    # After loading all pages, create string-keyed aliases for expected parser keys
    # Convert integer keys to string keys for compatibility
    optic_pages_str = {}
    for key, value in optic_pages.items():
        if isinstance(key, int):
            # Convert integer keys to string keys
            str_key = f'{key:02x}h'
            optic_pages_str[str_key] = value
        else:
            # Keep string keys as-is
            optic_pages_str[key] = value
    
    # Update optic_pages with string keys
    optic_pages.clear()
    optic_pages.update(optic_pages_str)
   
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
        if (get_byte(optic_pages, '00h', 65) & 0x40):
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
    optic_type = get_byte(optic_pages, '00h', 0)

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

    return optic_type, sff_type_text


def read_optic_mod_def():
    # SFF-8472 Physical Device Extended Identifer Values
    # Byte 1 Table 5-2

    val = get_byte(optic_pages, '00h', 1)
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

    val = get_byte(optic_pages, '00h', 11)
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
    if (get_byte(optic_pages, '00h', 139) & 0x80): # bit 7
        xfp_encoding.append('64B/66B')
    if (get_byte(optic_pages, '00h', 139) & 0x40): # bit 6
        xfp_encoding.append('8B10B')
    if (get_byte(optic_pages, '00h', 139) & 0x20): # bit 5
        xfp_encoding.append('SONET Scrambled')
    if (get_byte(optic_pages, '00h', 139) & 0x10): # bit 4
        xfp_encoding.append('NRZ')
    if (get_byte(optic_pages, '00h', 139) & 0x8):  # bit 3
        xfp_encoding.append('RZ')
    if (get_byte(optic_pages, '00h', 139) & 0x4):  # bit 2
        xfp_encoding.append('139-2-Reserved')
    if (get_byte(optic_pages, '00h', 139) & 0x2):  # bit 1
        xfp_encoding.append('139-1-Reserved')
    if (get_byte(optic_pages, '00h', 139) & 0x1):  # bit 0
        xfp_encoding.append('139-0-Reserved')

    comma=","
    print("XFP Encoding:", comma.join(xfp_encoding))

def read_xfp_br():
    xfp_min_br = get_byte(optic_pages, '00h', 140) * 100
    xfp_max_br = get_byte(optic_pages, '00h', 141) * 100
    print("XFP Min-Bitrate = %d Mbps" % xfp_min_br)
    print("XFP Max-Bitrate = %d Mbps" % xfp_max_br)

def read_xfp_lengths():
    xfp_len_km_smf = get_byte(optic_pages, '00h', 142)
    xfp_len_om2_mmf = get_byte(optic_pages, '00h', 143) *2 # convert to meters
    xfp_len_mmf = get_byte(optic_pages, '00h', 144)
    xfp_len_om1_mmf = get_byte(optic_pages, '00h', 145)
    xfp_len_copper = get_byte(optic_pages, '00h', 146) # meters

    print("XFP Distances:")
    print("\tSMF %d KM" % xfp_len_km_smf)
    print("\tOM2 MMF %d meters" % xfp_len_om2_mmf)
    print("\tOM2 MMF %d meters" % xfp_len_mmf)
    print("\tOM1 MMF %d meters" % xfp_len_om1_mmf)
    print("\tCopper %d meters" % xfp_len_copper)

def read_xfp_technology():
    xfp_device_technology = []
    if (get_byte(optic_pages, '00h', 147) & 0x8): # bit 3
        xfp_device_technology.append('Active Wavelength Control')
    else:
        xfp_device_technology.append('No Wavelength Control')
    if (get_byte(optic_pages, '00h', 147) & 0x4): # bit 2
        xfp_device_technology.append('Cooled transmitter')
    else:
        xfp_device_technology.append('Uncooled transmitter')
    if (get_byte(optic_pages, '00h', 147) & 0x2): # bit 1
        xfp_device_technology.append('APD Detector')
    else:
        xfp_device_technology.append('PIN detector')
    if (get_byte(optic_pages, '00h', 147) & 0x1): # bit 0
        xfp_device_technology.append('Transmitter Tunable')
    else:
        xfp_device_technology.append('Transmitter not Tunable')
    comma=","
    print("XFP Technology:", comma.join(xfp_device_technology))

    xfp_technology_bits = get_byte(optic_pages, '00h', 147) >> 4
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




def read_xfp_vendor():
    # INF-8077 5.XX
    # 16 bytes ASCII at bytes 148-163
    vendor = get_bytes(optic_pages, '00h', 148, 164).decode('ascii', errors='ignore').strip()
    print("Vendor:", vendor)

def read_xfp_vendor_pn():
    # INF-8077 5.31
    vendor_pn = get_bytes(optic_pages, '00h', 168, 184).decode('ascii', errors='ignore').strip()
    print("Vendor PN:", vendor_pn)





def read_xfp_vendor_rev():
    # INF-8077 5.32 (184-185)
    vendor_rev = get_bytes(optic_pages, '00h', 184, 186).decode('ascii', errors='ignore').strip()
    print("Vendor REV:", vendor_rev)

def read_xfp_wavelength():
    # INF-8077 5.33 (186,187)
    xfp_wavelength = ((get_byte(optic_pages, '00h', 186)*256)+get_byte(optic_pages, '00h', 187))*.05

    print("XFP Wavelength: %d nm" % xfp_wavelength)
    # INF-8077 5.34
    print("XFP Wavelength Tolerance: %d nm" % (((get_byte(optic_pages, '00h', 188)*256)+get_byte(optic_pages, '00h', 189)) *.005))

def read_xfp_max_temp():
    # INF-8077 5.35
    xfp_max_temp_c = get_byte(optic_pages, '00h', 190)
    print("XFP Max Temp: %d C" % xfp_max_temp_c)

def read_xfp_cc_base():
    # INF-8077 5.36
    # checksum of bytes 128-190
    calc_cc_base = 0
    for byte in range (128, 191):
        calc_cc_base = calc_cc_base + get_byte(optic_pages, '00h', byte)
    print("XFP CC Base = %x, Calc = %x" % (get_byte(optic_pages, '00h', 191), calc_cc_base & 0xff))

def read_xfp_power_supply():
    # INF-8077 5.37
    # 192-195
    xfp_max_power_disp = get_byte(optic_pages, '00h', 192) * 20
    xfp_total_power_disp = get_byte(optic_pages, '00h', 193) * 10
    xfp_max_current_5v = (get_byte(optic_pages, '00h', 194) >> 4) * 50
    xfp_max_current_3v = (get_byte(optic_pages, '00h', 194) & 0xf) * 100
    xfp_max_current_1v = (get_byte(optic_pages, '00h', 195) >> 4) * 100
    xfp_max_current_neg5v = (get_byte(optic_pages, '00h', 195) & 0xf) * 50
    print("Maximum Power Dissipation: %d mW" % xfp_max_power_disp)
    print("Maximum Total Power Dissipation (P_Down): %d mW" % xfp_total_power_disp)
    print("Maximum current required 5V: %d mA" % xfp_max_current_5v)
    print("Maximum current required 3V3: %d mA" % xfp_max_current_3v)
    print("Maximum current required 1V8: %d mA" % xfp_max_current_1v)
    print("Maximum current required -5.2V: %d mA" % xfp_max_current_neg5v)

def read_xfp_ext_ddm_type():
    # INF-8077 5.40 Byte 220
    xfp_ddm_type=[]

    if (get_byte(optic_pages, '00h', 220) & 0x10): # bit 4
        xfp_ddm_type.append('BER Support')
    else:
        xfp_ddm_type.append('No BER Support')
    if (get_byte(optic_pages, '00h', 220) & 0x8): # bit 3
        xfp_ddm_type.append('OMA')
    else:
        xfp_ddm_type.append('Average Power')
    comma=','
    print("XFP DDM Type:", comma.join(xfp_ddm_type))

def read_xfp_ext_enh_monitoring():
    # INF-8077 5.41 Table 57 Byte 221
    xfp_enh_options=[]
    if (get_byte(optic_pages, '00h', 221) & 0x80): # bit 7
        xfp_enh_options.append('VPS supported')
    if (get_byte(optic_pages, '00h', 221) & 0x40): # bit 6
        xfp_enh_options.append('Soft TX_DISABLE supported')
    if (get_byte(optic_pages, '00h', 221) & 0x20): # bit 5
        xfp_enh_options.append('Soft P_Down supported')
    if (get_byte(optic_pages, '00h', 221) & 0x10): # bit 4
        xfp_enh_options.append('VPS LV regulator supported')
    if (get_byte(optic_pages, '00h', 221) & 0x8): # bit 3
        xfp_enh_options.append('VPS bypassed regulator modes supported')
    if (get_byte(optic_pages, '00h', 221) & 0x4): # bit 2
        xfp_enh_options.append('Active FEC control functions supported')
    if (get_byte(optic_pages, '00h', 221) & 0x2): # bit 1
        xfp_enh_options.append('Wavelength tunable supported')
    if (get_byte(optic_pages, '00h', 221) & 0x1): # bit 0
        xfp_enh_options.append('CMU Support Mode Supported')
    comma=','
    print("XFP Enhanced Options:", comma.join(xfp_enh_options))




def read_optic_rate_identifier():
    # SFF-8472 13

    print("Optic Rate Identifier: %d" % get_byte(optic_pages, '00h', 13))

def read_optic_vendor():
    # SFF-8472
    # 16 bytes ASCII at bytes 20-35
    vendor = get_bytes(optic_pages, '00h', 20, 36).decode('ascii', errors='ignore').strip()
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
        identifier = get_byte(optic_pages, '00h', 0)
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
        ext_id = get_byte(optic_pages, '00h', 1)
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
        connector = get_byte(optic_pages, '00h', 2)
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
    """Read SFP Transceiver codes according to SFF-8472 Table 5-3"""
    try:
        print("\n--- SFP Transceiver Codes ---")
       
        # Read bytes 3-10 (8 bytes total)
        transceiver_bytes = get_bytes(optic_pages, '00h', 3, 11)
        if transceiver_bytes:
            print(f"Raw Transceiver Codes: {transceiver_bytes}")
           
            # Parse each byte according to SFF-8472 Table 5-3
            for i, byte_val in enumerate(transceiver_bytes):
                if byte_val != 0:  # Only show non-zero bytes
                    print(f"  Byte {3+i}: 0x{byte_val:02x}")
                   
                    if i == 0:  # Byte 3 - 10G Ethernet, Infiniband, ESCON, SONET
                        if byte_val & 0x80:
                            print("    - 10GBASE-ER")
                        if byte_val & 0x40:
                            print("    - 10GBASE-LRM")
                        if byte_val & 0x20:
                            print("    - 10GBASE-LR")
                        if byte_val & 0x10:
                            print("    - 10GBASE-SR")
                        if byte_val & 0x08:
                            print("    - 1X SX (Infiniband)")
                        if byte_val & 0x04:
                            print("    - 1X LX (Infiniband)")
                        if byte_val & 0x02:
                            print("    - 1X Copper Active (Infiniband)")
                        if byte_val & 0x01:
                            print("    - 1X Copper Passive (Infiniband)")
                   
                    elif i == 1:  # Byte 4 - ESCON, SONET
                        if byte_val & 0x80:
                            print("    - ESCON MMF, 1310nm LED")
                        if byte_val & 0x40:
                            print("    - ESCON SMF, 1310nm Laser")
                        if byte_val & 0x20:
                            print("    - OC-192, short reach")
                        if byte_val & 0x10:
                            print("    - SONET reach specifier bit 1")
                        if byte_val & 0x08:
                            print("    - SONET reach specifier bit 2")
                        if byte_val & 0x04:
                            print("    - OC-48, long reach")
                        if byte_val & 0x02:
                            print("    - OC-48, intermediate reach")
                        if byte_val & 0x01:
                            print("    - OC-48, short reach")
                   
                    elif i == 2:  # Byte 5 - SONET, Reserved
                        if byte_val & 0x40:
                            print("    - OC-12, single mode, long reach")
                        if byte_val & 0x20:
                            print("    - OC-12, single mode, inter. reach")
                        if byte_val & 0x10:
                            print("    - OC-12, short reach")
                        if byte_val & 0x04:
                            print("    - OC-3, single mode, long reach")
                        if byte_val & 0x02:
                            print("    - OC-3, single mode, inter. reach")
                        if byte_val & 0x01:
                            print("    - OC-3, short reach")
                   
                    elif i == 3:  # Byte 6 - Ethernet
                        if byte_val & 0x80:
                            print("    - BASE-PX")
                        if byte_val & 0x40:
                            print("    - BASE-BX10")
                        if byte_val & 0x20:
                            print("    - 100BASE-FX")
                        if byte_val & 0x10:
                            print("    - 100BASE-LX/LX10")
                        if byte_val & 0x08:
                            print("    - 1000BASE-T")
                        if byte_val & 0x04:
                            print("    - 1000BASE-CX")
                        if byte_val & 0x02:
                            print("    - 1000BASE-LX")
                        if byte_val & 0x01:
                            print("    - 1000BASE-SX")
                   
                    elif i == 4:  # Byte 7 - Fibre Channel Link Length
                        if byte_val & 0x80:
                            print("    - Very long distance (V)")
                        if byte_val & 0x40:
                            print("    - Short distance (S)")
                        if byte_val & 0x20:
                            print("    - Intermediate distance (I)")
                        if byte_val & 0x10:
                            print("    - Long distance (L)")
                        if byte_val & 0x08:
                            print("    - Medium distance (M)")
                        if byte_val & 0x04:
                            print("    - Shortwave laser, linear Rx (SA)")
                        if byte_val & 0x02:
                            print("    - Longwave laser (LC)")
                        if byte_val & 0x01:
                            print("    - Electrical inter-enclosure (EL)")
                   
                    elif i == 5:  # Byte 8 - Fibre Channel Technology
                        if byte_val & 0x80:
                            print("    - Electrical intra-enclosure (EL)")
                        if byte_val & 0x40:
                            print("    - Shortwave laser w/o OFC (SN)")
                        if byte_val & 0x20:
                            print("    - Shortwave laser with OFC (SL)")
                        if byte_val & 0x10:
                            print("    - Longwave laser (LL)")
                        if byte_val & 0x08:
                            print("    - Active Cable")
                        if byte_val & 0x04:
                            print("    - Passive Cable")
                   
                    elif i == 6:  # Byte 9 - Fibre Channel Transmission Media
                        if byte_val & 0x80:
                            print("    - Twin Axial Pair (TW)")
                        if byte_val & 0x40:
                            print("    - Twisted Pair (TP)")
                        if byte_val & 0x20:
                            print("    - Miniature Coax (MI)")
                        if byte_val & 0x10:
                            print("    - Video Coax (TV)")
                        if byte_val & 0x08:
                            print("    - Multimode, 62.5um (M6)")
                        if byte_val & 0x04:
                            print("    - Multimode, 50um (M5, M5E)")
                        if byte_val & 0x01:
                            print("    - Single Mode (SM)")
                   
                    elif i == 7:  # Byte 10 - Fibre Channel Speed
                        if byte_val & 0x80:
                            print("    - 1200 MBytes/s")
                        if byte_val & 0x40:
                            print("    - 800 MBytes/s")
                        if byte_val & 0x20:
                            print("    - 1600 MBytes/s")
                        if byte_val & 0x10:
                            print("    - 400 MBytes/s")
                        if byte_val & 0x08:
                            print("    - 3200 MBytes/s")
                        if byte_val & 0x04:
                            print("    - 200 MBytes/s")
                        if byte_val & 0x02:
                            print("    - See byte 62 'Fibre Channel Speed 2'")
                        if byte_val & 0x01:
                            print("    - 100 MBytes/s")
        else:
            print("SFP Transceiver Codes: Not available")
    except Exception as e:
        print(f"Error reading SFP Transceiver Codes: {e}")

def read_sfp_encoding():
    """Read SFP Encoding according to INF-8074_1.0 Table 3.5"""
    try:
        encoding = get_byte(optic_pages, '00h', 11)
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
        br_nominal = get_byte(optic_pages, '00h', 12)
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
        length_9m_km = get_byte(optic_pages, '00h', 14)
        if length_9m_km is not None:
            print(f"Length (9m) - km: {length_9m_km}")
            if length_9m_km == 0:
                print("  Description: Does not support single mode fiber")
            elif length_9m_km == 255:
                print("  Description: Supports link length > 254 km")
            else:
                print(f"  Description: Supports {length_9m_km} km on single mode fiber")
       
        # Length (9m)
        length_9m = get_byte(optic_pages, '00h', 15)
        if length_9m is not None:
            print(f"Length (9m): {length_9m}")
            if length_9m == 0:
                print("  Description: Does not support single mode fiber")
            elif length_9m == 255:
                print("  Description: Supports link length > 25.4 km")
            else:
                print(f"  Description: Supports {length_9m * 100} m on single mode fiber")
       
        # Length (50m)
        length_50m = get_byte(optic_pages, '00h', 16)
        if length_50m is not None:
            print(f"Length (50m): {length_50m}")
            if length_50m == 0:
                print("  Description: Does not support 50 micron multi-mode fiber")
            elif length_50m == 255:
                print("  Description: Supports link length > 2.54 km")
            else:
                print(f"  Description: Supports {length_50m * 10} m on 50 micron multi-mode fiber")
       
        # Length (62.5m)
        length_62_5m = get_byte(optic_pages, '00h', 17)
        if length_62_5m is not None:
            print(f"Length (62.5m): {length_62_5m}")
            if length_62_5m == 0:
                print("  Description: Does not support 62.5 micron multi-mode fiber")
            elif length_62_5m == 255:
                print("  Description: Supports link length > 2.54 km")
            else:
                print(f"  Description: Supports {length_62_5m * 10} m on 62.5 micron multi-mode fiber")
       
        # Length (Copper)
        length_copper = get_byte(optic_pages, '00h', 18)
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
        vendor_name = get_bytes(optic_pages, '00h', 20, 36).decode('ascii', errors='ignore').strip()
        print(f"Vendor Name: {vendor_name}")
       
        # Vendor OUI (bytes 37-39, 3 bytes)
        vendor_oui = get_bytes(optic_pages, '00h', 37, 40)
        if vendor_oui and any(b != 0 for b in vendor_oui):
            oui_str = ''.join([f"{b:02x}" for b in vendor_oui])
            print(f"Vendor OUI: {oui_str}")
        else:
            print("Vendor OUI: Unspecified")
       
        # Vendor Part Number (bytes 40-55, 16 bytes)
        vendor_pn = get_bytes(optic_pages, '00h', 40, 56).decode('ascii', errors='ignore').strip()
        print(f"Vendor Part Number: {vendor_pn}")
       
        # Vendor Revision (bytes 56-59, 4 bytes)
        vendor_rev = get_bytes(optic_pages, '00h', 56, 60).decode('ascii', errors='ignore').strip()
        print(f"Vendor Revision: {vendor_rev}")
       
    except Exception as e:
        print(f"Error reading SFP Vendor Info: {e}")

def read_sfp_extended_info():
    """Read SFP Extended information according to INF-8074_1.0"""
    try:
        print("\n--- SFP Extended Information ---")
       
        # Options (bytes 64-65, 2 bytes)
        options_bytes = get_bytes(optic_pages, '00h', 64, 66)
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
        br_max = get_byte(optic_pages, '00h', 66)
        if br_max is not None:
            print(f"BR, max: {br_max}% above nominal bit rate")
       
        # BR, min (byte 67)
        br_min = get_byte(optic_pages, '00h', 67)
        if br_min is not None:
            print(f"BR, min: {br_min}% below nominal bit rate")
       
        # Vendor Serial Number (bytes 68-83, 16 bytes)
        vendor_sn = get_bytes(optic_pages, '00h', 68, 84).decode('ascii', errors='ignore').strip()
        print(f"Vendor Serial Number: {vendor_sn}")
       
        # Date Code (bytes 84-91, 8 bytes)
        date_code = get_bytes(optic_pages, '00h', 84, 92).decode('ascii', errors='ignore').strip()
        print(f"Date Code: {date_code}")
       
    except Exception as e:
        print(f"Error reading SFP Extended Info: {e}")

def read_sfp_check_codes():
    """Read SFP Check codes according to INF-8074_1.0"""
    try:
        print("\n--- SFP Check Codes ---")
       
        # CC_BASE (byte 63)
        cc_base = get_byte(optic_pages, '00h', 63)
        if cc_base is not None:
            print(f"CC_BASE: 0x{cc_base:02x}")
       
        # CC_EXT (byte 95)
        cc_ext = get_byte(optic_pages, '00h', 95)
        if cc_ext is not None:
            print(f"CC_EXT: 0x{cc_ext:02x}")
       
    except Exception as e:
        print(f"Error reading SFP Check Codes: {e}")

def read_sfp_vendor_specific():
    """Read SFP Vendor specific data according to INF-8074_1.0"""
    try:
        print("\n--- SFP Vendor Specific Data ---")
       
        # Read-only vendor specific data (bytes 96-127, 32 bytes)
        vendor_specific = get_bytes(optic_pages, '00h', 96, 128)
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
    if (get_byte(optic_pages, '00h', 3) & 0x80):
        print("10G-Base-ER")
    if (get_byte(optic_pages, '00h', 3) & 0x40):
        print("10G-Base-LRM")
    if (get_byte(optic_pages, '00h', 3) & 0x20):
        print("10G-Base-LR")
    if (get_byte(optic_pages, '00h', 3) & 0x10):
        print("10G-Base-SR")
    if (get_byte(optic_pages, '00h', 3) & 0x08):
        print("Infiniband 1X SX")
    if (get_byte(optic_pages, '00h', 3) & 0x04):
        print("Infiniband 1X LX")
    if (get_byte(optic_pages, '00h', 3) & 0x02):
        print("infiniband 1X Copper Active")
    if (get_byte(optic_pages, '00h', 3) & 0x01):
        print("Infiniband 1X Copper Passive")

    if (get_byte(optic_pages, '00h', 6) & 0x80):
        print("Base-PX")
    if (get_byte(optic_pages, '00h', 6) & 0x40):
        print("Base-BX10")
    if (get_byte(optic_pages, '00h', 6) & 0x20):
        print("100Base-FX")
    if (get_byte(optic_pages, '00h', 6) & 0x10):
        print("100Base-LX/LX10")
    if (get_byte(optic_pages, '00h', 6) & 0x08):
        print("1000Base-T")
    if (get_byte(optic_pages, '00h', 6) & 0x04):
        print("1000Base-CX")
    if (get_byte(optic_pages, '00h', 6) & 0x02):
        print("1000Base-LX")
    if (get_byte(optic_pages, '00h', 6) & 0x01):
        print("1000Base-SX")


    print("extended compliance_code %d" % get_byte(optic_pages, '00h', 36))




def read_optic_vendor_oui():
    # SFF-8472 4-1
    # 3 bytes 37-39

    vendor_oui=""
    for byte in range (37, 40):
        vendor_oui = vendor_oui + ("%2.2x" % get_byte(optic_pages, '00h', byte))
    print("vendor_oui: %s" % vendor_oui)

def read_xfp_vendor_oui():
    # INF-8077 5.30
    # 3 bytes 165-167

    vendor_oui=""
    for byte in range (165, 168):
        vendor_oui = vendor_oui + ("%2.2x" % get_byte(optic_pages, '00h', byte))
    print("vendor_oui: %s" % vendor_oui)




def read_sff8472_vendor_partnum():
    # SFF-8472
    # 16 bytes ASCII at bytes 40-55
    vendor_partnum = get_bytes(optic_pages, '00h', 40, 56).decode('ascii', errors='ignore').strip()
    print("PN:", vendor_partnum)




def read_optic_vendor_serialnum():
    # SFF-8472
    # 16 bytes ASCII at bytes 68-83
    vendor_serialnum = ""

    for byte in range (68, 84):
        if (get_byte(optic_pages, '00h', byte) == 0 or get_byte(optic_pages, '00h', byte) == 0xff):
            break
        vendor_serialnum=vendor_serialnum +('%c' % get_byte(optic_pages, '00h', byte))
    print("SN:", vendor_serialnum)

def read_xfp_ext_vendor_sn():
    # INF-8077 5.38 196-211
    vendor_serialnum = ""

    for byte in range (196, 212):
        if (get_byte(optic_pages, '00h', byte) == 0 or get_byte(optic_pages, '00h', byte) == 0xff):
            break
        vendor_serialnum=vendor_serialnum +('%c' % get_byte(optic_pages, '00h', byte))
    print("Vendor SN:", vendor_serialnum)








def read_optic_datecode():
    # SFF-8472
    # 8 bytes ASCII at bytes 84-91
    vendor_datecode = ""

    for byte in range (84, 92):
        if (get_byte(optic_pages, '00h', byte) == 0 or get_byte(optic_pages, '00h', byte) == 0xff):
            break
        vendor_datecode = vendor_datecode + ('%c' % get_byte(optic_pages, '00h', byte))

    print("Date Code:", vendor_datecode)

def read_xfp_datecode():
    # INF-8077
    # 8 Bytes ASCII at 212-219
    vendor_datecode = ""

    for byte in range (212, 220):
        if (get_byte(optic_pages, '00h', byte) == 0 or get_byte(optic_pages, '00h', byte) == 0xff):
            break
        vendor_datecode = vendor_datecode + ('%c' % get_byte(optic_pages, '00h', byte))

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

def read_xfp_status_bits():
    # XFP MSA INF-8077
    # byte 110 Table 42

    try:
        print("Status Bits:")

        if (get_byte(optic_pages, '00h', 110) & 0x80): # bit 7
            print("\tTX_Disable Set")
        if (get_byte(optic_pages, '00h', 110) & 0x40): # bit 6
            print("\tSoft TX Disable Selected")
        if (get_byte(optic_pages, '00h', 110) & 0x20): # bit 5
            print("\tMOD_NR State set")
        if (get_byte(optic_pages, '00h', 110) & 0x10): # bit 4
            print("\tP_Down Set")
        if (get_byte(optic_pages, '00h', 110) & 0x08): # bit 3
            print("\tSoft P_Down set")
        if (get_byte(optic_pages, '00h', 110) & 0x04): # bit 2
            print("\tInterrupt")
        if (get_byte(optic_pages, '00h', 110) & 0x02): # bit 1
            print("\tRX_LOS")
        if (get_byte(optic_pages, '00h', 110) & 0x01): # bit 0
            print("\tData NOT Ready")

    except IndexError:
        print("got IndexError on optic_sff byte 110")



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
    xfp_speed = get_byte(optic_pages, '00h', 1)
    if (xfp_speed > 0):
        xfp_speed = get_byte(optic_pages, '00h', 1) >> 4
        print("XFP Speed = %d, %x" % (xfp_speed, get_byte(optic_pages, '00h', 1)))

def read_optic_xfp_thresholds():
    # INF-8077
    print("FIXME: read_optic_xfp_thresholds Unimplemented")

def read_optic_xfp_vps_control_registers():
    # INF-8077 Table 33 Bytes 58-59
    print("XFP: Lowest Voltage Supported: %d" % (get_byte(optic_pages, '00h', 58)>>4))
    print("XFP: Voltage Supplied on VCC2: %d" % (get_byte(optic_pages, '00h', 58) & 0xf))
    print("XFP: Voltage Supported with Bypasss regulator: %d" % (get_byte(optic_pages, '00h', 59)<<4))
    print("XFP: Regulator bypass mode: %d" % (get_byte(optic_pages, '00h', 59) & 0x1))

def read_xfp_transciever():
    # INF-8077 Table 49
    #

    transciever_type=[]
    if (get_byte(optic_pages, '00h', 131) & 0x80): # bit 7
        transciever_type.append('10Gbase-SR')
    if (get_byte(optic_pages, '00h', 131) & 0x40): # bit 6
        transciever_type.append('10GBase-LR')
    if (get_byte(optic_pages, '00h', 131) & 0x20): # bit 5
        transciever_type.append('10Gbase-ER')
    if (get_byte(optic_pages, '00h', 131) & 0x10): # bit 4
        transciever_type.append('10Gbase-LRM')
    if (get_byte(optic_pages, '00h', 131) & 0x8): # bit 3
        transciever_type.append('10Gbase-SW')
    if (get_byte(optic_pages, '00h', 131) & 0x4): # bit 2
        transciever_type.append('10Gbase-LW')
    if (get_byte(optic_pages, '00h', 131) & 0x2): # bit 1
        transciever_type.append('10Gbase-EW')
    if (get_byte(optic_pages, '00h', 131) & 0x1): # bit 0
        transciever_type.append('131-0-Reserved')

    if (get_byte(optic_pages, '00h', 132) & 0x80): # bit 7
        transciever_type.append('1200-MX-SN-I')
    if (get_byte(optic_pages, '00h', 132) & 0x40): # bit 6
        transciever_type.append('1200-SM-LL-L')
    if (get_byte(optic_pages, '00h', 132) & 0x20): # bit 5
        transciever_type.append('132-5-Reserved')
    if (get_byte(optic_pages, '00h', 132) & 0x10): # bit 4
        transciever_type.append('132-4-Reserved')
    if (get_byte(optic_pages, '00h', 132) & 0x8):  # bit 3
        transciever_type.append('132-3-Reserved')
    if (get_byte(optic_pages, '00h', 132) & 0x4):  # bit 2
        transciever_type.append('132-2-Reserved')
    if (get_byte(optic_pages, '00h', 132) & 0x2):  # bit 1
        transciever_type.append('132-1-Reserved')
    if (get_byte(optic_pages, '00h', 132) & 0x1):  # bit 0
        transciever_type.append('132-0-Reserved')

    if (get_byte(optic_pages, '00h', 133) & 0x80): # bit 7
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, '00h', 133) & 0x40): # bit 6
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, '00h', 133) & 0x20): # bit 5
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, '00h', 133) & 0x10): # bit 4
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, '00h', 133) & 0x8):  # bit 3
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, '00h', 133) & 0x4):  # bit 2
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, '00h', 133) & 0x2):  # bit 1
        transciever_type.append('133-Reserved')
    if (get_byte(optic_pages, '00h', 133) & 0x1):  # bit 0
        transciever_type.append('133-Reserved')

    if (get_byte(optic_pages, '00h', 134) & 0x80): # bit 7
        transciever_type.append('1000Base-SX/1xFC MMF')
    if (get_byte(optic_pages, '00h', 134) & 0x40): # bit 6
        transciever_type.append('1000Base-LX/1xFC SMF')
    if (get_byte(optic_pages, '00h', 134) & 0x20): # bit 5
        transciever_type.append('2xFC MMF')
    if (get_byte(optic_pages, '00h', 134) & 0x10): # bit 4
        transciever_type.append('2xFC SMF')
    if (get_byte(optic_pages, '00h', 134) & 0x8):  # bit 3
        transciever_type.append('OC-48-SR')
    if (get_byte(optic_pages, '00h', 134) & 0x4):  # bit 2
        transciever_type.append('OC-48-IR')
    if (get_byte(optic_pages, '00h', 134) & 0x2):  # bit 1
        transciever_type.append('OC-48-LR')
    if (get_byte(optic_pages, '00h', 134) & 0x1):  # bit 0
        transciever_type.append('134-Reserved')

    if (get_byte(optic_pages, '00h', 135) & 0x80): # bit 7
        transciever_type.append('I-64.1r')
    if (get_byte(optic_pages, '00h', 135) & 0x40): # bit 6
        transciever_type.append('I-64.1')
    if (get_byte(optic_pages, '00h', 135) & 0x20): # bit 5
        transciever_type.append('I-64.2r')
    if (get_byte(optic_pages, '00h', 135) & 0x10): # bit 4
        transciever_type.append('I-64.2')
    if (get_byte(optic_pages, '00h', 135) & 0x8):  # bit 3
        transciever_type.append('I-64.3')
    if (get_byte(optic_pages, '00h', 135) & 0x4):  # bit 2
        transciever_type.append('I-64.5')
    if (get_byte(optic_pages, '00h', 135) & 0x2):  # bit 1
        transciever_type.append('135-1-Reserved')
    if (get_byte(optic_pages, '00h', 135) & 0x1):  # bit 0
        transciever_type.append('135-0-Reserved')

    if (get_byte(optic_pages, '00h', 136) & 0x80): # bit 7
        transciever_type.append('S-64.1')
    if (get_byte(optic_pages, '00h', 136) & 0x40): # bit 6
        transciever_type.append('S-64.2a')
    if (get_byte(optic_pages, '00h', 136) & 0x20): # bit 5
        transciever_type.append('S-64.2b')
    if (get_byte(optic_pages, '00h', 136) & 0x10): # bit 4
        transciever_type.append('S-64.3a')
    if (get_byte(optic_pages, '00h', 136) & 0x8):  # bit 3
        transciever_type.append('S-64.3b')
    if (get_byte(optic_pages, '00h', 136) & 0x4):  # bit 2
        transciever_type.append('S-64.5a')
    if (get_byte(optic_pages, '00h', 136) & 0x2):  # bit 1
        transciever_type.append('S-64.5b')
    if (get_byte(optic_pages, '00h', 136) & 0x1):  # bit 0
        transciever_type.append('136-0-Reserved')

    if (get_byte(optic_pages, '00h', 137) & 0x80): # bit 7
        transciever_type.append('L-64.1')
    if (get_byte(optic_pages, '00h', 137) & 0x40): # bit 6
        transciever_type.append('L-64.2a')
    if (get_byte(optic_pages, '00h', 137) & 0x20): # bit 5
        transciever_type.append('L-64.2b')
    if (get_byte(optic_pages, '00h', 137) & 0x10): # bit 4
        transciever_type.append('L-64.2c')
    if (get_byte(optic_pages, '00h', 137) & 0x8):  # bit 3
        transciever_type.append('L-64.3')
    if (get_byte(optic_pages, '00h', 137) & 0x4):  # bit 2
        transciever_type.append('G.959.1 P1L1-2D2')
    if (get_byte(optic_pages, '00h', 137) & 0x2):  # bit 1
        transciever_type.append('137-1-Reserved')
    if (get_byte(optic_pages, '00h', 137) & 0x1):  # bit 0
        transciever_type.append('137-0-Reserved')

    if (get_byte(optic_pages, '00h', 138) & 0x80): # bit 7
        transciever_type.append('V-64.2a')
    if (get_byte(optic_pages, '00h', 138) & 0x40): # bit 6
        transciever_type.append('V-64-2b')
    if (get_byte(optic_pages, '00h', 138) & 0x20): # bit 5
        transciever_type.append('V-64-3')
    if (get_byte(optic_pages, '00h', 138) & 0x10): # bit 4
        transciever_type.append('138-Reserved')
    if (get_byte(optic_pages, '00h', 138) & 0x8):  # bit 3
        transciever_type.append('138-Reserved')
    if (get_byte(optic_pages, '00h', 138) & 0x4):  # bit 2
        transciever_type.append('138-Reserved')
    if (get_byte(optic_pages, '00h', 138) & 0x2):  # bit 1
        transciever_type.append('138-Reserved')
    if (get_byte(optic_pages, '00h', 138) & 0x1):  # bit 0
        transciever_type.append('138-Reserved')

    comma=','
    print("Transciever Type:", comma.join(transciever_type))

def read_optic_xfp_fec_control_registers():
    # INF-8077 I Table 38
    xfp_amplitude_adustment = get_byte(optic_pages, '00h', 76)
    xfp_phase_adjustment = get_byte(optic_pages, '00h', 77)
    print("XFP Amplitude Adustment: %d" % xfp_amplitude_adustment)
    print("XFP Phase Adjustment: %d" % xfp_phase_adjustment)

def read_optic_xfp_flags():
    # INF-8077 I Table 39 Bytes 80-95
    xfp_flags =[]

    if (get_byte(optic_pages, '00h', 80) & 0x80): # bit 7
        xfp_flags.append('L-Temp High Alarm')
    if (get_byte(optic_pages, '00h', 80) & 0x40): # bit 6
        xfp_flags.append('L-Temp Low Alarm')
    if (get_byte(optic_pages, '00h', 80) & 0x20): # bit 5
        xfp_flags.append('80-5-Reserved')
    if (get_byte(optic_pages, '00h', 80) & 0x10): # bit 4
        xfp_flags.append('80-4-Reserved')
    if (get_byte(optic_pages, '00h', 80) & 0x8):  # bit 3
        xfp_flags.append('L-TX Bias High Alarm')
    if (get_byte(optic_pages, '00h', 80) & 0x4):  # bit 2
        xfp_flags.append('L-TX Biase Low Alarm')
    if (get_byte(optic_pages, '00h', 80) & 0x2):  # bit 1
        xfp_flags.append('L-TX Power High Alarm')
    if (get_byte(optic_pages, '00h', 80) & 0x1):  # bit 0
        xfp_flags.append('L-TX Power Low Alarm')

    if (get_byte(optic_pages, '00h', 81) & 0x80): # bit 7
        xfp_flags.append('L-RX Power High Alarm')
    if (get_byte(optic_pages, '00h', 81) & 0x40): # bit 6
        xfp_flags.append('L-RX Power Low Alarm')
    if (get_byte(optic_pages, '00h', 81) & 0x20): # bit 5
        xfp_flags.append('L-AUX-1 High Alarm')
    if (get_byte(optic_pages, '00h', 81) & 0x10): # bit 4
        xfp_flags.append('L-AUX-1 Low Alarm')
    if (get_byte(optic_pages, '00h', 81) & 0x8):  # bit 3
        xfp_flags.append('L-AUX-2 High Alarm')
    if (get_byte(optic_pages, '00h', 81) & 0x4):  # bit 2
        xfp_flags.append('L-AUX-2 Low Alarm')
    if (get_byte(optic_pages, '00h', 81) & 0x2):  # bit 1
        xfp_flags.append('81-1-Reserved')
    if (get_byte(optic_pages, '00h', 81) & 0x1):  # bit 0
        xfp_flags.append('81-0-Reserved')

    if (get_byte(optic_pages, '00h', 82) & 0x80): # bit 7
        xfp_flags.append('L-Temp High Warning')
    if (get_byte(optic_pages, '00h', 82) & 0x40): # bit 6
        xfp_flags.append('L-Temp Low Warning')
    if (get_byte(optic_pages, '00h', 82) & 0x20): # bit 5
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 82) & 0x10): # bit 4
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 82) & 0x8):  # bit 3
        xfp_flags.append('L-TX Bias High Warning')
    if (get_byte(optic_pages, '00h', 82) & 0x4):  # bit 2
        xfp_flags.append('L-TX Bias Low Warning')
    if (get_byte(optic_pages, '00h', 82) & 0x2):  # bit 1
        xfp_flags.append('L-TX Power High Warning')
    if (get_byte(optic_pages, '00h', 82) & 0x1):  # bit 0
        xfp_flags.append('L-TX Power Low Warning')

    if (get_byte(optic_pages, '00h', 83) & 0x80): # bit 7
        xfp_flags.append('L-RX Power High Warning')
    if (get_byte(optic_pages, '00h', 83) & 0x40): # bit 6
        xfp_flags.append('L-RX Power Low Warning')
    if (get_byte(optic_pages, '00h', 83) & 0x20): # bit 5
        xfp_flags.append('L-AUX-1 High Warning')
    if (get_byte(optic_pages, '00h', 83) & 0x10): # bit 4
        xfp_flags.append('L-AUX-1 Low Warning')
    if (get_byte(optic_pages, '00h', 83) & 0x8):  # bit 3
        xfp_flags.append('L-AUX-2 High Warning')
    if (get_byte(optic_pages, '00h', 83) & 0x4):  # bit 2
        xfp_flags.append('L-AUX-2 Low Warning')
    if (get_byte(optic_pages, '00h', 83) & 0x2):  # bit 1
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 83) & 0x1):  # bit 0
        xfp_flags.append('Reserved')

    if (get_byte(optic_pages, '00h', 84) & 0x80): # bit 7
        xfp_flags.append('L-TX Not Ready')
    if (get_byte(optic_pages, '00h', 84) & 0x40): # bit 6
        xfp_flags.append('L-TX Fault')
    if (get_byte(optic_pages, '00h', 84) & 0x20): # bit 5
        xfp_flags.append('L-TX CDR not Locked')
    if (get_byte(optic_pages, '00h', 84) & 0x10): # bit 4
        xfp_flags.append('L-RX Not Ready')
    if (get_byte(optic_pages, '00h', 84) & 0x8):  # bit 3
        xfp_flags.append('L-RX LOS')
    if (get_byte(optic_pages, '00h', 84) & 0x4):  # bit 2
        xfp_flags.append('L-RX CDR not Locked')
    if (get_byte(optic_pages, '00h', 84) & 0x2):  # bit 1
        xfp_flags.append('L-Module Not Ready')
    if (get_byte(optic_pages, '00h', 84) & 0x1):  # bit 0
        xfp_flags.append('L-Reset Complete')

    if (get_byte(optic_pages, '00h', 85) & 0x80): # bit 7
        xfp_flags.append('L-APD Supply Fault')
    if (get_byte(optic_pages, '00h', 85) & 0x40): # bit 6
        xfp_flags.append('L-TEC Fault')
    if (get_byte(optic_pages, '00h', 85) & 0x20): # bit 5
        xfp_flags.append('L-Wavelength Unlocked')
    if (get_byte(optic_pages, '00h', 85) & 0x10): # bit 4
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 85) & 0x8):  # bit 3
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 85) & 0x4):  # bit 2
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 85) & 0x2):  # bit 1
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 85) & 0x1):  # bit 0
        xfp_flags.append('Reserved')

    if (get_byte(optic_pages, '00h', 86) & 0x80): # bit 7
        xfp_flags.append('L-VCC5 High Alarm')
    if (get_byte(optic_pages, '00h', 86) & 0x40): # bit 6
        xfp_flags.append('L-VCC5 Low Alarm')
    if (get_byte(optic_pages, '00h', 86) & 0x20): # bit 5
        xfp_flags.append('L-VCC3 High Alarm')
    if (get_byte(optic_pages, '00h', 86) & 0x10): # bit 4
        xfp_flags.append('L-VCC3 Low Alarm')
    if (get_byte(optic_pages, '00h', 86) & 0x8):  # bit 3
        xfp_flags.append('L-VCC2 High Alarm')
    if (get_byte(optic_pages, '00h', 86) & 0x4):  # bit 2
        xfp_flags.append('L-VCC2 Low Alarm')
    if (get_byte(optic_pages, '00h', 86) & 0x2):  # bit 1
        xfp_flags.append('L-Vee5 High Alarm')
    if (get_byte(optic_pages, '00h', 86) & 0x1):  # bit 0
        xfp_flags.append('L-Vee5 Low Alarm')

    if (get_byte(optic_pages, '00h', 87) & 0x80): # bit 7
        xfp_flags.append('L-VCC5 High Warning')
    if (get_byte(optic_pages, '00h', 87) & 0x40): # bit 6
        xfp_flags.append('L-VCC5 Low Warning')
    if (get_byte(optic_pages, '00h', 87) & 0x20): # bit 5
        xfp_flags.append('L-VCC3 High Warning')
    if (get_byte(optic_pages, '00h', 87) & 0x10): # bit 4
        xfp_flags.append('L-VCC3 Low Warning')
    if (get_byte(optic_pages, '00h', 87) & 0x8):  # bit 3
        xfp_flags.append('L-VCC2 High Warning')
    if (get_byte(optic_pages, '00h', 87) & 0x4):  # bit 2
        xfp_flags.append('L-VCC2 Low Warning')
    if (get_byte(optic_pages, '00h', 87) & 0x2):  # bit 1
        xfp_flags.append('L-Vee5 High Warning')
    if (get_byte(optic_pages, '00h', 87) & 0x1):  # bit 0
        xfp_flags.append('L-Vee5 Low Warning')

    if (get_byte(optic_pages, '00h', 88) & 0x80): # bit 7
        xfp_flags.append('M-Temp High Alarm')
    if (get_byte(optic_pages, '00h', 88) & 0x40): # bit 6
        xfp_flags.append('M-Temp Low Alarm')
    if (get_byte(optic_pages, '00h', 88) & 0x20): # bit 5
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 88) & 0x10): # bit 4
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 88) & 0x8):  # bit 3
        xfp_flags.append('M-TX Bias High Alarm')
    if (get_byte(optic_pages, '00h', 88) & 0x4):  # bit 2
        xfp_flags.append('M-TX Bias Low Alarm')
    if (get_byte(optic_pages, '00h', 88) & 0x2):  # bit 1
        xfp_flags.append('M-TX Power High Alarm')
    if (get_byte(optic_pages, '00h', 88) & 0x1):  # bit 0
        xfp_flags.append('M-TX Power Low Alarm')

    if (get_byte(optic_pages, '00h', 89) & 0x80): # bit 7
        xfp_flags.append('M-RX Power High Alarm')
    if (get_byte(optic_pages, '00h', 89) & 0x40): # bit 6
        xfp_flags.append('M-RX Power Low Alarm')
    if (get_byte(optic_pages, '00h', 89) & 0x20): # bit 5
        xfp_flags.append('M-AUX-1 High Alarm')
    if (get_byte(optic_pages, '00h', 89) & 0x10): # bit 4
        xfp_flags.append('M-AUX-1 Low Alarm')
    if (get_byte(optic_pages, '00h', 89) & 0x8):  # bit 3
        xfp_flags.append('M-AUX-2 High Alarm')
    if (get_byte(optic_pages, '00h', 89) & 0x4):  # bit 2
        xfp_flags.append('M-AUX-2 Low Alarm')
    if (get_byte(optic_pages, '00h', 89) & 0x2):  # bit 1
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 89) & 0x1):  # bit 0
        xfp_flags.append('Reserved')

    if (get_byte(optic_pages, '00h', 90) & 0x80): # bit 7
        xfp_flags.append('M-Temp High Warning')
    if (get_byte(optic_pages, '00h', 90) & 0x40): # bit 6
        xfp_flags.append('M-Temp Low Warning')
    if (get_byte(optic_pages, '00h', 90) & 0x20): # bit 5
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 90) & 0x10): # bit 4
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 90) & 0x8):  # bit 3
        xfp_flags.append('M-TX Bias High Warning')
    if (get_byte(optic_pages, '00h', 90) & 0x4):  # bit 2
        xfp_flags.append('M-TX Bias Low Warning')
    if (get_byte(optic_pages, '00h', 90) & 0x2):  # bit 1
        xfp_flags.append('M-Tx Power High Warning')
    if (get_byte(optic_pages, '00h', 90) & 0x1):  # bit 0
        xfp_flags.append('M-Tx Power Low Warning')

    if (get_byte(optic_pages, '00h', 91) & 0x80): # bit 7
        xfp_flags.append('M-Rx Power High Warning')
    if (get_byte(optic_pages, '00h', 91) & 0x40): # bit 6
        xfp_flags.append('M-Rx Power Low Warning')
    if (get_byte(optic_pages, '00h', 91) & 0x20): # bit 5
        xfp_flags.append('M-AUX-1 High Warning')
    if (get_byte(optic_pages, '00h', 91) & 0x10): # bit 4
        xfp_flags.append('M-AUX-1 Low Warning')
    if (get_byte(optic_pages, '00h', 91) & 0x2):  # bit 1
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 91) & 0x1):  # bit 0
        xfp_flags.append('Reserved')

    if (get_byte(optic_pages, '00h', 92) & 0x80): # bit 7
        xfp_flags.append('M-TX Not Ready')
    if (get_byte(optic_pages, '00h', 92) & 0x40): # bit 6
        xfp_flags.append('M-TX Fault')
    if (get_byte(optic_pages, '00h', 92) & 0x20): # bit 5
        xfp_flags.append('M-TX CDR not Locked')
    if (get_byte(optic_pages, '00h', 92) & 0x10): # bit 4
        xfp_flags.append('M-RX not Ready')
    if (get_byte(optic_pages, '00h', 92) & 0x8):  # bit 3
        xfp_flags.append('M-RX LOS')
    if (get_byte(optic_pages, '00h', 92) & 0x4):  # bit 2
        xfp_flags.append('M-RX CDR not Locked')
    if (get_byte(optic_pages, '00h', 92) & 0x2):  # bit 1
        xfp_flags.append('M-Module not Ready')
    if (get_byte(optic_pages, '00h', 92) & 0x1):  # bit 0
        xfp_flags.append('M-Reset Complete')

    if (get_byte(optic_pages, '00h', 93) & 0x80): # bit 7
        xfp_flags.append('M-APD Supply Fault')
    if (get_byte(optic_pages, '00h', 93) & 0x40): # bit 6
        xfp_flags.append('M-TEC Fault')
    if (get_byte(optic_pages, '00h', 93) & 0x20): # bit 5
        xfp_flags.append('M-Wavelength Unlocked')
    if (get_byte(optic_pages, '00h', 93) & 0x10): # bit 4
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 93) & 0x8):  # bit 3
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 93) & 0x4):  # bit 2
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 93) & 0x2):  # bit 1
        xfp_flags.append('Reserved')
    if (get_byte(optic_pages, '00h', 93) & 0x1):  # bit 0
        xfp_flags.append('Reserved')

    if (get_byte(optic_pages, '00h', 94) & 0x80): # bit 7
        xfp_flags.append('M-VCC5 High Alarm')
    if (get_byte(optic_pages, '00h', 94) & 0x40): # bit 6
        xfp_flags.append('M-VCC5 Low Alarm')
    if (get_byte(optic_pages, '00h', 94) & 0x20): # bit 5
        xfp_flags.append('M-VCC3 High Alarm')
    if (get_byte(optic_pages, '00h', 94) & 0x10): # bit 4
        xfp_flags.append('M-VCC3 Low Alarm')
    if (get_byte(optic_pages, '00h', 94) & 0x8):  # bit 3
        xfp_flags.append('M-VCC2 High Alarm')
    if (get_byte(optic_pages, '00h', 94) & 0x4):  # bit 2
        xfp_flags.append('M-VCC2 Low Alarm')
    if (get_byte(optic_pages, '00h', 94) & 0x2):  # bit 1
        xfp_flags.append('M-Vee5 High Alarm')
    if (get_byte(optic_pages, '00h', 94) & 0x1):  # bit 0
        xfp_flags.append('M-Vee5 Low Alarm')

    if (get_byte(optic_pages, '00h', 95) & 0x80): # bit 7
        xfp_flags.append('M-VCC5 High Warning')
    if (get_byte(optic_pages, '00h', 95) & 0x40): # bit 6
        xfp_flags.append('M-VCC5 Low Warning')
    if (get_byte(optic_pages, '00h', 95) & 0x20): # bit 5
        xfp_flags.append('M-VCC3 High Warning')
    if (get_byte(optic_pages, '00h', 95) & 0x10): # bit 4
        xfp_flags.append('M-VCC3 Low Warning')
    if (get_byte(optic_pages, '00h', 95) & 0x8):  # bit 3
        xfp_flags.append('M-VCC2 High Warning')
    if (get_byte(optic_pages, '00h', 95) & 0x4):  # bit 2
        xfp_flags.append('M-VCC2 Low Warning')
    if (get_byte(optic_pages, '00h', 95) & 0x2):  # bit 1
        xfp_flags.append('M-Vee5 High Warning')
    if (get_byte(optic_pages, '00h', 95) & 0x1):  # bit 0
        xfp_flags.append('M-Vee5 Low Warning')

    comma=','
    print("XFP Flags:", comma.join(xfp_flags))

def read_optic_xfp_ad_readout():
    # INF-8077 I Table 41
    xfp_temp = (get_byte(optic_pages, '00h', 96)<<8)+get_byte(optic_pages, '00h', 97)
    xfp_tx_bias = (get_byte(optic_pages, '00h', 100)<<8)+get_byte(optic_pages, '00h', 101)
    xfp_tx_power = (get_byte(optic_pages, '00h', 102)<<8)+get_byte(optic_pages, '00h', 103)
    xfp_rx_power = (get_byte(optic_pages, '00h', 104)<<8)+get_byte(optic_pages, '00h', 105)
    xfp_aux1 = (get_byte(optic_pages, '00h', 106)<<8)+get_byte(optic_pages, '00h', 107)
    xfp_aux2 = (get_byte(optic_pages, '00h', 108)<<8)+get_byte(optic_pages, '00h', 109)
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
        
    Returns:
        bool: True if unified processing succeeded, False otherwise
    """
    if not SPEC_MODULES_AVAILABLE:
        print("Warning: Specification modules not available, falling back to legacy processing")
        return False
   
    if VERBOSE:
        print(f"\n=== Processing {optic_type} Module ===")
   
    # Determine optic type and use appropriate parser
    if optic_type in ['QSFP-DD', 'CMIS']:
        try:
            cmis_data = oif_cmis.parse_cmis_data_centralized(page_dict)
            oif_cmis.output_cmis_data_unified(cmis_data)
            return True
        except Exception as e:
            print(f"Error processing CMIS data: {e}")
            print("Falling back to legacy processing...")
            return False
   
    elif optic_type in ['SFP+', 'SFP']:
        try:
            sff8472_data = sff_8472.parse_sff8472_data_centralized(page_dict)
            sff_8472.output_sff8472_data_unified(sff8472_data)
            return True
        except Exception as e:
            print(f"Error processing SFF-8472 data: {e}")
            print("Falling back to legacy processing...")
            return False
   
    elif optic_type in ['QSFP+', 'QSFP28']:
        try:
            sff8636_data = sff_8636.parse_sff8636_data_centralized(page_dict)
            sff_8636.output_sff8636_data_unified(sff8636_data)
            return True
        except Exception as e:
            print(f"Error processing SFF-8636 data: {e}")
            print("Falling back to legacy processing...")
            return False
   
    else:
        print(f"Unknown optic type: {optic_type}")
        print("Falling back to legacy processing...")
        return False

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
        optic_type, optic_type_text = read_optic_type() # SFF
        print(f"read_optic_type = {optic_type} ({optic_type_text})")
       
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
               
                if VERBOSE:
                    print(f"Attempting unified processing for {optic_type_name}...")
                    print(f"Available pages: {list(optic_pages.keys())}")
                    print(f"Page sizes: {[(k, len(v)) for k, v in optic_pages.items()]}")
                if process_optic_data_unified(optic_pages, optic_type_name):
                    if VERBOSE:
                        print("Unified processing completed successfully")
                    return  # Exit early if unified processing succeeds
                else:
                    if VERBOSE:
                        print("Unified processing failed, falling back to legacy processing...")
            except Exception as e:
                if VERBOSE:
                    print(f"Unified processing failed: {e}")
                    print("Falling back to legacy processing...")
        else:
            if VERBOSE:
                print("Specification modules not available, using legacy processing...")
       
        cmis_ver_major = 0
        if optic_type > 0x18:
            cmis_ver_major = get_byte(optic_pages, '00h', 1) >> 4
            cmis_ver_minor = get_byte(optic_pages, '00h', 1) & 0xf
            print(f"CMIS Version: {cmis_ver_major}.{cmis_ver_minor}")
        elif optic_type == 0x18:
            cmis_ver_major = get_byte(optic_pages, '00h', 1) >> 4
            cmis_ver_minor = get_byte(optic_pages, '00h', 1) & 0xf
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
            if (get_byte(optic_pages, '00h', 127) == 0x01):
                read_optic_connector_type(get_byte(optic_pages, '00h', 130))
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
            if '10h' in optic_pages:
                oif_cmis.read_cmis_page_10h(optic_pages)  # Page 10h (Lane Control)
            if '11h' in optic_pages:
                oif_cmis.read_cmis_page_11h(optic_pages)  # Page 11h (Lane Status)
            if '04h' in optic_pages:
                oif_cmis.read_cmis_page_04h(optic_pages)  # Page 04h (Vendor-specific)
            if '12h' in optic_pages:
                oif_cmis.read_cmis_page_12h(optic_pages)  # Page 12h (Tunable Laser)
            if '13h' in optic_pages:
                oif_cmis.read_cmis_page_13h(optic_pages)  # Page 13h (Diagnostics)
            if '06h' in optic_pages:
                oif_cmis.read_cmis_page_06h(optic_pages)  # Page 06h (SNR/OSNR Values)
            if '25h' in optic_pages:
                oif_cmis.read_cmis_page_25h(optic_pages)  # Page 25h (Vendor-specific)
            
            # Read PAM4 VDM observables (Pages 20h-27h)
            if any(f'{i:02x}h' in optic_pages for i in range(0x20, 0x28)):
                print("Reading PAM4 VDM observables...")
                oif_cmis.read_cmis_vdm_pam4_pages(optic_pages)  # VDM Pages 20h-27h (PAM4 Observables)
           
            # Legacy functions for backward compatibility (keeping only essential ones)
            oif_cmis.read_cmis_global_status_detailed(optic_pages)
           
            # Only read copper attenuation if this is a copper module
            # Check media interface technology to determine if it's copper
            tech = get_byte(optic_pages, '100', 0x87) if '100' in optic_pages else 0  # Media Interface Technology
            copper_techs = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x30, 0x31, 0x32, 0x33, 0x34]  # Copper technologies
            if tech in copper_techs:
                oif_cmis.read_cmis_copper_attenuation(optic_pages)
            # Suppress copper attenuation message for optical modules
            oif_cmis.read_cmis_media_lane_info(optic_pages)
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
        elif optic_type in ['0B', '0C', '0D', '11']:  # QSFP/QSFP+/QSFP28
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
        elif optic_type in ['0E', '12']:  # CXP/CXP2
            read_cxp_data()
        elif optic_type == 0x19:  # OSFP
            read_osfp_data()
        elif optic_type == 0x1A:  # SFP-DD
            read_sfpdd_data()
        elif optic_type == 0x1B:  # DSFP
            read_dsfp_data()
        elif optic_type in ['1C', '1D']:  # MiniLink/OcuLink
            read_minilink_data()
        elif optic_type == 0x00:  # Unknown or unspecified
            read_unknown_optic_data()
        elif optic_type in [0x04, 0x05, 0x07, 0x08, 0x09, 0x0A, 0x0F, 0x10, 0x13, 0x14, 0x15, 0x16, 0x17]:  # Legacy types
            read_legacy_optic_data()
        else:
            if optic_type == 0x03:
                return optic_sff_read
            print("Reading standard SFF module data...")
            read_optic_mod_def()
            read_optic_connector_type(get_byte(optic_pages, '00h', 2))
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
            sff_8472.read_optic_distances(optic_pages)
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
            if (real_hardware and (get_byte(optic_pages, '00h', 110) & 0x40) | (get_byte(optic_pages, '00h', 110) & 0x80)):
                print("%x would be %x" % (get_byte(optic_pages, '00h', 110), (get_byte(optic_pages, '00h', 110)&~(0x80 + 0x40))))
                try:
                    bus.write_byte_data(address_one, 110, get_byte(optic_pages, '00h', 110)&~(0x80 + 0x40))
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
                if (get_byte(optic_pages, '00h', 65) & 0x40): # bit 6 - SFF-8690 4.1
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
        read_optic_connector_type(get_byte(optic_pages, '00h', 2))
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
        sff_8472.read_optic_distances(optic_pages)
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
        read_optic_connector_type(get_byte(optic_pages, '00h', 2))
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
        sff_8472.read_optic_distances(optic_pages)
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
        if '10h' in optic_pages:
            oif_cmis.read_cmis_page_10h(optic_pages)
        if '11h' in optic_pages:
            oif_cmis.read_cmis_page_11h(optic_pages)
        if '04h' in optic_pages:
            oif_cmis.read_cmis_page_04h(optic_pages)
        if '12h' in optic_pages:
            oif_cmis.read_cmis_page_12h(optic_pages)
        if '13h' in optic_pages:
            oif_cmis.read_cmis_page_13h(optic_pages)
        if '06h' in optic_pages:
            oif_cmis.read_cmis_page_06h(optic_pages)  # Page 06h (SNR/OSNR Values)
        if '25h' in optic_pages:
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
        read_optic_connector_type(get_byte(optic_pages, '00h', 2))
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
        sff_8472.read_optic_distances(optic_pages)
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
        read_optic_connector_type(get_byte(optic_pages, '00h', 2))
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
        sff_8472.read_optic_distances(optic_pages)
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
        read_optic_connector_type(get_byte(optic_pages, '00h', 2))
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
        sff_8472.read_optic_distances(optic_pages)
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
        optic_type, optic_type_text = read_optic_type()
        print(f"Detected optic type: 0x{optic_type:02x} ({optic_type_text})")
       
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
       
        optic_type, optic_type_text = read_optic_type()
        print(f"Legacy optic type: 0x{optic_type:02x} ({optic_type_text})")
       
        # Try to read basic information
        try:
            read_optic_mod_def()
        except:
            print("Module definition not available")
           
        try:
            read_optic_connector_type(get_byte(optic_pages, '00h', 2))
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

# Add missing functions that are called but don't exist in this file

def read_optic_signaling_rate():
    """Read optic signaling rate - placeholder function"""
    print("Signaling Rate: Function not yet implemented")

def read_optic_rev():
    """Read optic revision - placeholder function"""
    print("Revision: Function not yet implemented")

def read_optic_frequency():
    """Read optic frequency - placeholder function"""
    print("Frequency: Function not yet implemented")

def read_optic_monitoring_type():
    """Read optic monitoring type - placeholder function"""
    print("Monitoring Type: Function not yet implemented")

def read_option_values():
    """Read option values - placeholder function"""
    print("Option Values: Function not yet implemented")

def read_enhanced_options():
    """Read enhanced options - placeholder function"""
    print("Enhanced Options: Function not yet implemented")

def read_sff_8472_compliance():
    """Read SFF-8472 compliance - placeholder function"""
    print("SFF-8472 Compliance: Function not yet implemented")

def read_sfp_status_bits():
    """Read SFP status bits - placeholder function"""
    print("SFP Status Bits: Function not yet implemented")

def read_optic_temperature():
    """Read optic temperature - placeholder function"""
    print("Temperature: Function not yet implemented")

def read_optic_rxpower():
    """Read optic RX power - placeholder function"""
    print("RX Power: Function not yet implemented")

def read_optic_txpower():
    """Read optic TX power - placeholder function"""
    print("TX Power: Function not yet implemented")

def read_laser_temperature():
    """Read laser temperature - placeholder function"""
    print("Laser Temperature: Function not yet implemented")

def read_optic_vcc():
    """Read optic VCC - placeholder function"""
    print("VCC: Function not yet implemented")

def read_measured_current():
    """Read measured current - placeholder function"""
    print("Measured Current: Function not yet implemented")

def read_alarm_warning_thresholds():
    """Read alarm warning thresholds - placeholder function"""
    print("Alarm Warning Thresholds: Function not yet implemented")

def check_alarm_status():
    """Check alarm status - placeholder function"""
    print("Alarm Status: Function not yet implemented")

def read_ext_cal_constants():
    """Read extended calibration constants - placeholder function"""
    print("Extended Calibration Constants: Function not yet implemented")

def read_vendor_specific():
    """Read vendor specific data - placeholder function"""
    print("Vendor Specific: Function not yet implemented")

def decode_dwdm_data():
    """Decode DWDM data - placeholder function"""
    print("DWDM Data: Function not yet implemented")

def read_cmis_lower_memory():
    """Read CMIS lower memory - placeholder function"""
    print("CMIS Lower Memory: Function not yet implemented")

def read_cmis_page_00h():
    """Read CMIS page 00h - placeholder function"""
    print("CMIS Page 00h: Function not yet implemented")

def read_cmis_page_01h():
    """Read CMIS page 01h - placeholder function"""
    print("CMIS Page 01h: Function not yet implemented")


# Add at the top, after imports
VERBOSE = False

# ...

# In main, add the verbose flag
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Read and decode optic module data')
    parser.add_argument('-f', '--file', help='Parse optic data from file instead of hardware')
    parser.add_argument('--no-hardware', action='store_true', help='Disable hardware access (for testing)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose/debug output')
    args = parser.parse_args()
    
    VERBOSE = args.verbose
    
    if args.no_hardware:
        real_hardware = False
    
    if args.file:
        # Parse from file
        if parse_optic_file(args.file):
            process_optic_data(None, 0, 0, 0, "file")
    else:
        # Poll hardware
        poll_busses()

# ...
# In process_optic_data and process_optic_data_unified, wrap debug prints:
# Example:
# if VERBOSE:
#     print(f"Attempting unified processing for {optic_type_name}...")
# ...
# (Do this for all debug/info prints as described)
