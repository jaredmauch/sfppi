#!/usr/bin/env python3
"""
OIF-CMIS (Common Management Interface Specification) parsing functions
Based on OIF-CMIS 5.3 specification

This module provides centralized parsing and unified output for QSFP-DD/CMIS modules.
"""

import struct
import math
from enum import Enum
from sff_8024 import CONNECTOR_TYPES, IDENTIFIERS

# CMIS Constants and Enums based on OIF-CMIS 5.3 specification

class ModuleState(Enum):
    """Module State Encodings (Table 8-7)"""
    RESERVED_000 = 0x00
    MODULE_LOW_PWR = 0x01
    MODULE_PWR_UP = 0x02
    MODULE_READY = 0x03
    MODULE_PWR_DN = 0x04
    MODULE_FAULT = 0x05
    MODULE_TX_OFF = 0x06
    MODULE_TX_TUNING = 0x07
    MODULE_RX_TUNING = 0x08
    MODULE_LOOPBACK = 0x09
    MODULE_TEST = 0x0A
    MODULE_FAULT_PWR_DN = 0x0B
    MODULE_TX_FAULT = 0x0C
    MODULE_RX_FAULT = 0x0D
    MODULE_TX_RX_FAULT = 0x0E
    MODULE_TX_RX_FAULT_PWR_DN = 0x0F

class MediaInterfaceTechnology(Enum):
    """Media Interface Technology encodings (Table 8-40)"""
    VCSEL_850NM = 0x00
    VCSEL_1310NM = 0x01
    VCSEL_1550NM = 0x02
    FP_LASER_1310NM = 0x03
    DFB_LASER_1310NM = 0x04
    DFB_LASER_1550NM = 0x05
    EML_1310NM = 0x06
    EML_1550NM = 0x07
    OTHERS = 0x08
    DFB_LASER_1490NM = 0x09
    COPPER_PASSIVE_UNEQUALIZED = 0x0A
    COPPER_PASSIVE_EQUALIZED = 0x0B
    COPPER_NEAR_FAR_LIMITING = 0x0C
    COPPER_FAR_LIMITING = 0x0D
    COPPER_NEAR_LIMITING = 0x0E
    COPPER_LINEAR_ACTIVE = 0x0F  # deprecated
    C_BAND_TUNABLE = 0x10
    L_BAND_TUNABLE = 0x11
    COPPER_NEAR_FAR_LINEAR = 0x12
    COPPER_FAR_LINEAR = 0x13
    COPPER_NEAR_LINEAR = 0x14

# VDM Observable Types (Table 8-170)
VDM_OBSERVABLE_TYPES = {
    0: "Not Used indicator",
    1: "Laser Age (0% at BOL, 100% EOL) (Media Lane)",
    2: "TEC Current (Module)",
    3: "Laser Frequency Error (Media Lane)",
    4: "Laser Temperature (Media Lane)",
    5: "SNR (dB) Media Input (Media Lane)",
    6: "SNR (dB) Host Input (Lane)",
    7: "PAM4 Level Transition Parameter Media Input (Media Lane)",
    8: "PAM4 Level Transition Parameter Host Input (Lane)",
    9: "Pre-FEC BER Minimum Sample Media Input (Data Path)",
    10: "Pre-FEC BER Minimum Sample Host Input (Data Path)",
    11: "Pre-FEC BER Maximum Sample Media Input (Data Path)",
    12: "Pre-FEC BER Maximum Sample Host Input (Data Path)",
    13: "Pre-FEC BER Sample Average Media Input (Data Path)",
    14: "Pre-FEC BER Sample Average Host Input (Data Path)",
    15: "Pre-FEC BER Current Sample Media Input (Data Path)",
    16: "Pre-FEC BER Current Sample Host Input (Data Path)",
    17: "FERC Minimum Sample Value Media Input (Data Path)",
    18: "FERC Minimum Sample Value Host Input (Data Path)",
    19: "FERC Maximum Sample Value Media Input (Data Path)",
    20: "FERC Maximum Sample Value Host Input (Data Path)",
    21: "FERC Sample Average Value Media Input (Data Path)",
    22: "FERC Sample Average Value Host Input (Data Path)",
    23: "FERC Current Sample Value Media Input (Data Path)",
    24: "FERC Current Sample Value Host Input (Data Path)",
    25: "FERC Total Accumulated Media Input (Data Path)",
    26: "FERC Total Accumulated Host Input (Data Path)",
    27: "SEWmax Minimum Sample Value Media Input (Data Path)",
    28: "SEWmax Minimum Sample Value Host Input (Data Path)",
    29: "SEWmax Maximum Sample Value Media Input (Data Path)",
    30: "SEWmax Maximum Sample Value Host Input (Data Path)",
    31: "SEWmax Sample Average Value Media Input (Data Path)",
    32: "SEWmax Sample Average Value Host Input (Data Path)",
    33: "SEWmax Current Sample Value Media Input (Data Path)",
    34: "SEWmax Current Sample Value Host Input (Data Path)",
    # Types 35-76 are Reserved
    77: "Vcc2p6 Voltage Monitor (Module)",
    78: "Vcc1p8 Voltage Monitor (Module)",
    79: "Vcc1p2 Voltage Monitor (Module)",
    80: "Vcc0p9 Voltage Monitor (Module)",
    81: "Vcc0p7A Voltage Monitor (Module)",
    82: "Vcc0p7B Voltage Monitor (Module)",
    83: "Vcc12 Voltage Monitor (Module)",
    84: "ELS Input Power (Lane=Laser ID)"
    # Types 85-99 are Reserved for CPO Observables
    # Types 100-127 are Custom Observables
    # Types 128-255 are Restricted OIF
}

# CDB Command IDs (Table 8-178)
CDB_COMMANDS = {
    0x0000: "Query Status",
    0x0001: "Enter Password",
    0x0002: "Change Password",
    0x0004: "Abort",
    0x0040: "Module Features",
    0x0041: "Firmware Management Features",
    0x0042: "Performance Monitoring Features",
    0x0043: "BERT and Diagnostics Features",
    0x0044: "Security Features and Capabilities",
    0x0045: "Externally Defined Features",
    0x0050: "Get Application Attributes",
    0x0051: "Get Interface Code Description",
    0x0100: "Get Firmware Info",
    0x0101: "Start Firmware Download",
    0x0102: "Abort Firmware Download",
    0x0103: "Write Firmware Block LPL",
    0x0104: "Write Firmware Block EPL",
    0x0105: "Read Firmware Block LPL",
    0x0106: "Read Firmware Block EPL",
    0x0107: "Complete Firmware Download",
    0x0108: "Copy Firmware Image",
    0x0109: "Run Firmware Image",
    0x010A: "Commit Image",
    0x0200: "Control PM",
    0x0201: "Get PM Feature Information",
    0x0210: "Get Module PM LPL",
    0x0211: "Get Module PM EPL",
    0x0212: "Get PM Host Side LPL",
    0x0213: "Get PM Host Side EPL",
    0x0214: "Get PM Media Side LPL",
    0x0215: "Get PM Media Side EPL",
    0x0216: "Get Data Path PM LPL",
    0x0217: "Get Data Path PM EPL",
    0x0220: "Get Data Path RMON Statistics",
    0x0230: "Control FEC Symbol Error Weight Histogram",
    0x0231: "Get FEC Symbol Error Weight Histogram",
    0x0232: "Control Max FEC Symbol Error Weight",
    0x0233: "Get Max FEC Symbol Error Weight",
    0x0280: "Data Monitoring and Recording Controls",
    0x0281: "Data Monitoring and Recording Advertisements",
    0x0290: "Temperature Histogram",
    0x0380: "Loopbacks",
    0x0390: "PAM4 Histogram (Reserved)",
    0x03A0: "Eye Monitors (Reserved)",
    0x0400: "Get Initial Device ID Certificate in LPL",
    0x0401: "Get Initial Device ID Certificate in EPL",
    0x0402: "Set Digest To Sign given in LPL",
    0x0403: "Set Digest To Sign given in EPL",
    0x0404: "Get Digest Signature in LPL",
    0x0405: "Get Digest Signature in EPL"
}

# Application Codes (Table 8-8)
APPLICATION_CODES = {
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
    0x10: "800GAUI-8 C2M (PAM4)",
    0x11: "100GAUI-1 C2M (NRZ)",
    0x12: "200GAUI-2 C2M (PAM4)",
    0x13: "400GAUI-4 C2M (PAM4)",
    0x14: "800GAUI-4 C2M (PAM4)",
    0x15: "100GAUI-2 C2M (NRZ)",
    0x16: "200GAUI-4 C2M (NRZ)",
    0x17: "400GAUI-8 C2M (NRZ)",
    0x18: "800GAUI-8 C2M (NRZ)",
    0x19: "100GAUI-1 C2M (PAM4)",
    0x1A: "200GAUI-2 C2M (NRZ)",
    0x1B: "400GAUI-4 C2M (NRZ)",
    0x1C: "800GAUI-4 C2M (NRZ)",
    0x1D: "100GAUI-2 C2M (PAM4)",
    0x1E: "200GAUI-4 C2M (PAM4)",
    0x1F: "400GAUI-8 C2M (PAM4)",
    0x20: "800GAUI-8 C2M (PAM4)"
}

# Power Class Names
POWER_CLASS_NAMES = {
    0: "Power Class 1",
    1: "Power Class 2", 
    2: "Power Class 3",
    3: "Power Class 4",
    4: "Power Class 5",
    5: "Power Class 6",
    6: "Power Class 7",
    7: "Power Class 8"
}

# Connector Types (SFF-8024, as referenced by CMIS 5.3 Table 8-33)
CONNECTOR_TYPES = {
    0x00: "Unknown or unspecified",
    0x01: "SC",
    0x02: "FC Style 1 copper",
    0x03: "FC Style 2 copper",
    0x04: "BNC/TNC",
    0x05: "FC coax headers",
    0x06: "Fiber Jack",
    0x07: "LC",
    0x08: "MT-RJ",
    0x09: "MU",
    0x0A: "SG",
    0x0B: "Optical Pigtail",
    0x0C: "MPO 1x12",
    0x0D: "MPO 2x12",
    0x0E: "MPO 2x16",
    0x0F: "MPO 1x16",
    0x10: "HSSDC II",
    0x11: "Copper Pigtail",
    0x12: "RJ45",
    0x13: "No separable connector",
    0x14: "MXC 16",
    0x15: "CS optical",
    0x16: "SN optical",
    0x17: "MPO 16",
    0x18: "MPO 32",
    0x19: "MPO 24",
    0x1A: "MPO 48",
    0x1B: "MPO 72",
    0x1C: "MPO 96",
    0x1D: "MPO 144",
    0x1E: "MPO 288",
    0x1F: "MPO 12",
    0x20: "MXC 2x16",
    0x21: "Copper Pigtail",
    0x22: "RJ45",
    0x23: "No separable connector",
    0x24: "CS optical connector",
    0x25: "CS optical connector",
    0x26: "SN optical connector (Mini CS)",
    0x27: "MPO 2x12",
    0x28: "MPO 1x16"
    # Add more as defined in SFF-8024 if needed
}
# For all undefined codes, output logic will display 'Reserved' or 'Unknown'.

# Management Characteristics
MANAGEMENT_CHARACTERISTICS = {
    'memory_model': {
        0: 'Paged',
        1: 'Flat'
    },
    'configuration_support': {
        0: 'All',
        1: 'Only'
    }
}

# Module State Names (for backward compatibility)
MODULE_STATE_NAMES = {
    0x00: "Reserved",
    0x01: "ModuleLowPwr",
    0x02: "ModulePwrUp", 
    0x03: "ModuleReady",
    0x04: "ModulePwrDn",
    0x05: "ModuleFault",
    0x06: "ModuleTxOff",
    0x07: "ModuleTxTuning",
    0x08: "ModuleRxTuning",
    0x09: "ModuleLoopback",
    0x0A: "ModuleTest",
    0x0B: "ModuleFaultPwrDn",
    0x0C: "ModuleTxFault",
    0x0D: "ModuleRxFault",
    0x0E: "ModuleTxRxFault",
    0x0F: "ModuleTxRxFaultPwrDn"
}

# Media Interface Technology Names (for backward compatibility)
MEDIA_INTERFACE_TECH_NAMES = {
    0x00: '850 nm VCSEL',
    0x01: '1310 nm VCSEL',
    0x02: '1550 nm VCSEL',
    0x03: '1310 nm FP laser',
    0x04: '1310 nm DFB laser',
    0x05: '1550 nm DFB laser',
    0x06: '1310 nm EML',
    0x07: '1550 nm EML',
    0x08: 'Others',
    0x09: '1490 nm DFB laser',
    0x0A: 'Copper cable, passive, unequalized',
    0x0B: 'Copper cable, passive, equalized',
    0x0C: 'Copper cable with near and far end limiting active equalizers',
    0x0D: 'Copper cable with far end limiting active equalizers',
    0x0E: 'Copper cable with near end limiting active equalizers',
    0x0F: 'Copper cable with linear active equalizers (deprecated)',
    0x10: 'C-band tunable laser',
    0x11: 'L-band tunable laser',
    0x12: 'Copper cable with near and far end linear active equalizers',
    0x13: 'Copper cable with far end linear active equalizers',
    0x14: 'Copper cable with near end linear active equalizers'
}

# Application Code Names (Table 8-8)
APPLICATION_CODE_NAMES = {
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
    0x10: "100GAUI-2 C2M (NRZ)",
    0x11: "200GAUI-4 C2M (NRZ)",
    0x12: "400GAUI-8 C2M (NRZ)",
    0x13: "50GAUI-1 C2M (NRZ)",
    0x14: "100GAUI-1 C2M (NRZ)",
    0x15: "200GAUI-2 C2M (NRZ)",
    0x16: "400GAUI-4 C2M (NRZ)",
    0x17: "100GAUI-1 C2M (PAM4)",
    0x18: "200GAUI-2 C2M (PAM4)",
    0x19: "400GAUI-4 C2M (PAM4)",
    0x1A: "25GAUI-1 C2M (NRZ) - 25G",
    0x1B: "50GAUI-1 C2M (NRZ) - 50G",
    0x1C: "100GAUI-1 C2M (NRZ) - 100G",
    0x1D: "200GAUI-1 C2M (NRZ) - 200G",
    0x1E: "400GAUI-1 C2M (NRZ) - 400G",
    0x1F: "800GAUI-1 C2M (NRZ) - 800G"
}

# NOTE: CMIS Upper Page 00h Byte Offsets (OIF-CMIS 5.3)
# -----------------------------------------------------------------------------
# All CMIS parsing functions in this file have been updated to use the correct
# relative byte offsets within Upper Page 00h (0x80) as per the OIF-CMIS 5.3 spec.
# The file parsing now correctly maps addresses 0x80-0xFF to bytes 0-127 in the page.
# The specification shows that Page 00h starts at byte 128, so we need to subtract 128
# from the absolute spec offsets to get the relative offset within the page data.
# For example:
#   - Vendor Name: bytes 129-144 → relative 1-16 (129-128 = 1, 144-128 = 16)
#   - Vendor OUI: bytes 145-147 → relative 17-19 (145-128 = 17, 147-128 = 19)
#   - Vendor Part Number: bytes 148-163 → relative 20-35 (148-128 = 20, 163-128 = 35)
#   - Vendor Revision: bytes 164-165 → relative 36-37 (164-128 = 36, 165-128 = 37)
#   - Vendor Serial Number: bytes 166-181 → relative 38-53 (166-128 = 38, 181-128 = 53)
#   - Date Code: bytes 182-189 → relative 54-61 (182-128 = 54, 189-128 = 61)
#   - CLEI Code: bytes 190-199 → relative 62-71 (190-128 = 62, 199-128 = 71)
#   - Module Power: bytes 200-201 → relative 72-73 (200-128 = 72, 201-128 = 73)
#   - Cable Length: byte 202 → relative 74 (202-128 = 74)
#   - Connector Type: byte 203 → relative 75 (203-128 = 75)
#   - Attenuation: bytes 204-209 → relative 76-81 (204-128 = 76, 209-128 = 81)
#   - Media Lane Information: byte 210 → relative 82 (210-128 = 82)
#   - Media Interface Technology: byte 212 → relative 84 (212-128 = 84)
# Always use these relative offsets when reading from page_dict['80h'] (Upper Page 00h).
# -----------------------------------------------------------------------------

def parse_cmis_data_centralized(page_dict, verbose=False, debug=False):
    """Parse CMIS data using centralized approach with correct byte offsets (relative to page start, per OIF-CMIS 5.3)."""
    cmis_data = {
        'vendor_info': {},
        'media_info': {},
        'cable_info': {},
        'monitoring': {},
        'thresholds': {},
        'application_info': {}
    }
    # Vendor Information (Upper Memory, bytes 1-71 in 80h page)
    if '80h' in page_dict and len(page_dict['80h']) >= 73:
        if debug:
            print(f"DEBUG: 80h page data (first 32 bytes): {page_dict['80h'][:32]}")
        # Vendor Name (bytes 129-144 → relative 1-16)
        vendor_name_bytes = page_dict['80h'][1:17]
        if debug:
            print(f"DEBUG: Vendor Name raw bytes: {vendor_name_bytes}")
        vendor_name = ''.join([chr(b) for b in vendor_name_bytes if b != 0]).strip()
        if vendor_name:
            cmis_data['vendor_info']['name'] = vendor_name
        # Vendor OUI (bytes 145-147 → relative 17-19)
        oui_bytes = page_dict['80h'][17:20]
        if debug:
            print(f"DEBUG: Vendor OUI raw bytes: {oui_bytes}")
        oui = ''.join([f'{b:02x}' for b in oui_bytes])
        cmis_data['vendor_info']['oui'] = oui
        # Part Number (bytes 148-163 → relative 20-35)
        part_number_bytes = page_dict['80h'][20:36]
        part_number = ''.join([chr(b) for b in part_number_bytes if b != 0]).strip()
        if part_number:
            cmis_data['vendor_info']['part_number'] = part_number
        # Revision (bytes 164-165 → relative 36-37)
        revision_bytes = page_dict['80h'][36:38]
        revision = ''.join([chr(b) for b in revision_bytes if b != 0]).strip()
        if revision:
            cmis_data['vendor_info']['revision'] = revision
        # Serial Number (bytes 166-181 → relative 38-53)
        serial_bytes = page_dict['80h'][38:54]
        serial = ''.join([chr(b) for b in serial_bytes if b != 0]).strip()
        if serial:
            cmis_data['vendor_info']['serial_number'] = serial
        # Date Code (bytes 182-189 → relative 54-61)
        date_bytes = page_dict['80h'][54:62]
        date_code = ''.join([chr(b) for b in date_bytes if b != 0]).strip()
        if date_code:
            cmis_data['vendor_info']['date_code'] = date_code
        # CLEI Code (bytes 190-199 → relative 62-71)
        clei_bytes = page_dict['80h'][62:72]
        clei_code = ''.join([chr(b) for b in clei_bytes if b != 0]).strip()
        if clei_code:
            cmis_data['vendor_info']['clei_code'] = clei_code
    # Media Information (Upper Memory, bytes 72+)
    if '80h' in page_dict and len(page_dict['80h']) >= 85:
        # Power Class (byte 200 → relative 72)
        power_class_byte = page_dict['80h'][72]
        power_class = (power_class_byte >> 5) & 0x07
        cmis_data['media_info']['power_class'] = power_class
        # Max Power (byte 201 → relative 73)
        max_power_raw = page_dict['80h'][73]
        if debug:
            print(f"DEBUG: Max Power raw byte: {max_power_raw}")
        max_power = max_power_raw * 0.25  # 0.25W units
        cmis_data['media_info']['max_power'] = max_power
        # Connector Type (byte 203 → relative 75)
        connector_type = page_dict['80h'][75]
        cmis_data['media_info']['connector_type'] = connector_type
        # Interface Technology (byte 212 → relative 84)
        interface_tech = page_dict['80h'][84]
        cmis_data['media_info']['interface_technology'] = interface_tech
    # Supported Lanes (byte 210 → relative 82)
    if '80h' in page_dict and len(page_dict['80h']) >= 83:
        lane_info = page_dict['80h'][82]
        supported_lanes = []
        for lane in range(8):
            if not (lane_info & (1 << lane)):
                supported_lanes.append(lane + 1)
        cmis_data['media_info']['supported_lanes'] = supported_lanes
    # Nominal Wavelength (Page 01h, bytes 138-139 → relative 10-11)
    nominal_wavelength_nm = None
    if '01h' in page_dict and len(page_dict['01h']) >= 12:
        # Big-endian
        high = page_dict['01h'][10]
        low = page_dict['01h'][11]
        nominal_wavelength_raw = (high << 8) | low
        nominal_wavelength_nm = nominal_wavelength_raw * 0.05
        cmis_data['media_info']['nominal_wavelength'] = nominal_wavelength_nm
    # Remove per-lane wavelength calculation from Page 01h (bytes 144-159)
    # If tunable laser (Page 12h) is present, handle lane wavelengths there
    if '12h' in page_dict and len(page_dict['12h']) >= 24:
        # Page 12h: Channel Offset Numbers (bytes 136-151, relative 8x2 for 8 lanes)
        lane_wavelengths = {}
        for lane_num in range(1, 9):
            offset = 8 + (lane_num - 1) * 2  # relative to start of Page 12h
            if offset + 1 < len(page_dict['12h']):
                high = page_dict['12h'][offset]
                low = page_dict['12h'][offset + 1]
                raw = (high << 8) | low
                if raw >= 0x8000:
                    raw_signed = raw - 0x10000
                else:
                    raw_signed = raw
                # Channel offset is in grid units, actual wavelength calculation depends on grid spacing (not handled here)
                lane_wavelengths[f'lane_{lane_num}'] = {'raw': raw_signed}
        if lane_wavelengths:
            cmis_data['media_info']['lane_wavelengths'] = lane_wavelengths
    # Monitoring Data (Lower Memory, bytes 14-25) - Table 8-10
    if '00h' in page_dict and len(page_dict['00h']) >= 26:
        # Temperature Monitor (bytes 14-15), little-endian signed
        if len(page_dict['00h']) >= 16:
            high = page_dict['00h'][14]
            low = page_dict['00h'][15]
            temp_raw = (high << 8) | low
            if temp_raw >= 0x8000:
                temp_raw = temp_raw - 0x10000
            temp_celsius = temp_raw / 256.0
            cmis_data['monitoring']['module'] = cmis_data['monitoring'].get('module', {})
            cmis_data['monitoring']['module']['temperature'] = temp_celsius
        # VCC Monitor (bytes 16-17)
        if len(page_dict['00h']) >= 18:
            vcc_raw = struct.unpack_from('<H', bytes(page_dict['00h'][16:18]))[0]
            vcc_volts = vcc_raw * 0.0001  # Convert from 100 µV increments to volts
            cmis_data['monitoring']['module'] = cmis_data['monitoring'].get('module', {})
            cmis_data['monitoring']['module']['vcc'] = vcc_volts
        # Aux1 Monitor (bytes 18-19)
        if len(page_dict['00h']) >= 20:
            aux1_raw = struct.unpack_from('<h', bytes(page_dict['00h'][18:20]))[0]
            cmis_data['monitoring']['module'] = cmis_data['monitoring'].get('module', {})
            cmis_data['monitoring']['module']['aux1'] = aux1_raw
        # Aux2 Monitor (bytes 20-21)
        if len(page_dict['00h']) >= 22:
            aux2_raw = struct.unpack_from('<h', bytes(page_dict['00h'][20:22]))[0]
            cmis_data['monitoring']['module'] = cmis_data['monitoring'].get('module', {})
            cmis_data['monitoring']['module']['aux2'] = aux2_raw
        # Aux3 Monitor (bytes 22-23)
        if len(page_dict['00h']) >= 24:
            aux3_raw = struct.unpack_from('<h', bytes(page_dict['00h'][22:24]))[0]
            cmis_data['monitoring']['module'] = cmis_data['monitoring'].get('module', {})
            cmis_data['monitoring']['module']['aux3'] = aux3_raw
        # Custom Monitor (bytes 24-25)
        if len(page_dict['00h']) >= 26:
            custom_raw = struct.unpack_from('<h', bytes(page_dict['00h'][24:26]))[0]
            cmis_data['monitoring']['module'] = cmis_data['monitoring'].get('module', {})
            cmis_data['monitoring']['module']['custom'] = custom_raw
    parse_cmis_auxiliary_monitoring(page_dict, cmis_data)
    parse_cmis_thresholds_complete(page_dict, cmis_data)
    # parse_cmis_monitoring_complete(page_dict, cmis_data)  # Disabled to avoid overriding basic monitoring
    parse_cmis_application_descriptors_complete(page_dict, cmis_data)
    parse_cmis_page_support(page_dict, cmis_data)
    parse_cmis_vdm_observables_complete(page_dict, cmis_data)
    parse_cmis_cdb_pam4_histogram(page_dict, cmis_data)
    return cmis_data

def output_cmis_data_unified(cmis_data, verbose=False, debug=False):
    if verbose:
        print("\n=== CMIS Module Information ===")
    # Vendor Information
    if cmis_data.get('vendor_info'):
        if verbose:
            print("\n--- Vendor Information ---")
        vendor_info = cmis_data['vendor_info']
        if 'name' in vendor_info:
            print(f"Vendor Name: {vendor_info['name']}")
        if 'oui' in vendor_info:
            print(f"Vendor OUI: {vendor_info['oui']}")
        if 'part_number' in vendor_info:
            print(f"Part Number: {vendor_info['part_number']}")
        if 'revision' in vendor_info:
            print(f"Revision: {vendor_info['revision']}")
        if 'serial_number' in vendor_info:
            print(f"Serial Number: {vendor_info['serial_number']}")
        if 'date_code' in vendor_info:
            print(f"Date Code: {vendor_info['date_code']}")
        if 'clei_code' in vendor_info:
            print(f"CLEI Code: {vendor_info['clei_code']}")
    # Media Information
    if cmis_data.get('media_info'):
        if verbose:
            print("\n--- Media Information ---")
        media_info = cmis_data['media_info']
        if 'power_class' in media_info:
            power_class = media_info['power_class']
            power_class_name = POWER_CLASS_NAMES.get(power_class, f"Power Class {power_class}")
            print(f"Power Class: {power_class} ({power_class_name})")
        if 'max_power' in media_info:
            print(f"Max Power: {media_info['max_power']}W")
        if 'connector_type' in media_info:
            connector_names = CONNECTOR_TYPES
            connector_name = connector_names.get(media_info['connector_type'], f"Unknown({media_info['connector_type']:02x})")
            print(f"Connector Type: {media_info['connector_type']:02x} ({connector_name})")
        if 'interface_technology' in media_info:
            tech = media_info['interface_technology']
            try:
                tech_enum = MediaInterfaceTechnology(tech)
                print(f"Interface Technology: {tech:02x} ({tech_enum.name})")
            except ValueError:
                print(f"Interface Technology: {tech:02x} (Unknown)")
        if 'supported_lanes' in media_info:
            print(f"Supported Lanes: {media_info['supported_lanes']}")
        if 'nominal_wavelength' in media_info:
            print(f"Wavelength: {media_info['nominal_wavelength']:.2f}nm")
        # Only display lane wavelengths if present and valid
        if 'lane_wavelengths' in media_info:
            supported_lanes = set(media_info.get('supported_lanes', []))
            lane_wavelengths = media_info['lane_wavelengths']
            # Only print header if there are valid lanes to print
            valid_lanes = [lane for lane in lane_wavelengths if (lane_wavelengths[lane].get('nm') is not None and (not supported_lanes or int(lane.split('_')[1]) in supported_lanes))]
            if valid_lanes:
                print("Lane Wavelengths:")
                for lane in valid_lanes:
                    data = lane_wavelengths[lane]
                    # Only print if 'nm' key exists
                    if 'nm' in data:
                        print(f"  {lane}: {data['nm']:.2f} nm (offset: {data.get('offset_nm','?'):+.2f} nm, raw: {data.get('raw','?')})")
            # If no valid lanes, do not print header or error
    # Cable Information
    if cmis_data.get('cable_info'):
        if verbose:
            print("\n--- Cable Information ---")
        cable_info = cmis_data['cable_info']
        if 'length' in cable_info:
            print(f"Cable Length: {cable_info['length']}m")
        if 'attenuation' in cable_info:
            if verbose:
                print("Attenuation:")
            atten = cable_info['attenuation']
            print(f"  5 GHz: {atten['at_5ghz']} dB")
            print(f"  7 GHz: {atten['at_7ghz']} dB")
            print(f"  12.9 GHz: {atten['at_12p9ghz']} dB")
            print(f"  25.8 GHz: {atten['at_25p8ghz']} dB")
            print(f"  53.1 GHz: {atten['at_53p1ghz']} dB")
        if 'interface_data_rate_gbps' in cable_info or 'lane_signaling_rate_gbd' in cable_info:
            if verbose:
                print("Signaling Rate Information:")
            if 'interface_data_rate_gbps' in cable_info:
                print(f"  Interface Data Rate: {cable_info['interface_data_rate_gbps']:.2f} Gb/s")
            if 'lane_signaling_rate_gbd' in cable_info:
                print(f"  Lane Signaling Rate: {cable_info['lane_signaling_rate_gbd']:.2f} GBd")
                supported_lanes = cmis_data.get('media_info', {}).get('supported_lanes', [])
                num_lanes = len(supported_lanes) if supported_lanes else 8
                total_rate_gbps = cable_info['lane_signaling_rate_gbd'] * num_lanes
                print(f"  Active Lanes: {num_lanes}")
                print(f"  Total Rate: {num_lanes} × {cable_info['lane_signaling_rate_gbd']:.2f} GBd = {total_rate_gbps:.2f} Gb/s")
    # Monitoring Information
    if cmis_data.get('monitoring'):
        if verbose:
            print("\n--- Monitoring Information ---")
        monitoring = cmis_data['monitoring']
        if 'module' in monitoring:
            module_mon = monitoring['module']
            if 'temperature' in module_mon:
                print(f"Module Temperature: {module_mon['temperature']:.1f}°C")
            if 'vcc' in module_mon:
                print(f"Module VCC: {module_mon['vcc']:.2f}V")
            if 'aux1' in module_mon:
                aux1 = module_mon['aux1']
                if isinstance(aux1, dict):
                    print(f"Module Aux1 ({aux1['type']}): {aux1['value']:.2f} {aux1['unit']}")
                else:
                    print(f"Module Aux1: {aux1}")
            if 'aux2' in module_mon:
                aux2 = module_mon['aux2']
                if isinstance(aux2, dict):
                    print(f"Module Aux2 ({aux2['type']}): {aux2['value']:.2f} {aux2['unit']}")
                else:
                    print(f"Module Aux2: {aux2}")
            if 'aux3' in module_mon:
                aux3 = module_mon['aux3']
                if isinstance(aux3, dict):
                    print(f"Module Aux3 ({aux3['type']}): {aux3['value']:.2f} {aux3['unit']}")
                else:
                    print(f"Module Aux3: {aux3}")
            if 'custom' in module_mon:
                print(f"Module Custom: {module_mon['custom']}")
        if 'lanes' in monitoring:
            if verbose:
                print("Lane Monitoring:")
            supported_lanes = cmis_data.get('media_info', {}).get('supported_lanes', [])
            for lane_name, lane_data in monitoring['lanes'].items():
                lane_num = int(lane_name.split('_')[1])
                if lane_num in supported_lanes:
                    tx_mw = lane_data['tx_power'] * 0.01
                    rx_mw = lane_data['rx_power'] * 0.01
                    tx_dbm = float('-inf') if tx_mw == 0 else 10 * math.log10(tx_mw)
                    rx_dbm = float('-inf') if rx_mw == 0 else 10 * math.log10(rx_mw)
                    bias_ma = lane_data['tx_bias']
                    print(f"  {lane_name}: TX={tx_mw:.2f} mW ({tx_dbm:.2f} dBm), RX={rx_mw:.2f} mW ({rx_dbm:.2f} dBm), Bias={bias_ma}, Ratio={lane_data['rx_power_ratio']}")
        if 'snr' in monitoring:
            if verbose:
                print("SNR (OSNR) Data:")
            snr_data = monitoring['snr']
            if 'host_side' in snr_data:
                if verbose:
                    print("  Host Side:")
                for lane, snr in snr_data['host_side'].items():
                    print(f"    {lane}: {snr:.2f} dB")
            if 'media_side' in snr_data:
                if verbose:
                    print("  Media Side:")
                for lane, snr in snr_data['media_side'].items():
                    print(f"    {lane}: {snr:.2f} dB")
        if cmis_data.get('thresholds'):
            if verbose:
                print("\n--- Thresholds ---")
            thresholds = cmis_data['thresholds']
            if 'module' in thresholds:
                module_thresh = thresholds['module']
                if verbose:
                    print("Module Thresholds:")
                if 'temperature' in module_thresh:
                    temp = module_thresh['temperature']
                    print(f"  Temperature High Alarm: {temp['high_alarm']:.1f}°C")
                    print(f"  Temperature Low Alarm: {temp['low_alarm']:.1f}°C")
                    print(f"  Temperature High Warning: {temp['high_warning']:.1f}°C")
                    print(f"  Temperature Low Warning: {temp['low_warning']:.1f}°C")
                if 'vcc' in module_thresh:
                    vcc = module_thresh['vcc']
                    print(f"  VCC High Alarm: {vcc['high_alarm']:.3f}V")
                    print(f"  VCC Low Alarm: {vcc['low_alarm']:.3f}V")
                    print(f"  VCC High Warning: {vcc['high_warning']:.3f}V")
                    print(f"  VCC Low Warning: {vcc['low_warning']:.3f}V")
                if 'aux1' in module_thresh:
                    aux1 = module_thresh['aux1']
                    print(f"  Aux1 High Alarm: {aux1['high_alarm']}")
                    print(f"  Aux1 Low Alarm: {aux1['low_alarm']}")
                    print(f"  Aux1 High Warning: {aux1['high_warning']}")
                    print(f"  Aux1 Low Warning: {aux1['low_warning']}")
                if 'aux2' in module_thresh:
                    aux2 = module_thresh['aux2']
                    print(f"  Aux2 High Alarm: {aux2['high_alarm']}")
                    print(f"  Aux2 Low Alarm: {aux2['low_alarm']}")
                    print(f"  Aux2 High Warning: {aux2['high_warning']}")
                    print(f"  Aux2 Low Warning: {aux2['low_warning']}")
                if 'aux3' in module_thresh:
                    aux3 = module_thresh['aux3']
                    print(f"  Aux3 High Alarm: {aux3['high_alarm']}")
                    print(f"  Aux3 Low Alarm: {aux3['low_alarm']}")
                    print(f"  Aux3 High Warning: {aux3['high_warning']}")
                    print(f"  Aux3 Low Warning: {aux3['low_warning']}")
            if 'lanes' in thresholds:
                if verbose:
                    print("Lane Thresholds:")
                # Get supported lanes from media_info
                supported_lanes = cmis_data.get('media_info', {}).get('supported_lanes', [])
                for lane_name, lane_thresh in thresholds['lanes'].items():
                    # Extract lane number from lane_name (e.g., "lane_1" -> 1)
                    try:
                        lane_num = int(lane_name.split('_')[1])
                        if lane_num in supported_lanes:
                            print(f"  {lane_name}:")
                            print(f"    TX Power High Alarm: {lane_thresh['tx_power_high_alarm']:.2f} mW")
                            print(f"    TX Power Low Alarm: {lane_thresh['tx_power_low_alarm']:.2f} mW")
                            print(f"    TX Power High Warning: {lane_thresh['tx_power_high_warning']:.2f} mW")
                            print(f"    TX Power Low Warning: {lane_thresh['tx_power_low_warning']:.2f} mW")
                            print(f"    RX Power High Alarm: {lane_thresh['rx_power_high_alarm']:.2f} mW")
                    except (ValueError, IndexError):
                        # If lane_name doesn't match expected format, skip it
                        continue
        if cmis_data.get('application_info', {}).get('applications'):
            if verbose:
                print("\n--- Application Descriptors ---")
            for app in cmis_data['application_info']['applications']:
                print(f"  {app['name']} (Code: 0x{app['code']:02x})")
                print(f"    Host Lanes: {app['host_lane_count']}, Media Lanes: {app['media_lane_count']}")
                print(f"    Host Interface ID: 0x{app['code']:02x}")
                print(f"    Media Interface ID: 0x{app.get('media_interface_id', 0):02x}")
                print(f"    Host Assignment: 0x{app['host_lane_assignment']:02x}")
                print(f"    Media Assignment: 0x{app['media_lane_assignment']:02x}")
                # If available, print lane signaling rate and modulation from CDB or vendor fields
                if 'lane_signaling_rate_gbd' in app:
                    print(f"    Lane Signaling Rate: {app['lane_signaling_rate_gbd']:.2f} GBd")
                if 'modulation' in app:
                    print(f"    Modulation: {app['modulation']}")
    # Also print Nominal Wavelength and Tolerance if present
    media_info = cmis_data.get('media_info', {})
    if 'nominal_wavelength' in media_info:
        print(f"Nominal Wavelength: {media_info['nominal_wavelength']:.2f} nm")
    if 'wavelength_tolerance' in media_info:
        print(f"Wavelength Tolerance: ±{media_info['wavelength_tolerance']:.3f} nm")
    # Add comprehensive output functions
    if verbose:
        output_cmis_page_support(cmis_data)
        output_cmis_thresholds_complete(cmis_data)
        output_cmis_monitoring_complete(cmis_data)
        output_cmis_vdm_complete(cmis_data)
        output_cmis_application_descriptors_complete(cmis_data)
    # Add PAM4 eye and histogram output
    output_cmis_pam4_data(cmis_data, verbose=verbose)
    # Add CDB command output
    output_cmis_cdb_data(cmis_data, verbose=verbose)

def get_byte(page_dict, page, offset):
    """Get a single byte from a specific page using string keys."""
    if page not in page_dict:
        return None
    page_data = page_dict[page]
    if offset < len(page_data):
        return page_data[offset]
    return None

def get_bytes(page_dict, page, start, end):
    """Get a range of bytes from a specific page using string keys."""
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

# Legacy functions for backward compatibility
def read_cmis_vendor_info(page_dict):
    """Read vendor information from CMIS module."""
    cmis_data = parse_cmis_data_centralized(page_dict)
    return cmis_data['vendor_info']

def read_cmis_module_info(page_dict):
    """Read module information from CMIS module."""
    cmis_data = parse_cmis_data_centralized(page_dict)
    return cmis_data['module_info']

def read_cmis_power_info(page_dict):
    """Read power information from CMIS module."""
    cmis_data = parse_cmis_data_centralized(page_dict)
    return cmis_data['power_info']

def read_cmis_monitoring_data(page_dict):
    """Read monitoring data from CMIS module."""
    cmis_data = parse_cmis_data_centralized(page_dict)
    return cmis_data['monitoring']

# Core CMIS functions moved from read-optic.py
def read_cmis_application_codes(page_dict):
    """Read CMIS application codes from Upper Page 01h (per OIF-CMIS 5.3 Table 8-7)."""
    # Application codes are in Upper Page 01h, bytes 128-131 → relative 0-3 in '100h'
    app_codes = []
    for i in range(4):
        app_code = get_byte(page_dict, '100h', i)  # relative offset 0-3
        if app_code is not None and app_code != 0:
            app_codes.append(app_code)
    return app_codes

def read_cmis_lane_status(page_dict):
    """Read CMIS lane status from Upper Page 00h."""
    # Media Lane Information: byte 210 → relative 82
    lane_info = get_byte(page_dict, '80h', 82)  # relative offset 82
    if lane_info is not None:
        supported_lanes = [lane + 1 for lane in range(8) if not (lane_info & (1 << lane))]
        return f"0x{lane_info:02x} (Supported: {supported_lanes})"
    return "Not available"

def read_cmis_module_state(page_dict):
    """Read and print CMIS Module State (Table 8-7)"""
    try:
        state = get_byte(page_dict, '00h', 3) & 0x0F
        try:
            module_state = ModuleState(state)
            print(f"Module State: {module_state.name} (0x{state:02x})")
        except ValueError:
            print(f"Module State: Unknown({state:02x})")
    except Exception as e:
        print(f"Error reading module state: {e}")

def read_cmis_module_power(page_dict):
    """Read CMIS module power from Upper Page 00h."""
    # Module Power: bytes 200-201 → relative 72-73
    power_class_byte = get_byte(page_dict, '80h', 72)  # relative offset
    max_power_byte = get_byte(page_dict, '80h', 73)  # relative offset
   
    if power_class_byte is not None and max_power_byte is not None:
        power_class = (power_class_byte >> 5) & 0x07
        max_power = max_power_byte * 0.25
        return f"Power Class: {power_class}, Max Power: {max_power}W"
    return "Not available"

def read_cmis_module_config(page_dict):
    """Read CMIS module configuration from Lower Page 00h."""
    # Module configuration is in Lower Page 00h, bytes 0-2
    if '00h' in page_dict and len(page_dict['00h']) >= 3:
        module_flags = page_dict['00h'][0]
        lane_flags = page_dict['00h'][1]
        module_state = page_dict['00h'][2]
       
        return {
            'module_flags': module_flags,
            'lane_flags': lane_flags,
            'module_state': module_state
        }
    return "Not available"

def read_cmis_copper_attenuation(page_dict):
    """Read CMIS copper attenuation from Upper Page 00h."""
    # Attenuation: bytes 204-209 → relative 76-81
    attenuation = get_bytes(page_dict, '80h', 76, 82)  # relative offsets
    if attenuation and len(attenuation) >= 6:
        return {
            'at_5ghz': attenuation[0],
            'at_7ghz': attenuation[1],
            'at_12p9ghz': attenuation[2],
            'at_25p8ghz': attenuation[3],
            'at_53p1ghz': attenuation[4]
        }
    return "Not available"

def read_cmis_media_lane_info(page_dict):
    """Read and display CMIS Media Lane Information."""
    # Media lane information is in Upper Page 00h (0x80), byte 210 → relative offset 82
    lane_info = get_byte(page_dict, '80h', 82)  # relative offset 82
    source = "Upper Page 00h, byte 210 (relative 82)"
   
    if lane_info is not None:
        print(f"\nMedia Lane Support [{source}]:")
        for lane in range(8):
            # According to OIF-CMIS 5.3 Table 8-35, this uses NEGATIVE logic
            # 0 = supported, 1 = not supported
            print(f"Lane {lane + 1}: {'Supported' if not (lane_info & (1 << lane)) else 'Not Supported'}")
    else:
        print(f"\nMedia Lane Support [{source}]: Not available")

def get_cmis_supported_lanes(page_dict):
    """Return a list of supported lane indices (0-based) according to the Media Lane Support bitmap."""
    # Media lane information is in Upper Page 00h (0x80), byte 210 → relative offset 82
    # According to the spec, this uses NEGATIVE logic: 0 = supported, 1 = not supported
    lane_info = get_byte(page_dict, '80h', 82)  # relative offset 82
    if lane_info is None:
        lane_info = 0
    # Return lanes where the bit is 0 (supported) - negative logic
    return [lane for lane in range(8) if not (lane_info & (1 << lane))]

def read_cmis_monitoring_data(page_dict):
    """Read CMIS monitoring data from Lower Page 00h and Page 11h."""
    monitoring_data = {}
   
    # Module monitoring from Lower Page 00h, bytes 14-19
    if '00h' in page_dict and len(page_dict['00h']) >= 20:
        monitoring_data['module'] = {
            'temperature': page_dict['00h'][14],
            'vcc': page_dict['00h'][15],
            'tx_power': page_dict['00h'][16],
            'rx_power': page_dict['00h'][17]
        }
   
    # Lane monitoring from Page 11h, bytes 144-159 for lane 1
    page_11h = page_dict.get('11h', [])
    if len(page_11h) >= 160:
        # Get supported lanes from Upper Page 00h
        lane_info = get_byte(page_dict, '80h', 82)  # relative offset 82
        if lane_info is not None:
            supported_lanes = [lane for lane in range(8) if not (lane_info & (1 << lane))]
            monitoring_data['lanes'] = {}
            for lane in supported_lanes:
                lane_num = lane + 1
                base_offset = 144 + (lane_num - 1) * 16
                if len(page_11h) >= base_offset + 16:
                    monitoring_data['lanes'][f'lane_{lane_num}'] = {
                        'tx_power': page_11h[base_offset],
                        'rx_power': page_11h[base_offset + 1],
                        'tx_bias': page_11h[base_offset + 2],
                        'rx_power_ratio': page_11h[base_offset + 3]
                    }
   
    return monitoring_data

def read_cmis_thresholds(page_dict):
    """Read CMIS thresholds from Page 02h."""
    # Thresholds are in Page 02h, bytes 128-191
    if '02h' in page_dict and len(page_dict['02h']) >= 192:
        return {
            'module': {
                'temp_high_alarm': page_dict['02h'][128],
                'temp_low_alarm': page_dict['02h'][129],
                'temp_high_warning': page_dict['02h'][130],
                'temp_low_warning': page_dict['02h'][131],
                'vcc_high_alarm': page_dict['02h'][132],
                'vcc_low_alarm': page_dict['02h'][133],
                'vcc_high_warning': page_dict['02h'][134],
                'vcc_low_warning': page_dict['02h'][135],
                'tx_power_high_alarm': page_dict['02h'][136],
                'tx_power_low_alarm': page_dict['02h'][137],
                'tx_power_high_warning': page_dict['02h'][138],
                'tx_power_low_warning': page_dict['02h'][139],
                'rx_power_high_alarm': page_dict['02h'][140],
                'rx_power_low_alarm': page_dict['02h'][141],
                'rx_power_high_warning': page_dict['02h'][142],
                'rx_power_low_warning': page_dict['02h'][143]
            }
        }
    return "Not available"

def read_cmis_application_advertisement(page_dict):
    """Read and print CMIS Application Advertisement (Tables 8-7, 8-8, 8-9)"""
    try:
        print("\nApplication Advertisement:")
        # Application codes are in Upper Page 0x01, bytes 128-191 (0x180-0x1BF)
        for app in range(8):
            base = 0x180 + app * 8
            code = get_byte(page_dict, '01h', base - 0x180)  # Convert to Upper Page 01h offset
            if code == 0:
                continue
            host_lane_count = get_byte(page_dict, '01h', base - 0x180 + 1)
            media_lane_count = get_byte(page_dict, '01h', base - 0x180 + 2)
            host_lane_assignment = get_byte(page_dict, '01h', base - 0x180 + 3)
            media_lane_assignment = get_byte(page_dict, '01h', base - 0x180 + 4)
            # Table 8-8: Application Code meanings
            app_map = APPLICATION_CODE_NAMES
            print(f"  App {app}: Code 0x{code:02x} ({app_map.get(code, 'Unknown')}) | Host Lanes: {host_lane_count} | Media Lanes: {media_lane_count} | Host Lane Assignment: 0x{host_lane_assignment:02x} | Media Lane Assignment: 0x{media_lane_assignment:02x}")
    except Exception as e:
        print(f"Error reading application advertisement: {e}")

def read_cmis_global_status_detailed(page_dict):
    """Read and print CMIS Global Status/Interrupts (Table 8-4)"""
    try:
        status = get_byte(page_dict, '00h', 2)
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

def read_cmis_advanced_monitoring(page_dict):
    """Read and display CMIS Advanced Monitoring Data."""
    # Get lane information from Upper Page 00h
    lane_info = get_byte(page_dict, '80h', 82)  # relative offset 82
    source = "Upper Page 00h, byte 210 (relative 82)"
   
    if lane_info is not None:
        print(f"\nAdvanced Lane Monitoring [{source}]:")
        supported_lanes = []
        for lane in range(8):
            # According to OIF-CMIS 5.3 Table 8-35, this uses NEGATIVE logic
            # 0 = supported, 1 = not supported
            if not (lane_info & (1 << lane)):
                supported_lanes.append(lane)
       
        print(f"Supported lanes: {[lane + 1 for lane in supported_lanes]}")
       
        # Display monitoring data for supported lanes
        for lane in supported_lanes:
            lane_num = lane + 1
            print(f"Lane {lane_num}: Supported")
    else:
        print(f"\nAdvanced Lane Monitoring [{source}]: Not available")

def read_cmis_wavelength_info(page_dict):
    """Read CMIS wavelength information from Page 01h"""
    try:
        print("\nCMIS Wavelength Information:")
       
        # Read nominal wavelength from Page 01h bytes 138-139 (0x8A-0x8B)
        nominal_wavelength_raw = get_bytes(page_dict, '100h', 0x8A, 0x8C)
        if nominal_wavelength_raw:
            nominal_wavelength = struct.unpack_from('>H', bytes(nominal_wavelength_raw))[0] * 0.05
            print(f"Nominal Wavelength: {nominal_wavelength:.2f} nm")
       
        # Read wavelength tolerance from Page 01h bytes 140-141 (0x8C-0x8D)
        wavelength_tolerance_raw = get_bytes(page_dict, '100h', 0x8C, 0x8E)
        if wavelength_tolerance_raw:
            wavelength_tolerance = struct.unpack_from('>H', bytes(wavelength_tolerance_raw))[0] * 0.005
            print(f"Wavelength Tolerance: ±{wavelength_tolerance:.3f} nm")
       
        # Read supported fiber link length from Page 01h bytes 131-137 (0x83-0x89)
        fiber_length = get_bytes(page_dict, '100h', 0x83, 0x8A)
        if fiber_length:
            print(f"Supported Fiber Link Length: {fiber_length}")
           
    except Exception as e:
        print(f"Error reading CMIS wavelength information: {e}")

def read_cmis_lower_memory(page_dict):
    """Read CMIS Lower Memory (bytes 0-127) according to OIF-CMIS 5.3 Table 8-5"""
    try:
        print("\n=== CMIS Lower Memory ===")
       
        # Table 8-5: Management Characteristics
        print("\n--- Management Characteristics ---")
        sff8024_id = get_byte(page_dict, '00h', 0)
        cmis_rev = get_byte(page_dict, '00h', 1)
        mgmt_chars = get_byte(page_dict, '00h', 2)
       
        if sff8024_id is not None:
            sff8024_names = {
                0x03: 'SFP/SFP+',
                0x0C: 'QSFP',
                0x0D: 'QSFP+',
                0x11: 'QSFP28',
                0x18: 'QSFP-DD'
            }
            identifier_name = sff8024_names.get(sff8024_id, f'Unknown({sff8024_id:02x})')
            print(f"SFF8024 Identifier: 0x{sff8024_id:02x} ({identifier_name})")
       
        if cmis_rev is not None:
            major_rev = (cmis_rev >> 4) & 0x0F
            minor_rev = cmis_rev & 0x0F
            print(f"CMIS Revision: {major_rev}.{minor_rev}")
       
        if mgmt_chars is not None:
            memory_model = "Flat" if (mgmt_chars & 0x80) else "Paged"
            stepped_config = "Only" if (mgmt_chars & 0x40) else "All"
            mci_max_speed = (mgmt_chars >> 2) & 0x0F
            auto_commissioning = mgmt_chars & 0x03
           
            print(f"Memory Model: {memory_model}")
            print(f"Configuration Support: {stepped_config}")
            print(f"MCI Max Speed: {mci_max_speed}")
            print(f"Auto Commissioning: {auto_commissioning}")
       
        # Module State (byte 3)
        module_state = get_byte(page_dict, '00h', 3)
        if module_state is not None:
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
            print(f"Module State: {state_map.get(module_state & 0x0F, f'Unknown({module_state & 0x0F:02x})')}")
       
        # Global Status (byte 2)
        global_status = get_byte(page_dict, '00h', 2)
        if global_status is not None:
            print("\nGlobal Status:")
            print(f"  Module State Changed: {'Yes' if global_status & 0x80 else 'No'}")
            print(f"  Module Interrupt: {'Yes' if global_status & 0x40 else 'No'}")
            print(f"  Data Path State Changed: {'Yes' if global_status & 0x20 else 'No'}")
            print(f"  Data Path Interrupt: {'Yes' if global_status & 0x10 else 'No'}")
            print(f"  Module Fault: {'Yes' if global_status & 0x08 else 'No'}")
            print(f"  Module Warning: {'Yes' if global_status & 0x04 else 'No'}")
            print(f"  Reserved: {global_status & 0x03:02b}")
       
        # Lane Flags Summary (byte 1)
        lane_flags = get_byte(page_dict, '00h', 1)
        if lane_flags is not None:
            print("\nLane Flags Summary:")
            for lane in range(8):
                tx_fault = bool(lane_flags & (1 << (lane * 2)))
                rx_los = bool(lane_flags & (1 << (lane * 2 + 1)))
                print(f"  Lane {lane+1}: TX Fault={'Yes' if tx_fault else 'No'}, RX LOS={'Yes' if rx_los else 'No'}")
       
        # Module Flags (byte 0)
        module_flags = get_byte(page_dict, '00h', 0)
        if module_flags is not None:
            print("\nModule Flags:")
            print(f"  Data Path Ready: {'Yes' if module_flags & 0x01 else 'No'}")
            print(f"  Module Ready: {'Yes' if module_flags & 0x02 else 'No'}")
            print(f"  Module Fault: {'Yes' if module_flags & 0x04 else 'No'}")
            print(f"  Module Power Good: {'Yes' if module_flags & 0x08 else 'No'}")
            print(f"  TX Fault: {'Yes' if module_flags & 0x10 else 'No'}")
            print(f"  RX LOS: {'Yes' if module_flags & 0x20 else 'No'}")
            print(f"  TX CDR LOL: {'Yes' if module_flags & 0x40 else 'No'}")
            print(f"  RX CDR LOL: {'Yes' if module_flags & 0x80 else 'No'}")
       
    except Exception as e:
        print(f"Error reading CMIS Lower Memory: {e}")

# CMIS Page-specific functions
def read_cmis_page_00h(page_dict):
    """Read and print all CMIS Page 00h (Upper Memory) fields according to OIF-CMIS 5.3."""
    try:
        print("\n=== CMIS Page 00h (Upper Memory) ===")
       
        # Table 8-28: Vendor Information
        print("\n--- Vendor Information ---")
        vendor_name = get_bytes(page_dict, '80h', 0x00, 0x10)
        if vendor_name:
            vendor_name = vendor_name.decode('ascii', errors='ignore').strip()
            print(f"Vendor Name: {vendor_name}")
       
        vendor_oui = get_bytes(page_dict, '80h', 0x10, 0x13)
        if vendor_oui:
            oui_str = ''.join([f"{b:02x}" for b in vendor_oui])
            print(f"Vendor OUI: {oui_str}")
       
        vendor_pn = get_bytes(page_dict, '80h', 148, 164)
        if vendor_pn:
            vendor_pn = vendor_pn.decode('ascii', errors='ignore').strip()
            print(f"Vendor Part Number: {vendor_pn}")
       
        vendor_rev = get_bytes(page_dict, '80h', 0x20, 0x22)
        if vendor_rev:
            vendor_rev = vendor_rev.decode('ascii', errors='ignore').strip()
            print(f"Vendor Revision: {vendor_rev}")
       
        vendor_sn = get_bytes(page_dict, '80h', 0x22, 0x32)
        if vendor_sn:
            vendor_sn = vendor_sn.decode('ascii', errors='ignore').strip()
            print(f"Vendor Serial Number: {vendor_sn}")
       
        # Table 8-29: Date Code
        print("\n--- Date Code ---")
        date_code = get_bytes(page_dict, '80h', 0x32, 0x3A)
        if date_code:
            date_code = date_code.decode('ascii', errors='ignore').strip()
            print(f"Date Code: {date_code}")
       
        # Table 8-30: CLEI Code
        print("\n--- CLEI Code ---")
        clei_code = get_bytes(page_dict, '80h', 0x3A, 0x44)
        if clei_code:
            clei_code = clei_code.decode('ascii', errors='ignore').strip()
            print(f"CLEI Code: {clei_code}")
       
        # Table 8-31: Module Power Class and Max Power
        print("\n--- Module Power Class and Max Power ---")
        power_class_byte = get_byte(page_dict, '80h', 0x48)
        max_power_byte = get_byte(page_dict, '80h', 0x49)
       
        if power_class_byte is not None:
            power_class = (power_class_byte >> 5) & 0x07
            print(f"Power Class: {power_class}")
       
        if max_power_byte is not None:
            max_power = max_power_byte * 0.25
            print(f"Max Power: {max_power:.2f} W")
       
        # Table 8-32: Cable Assembly Link Length
        # Note: Cable length is already handled by unified processing
        # This section is suppressed to avoid duplicate output
        length_byte = get_byte(page_dict, '80h', 0x4A)
        if length_byte is not None:
            # Only output if not already handled by unified processing
            # length_multiplier = (length_byte >> 6) & 0x03
            # base_length = length_byte & 0x1F
            # print(f"Length Multiplier: {length_multiplier}")
            # print(f"Base Length: {base_length}")
            pass
       
        # Table 8-33: Media Connector Type
        print("\n--- Media Connector Type ---")
        connector_type = get_byte(page_dict, '80h', 0x4B)
        if connector_type is not None:
            connector_names = CONNECTOR_TYPES
            connector_name = connector_names.get(connector_type, f'Unknown({connector_type:02x})')
            print(f"Connector Type: 0x{connector_type:02x} ({connector_name})")
        # Table 8-34: Media Interface Technology (Page 0x100, byte 0x87)
        tech = get_byte(page_dict, '100h', 0x87) if '100h' in page_dict else None
        if tech is not None:
            tech_names = {
                0x01: '850 nm VCSEL',
                0x02: '1310 nm VCSEL',
                0x03: '1550 nm VCSEL',
                0x04: '1310 nm FP',
                0x05: '1310 nm DFB',
                0x06: '1550 nm DFB',
                0x07: '1310 nm EML',
                0x08: '1550 nm EML',
                0x09: 'Copper cable (passive)',
                0x0A: 'Copper cable (active)',
                0x0B: 'Copper cable (active, SFI)',
                0x0C: 'Copper cable (active, SFP+)',
                0x0D: 'Copper cable (active, QSFP+)',
                0x0E: 'Copper cable (active, QSFP28)',
                0x10: 'Shortwave WDM',
                0x11: 'Longwave WDM',
                0x12: 'Coherent',
                0x30: 'Copper cable (passive, SFP+)',
                0x31: 'Copper cable (passive, QSFP+)',
                0x32: 'Copper cable (passive, QSFP28)',
                0x33: 'Copper cable (passive, QSFP-DD)',
                0x34: 'Copper cable (passive, OSFP)'
            }
            tech_name = tech_names.get(tech, f'Unknown({tech:02x})')
            print(f"Interface Technology: 0x{tech:02x} ({tech_name})")
       
        # Table 8-35: Media Interface Technology (Page 0x100, byte 0x87)
        tech = get_byte(page_dict, '100h', 0x87) if '100h' in page_dict else None
        if tech is not None:
            tech_names = {
                0x01: '850 nm VCSEL',
                0x02: '1310 nm VCSEL',
                0x03: '1550 nm VCSEL',
                0x04: '1310 nm FP',
                0x05: '1310 nm DFB',
                0x06: '1550 nm DFB',
                0x07: '1310 nm EML',
                0x08: '1550 nm EML',
                0x09: 'Copper cable (passive)',
                0x0A: 'Copper cable (active)',
                0x0B: 'Copper cable (active, SFI)',
                0x0C: 'Copper cable (active, SFP+)',
                0x0D: 'Copper cable (active, QSFP+)',
                0x0E: 'Copper cable (active, QSFP28)',
                0x10: 'Shortwave WDM',
                0x11: 'Longwave WDM',
                0x12: 'Coherent',
                0x30: 'Copper cable (passive, SFP+)',
                0x31: 'Copper cable (passive, QSFP+)',
                0x32: 'Copper cable (passive, QSFP28)',
                0x33: 'Copper cable (passive, QSFP-DD)',
                0x34: 'Copper cable (passive, OSFP)'
            }
            tech_name = tech_names.get(tech, f'Unknown({tech:02x})')
            print(f"Interface Technology: 0x{tech:02x} ({tech_name})")
       
        # Table 8-36: Media Lane Information
        print("\n--- Media Lane Information ---")
        lane_info = get_byte(page_dict, '80h', 0x52)
        if lane_info is not None:
            print(f"Media Lane Info: 0x{lane_info:02x}")
            for lane in range(8):
                supported = (lane_info & (1 << lane)) != 0
                print(f"  Lane {lane+1}: {'Supported' if supported else 'Not Supported'}")
       
        # Table 8-37/8-38: Far End Configurations
        print("\n--- Far End Configurations ---")
        far_end_config = get_bytes(page_dict, '80h', 0x58, 0x68)
        if far_end_config:
            print(f"Far End Configurations: {far_end_config}")
       
        # Table 8-39: Media Connector Type (additional)
        print("\n--- Additional Media Connector Type ---")
        addl_connector = get_byte(page_dict, '80h', 0x68)
        if addl_connector is not None:
            print(f"Additional Connector Type: 0x{addl_connector:02x}")
       
        # Table 8-41: MCI Related Advertisements
        print("\n--- MCI Related Advertisements ---")
        mci_info = get_bytes(page_dict, '80h', 0x69, 0x80)
        if mci_info:
            print(f"MCI Related Advertisements: {mci_info}")
       
    except Exception as e:
        print(f"Error reading CMIS Page 00h: {e}")

def read_cmis_page_01h(page_dict):
    """Read and print all CMIS Page 01h (Upper Memory) fields according to OIF-CMIS 5.3."""
    try:
        print("\n=== CMIS Page 01h (Upper Memory) ===")
       
        # Table 8-43: Module Inactive Firmware and Hardware Revisions
        print("\n--- Module Inactive Firmware and Hardware Revisions ---")
        inactive_fw_major = get_byte(page_dict, '100h', 0x80)
        inactive_fw_minor = get_byte(page_dict, '100h', 0x81)
        if inactive_fw_major is not None and inactive_fw_minor is not None:
            print(f"Inactive Firmware Version: {inactive_fw_major}.{inactive_fw_minor}")
       
        hw_rev = get_byte(page_dict, '100h', 0x82)
        if hw_rev is not None:
            print(f"Hardware Revision: {hw_rev}")
       
        # Table 8-44: Supported Fiber Link Length
        print("\n--- Supported Fiber Link Length ---")
        fiber_length = get_bytes(page_dict, '100h', 0x83, 0x8A)
        if fiber_length:
            print(f"Supported Fiber Link Length: {fiber_length}")
       
        # Table 8-45: Wavelength Information
        print("\n--- Wavelength Information ---")
        nominal_wavelength_raw = get_bytes(page_dict, '100h', 0x8A, 0x8C)
        if nominal_wavelength_raw:
            nominal_wavelength = struct.unpack_from('>H', bytes(nominal_wavelength_raw))[0] * 0.05
            print(f"Nominal Wavelength: {nominal_wavelength:.2f} nm")
       
        wavelength_tolerance_raw = get_bytes(page_dict, '100h', 0x8C, 0x8E)
        if wavelength_tolerance_raw:
            wavelength_tolerance = struct.unpack_from('>H', bytes(wavelength_tolerance_raw))[0] * 0.005
            print(f"Wavelength Tolerance: ±{wavelength_tolerance:.3f} nm")
       
        # Table 8-46: Supported Pages Advertising
        print("\n--- Supported Pages Advertising ---")
        supported_pages = get_bytes(page_dict, '100h', 0x8E, 0x90)
        if supported_pages:
            print(f"Supported Pages: {supported_pages}")
            pages_bitmap = supported_pages[0] if len(supported_pages) > 0 else 0
            print("  Supported Pages:")
            if pages_bitmap & 0x01:
                print("    - Page 02h (Monitor Thresholds)")
            if pages_bitmap & 0x02:
                print("    - Page 03h (Module Control)")
            if pages_bitmap & 0x04:
                print("    - Page 04h (Laser Tuning)")
            if pages_bitmap & 0x08:
                print("    - Page 05h (Vendor Specific)")
            if pages_bitmap & 0x10:
                print("    - Page 10h (Lane Control)")
            if pages_bitmap & 0x20:
                print("    - Page 11h (Lane Status)")
            if pages_bitmap & 0x40:
                print("    - Page 12h (Tunable Laser)")
            if pages_bitmap & 0x80:
                print("    - Page 13h (Diagnostics)")
       
        # Table 8-47: Durations Advertising
        print("\n--- Durations Advertising ---")
        durations = get_bytes(page_dict, '100h', 0x91, 0x93)
        if durations:
            print(f"Durations: {durations}")
       
        # Table 8-49: Module Characteristics Advertisement
        print("\n--- Module Characteristics Advertisement ---")
        module_chars = get_bytes(page_dict, '100h', 0xA0, 0xA4)
        if module_chars:
            print(f"Module Characteristics: {module_chars}")
       
        # Table 8-50: Supported Controls Advertisement
        print("\n--- Supported Controls Advertisement ---")
        supported_controls = get_bytes(page_dict, '100h', 0xA4, 0xA8)
        if supported_controls:
            print(f"Supported Controls: {supported_controls}")
       
        # Table 8-51: Supported Flags Advertisement
        print("\n--- Supported Flags Advertisement ---")
        supported_flags = get_bytes(page_dict, '100h', 0xA8, 0xAC)
        if supported_flags:
            print(f"Supported Flags: {supported_flags}")
       
        # Table 8-52: Supported Monitors Advertisement
        print("\n--- Supported Monitors Advertisement ---")
        supported_monitors = get_bytes(page_dict, '100h', 0xAC, 0xB0)
        if supported_monitors:
            print(f"Supported Monitors: {supported_monitors}")
       
        # Table 8-53: Supported Signal Integrity Controls Advertisement
        print("\n--- Supported Signal Integrity Controls Advertisement ---")
        signal_integrity = get_bytes(page_dict, '100h', 0xB0, 0xB4)
        if signal_integrity:
            print(f"Signal Integrity Controls: {signal_integrity}")
       
        # Table 8-54: CDB Advertisement
        print("\n--- CDB Advertisement ---")
        cdb_support = get_bytes(page_dict, '100h', 0xB4, 0xB8)
        if cdb_support:
            print(f"CDB Support: {cdb_support}")
       
        # Table 8-56: Additional Durations Advertising
        print("\n--- Additional Durations Advertising ---")
        addl_durations = get_bytes(page_dict, '100h', 0xB8, 0xBA)
        if addl_durations:
            print(f"Additional Durations: {addl_durations}")
       
        # Table 8-57: Normalized Application Descriptors Support
        print("\n--- Normalized Application Descriptors Support ---")
        norm_app_desc = get_bytes(page_dict, '100h', 0xBA, 0xBE)
        if norm_app_desc:
            print(f"Normalized Application Descriptors: {norm_app_desc}")
       
        # Table 8-58: Media Lane Assignment Advertising
        print("\n--- Media Lane Assignment Advertising ---")
        lane_assignment = get_bytes(page_dict, '100h', 0xBE, 0xC2)
        if lane_assignment:
            print(f"Media Lane Assignment: {lane_assignment}")
       
        # Table 8-59: Additional Application Descriptor Registers
        print("\n--- Additional Application Descriptor Registers ---")
        for i in range(8):
            app_desc = get_bytes(page_dict, '100h', 0xC2 + i*4, 0xC6 + i*4)
            if app_desc:
                print(f"Additional Application Descriptor {i+1}: {app_desc}")
       
        # Table 8-60: Miscellaneous Advertisements
        print("\n--- Miscellaneous Advertisements ---")
        misc_ads = get_bytes(page_dict, '100h', 0xE2, 0xFF)
        if misc_ads:
            print(f"Miscellaneous Advertisements: {misc_ads}")
       
        # Per-lane wavelengths (bytes 144-159) - Table 8-45
        if len(page_dict['80h']) >= 160: # Changed from page_01h to page_dict['80h']
            lane_wavelengths = {}
            for lane in range(1, 9):
                offset = 144 + (lane - 1) * 2
                raw = (page_dict['80h'][offset] << 8) | page_dict['80h'][offset + 1]
                nm = raw * 0.05
                lane_wavelengths[lane] = {'raw': raw, 'nm': nm}
            cmis_data['media_info']['lane_wavelengths'] = lane_wavelengths
       
    except Exception as e:
        print(f"Error reading CMIS Page 01h: {e}")

def read_cmis_page_02h(page_dict):
    """Read and print all CMIS Page 02h (Monitor Thresholds) fields according to OIF-CMIS 5.3."""
    try:
        print("\n=== CMIS Page 02h (Monitor Thresholds) ===")
       
        # Table 8-62: Module-Level Monitor Thresholds
        print("\n--- Module-Level Monitor Thresholds ---")
       
        # Temperature thresholds (bytes 128-131)
        temp_high_alarm = get_bytes(page_dict, '200h', 0x00, 0x02)
        if temp_high_alarm:
            temp_high_alarm_val = struct.unpack_from('>H', bytes(temp_high_alarm))[0] / 256.0
            print(f"Temperature High Alarm: {temp_high_alarm_val:.1f}°C")
       
        temp_low_alarm = get_bytes(page_dict, '200h', 0x02, 0x04)
        if temp_low_alarm:
            temp_low_alarm_val = struct.unpack_from('>H', bytes(temp_low_alarm))[0] / 256.0
            print(f"Temperature Low Alarm: {temp_low_alarm_val:.1f}°C")
       
        temp_high_warning = get_bytes(page_dict, '200h', 0x04, 0x06)
        if temp_high_warning:
            temp_high_warning_val = struct.unpack_from('>H', bytes(temp_high_warning))[0] / 256.0
            print(f"Temperature High Warning: {temp_high_warning_val:.1f}°C")
       
        temp_low_warning = get_bytes(page_dict, '200h', 0x06, 0x08)
        if temp_low_warning:
            temp_low_warning_val = struct.unpack_from('>H', bytes(temp_low_warning))[0] / 256.0
            print(f"Temperature Low Warning: {temp_low_warning_val:.1f}°C")
       
        # Voltage thresholds (bytes 132-139)
        vcc_high_alarm = get_bytes(page_dict, '200h', 0x08, 0x0A)
        if vcc_high_alarm:
            vcc_high_alarm_val = struct.unpack_from('>H', bytes(vcc_high_alarm))[0] / 10000.0
            print(f"VCC High Alarm: {vcc_high_alarm_val:.3f}V")
       
        vcc_low_alarm = get_bytes(page_dict, '200h', 0x0A, 0x0C)
        if vcc_low_alarm:
            vcc_low_alarm_val = struct.unpack_from('>H', bytes(vcc_low_alarm))[0] / 10000.0
            print(f"VCC Low Alarm: {vcc_low_alarm_val:.3f}V")
       
        vcc_high_warning = get_bytes(page_dict, '200h', 0x0C, 0x0E)
        if vcc_high_warning:
            vcc_high_warning_val = struct.unpack_from('>H', bytes(vcc_high_warning))[0] / 10000.0
            print(f"VCC High Warning: {vcc_high_warning_val:.3f}V")
       
        vcc_low_warning = get_bytes(page_dict, '200h', 0x0E, 0x10)
        if vcc_low_warning:
            vcc_low_warning_val = struct.unpack_from('>H', bytes(vcc_low_warning))[0] / 10000.0
            print(f"VCC Low Warning: {vcc_low_warning_val:.3f}V")
       
        # TX Power thresholds (bytes 140-147)
        tx_power_high_alarm = get_bytes(page_dict, '200h', 0x10, 0x12)
        if tx_power_high_alarm:
            tx_power_high_alarm_val = struct.unpack_from('>H', bytes(tx_power_high_alarm))[0] / 10000.0
            print(f"TX Power High Alarm: {tx_power_high_alarm_val:.3f}mW")
       
        tx_power_low_alarm = get_bytes(page_dict, '200h', 0x12, 0x14)
        if tx_power_low_alarm:
            tx_power_low_alarm_val = struct.unpack_from('>H', bytes(tx_power_low_alarm))[0] / 10000.0
            print(f"TX Power Low Alarm: {tx_power_low_alarm_val:.3f}mW")
       
        tx_power_high_warning = get_bytes(page_dict, '200h', 0x14, 0x16)
        if tx_power_high_warning:
            tx_power_high_warning_val = struct.unpack_from('>H', bytes(tx_power_high_warning))[0] / 10000.0
            print(f"TX Power High Warning: {tx_power_high_warning_val:.3f}mW")
       
        tx_power_low_warning = get_bytes(page_dict, '200h', 0x16, 0x18)
        if tx_power_low_warning:
            tx_power_low_warning_val = struct.unpack_from('>H', bytes(tx_power_low_warning))[0] / 10000.0
            print(f"TX Power Low Warning: {tx_power_low_warning_val:.3f}mW")
       
        # RX Power thresholds (bytes 148-155)
        rx_power_high_alarm = get_bytes(page_dict, '200h', 0x18, 0x1A)
        if rx_power_high_alarm:
            rx_power_high_alarm_val = struct.unpack_from('>H', bytes(rx_power_high_alarm))[0] / 10000.0
            print(f"RX Power High Alarm: {rx_power_high_alarm_val:.3f}mW")
       
        rx_power_low_alarm = get_bytes(page_dict, '200h', 0x1A, 0x1C)
        if rx_power_low_alarm:
            rx_power_low_alarm_val = struct.unpack_from('>H', bytes(rx_power_low_alarm))[0] / 10000.0
            print(f"RX Power Low Alarm: {rx_power_low_alarm_val:.3f}mW")
       
        rx_power_high_warning = get_bytes(page_dict, '200h', 0x1C, 0x1E)
        if rx_power_high_warning:
            rx_power_high_warning_val = struct.unpack_from('>H', bytes(rx_power_high_warning))[0] / 10000.0
            print(f"RX Power High Warning: {rx_power_high_warning_val:.3f}mW")
       
        rx_power_low_warning = get_bytes(page_dict, '200h', 0x1E, 0x20)
        if rx_power_low_warning:
            rx_power_low_warning_val = struct.unpack_from('>H', bytes(rx_power_low_warning))[0] / 10000.0
            print(f"RX Power Low Warning: {rx_power_low_warning_val:.3f}mW")
       
        # Lane-specific thresholds (bytes 160-191)
        print("\n--- Lane-Specific Thresholds ---")
        for lane in range(8):
            base_offset = 0x20 + lane * 16
            lane_data = get_bytes(page_dict, '200h', base_offset, base_offset + 16)
            if lane_data:
                print(f"Lane {lane+1} thresholds: {lane_data}")
       
    except Exception as e:
        print(f"Error reading CMIS Page 02h: {e}")

def read_cmis_page_10h(page_dict):
    """Read and print all CMIS Page 10h (Lane Control) fields according to OIF-CMIS 5.3."""
    try:
        print("\n=== CMIS Page 10h (Lane Control) ===")
       
        # Table 8-89: Lane Control Registers
        print("\n--- Lane Control Registers ---")
        for lane in range(8):
            lane_control = get_byte(page_dict, '1000h', lane)
            if lane_control is not None:
                print(f"Lane {lane+1} Control: 0x{lane_control:02x}")
                print(f"  TX Disable: {'Yes' if lane_control & 0x01 else 'No'}")
                print(f"  TX Squelch: {'Yes' if lane_control & 0x02 else 'No'}")
                print(f"  TX Equalization: {'Yes' if lane_control & 0x04 else 'No'}")
                print(f"  TX Pre-emphasis: {'Yes' if lane_control & 0x08 else 'No'}")
                print(f"  TX De-emphasis: {'Yes' if lane_control & 0x10 else 'No'}")
                print(f"  TX Swing: {'Yes' if lane_control & 0x20 else 'No'}")
                print(f"  TX Bias: {'Yes' if lane_control & 0x40 else 'No'}")
                print(f"  TX Power: {'Yes' if lane_control & 0x80 else 'No'}")
       
    except Exception as e:
        print(f"Error reading CMIS Page 10h: {e}")

def read_cmis_page_11h(page_dict):
    """Read and print all CMIS Page 11h (Lane Status) fields according to OIF-CMIS 5.3."""
    try:
        print("\n=== CMIS Page 11h (Lane Status) ===")
       
        # Table 8-89: Lane Status Registers
        print("\n--- Lane Status Registers ---")
        for lane in range(8):
            lane_status = get_byte(page_dict, '1100h', lane)
            if lane_status is not None:
                print(f"Lane {lane+1} Status: 0x{lane_status:02x}")
                print(f"  TX Fault: {'Yes' if lane_status & 0x01 else 'No'}")
                print(f"  RX LOS: {'Yes' if lane_status & 0x02 else 'No'}")
                print(f"  TX CDR LOL: {'Yes' if lane_status & 0x04 else 'No'}")
                print(f"  RX CDR LOL: {'Yes' if lane_status & 0x08 else 'No'}")
                print(f"  TX Power: {'Yes' if lane_status & 0x10 else 'No'}")
                print(f"  RX Power: {'Yes' if lane_status & 0x20 else 'No'}")
                print(f"  TX Bias: {'Yes' if lane_status & 0x40 else 'No'}")
                print(f"  TX Temperature: {'Yes' if lane_status & 0x80 else 'No'}")
       
    except Exception as e:
        print(f"Error reading CMIS Page 11h: {e}")

def read_cmis_page_04h(page_dict):
    """Read and print all CMIS Page 04h (Vendor-specific) fields according to OIF-CMIS 5.3."""
    try:
        print("\n=== CMIS Page 04h (Vendor-specific) ===")
       
        # Vendor-specific data (bytes 0-255)
        vendor_data = get_bytes(page_dict, '400h', 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
       
    except Exception as e:
        print(f"Error reading CMIS Page 04h: {e}")

def read_cmis_page_12h(page_dict):
    """Read and print all CMIS Page 12h (Tunable Laser) fields according to OIF-CMIS 5.3."""
    try:
        print("\n=== CMIS Page 12h (Tunable Laser) ===")
       
        # Tunable laser control and status registers
        print("\n--- Tunable Laser Control and Status ---")
       
        # Laser control registers (bytes 0-15)
        laser_control = get_bytes(page_dict, '1200h', 0x00, 0x10)
        if laser_control:
            print(f"Laser Control: {laser_control}")
       
        # Laser status registers (bytes 16-31)
        laser_status = get_bytes(page_dict, '1200h', 0x10, 0x20)
        if laser_status:
            print(f"Laser Status: {laser_status}")
       
        # Wavelength control registers (bytes 32-47)
        wavelength_control = get_bytes(page_dict, '1200h', 0x20, 0x30)
        if wavelength_control:
            print(f"Wavelength Control: {wavelength_control}")
       
        # Wavelength status registers (bytes 48-63)
        wavelength_status = get_bytes(page_dict, '1200h', 0x30, 0x40)
        if wavelength_status:
            print(f"Wavelength Status: {wavelength_status}")
       
    except Exception as e:
        print(f"Error reading CMIS Page 12h: {e}")

def read_cmis_page_13h(page_dict):
    """Read and print all CMIS Page 13h (Diagnostics) fields according to OIF-CMIS 5.3."""
    try:
        print("\n=== CMIS Page 13h (Diagnostics) ===")
       
        # Diagnostic control and status registers
        print("\n--- Diagnostic Control and Status ---")
       
        # Diagnostic control registers (bytes 0-15)
        diag_control = get_bytes(page_dict, '1300h', 0x00, 0x10)
        if diag_control:
            print(f"Diagnostic Control: {diag_control}")
       
        # Diagnostic status registers (bytes 16-31)
        diag_status = get_bytes(page_dict, '1300h', 0x10, 0x20)
        if diag_status:
            print(f"Diagnostic Status: {diag_status}")
       
        # Diagnostic data registers (bytes 32-255)
        diag_data = get_bytes(page_dict, '1300h', 0x20, 0x100)
        if diag_data:
            print(f"Diagnostic Data: {diag_data}")
       
    except Exception as e:
        print(f"Error reading CMIS Page 13h: {e}")

def read_cmis_page_25h(page_dict):
    """Read and print all CMIS Page 25h (Vendor-specific) fields according to OIF-CMIS 5.3."""
    try:
        print("\n=== CMIS Page 25h (Vendor-specific) ===")
       
        # Vendor-specific data (bytes 0-255)
        vendor_data = get_bytes(page_dict, '2500h', 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
       
    except Exception as e:
        print(f"Error reading CMIS Page 25h: {e}")

# Additional CMIS page functions (14h-19h, 1Ch, 1Dh)
def read_cmis_page_14h(page_dict):
    """Read CMIS Page 14h (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 14h (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, '1400h', 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 14h: {e}")

def read_cmis_page_15h(page_dict):
    """Read CMIS Page 15h (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 15h (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, '1500h', 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 15h: {e}")

def read_cmis_page_16h(page_dict):
    """Read CMIS Page 16h (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 16h (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, '1600h', 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 16h: {e}")

def read_cmis_page_17h(page_dict):
    """Read CMIS Page 17h (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 17h (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, '1700h', 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 17h: {e}")

def read_cmis_page_18h(page_dict):
    """Read CMIS Page 18h (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 18h (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, '1800h', 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 18h: {e}")

def read_cmis_page_19h(page_dict):
    """Read CMIS Page 19h (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 19h (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, '1900h', 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 19h: {e}")

def read_cmis_page_1Ch(page_dict):
    """Read CMIS Page 1Ch (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 1Ch (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, '1C00h', 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 1Ch: {e}")

def read_cmis_page_1Dh(page_dict):
    """Read CMIS Page 1Dh (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 1Dh (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, '1D00h', 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 1Dh: {e}")

# Additional CMIS functions for performance monitoring, coherent monitoring, etc.
def read_cmis_performance_monitoring(page_dict):
    """Read CMIS performance monitoring data"""
    try:
        print("\n=== CMIS Performance Monitoring ===")
        print("Performance monitoring data not yet implemented")
    except Exception as e:
        print(f"Error reading CMIS performance monitoring: {e}")

def read_cmis_coherent_monitoring(page_dict):
    """Read CMIS coherent monitoring data"""
    try:
        print("\n=== CMIS Coherent Monitoring ===")
        print("Coherent monitoring data not yet implemented")
    except Exception as e:
        print(f"Error reading CMIS coherent monitoring: {e}")

def read_cmis_page_06h(page_dict):
    """Read CMIS Page 06h - SNR (OSNR) values for host and media sides."""
    if '06h' not in page_dict:
        print("Page 06h not available")
        return
   
    page_06h = page_dict['06h']
    print("\n--- CMIS Page 06h - SNR (OSNR) Values ---")
   
    # Host Side SNR values (bytes 208-223, relative 80-95)
    print("Host Side SNR (dB):")
    for lane in range(8):
        offset = 80 + (lane * 2)  # Relative offset within page
        if offset + 1 < len(page_06h):
            snr_raw = struct.unpack_from('<H', bytes(page_06h[offset:offset+2]))[0]
            snr_db = snr_raw / 256.0  # Convert from 1/256 dB units to dB
            print(f"  Lane {lane+1}: {snr_db:.2f} dB")
        else:
            print(f"  Lane {lane+1}: Not available")
   
    # Media Side SNR values (bytes 240-255, relative 112-127)
    print("Media Side SNR (dB):")
    for lane in range(8):
        offset = 112 + (lane * 2)  # Relative offset within page
        if offset + 1 < len(page_06h):
            snr_raw = struct.unpack_from('<H', bytes(page_06h[offset:offset+2]))[0]
            snr_db = snr_raw / 256.0  # Convert from 1/256 dB units to dB
            print(f"  Lane {lane+1}: {snr_db:.2f} dB")
        else:
            print(f"  Lane {lane+1}: Not available")

def parse_cmis_auxiliary_monitoring(page_dict, cmis_data):
    """Parse CMIS auxiliary monitoring data with proper scaling according to OIF-CMIS 5.3."""
    if '00h' not in page_dict or len(page_dict['00h']) < 26:
        return
    
    # Initialize monitoring structure if it doesn't exist
    if 'monitoring' not in cmis_data:
        cmis_data['monitoring'] = {}
    if 'module' not in cmis_data['monitoring']:
        cmis_data['monitoring']['module'] = {}
    
    # Get auxiliary monitor configuration from Page 01h byte 145
    aux_config = get_byte(page_dict, '01h', 145) if '01h' in page_dict else 0
    
    # Aux1 Monitor (bytes 18-19) - Table 8-10
    if len(page_dict['00h']) >= 20:
        aux1_raw = struct.unpack_from('<h', bytes(page_dict['00h'][18:20]))[0]
        aux1_config = (aux_config >> 0) & 0x01
        
        if aux1_config == 0:
            # Custom Aux1 monitor
            aux1_value = aux1_raw
            aux1_unit = "raw"
        else:
            # TEC Current monitor
            # Scale: 100%/32767 increments of maximum TEC current magnitude
            aux1_value = (aux1_raw / 32767.0) * 100.0  # Convert to percentage
            aux1_unit = "% of max TEC current"
        
        cmis_data['monitoring']['module']['aux1'] = {
            'raw': aux1_raw,
            'value': aux1_value,
            'unit': aux1_unit,
            'type': 'TEC Current' if aux1_config else 'Custom'
        }
    
    # Aux2 Monitor (bytes 20-21) - Table 8-10
    if len(page_dict['00h']) >= 22:
        aux2_raw = struct.unpack_from('<h', bytes(page_dict['00h'][20:22]))[0]
        aux2_config = (aux_config >> 1) & 0x01
        
        if aux2_config == 0:
            # Laser Temperature monitor
            aux2_value = aux2_raw / 256.0  # Convert from 1/256 degree Celsius increments
            aux2_unit = "°C"
        else:
            # TEC Current monitor
            aux2_value = (aux2_raw / 32767.0) * 100.0  # Convert to percentage
            aux2_unit = "% of max TEC current"
        
        cmis_data['monitoring']['module']['aux2'] = {
            'raw': aux2_raw,
            'value': aux2_value,
            'unit': aux2_unit,
            'type': 'Laser Temperature' if aux2_config == 0 else 'TEC Current'
        }
    
    # Aux3 Monitor (bytes 22-23) - Table 8-10
    if len(page_dict['00h']) >= 24:
        aux3_raw = struct.unpack_from('<h', bytes(page_dict['00h'][22:24]))[0]
        aux3_config = (aux_config >> 2) & 0x01
        
        if aux3_config == 0:
            # Laser Temperature monitor
            aux3_value = aux3_raw / 256.0  # Convert from 1/256 degree Celsius increments
            aux3_unit = "°C"
        else:
            # Additional Supply Voltage monitor
            aux3_value = aux3_raw * 0.0001  # Convert from 100 µV increments to volts
            aux3_unit = "V"
        
        cmis_data['monitoring']['module']['aux3'] = {
            'raw': aux3_raw,
            'value': aux3_value,
            'unit': aux3_unit,
            'type': 'Laser Temperature' if aux3_config == 0 else 'Additional Supply Voltage'
        }

def parse_cmis_thresholds(page_dict, cmis_data):
    """Parse CMIS thresholds from Page 02h according to OIF-CMIS 5.3 Table 8-62."""
    if '02h' not in page_dict or len(page_dict['02h']) < 176:
        return
    
    page_02h = page_dict['02h']
    thresholds = {}
    
    # Module-level thresholds (bytes 128-175)
    if len(page_02h) >= 176:
        # Temperature thresholds (bytes 128-135)
        temp_high_alarm = struct.unpack_from('<h', bytes(page_02h[128:130]))[0] / 256.0
        temp_low_alarm = struct.unpack_from('<h', bytes(page_02h[130:132]))[0] / 256.0
        temp_high_warning = struct.unpack_from('<h', bytes(page_02h[132:134]))[0] / 256.0
        temp_low_warning = struct.unpack_from('<h', bytes(page_02h[134:136]))[0] / 256.0
        
        # VCC thresholds (bytes 136-143)
        vcc_high_alarm = struct.unpack_from('<H', bytes(page_02h[136:138]))[0] * 0.0001
        vcc_low_alarm = struct.unpack_from('<H', bytes(page_02h[138:140]))[0] * 0.0001
        vcc_high_warning = struct.unpack_from('<H', bytes(page_02h[140:142]))[0] * 0.0001
        vcc_low_warning = struct.unpack_from('<H', bytes(page_02h[142:144]))[0] * 0.0001
        
        # Aux1 thresholds (bytes 144-151)
        aux1_high_alarm = struct.unpack_from('<h', bytes(page_02h[144:146]))[0]
        aux1_low_alarm = struct.unpack_from('<h', bytes(page_02h[146:148]))[0]
        aux1_high_warning = struct.unpack_from('<h', bytes(page_02h[148:150]))[0]
        aux1_low_warning = struct.unpack_from('<h', bytes(page_02h[150:152]))[0]
        
        # Aux2 thresholds (bytes 152-159)
        aux2_high_alarm = struct.unpack_from('<h', bytes(page_02h[152:154]))[0]
        aux2_low_alarm = struct.unpack_from('<h', bytes(page_02h[154:156]))[0]
        aux2_high_warning = struct.unpack_from('<h', bytes(page_02h[156:158]))[0]
        aux2_low_warning = struct.unpack_from('<h', bytes(page_02h[158:160]))[0]
        
        # Aux3 thresholds (bytes 160-167)
        aux3_high_alarm = struct.unpack_from('<h', bytes(page_02h[160:162]))[0]
        aux3_low_alarm = struct.unpack_from('<h', bytes(page_02h[162:164]))[0]
        aux3_high_warning = struct.unpack_from('<h', bytes(page_02h[164:166]))[0]
        aux3_low_warning = struct.unpack_from('<h', bytes(page_02h[166:168]))[0]
        
        # Custom monitor thresholds (bytes 168-175)
        custom_high_alarm = struct.unpack_from('<h', bytes(page_02h[168:170]))[0]
        custom_low_alarm = struct.unpack_from('<h', bytes(page_02h[170:172]))[0]
        custom_high_warning = struct.unpack_from('<h', bytes(page_02h[172:174]))[0]
        custom_low_warning = struct.unpack_from('<h', bytes(page_02h[174:176]))[0]
        
        thresholds['module'] = {
            'temperature': {
                'high_alarm': temp_high_alarm,
                'low_alarm': temp_low_alarm,
                'high_warning': temp_high_warning,
                'low_warning': temp_low_warning
            },
            'vcc': {
                'high_alarm': vcc_high_alarm,
                'low_alarm': vcc_low_alarm,
                'high_warning': vcc_high_warning,
                'low_warning': vcc_low_warning
            },
            'aux1': {
                'high_alarm': aux1_high_alarm,
                'low_alarm': aux1_low_alarm,
                'high_warning': aux1_high_warning,
                'low_warning': aux1_low_warning
            },
            'aux2': {
                'high_alarm': aux2_high_alarm,
                'low_alarm': aux2_low_alarm,
                'high_warning': aux2_high_warning,
                'low_warning': aux2_low_warning
            },
            'aux3': {
                'high_alarm': aux3_high_alarm,
                'low_alarm': aux3_low_alarm,
                'high_warning': aux3_high_warning,
                'low_warning': aux3_low_warning
            },
            'custom': {
                'high_alarm': custom_high_alarm,
                'low_alarm': custom_low_alarm,
                'high_warning': custom_high_warning,
                'low_warning': custom_low_warning
            }
        }
    
    cmis_data['thresholds'] = thresholds

def parse_cmis_lane_thresholds(page_dict, cmis_data):
    """Parse CMIS lane-specific thresholds from Page 02h."""
    if '02h' not in page_dict or len(page_dict['02h']) < 256:
        return
    
    page_02h = page_dict['02h']
    supported_lanes = cmis_data.get('media_info', {}).get('supported_lanes', [])
    
    lane_thresholds = {}
    for lane_num in supported_lanes:
        # Lane thresholds start at byte 176 + (lane_num - 1) * 16
        base_offset = 176 + (lane_num - 1) * 16
        if base_offset + 15 < len(page_02h):
            lane_thresholds[f'lane_{lane_num}'] = {
                'tx_power_high_alarm': struct.unpack_from('<H', bytes(page_02h[base_offset:base_offset+2]))[0] * 0.01,
                'tx_power_low_alarm': struct.unpack_from('<H', bytes(page_02h[base_offset+2:base_offset+4]))[0] * 0.01,
                'tx_power_high_warning': struct.unpack_from('<H', bytes(page_02h[base_offset+4:base_offset+6]))[0] * 0.01,
                'tx_power_low_warning': struct.unpack_from('<H', bytes(page_02h[base_offset+6:base_offset+8]))[0] * 0.01,
                'rx_power_high_alarm': struct.unpack_from('<H', bytes(page_02h[base_offset+8:base_offset+10]))[0] * 0.01,
                'rx_power_low_alarm': struct.unpack_from('<H', bytes(page_02h[base_offset+10:base_offset+12]))[0] * 0.01,
                'rx_power_high_warning': struct.unpack_from('<H', bytes(page_02h[base_offset+12:base_offset+14]))[0] * 0.01,
                'rx_power_low_warning': struct.unpack_from('<H', bytes(page_02h[base_offset+14:base_offset+16]))[0] * 0.01
            }
    
    if lane_thresholds:
        cmis_data['thresholds']['lanes'] = lane_thresholds

def parse_cmis_application_descriptors(page_dict, cmis_data):
    """Parse CMIS application descriptors from Page 01h."""
    if '01h' not in page_dict or len(page_dict['01h']) < 160:
        return
    
    page_01h = page_dict['01h']
    applications = []
    
    # Application descriptors start at byte 128
    for app in range(8):
        base = 128 + app * 8
        if base + 7 < len(page_01h):
            code = page_01h[base]
            if code != 0:  # Valid application code
                app_info = {
                    'code': code,
                    'host_lane_count': page_01h[base + 1],
                    'media_lane_count': page_01h[base + 2],
                    'host_lane_assignment': page_01h[base + 3],
                    'media_lane_assignment': page_01h[base + 4],
                    'host_lane_technology': page_01h[base + 5],
                    'media_lane_technology': page_01h[base + 6],
                    'media_lane_technology_2': page_01h[base + 7]
                }
                
                # Map application codes to names
                app_map = APPLICATION_CODE_NAMES
                
                app_info['name'] = app_map.get(code, f'Unknown({code:02x})')
                applications.append(app_info)
    
    if applications:
        cmis_data['application_info']['applications'] = applications

# Add PAM4 eye and histogram functionality based on OIF-CMIS 5.3 specification

def parse_cmis_vdm_pam4_observables(page_dict, cmis_data):
    """Parse CMIS VDM PAM4 observables (SNR and LTP) from Pages 20h-27h."""
    if not any(f'{i:02x}h' in page_dict for i in range(0x20, 0x28)):
        return
    
    # Initialize VDM data structure
    if 'vdm' not in cmis_data:
        cmis_data['vdm'] = {}
    
    # Parse VDM descriptors from Pages 20h-23h
    vdm_observables = {}
    for page_num in range(0x20, 0x24):
        page_key = f'{page_num:02x}h'
        if page_key in page_dict and len(page_dict[page_key]) >= 256:
            page_data = page_dict[page_key]
            # Each VDM descriptor is 2 bytes, starting at byte 128
            for instance in range(64):
                base_offset = 128 + (instance * 2)
                if base_offset + 1 < len(page_data):
                    # Parse VDM descriptor (2 bytes)
                    descriptor_bytes = page_data[base_offset:base_offset + 2]
                    if len(descriptor_bytes) == 2:
                        # Big Endian format
                        descriptor = (descriptor_bytes[0] << 8) | descriptor_bytes[1]
                        
                        # Extract fields from descriptor
                        observable_type = descriptor & 0xFF
                        instance_type = (descriptor >> 8) & 0x03
                        threshold_set = (descriptor >> 10) & 0x0F
                        lane_number = (descriptor >> 14) & 0x07
                        
                        # Map observable types to names (based on OIF-CMIS 5.3 Table 8-170)
                        observable_names = VDM_OBSERVABLE_TYPES
                        
                        # Include all valid observable types (excluding reserved ranges)
                        valid_types = set(range(0, 35)) | {77, 78, 79, 80, 81, 82, 83, 84}
                        if observable_type in valid_types and observable_type != 0:  # Skip "Not Used" indicator
                            vdm_observables[instance + 1] = {
                                'type': observable_type,
                                'name': observable_names[observable_type],
                                'instance_type': instance_type,
                                'threshold_set': threshold_set,
                                'lane_number': lane_number,
                                'page': page_key
                            }
    
    # Parse VDM samples from Pages 24h-27h
    vdm_samples = {}
    for page_num in range(0x24, 0x28):
        page_key = f'{page_num:02x}h'
        if page_key in page_dict and len(page_dict[page_key]) >= 256:
            page_data = page_dict[page_key]
            # Each sample is 2 bytes, starting at byte 128
            for instance in range(64):
                base_offset = 128 + (instance * 2)
                if base_offset + 1 < len(page_data):
                    # Parse sample value (Big Endian)
                    sample_bytes = page_data[base_offset:base_offset + 2]
                    if len(sample_bytes) == 2:
                        sample_raw = (sample_bytes[0] << 8) | sample_bytes[1]
                        
                        # Convert based on observable type
                        global_instance = (page_num - 0x24) * 64 + instance + 1
                        if global_instance in vdm_observables:
                            obs_type = vdm_observables[global_instance]['type']
                            obs_name = vdm_observables[global_instance]['name']
                            
                            # Handle different data types and scaling factors
                            sample_data = {
                                'raw': sample_raw,
                                'observable': vdm_observables[global_instance]
                            }
                            
                            # Type-specific conversions based on OIF-CMIS 5.3 Table 8-170
                            if obs_type in [1]:  # Laser Age - U16, scale 1, unit %
                                sample_data['value'] = sample_raw
                                sample_data['unit'] = '%'
                                sample_data['description'] = f"Laser Age: {sample_raw}%"
                                
                            elif obs_type in [2]:  # TEC Current - S16, scale 100/32767, unit %
                                # Convert signed 16-bit to percentage
                                if sample_raw > 32767:
                                    sample_raw = sample_raw - 65536  # Convert to signed
                                tec_percent = (sample_raw / 32767.0) * 100.0
                                sample_data['value'] = tec_percent
                                sample_data['unit'] = '%'
                                sample_data['description'] = f"TEC Current: {tec_percent:.2f}%"
                                
                            elif obs_type in [3]:  # Laser Frequency Error - S16, scale 10, unit MHz
                                if sample_raw > 32767:
                                    sample_raw = sample_raw - 65536  # Convert to signed
                                freq_error = sample_raw / 10.0
                                sample_data['value'] = freq_error
                                sample_data['unit'] = 'MHz'
                                sample_data['description'] = f"Laser Frequency Error: {freq_error:.1f} MHz"
                                
                            elif obs_type in [4]:  # Laser Temperature - S16, scale 1/256, unit C
                                if sample_raw > 32767:
                                    sample_raw = sample_raw - 65536  # Convert to signed
                                temp_celsius = sample_raw / 256.0
                                sample_data['value'] = temp_celsius
                                sample_data['unit'] = '°C'
                                sample_data['description'] = f"Laser Temperature: {temp_celsius:.2f}°C"
                                
                            elif obs_type in [5, 6, 7, 8]:  # SNR and LTP observables - U16, scale 1/256, unit dB
                                sample_dB = sample_raw / 256.0
                                sample_data['value'] = sample_dB
                                sample_data['unit'] = 'dB'
                                sample_data['description'] = f"{obs_name}: {sample_dB:.2f} dB"
                                
                            elif obs_type in [15, 16]:  # Pre-FEC BER Current Sample - F16, no scaling
                                # F16 format - handle as raw value for now
                                sample_data['value'] = sample_raw
                                sample_data['unit'] = 'raw'
                                sample_data['description'] = f"{obs_name}: {sample_raw} (raw F16)"
                                
                            elif obs_type in [23, 24]:  # FERC Current Sample - F16, no scaling
                                # F16 format - handle as raw value for now
                                sample_data['value'] = sample_raw
                                sample_data['unit'] = 'raw'
                                sample_data['description'] = f"{obs_name}: {sample_raw} (raw F16)"
                                
                            elif obs_type in [33, 34]:  # SEWmax Current Sample - U16, no scaling
                                sample_data['value'] = sample_raw
                                sample_data['unit'] = 'count'
                                sample_data['description'] = f"{obs_name}: {sample_raw}"
                                
                            elif obs_type in [77, 78, 79, 80, 81, 82, 83]:  # Voltage Monitors - U16, scale 100, unit uV
                                voltage_uV = sample_raw * 100
                                voltage_V = voltage_uV / 1000000.0
                                sample_data['value'] = voltage_V
                                sample_data['unit'] = 'V'
                                sample_data['description'] = f"{obs_name}: {voltage_V:.3f}V ({voltage_uV} µV)"
                                
                            elif obs_type in [84]:  # ELS Input Power - S16, scale 0.01, unit dBm
                                if sample_raw > 32767:
                                    sample_raw = sample_raw - 65536  # Convert to signed
                                power_dBm = sample_raw * 0.01
                                sample_data['value'] = power_dBm
                                sample_data['unit'] = 'dBm'
                                sample_data['description'] = f"{obs_name}: {power_dBm:.2f} dBm"
                                
                            else:
                                # Default handling for other types
                                sample_data['value'] = sample_raw
                                sample_data['unit'] = 'raw'
                                sample_data['description'] = f"{obs_name}: {sample_raw} (raw)"
                            
                            vdm_samples[global_instance] = sample_data
    
    if vdm_observables:
        cmis_data['vdm']['observables'] = vdm_observables
    if vdm_samples:
        cmis_data['vdm']['samples'] = vdm_samples

def parse_cmis_cdb_pam4_histogram(page_dict, cmis_data):
    """Parse CMIS CDB PAM4 histogram commands (0390h reserved for PAM4 Histogram)."""
    # Only proceed if Page 9Fh exists and is non-empty
    if '9Fh' not in page_dict or not page_dict['9Fh'] or len(page_dict['9Fh']) == 0:
        return
    
    # Initialize CDB data structure if not present
    if 'cdb' not in cmis_data:
        cmis_data['cdb'] = {}
    
    page_9f = page_dict['9Fh']
    if len(page_9f) < 136:  # Minimum header size
        return
    
    # Parse CDB Command Message Header (Table 8-178)
    # Bytes 128-129: CMDID (Command ID)
    cmd_id = (page_9f[128] << 8) | page_9f[129]
    
    # Bytes 130-131: EPLLength (Extended Payload Length)
    epl_length = (page_9f[130] << 8) | page_9f[131]
    
    # Byte 132: LPLLength (Local Payload Length)
    lpl_length = page_9f[132]
    
    # Byte 133: CdbChkCode (Check Code)
    cdb_chk_code = page_9f[133]
    
    # Bytes 134-135: Reply header fields (filled by module)
    rpl_length = page_9f[134]
    rpl_chk_code = page_9f[135]
    
    # Parse LPL (Local Payload) data if present
    lpl_data = None
    if lpl_length > 0 and len(page_9f) >= 136 + lpl_length:
        lpl_data = page_9f[136:136 + lpl_length]
    
    # Parse EPL (Extended Payload) data if present
    epl_data = None
    if epl_length > 0:
        # EPL data is in Pages A0h-AFh
        epl_pages = []
        for page_num in range(0xA0, 0xB0):  # Pages A0h-AFh
            page_key = f'{page_num:02X}h'
            if page_key in page_dict and page_dict[page_key] and len(page_dict[page_key]) > 0:
                epl_pages.append(page_dict[page_key])
        
        if epl_pages:
            epl_data = b''.join(epl_pages)[:epl_length]
    
    # Check if this is the PAM4 Histogram command (0390h)
    if cmd_id == 0x0390:
        # Parse PAM4 Histogram command data
        histogram_data = parse_pam4_histogram_command(lpl_data, epl_data, epl_length, lpl_length)
        
        cmis_data['cdb']['pam4_histogram'] = {
            'command_id': f'{cmd_id:04X}h',
            'status': 'PAM4 Histogram command detected',
            'description': 'CDB command 0390h is reserved for PAM4 histogram functionality as per OIF-CMIS 5.3',
            'epl_length': epl_length,
            'lpl_length': lpl_length,
            'cdb_chk_code': cdb_chk_code,
            'rpl_length': rpl_length,
            'rpl_chk_code': rpl_chk_code,
            'lpl_data': lpl_data,
            'epl_data': epl_data,
            'histogram_data': histogram_data
        }
    else:
        # Other CDB commands
        cmis_data['cdb']['other_commands'] = cmis_data['cdb'].get('other_commands', [])
        cmis_data['cdb']['other_commands'].append({
            'command_id': f'{cmd_id:04X}h',
            'epl_length': epl_length,
            'lpl_length': lpl_length,
            'cdb_chk_code': cdb_chk_code,
            'rpl_length': rpl_length,
            'rpl_chk_code': rpl_chk_code,
            'lpl_data': lpl_data,
            'epl_data': epl_data
        })

def parse_pam4_histogram_command(lpl_data, epl_data, epl_length, lpl_length):
    """Parse PAM4 Histogram command data (CDB command 0390h)."""
    histogram_data = {
        'status': 'Command structure parsed',
        'lpl_length': lpl_length,
        'epl_length': epl_length,
        'lpl_data_hex': None,
        'epl_data_hex': None,
        'histogram_bins': None,
        'histogram_parameters': None
    }
    
    # Convert data to hex for display
    if lpl_data:
        histogram_data['lpl_data_hex'] = lpl_data.hex()
    
    if epl_data:
        histogram_data['epl_data_hex'] = epl_data.hex()
    
    # Parse histogram parameters if LPL data is present
    if lpl_data and len(lpl_data) >= 4:
        # Example parsing - actual structure would be defined in future CMIS spec updates
        histogram_data['histogram_parameters'] = {
            'lane_number': lpl_data[0] if len(lpl_data) > 0 else 0,
            'bin_count': lpl_data[1] if len(lpl_data) > 1 else 0,
            'start_level': lpl_data[2] if len(lpl_data) > 2 else 0,
            'end_level': lpl_data[3] if len(lpl_data) > 3 else 0
        }
    
    # Parse histogram bins if EPL data is present
    if epl_data and len(epl_data) > 0:
        # Each bin could be 2-4 bytes depending on implementation
        bin_size = 2  # Assume 2 bytes per bin for now
        num_bins = len(epl_data) // bin_size
        
        histogram_bins = []
        for i in range(num_bins):
            offset = i * bin_size
            if offset + bin_size <= len(epl_data):
                bin_value = int.from_bytes(epl_data[offset:offset + bin_size], byteorder='big')
                histogram_bins.append(bin_value)
        
        histogram_data['histogram_bins'] = histogram_bins
        histogram_data['bin_count'] = len(histogram_bins)
    
    return histogram_data

def parse_cmis_cdb_commands(page_dict, cmis_data):
    """Parse all CMIS CDB commands from Page 9Fh."""
    if '9Fh' not in page_dict:
        return
    
    page_9f = page_dict['9Fh']
    if len(page_9f) < 136:  # Minimum header size
        return
    
    # Parse CDB Command Message Header (Table 8-178)
    cmd_id = (page_9f[128] << 8) | page_9f[129]
    epl_length = (page_9f[130] << 8) | page_9f[131]
    lpl_length = page_9f[132]
    cdb_chk_code = page_9f[133]
    rpl_length = page_9f[134]
    rpl_chk_code = page_9f[135]
    
    # Initialize CDB data structure
    if 'cdb' not in cmis_data:
        cmis_data['cdb'] = {}
    
    # Parse LPL data
    lpl_data = None
    if lpl_length > 0 and len(page_9f) >= 136 + lpl_length:
        lpl_data = page_9f[136:136 + lpl_length]
    
    # Parse EPL data
    epl_data = None
    if epl_length > 0:
        epl_pages = []
        for page_num in range(0xA0, 0xB0):  # Pages A0h-AFh
            page_key = f'{page_num:02X}h'
            if page_key in page_dict:
                epl_pages.append(page_dict[page_key])
        
        if epl_pages:
            epl_data = b''.join(epl_pages)[:epl_length]
    
    # Store CDB command information
    cdb_command = {
        'command_id': f'{cmd_id:04X}h',
        'command_name': get_cdb_command_name(cmd_id),
        'epl_length': epl_length,
        'lpl_length': lpl_length,
        'cdb_chk_code': cdb_chk_code,
        'rpl_length': rpl_length,
        'rpl_chk_code': rpl_chk_code,
        'lpl_data': lpl_data,
        'epl_data': epl_data
    }
    
    # Store in appropriate category
    if cmd_id == 0x0390:
        cmis_data['cdb']['pam4_histogram'] = cdb_command
    else:
        if 'other_commands' not in cmis_data['cdb']:
            cmis_data['cdb']['other_commands'] = []
        cmis_data['cdb']['other_commands'].append(cdb_command)

def get_cdb_command_name(cmd_id):
    """Get CDB command name based on command ID."""
    return CDB_COMMANDS.get(cmd_id, f"Unknown Command ({cmd_id:04X}h)")

def output_cmis_cdb_data(cmis_data, verbose=False):
    cdb = cmis_data.get('cdb', {})
    if verbose:
        print("\n=== CDB Command Data ===")
    # PAM4 Histogram command
    if 'pam4_histogram' in cdb:
        pam4_hist = cdb['pam4_histogram']
        unavailable_statuses = [
            'Page 9Fh not available - CDB data not present',
            'Page 9Fh too short - insufficient CDB header data',
            'Reserved for PAM4 Histogram (not yet implemented)'
        ]
        if pam4_hist.get('status') in unavailable_statuses:
            pass  # Do not output anything if data is not available
        else:
            if verbose:
                print(f"\n--- PAM4 Histogram Command ({pam4_hist['command_id']}) ---")
            if 'status' in pam4_hist:
                print(f"Status: {pam4_hist['status']}")
            if 'description' in pam4_hist:
                print(f"Description: {pam4_hist['description']}")
            if 'epl_length' in pam4_hist:
                print(f"EPL Length: {pam4_hist['epl_length']} bytes")
            if 'lpl_length' in pam4_hist:
                print(f"LPL Length: {pam4_hist['lpl_length']} bytes")
            if 'cdb_chk_code' in pam4_hist:
                print(f"CDB Check Code: 0x{pam4_hist['cdb_chk_code']:02X}")
            if 'rpl_length' in pam4_hist:
                print(f"Reply Length: {pam4_hist['rpl_length']} bytes")
            if 'rpl_chk_code' in pam4_hist:
                print(f"Reply Check Code: 0x{pam4_hist['rpl_chk_code']:02X}")
            # Display histogram data if available
            if 'histogram_data' in pam4_hist:
                hist_data = pam4_hist['histogram_data']
                if verbose:
                    print(f"Histogram Status: {hist_data['status']}")
                if hist_data['histogram_parameters']:
                    params = hist_data['histogram_parameters']
                    if verbose:
                        print(f"Lane Number: {params['lane_number']}")
                    if verbose:
                        print(f"Bin Count: {params['bin_count']}")
                    if verbose:
                        print(f"Start Level: {params['start_level']}")
                    if verbose:
                        print(f"End Level: {params['end_level']}")
                if hist_data['histogram_bins']:
                    if verbose:
                        print(f"Histogram Bins: {len(hist_data['histogram_bins'])} bins")
                    # Show first few bins as example
                    for i, bin_value in enumerate(hist_data['histogram_bins'][:10]):
                        if verbose:
                            print(f"  Bin {i}: {bin_value}")
                    if len(hist_data['histogram_bins']) > 10:
                        if verbose:
                            print(f"  ... and {len(hist_data['histogram_bins']) - 10} more bins")
            # Display raw data if available
            if 'lpl_data_hex' in pam4_hist.get('histogram_data', {}):
                if verbose:
                    print(f"LPL Data: {pam4_hist['histogram_data']['lpl_data_hex']}")
            if 'epl_data_hex' in pam4_hist.get('histogram_data', {}):
                epl_hex = pam4_hist['histogram_data']['epl_data_hex']
                if len(epl_hex) > 100:
                    if verbose:
                        print(f"EPL Data: {epl_hex[:100]}... (truncated)")
                else:
                    if verbose:
                        print(f"EPL Data: {epl_hex}")
    # Other CDB commands
    if 'other_commands' in cdb:
        if verbose:
            print(f"\n--- Other CDB Commands ({len(cdb['other_commands'])}) ---")
        for cmd in cdb['other_commands']:
            if verbose:
                print(f"Command: {cmd['command_id']} - {cmd.get('command_name', 'Unknown')}")
            if 'epl_length' in cmd:
                if verbose:
                    print(f"  EPL Length: {cmd['epl_length']} bytes")
            if 'lpl_length' in cmd:
                if verbose:
                    print(f"  LPL Length: {cmd['lpl_length']} bytes")
            if 'cdb_chk_code' in cmd:
                if verbose:
                    print(f"  CDB Check Code: 0x{cmd['cdb_chk_code']:02X}")
            if 'rpl_length' in cmd:
                if verbose:
                    print(f"  Reply Length: {cmd['rpl_length']} bytes")
            if 'rpl_chk_code' in cmd:
                if verbose:
                    print(f"  Reply Check Code: 0x{cmd['rpl_chk_code']:02X}")
            print()

# Add VDM page reading function for PAM4 observables
def read_cmis_vdm_pam4_pages(page_dict):
    """Read and display CMIS VDM pages (20h-27h) for PAM4 observables."""
    print("\n=== CMIS VDM Pages (PAM4 Observables) ===")
    
    # Check for VDM descriptor pages (20h-23h)
    for page_num in range(0x20, 0x24):
        page_key = f'{page_num:02x}h'
        if page_key in page_dict:
            print(f"\n--- Page {page_key} (VDM Descriptors) ---")
            page_data = page_dict[page_key]
            if len(page_data) >= 256:
                print(f"Page length: {len(page_data)} bytes")
                
                # Parse VDM descriptors
                for instance in range(64):
                    base_offset = 128 + (instance * 2)
                    if base_offset + 1 < len(page_data):
                        descriptor_bytes = page_data[base_offset:base_offset + 2]
                        if len(descriptor_bytes) == 2:
                            descriptor = (descriptor_bytes[0] << 8) | descriptor_bytes[1]
                            observable_type = descriptor & 0xFF
                            
                            # Only show PAM4-related observables
                            pam4_types = {5, 6, 7, 8}  # SNR and LTP observables
                            if observable_type in pam4_types:
                                observable_names = {
                                    5: "SNR (dB) Media Input",
                                    6: "SNR (dB) Host Input",
                                    7: "PAM4 Level Transition Parameter Media Input",
                                    8: "PAM4 Level Transition Parameter Host Input"
                                }
                                print(f"  Instance {instance + 1}: {observable_names.get(observable_type, f'Unknown({observable_type})')}")
            else:
                print(f"Page too short: {len(page_data)} bytes")
    
    # Check for VDM sample pages (24h-27h)
    for page_num in range(0x24, 0x28):
        page_key = f'{page_num:02x}h'
        if page_key in page_dict:
            print(f"\n--- Page {page_key} (VDM Samples) ---")
            page_data = page_dict[page_key]
            if len(page_data) >= 256:
                print(f"Page length: {len(page_data)} bytes")
                
                # Parse VDM samples
                for instance in range(64):
                    base_offset = 128 + (instance * 2)
                    if base_offset + 1 < len(page_data):
                        sample_bytes = page_data[base_offset:base_offset + 2]
                        if len(sample_bytes) == 2:
                            sample_raw = (sample_bytes[0] << 8) | sample_bytes[1]
                            sample_dB = sample_raw / 256.0
                            print(f"  Instance {instance + 1}: {sample_dB:.2f} dB (0x{sample_raw:04x})")
            else:
                print(f"Page too short: {len(page_data)} bytes")

def output_cmis_vdm_data(cmis_data):
    """Output VDM observables data in a unified format."""
    print("\n=== VDM Observables Data ===")
    
    # VDM Observables
    if cmis_data.get('vdm', {}).get('observables'):
        print("\n--- VDM Observables ---")
        observables = cmis_data['vdm']['observables']
        samples = cmis_data['vdm'].get('samples', {})
        
        for instance_id, observable in observables.items():
            print(f"Instance {instance_id}: {observable['name']}")
            print(f"  Type: {observable['type']}")
            print(f"  Instance Type: {observable['instance_type']}")
            print(f"  Threshold Set: {observable['threshold_set']}")
            print(f"  Lane Number: {observable['lane_number']}")
            print(f"  Page: {observable['page']}")
            
            # Display sample value if available
            if instance_id in samples:
                sample = samples[instance_id]
                print(f"  Raw Value: 0x{sample['raw']:04x}")
                print(f"  {sample['description']}")
            else:
                print("  Sample: Not available")
            print()
    
    # CDB PAM4 Histogram
    if cmis_data.get('cdb', {}).get('pam4_histogram'):
        print("\n--- CDB PAM4 Histogram ---")
        pam4_hist = cmis_data['cdb']['pam4_histogram']
        print(f"Command ID: {pam4_hist['command_id']}")
        print(f"Status: {pam4_hist['status']}")
        print(f"Description: {pam4_hist['description']}")

def output_cmis_pam4_data(cmis_data, verbose=False):
    if verbose:
        print("\n=== PAM4 Eye and Histogram Data ===")
    # VDM PAM4 Observables
    if cmis_data.get('vdm', {}).get('observables'):
        if verbose:
            print("\n--- VDM PAM4 Observables ---")
        observables = cmis_data['vdm']['observables']
        samples = cmis_data['vdm'].get('samples', {})
        
        # Filter for PAM4-related observables
        pam4_types = {5, 6, 7, 8}  # SNR and LTP observables
        
        for instance_id, observable in observables.items():
            if observable['type'] in pam4_types:
                if verbose:
                    print(f"Instance {instance_id}: {observable['name']}")
                print(f"  Type: {observable['type']}")
                print(f"  Instance Type: {observable['instance_type']}")
                print(f"  Threshold Set: {observable['threshold_set']}")
                print(f"  Lane Number: {observable['lane_number']}")
                print(f"  Page: {observable['page']}")
                
                # Display sample value if available
                if instance_id in samples:
                    sample = samples[instance_id]
                    if verbose:
                        print(f"  Raw Value: 0x{sample['raw']:04x}")
                    print(f"  {sample['description']}")
                else:
                    if verbose:
                        print("  Sample: Not available")
                print()
    # CDB PAM4 Histogram
    if cmis_data.get('cdb', {}).get('pam4_histogram'):
        if verbose:
            print("\n--- CDB PAM4 Histogram ---")
        pam4_hist = cmis_data['cdb']['pam4_histogram']
        print(f"Command ID: {pam4_hist['command_id']}")
        print(f"Status: {pam4_hist['status']}")
        print(f"Description: {pam4_hist['description']}")

def read_cmis_vdm_pages(page_dict):
    """Read and display CMIS VDM pages (20h-27h) for PAM4 observables."""
    print("\n=== CMIS VDM Pages (PAM4 Observables) ===")
    
    # Check for VDM descriptor pages (20h-23h)
    for page_num in range(0x20, 0x24):
        page_key = f'{page_num:02x}h'
        if page_key in page_dict:
            print(f"\n--- Page {page_key} (VDM Descriptors) ---")
            page_data = page_dict[page_key]
            if len(page_data) >= 256:
                print(f"Page length: {len(page_data)} bytes")
                
                # Parse VDM descriptors
                for instance in range(64):
                    base_offset = 128 + (instance * 2)
                    if base_offset + 1 < len(page_data):
                        descriptor_bytes = page_data[base_offset:base_offset + 2]
                        if len(descriptor_bytes) == 2:
                            descriptor = (descriptor_bytes[0] << 8) | descriptor_bytes[1]
                            observable_type = descriptor & 0xFF
                            
                            # Only show PAM4-related observables
                            pam4_types = {5, 6, 7, 8}  # SNR and LTP observables
                            if observable_type in pam4_types:
                                observable_names = {
                                    5: "SNR (dB) Media Input",
                                    6: "SNR (dB) Host Input",
                                    7: "PAM4 Level Transition Parameter Media Input",
                                    8: "PAM4 Level Transition Parameter Host Input"
                                }
                                print(f"  Instance {instance + 1}: {observable_names.get(observable_type, f'Unknown({observable_type})')}")
            else:
                print(f"Page too short: {len(page_data)} bytes")
    
    # Check for VDM sample pages (24h-27h)
    for page_num in range(0x24, 0x28):
        page_key = f'{page_num:02x}h'
        if page_key in page_dict:
            print(f"\n--- Page {page_key} (VDM Samples) ---")
            page_data = page_dict[page_key]
            if len(page_data) >= 256:
                print(f"Page length: {len(page_data)} bytes")
                
                # Parse VDM samples
                for instance in range(64):
                    base_offset = 128 + (instance * 2)
                    if base_offset + 1 < len(page_data):
                        sample_bytes = page_data[base_offset:base_offset + 2]
                        if len(sample_bytes) == 2:
                            sample_raw = (sample_bytes[0] << 8) | sample_bytes[1]
                            sample_dB = sample_raw / 256.0
                            print(f"  Instance {instance + 1}: {sample_dB:.2f} dB (0x{sample_raw:04x})")
            else:
                print(f"Page too short: {len(page_data)} bytes")

def parse_cmis_thresholds_complete(page_dict, cmis_data):
    """Parse all CMIS thresholds with complete structure according to OIF-CMIS 5.3."""
    if '02h' not in page_dict or len(page_dict['02h']) < 256:
        return
    
    page_02h = page_dict['02h']
    thresholds = {}
    
    # Module-level thresholds (bytes 128-175)
    if len(page_02h) >= 176:
        # Temperature thresholds (bytes 128-135)
        temp_high_alarm = struct.unpack_from('<h', bytes(page_02h[128:130]))[0] / 256.0
        temp_low_alarm = struct.unpack_from('<h', bytes(page_02h[130:132]))[0] / 256.0
        temp_high_warning = struct.unpack_from('<h', bytes(page_02h[132:134]))[0] / 256.0
        temp_low_warning = struct.unpack_from('<h', bytes(page_02h[134:136]))[0] / 256.0
        
        # VCC thresholds (bytes 136-143)
        vcc_high_alarm = struct.unpack_from('<H', bytes(page_02h[136:138]))[0] * 0.0001
        vcc_low_alarm = struct.unpack_from('<H', bytes(page_02h[138:140]))[0] * 0.0001
        vcc_high_warning = struct.unpack_from('<H', bytes(page_02h[140:142]))[0] * 0.0001
        vcc_low_warning = struct.unpack_from('<H', bytes(page_02h[142:144]))[0] * 0.0001
        
        # TX Power thresholds (bytes 144-151)
        tx_power_high_alarm = struct.unpack_from('<H', bytes(page_02h[144:146]))[0] * 0.01
        tx_power_low_alarm = struct.unpack_from('<H', bytes(page_02h[146:148]))[0] * 0.01
        tx_power_high_warning = struct.unpack_from('<H', bytes(page_02h[148:150]))[0] * 0.01
        tx_power_low_warning = struct.unpack_from('<H', bytes(page_02h[150:152]))[0] * 0.01
        
        # RX Power thresholds (bytes 152-159)
        rx_power_high_alarm = struct.unpack_from('<H', bytes(page_02h[152:154]))[0] * 0.01
        rx_power_low_alarm = struct.unpack_from('<H', bytes(page_02h[154:156]))[0] * 0.01
        rx_power_high_warning = struct.unpack_from('<H', bytes(page_02h[156:158]))[0] * 0.01
        rx_power_low_warning = struct.unpack_from('<H', bytes(page_02h[158:160]))[0] * 0.01
        
        # Aux1 thresholds (bytes 160-167)
        aux1_high_alarm = struct.unpack_from('<h', bytes(page_02h[160:162]))[0]
        aux1_low_alarm = struct.unpack_from('<h', bytes(page_02h[162:164]))[0]
        aux1_high_warning = struct.unpack_from('<h', bytes(page_02h[164:166]))[0]
        aux1_low_warning = struct.unpack_from('<h', bytes(page_02h[166:168]))[0]
        
        # Aux2 thresholds (bytes 168-175)
        aux2_high_alarm = struct.unpack_from('<h', bytes(page_02h[168:170]))[0]
        aux2_low_alarm = struct.unpack_from('<h', bytes(page_02h[170:172]))[0]
        aux2_high_warning = struct.unpack_from('<h', bytes(page_02h[172:174]))[0]
        aux2_low_warning = struct.unpack_from('<h', bytes(page_02h[174:176]))[0]
        
        thresholds['module'] = {
            'temperature': {
                'high_alarm': temp_high_alarm,
                'low_alarm': temp_low_alarm,
                'high_warning': temp_high_warning,
                'low_warning': temp_low_warning
            },
            'vcc': {
                'high_alarm': vcc_high_alarm,
                'low_alarm': vcc_low_alarm,
                'high_warning': vcc_high_warning,
                'low_warning': vcc_low_warning
            },
            'tx_power': {
                'high_alarm': tx_power_high_alarm,
                'low_alarm': tx_power_low_alarm,
                'high_warning': tx_power_high_warning,
                'low_warning': tx_power_low_warning
            },
            'rx_power': {
                'high_alarm': rx_power_high_alarm,
                'low_alarm': rx_power_low_alarm,
                'high_warning': rx_power_high_warning,
                'low_warning': rx_power_low_warning
            },
            'aux1': {
                'high_alarm': aux1_high_alarm,
                'low_alarm': aux1_low_alarm,
                'high_warning': aux1_high_warning,
                'low_warning': aux1_low_warning
            },
            'aux2': {
                'high_alarm': aux2_high_alarm,
                'low_alarm': aux2_low_alarm,
                'high_warning': aux2_high_warning,
                'low_warning': aux2_low_warning
            }
        }
    
    # Lane-specific thresholds (bytes 176-255)
    lane_thresholds = {}
    for lane in range(8):
        base_offset = 176 + (lane * 10)  # 10 bytes per lane
        if base_offset + 9 < len(page_02h):
            lane_thresholds[f'lane_{lane+1}'] = {
                'tx_power_high_alarm': struct.unpack_from('<H', bytes(page_02h[base_offset:base_offset+2]))[0] * 0.01,
                'tx_power_low_alarm': struct.unpack_from('<H', bytes(page_02h[base_offset+2:base_offset+4]))[0] * 0.01,
                'tx_power_high_warning': struct.unpack_from('<H', bytes(page_02h[base_offset+4:base_offset+6]))[0] * 0.01,
                'tx_power_low_warning': struct.unpack_from('<H', bytes(page_02h[base_offset+6:base_offset+8]))[0] * 0.01,
                'rx_power_high_alarm': struct.unpack_from('<H', bytes(page_02h[base_offset+8:base_offset+10]))[0] * 0.01
            }
    
    if lane_thresholds:
        thresholds['lanes'] = lane_thresholds
    
    cmis_data['thresholds'] = thresholds

def parse_cmis_monitoring_complete(page_dict, cmis_data):
    """Parse all CMIS monitoring values with complete structure according to OIF-CMIS 5.3."""
    if '00h' not in page_dict or len(page_dict['00h']) < 26:
        return
    
    page_00h = page_dict['00h']
    monitoring = {}
    
    # Module monitoring (bytes 14-25)
    if len(page_00h) >= 26:
        # Temperature Monitor (bytes 14-15)
        temp_raw = struct.unpack_from('<h', bytes(page_00h[14:16]))[0]
        temp_celsius = temp_raw / 256.0
        
        # VCC Monitor (bytes 16-17)
        vcc_raw = struct.unpack_from('<H', bytes(page_00h[16:18]))[0]
        vcc_volts = vcc_raw * 0.0001
        
        # Aux1 Monitor (bytes 18-19) - Table 8-10
        aux1_raw = struct.unpack_from('<h', bytes(page_00h[18:20]))[0]
        
        # Aux2 Monitor (bytes 20-21) - Table 8-10
        aux2_raw = struct.unpack_from('<h', bytes(page_00h[20:22]))[0]
        
        # Aux3 Monitor (bytes 22-23) - Table 8-10
        aux3_raw = struct.unpack_from('<h', bytes(page_00h[22:24]))[0]
        
        # Custom Monitor (bytes 24-25) - Table 8-10
        custom_raw = struct.unpack_from('<h', bytes(page_00h[24:26]))[0]
        
        monitoring['module'] = {
            'temperature': temp_celsius,
            'vcc': vcc_volts,
            'aux1': aux1_raw,
            'aux2': aux2_raw,
            'aux3': aux3_raw,
            'custom': custom_raw
        }
    
    # Lane monitoring from Page 11h
    if '11h' in page_dict and len(page_dict['11h']) >= 160:
        lane_monitoring = {}
        for lane in range(8):
            base_offset = 144 + (lane * 16)
            if base_offset + 15 < len(page_dict['11h']):
                lane_data = page_dict['11h'][base_offset:base_offset+16]
                lane_monitoring[f'lane_{lane+1}'] = {
                    'tx_power': lane_data[0] * 0.01,  # Convert to mW
                    'rx_power': lane_data[1] * 0.01,  # Convert to mW
                    'tx_bias': lane_data[2],  # mA
                    'rx_power_ratio': lane_data[3],
                    'tx_power_ratio': lane_data[4],
                    'rx_power_ratio_2': lane_data[5],
                    'tx_power_ratio_2': lane_data[6],
                    'rx_power_ratio_3': lane_data[7],
                    'tx_power_ratio_3': lane_data[8],
                    'rx_power_ratio_4': lane_data[9],
                    'tx_power_ratio_4': lane_data[10],
                    'rx_power_ratio_5': lane_data[11],
                    'tx_power_ratio_5': lane_data[12],
                    'rx_power_ratio_6': lane_data[13],
                    'tx_power_ratio_6': lane_data[14],
                    'rx_power_ratio_7': lane_data[15]
                }
        
        if lane_monitoring:
            monitoring['lanes'] = lane_monitoring
    
    cmis_data['monitoring'] = monitoring

def parse_cmis_page_support(page_dict, cmis_data):
    """Parse CMIS page support advertisements according to OIF-CMIS 5.3."""
    if '01h' not in page_dict or len(page_dict['01h']) < 160:
        return
    
    page_01h = page_dict['01h']
    
    # Supported Pages Advertisement (bytes 142-143)
    if len(page_01h) >= 144:
        supported_pages = page_01h[142:144]
        pages_bitmap = supported_pages[0] if len(supported_pages) > 0 else 0
        
        page_support = {
            'page_02h': bool(pages_bitmap & 0x01),  # Monitor Thresholds
            'page_03h': bool(pages_bitmap & 0x02),  # Module Control
            'page_04h': bool(pages_bitmap & 0x04),  # Laser Tuning
            'page_05h': bool(pages_bitmap & 0x08),  # Vendor Specific
            'page_10h': bool(pages_bitmap & 0x10),  # Lane Control
            'page_11h': bool(pages_bitmap & 0x20),  # Lane Status
            'page_12h': bool(pages_bitmap & 0x40),  # Tunable Laser
            'page_13h': bool(pages_bitmap & 0x80),  # Diagnostics
        }
        
        # Additional pages support (if available)
        if len(page_01h) >= 145:
            additional_pages = page_01h[144]
            page_support.update({
                'page_14h': bool(additional_pages & 0x01),  # Vendor Specific
                'page_15h': bool(additional_pages & 0x02),  # Vendor Specific
                'page_16h': bool(additional_pages & 0x04),  # Vendor Specific
                'page_17h': bool(additional_pages & 0x08),  # Vendor Specific
                'page_18h': bool(additional_pages & 0x10),  # Vendor Specific
                'page_19h': bool(additional_pages & 0x20),  # Vendor Specific
                'page_1Ch': bool(additional_pages & 0x40),  # Vendor Specific
                'page_1Dh': bool(additional_pages & 0x80),  # Vendor Specific
            })
        
        cmis_data['page_support'] = page_support

def parse_cmis_application_descriptors_complete(page_dict, cmis_data):
    """Parse CMIS application descriptors with complete structure."""
    if '01h' not in page_dict or len(page_dict['01h']) < 160:
        return
    
    page_01h = page_dict['01h']
    applications = []
    
    # Application descriptors start at byte 128
    for app in range(8):
        base = 128 + app * 8
        if base + 7 < len(page_01h):
            code = page_01h[base]
            if code != 0:  # Valid application code
                app_info = {
                    'code': code,
                    'name': APPLICATION_CODES.get(code, f'Unknown({code:02x})'),
                    'host_lane_count': page_01h[base + 1],
                    'media_lane_count': page_01h[base + 2],
                    'host_lane_assignment': page_01h[base + 3],
                    'media_lane_assignment': page_01h[base + 4],
                    'host_lane_technology': page_01h[base + 5],
                    'media_lane_technology': page_01h[base + 6],
                    'media_lane_technology_2': page_01h[base + 7]
                }
                applications.append(app_info)
    
    if applications:
        cmis_data['application_info']['applications'] = applications

def parse_cmis_vdm_observables_complete(page_dict, cmis_data):
    """Parse CMIS VDM observables with complete structure."""
    if not any(f'{i:02x}h' in page_dict for i in range(0x20, 0x28)):
        return
    
    # Initialize VDM data structure
    if 'vdm' not in cmis_data:
        cmis_data['vdm'] = {}
    
    # Parse VDM descriptors from Pages 20h-23h
    vdm_observables = {}
    for page_num in range(0x20, 0x24):
        page_key = f'{page_num:02x}h'
        if page_key in page_dict and len(page_dict[page_key]) >= 256:
            page_data = page_dict[page_key]
            # Each VDM descriptor is 2 bytes, starting at byte 128
            for instance in range(64):
                base_offset = 128 + (instance * 2)
                if base_offset + 1 < len(page_data):
                    # Parse VDM descriptor (2 bytes)
                    descriptor_bytes = page_data[base_offset:base_offset + 2]
                    if len(descriptor_bytes) == 2:
                        # Big Endian format
                        descriptor = (descriptor_bytes[0] << 8) | descriptor_bytes[1]
                        
                        # Extract fields from descriptor
                        observable_type = descriptor & 0xFF
                        instance_type = (descriptor >> 8) & 0x03
                        threshold_set = (descriptor >> 10) & 0x0F
                        lane_number = (descriptor >> 14) & 0x07
                        
                        # Only include valid observable types
                        if observable_type in VDM_OBSERVABLE_TYPES and observable_type != 0:
                            vdm_observables[instance + 1] = {
                                'type': observable_type,
                                'name': VDM_OBSERVABLE_TYPES[observable_type],
                                'instance_type': instance_type,
                                'threshold_set': threshold_set,
                                'lane_number': lane_number,
                                'page': page_key
                            }
    
    # Parse VDM samples from Pages 24h-27h
    vdm_samples = {}
    for page_num in range(0x24, 0x28):
        page_key = f'{page_num:02x}h'
        if page_key in page_dict and len(page_dict[page_key]) >= 256:
            page_data = page_dict[page_key]
            # Each sample is 2 bytes, starting at byte 128
            for instance in range(64):
                base_offset = 128 + (instance * 2)
                if base_offset + 1 < len(page_data):
                    # Parse sample value (Big Endian)
                    sample_bytes = page_data[base_offset:base_offset + 2]
                    if len(sample_bytes) == 2:
                        sample_raw = (sample_bytes[0] << 8) | sample_bytes[1]
                        
                        # Convert based on observable type
                        global_instance = (page_num - 0x24) * 64 + instance + 1
                        if global_instance in vdm_observables:
                            obs_type = vdm_observables[global_instance]['type']
                            obs_name = vdm_observables[global_instance]['name']
                            
                            # Handle different data types and scaling factors
                            sample_data = {
                                'raw': sample_raw,
                                'observable': vdm_observables[global_instance]
                            }
                            
                            # Type-specific conversions based on OIF-CMIS 5.3 Table 8-170
                            if obs_type in [1]:  # Laser Age - U16, scale 1, unit %
                                sample_data['value'] = sample_raw
                                sample_data['unit'] = '%'
                                sample_data['description'] = f"Laser Age: {sample_raw}%"
                                
                            elif obs_type in [2]:  # TEC Current - S16, scale 100/32767, unit %
                                # Convert signed 16-bit to percentage
                                if sample_raw > 32767:
                                    sample_raw = sample_raw - 65536  # Convert to signed
                                tec_percent = (sample_raw / 32767.0) * 100.0
                                sample_data['value'] = tec_percent
                                sample_data['unit'] = '%'
                                sample_data['description'] = f"TEC Current: {tec_percent:.2f}%"
                                
                            elif obs_type in [3]:  # Laser Frequency Error - S16, scale 10, unit MHz
                                if sample_raw > 32767:
                                    sample_raw = sample_raw - 65536  # Convert to signed
                                freq_error = sample_raw / 10.0
                                sample_data['value'] = freq_error
                                sample_data['unit'] = 'MHz'
                                sample_data['description'] = f"Laser Frequency Error: {freq_error:.1f} MHz"
                                
                            elif obs_type in [4]:  # Laser Temperature - S16, scale 1/256, unit C
                                if sample_raw > 32767:
                                    sample_raw = sample_raw - 65536  # Convert to signed
                                temp_celsius = sample_raw / 256.0
                                sample_data['value'] = temp_celsius
                                sample_data['unit'] = '°C'
                                sample_data['description'] = f"Laser Temperature: {temp_celsius:.2f}°C"
                                
                            elif obs_type in [5, 6, 7, 8]:  # SNR and LTP observables - U16, scale 1/256, unit dB
                                sample_dB = sample_raw / 256.0
                                sample_data['value'] = sample_dB
                                sample_data['unit'] = 'dB'
                                sample_data['description'] = f"{obs_name}: {sample_dB:.2f} dB"
                                
                            elif obs_type in [15, 16]:  # Pre-FEC BER Current Sample - F16, no scaling
                                # F16 format - handle as raw value for now
                                sample_data['value'] = sample_raw
                                sample_data['unit'] = 'raw'
                                sample_data['description'] = f"{obs_name}: {sample_raw} (raw F16)"
                                
                            elif obs_type in [23, 24]:  # FERC Current Sample - F16, no scaling
                                # F16 format - handle as raw value for now
                                sample_data['value'] = sample_raw
                                sample_data['unit'] = 'raw'
                                sample_data['description'] = f"{obs_name}: {sample_raw} (raw F16)"
                                
                            elif obs_type in [33, 34]:  # SEWmax Current Sample - U16, no scaling
                                sample_data['value'] = sample_raw
                                sample_data['unit'] = 'count'
                                sample_data['description'] = f"{obs_name}: {sample_raw}"
                                
                            elif obs_type in [77, 78, 79, 80, 81, 82, 83]:  # Voltage Monitors - U16, scale 100, unit uV
                                voltage_uV = sample_raw * 100
                                voltage_V = voltage_uV / 1000000.0
                                sample_data['value'] = voltage_V
                                sample_data['unit'] = 'V'
                                sample_data['description'] = f"{obs_name}: {voltage_V:.3f}V ({voltage_uV} µV)"
                                
                            elif obs_type in [84]:  # ELS Input Power - S16, scale 0.01, unit dBm
                                if sample_raw > 32767:
                                    sample_raw = sample_raw - 65536  # Convert to signed
                                power_dBm = sample_raw * 0.01
                                sample_data['value'] = power_dBm
                                sample_data['unit'] = 'dBm'
                                sample_data['description'] = f"{obs_name}: {power_dBm:.2f} dBm"
                                
                            else:
                                # Default handling for other types
                                sample_data['value'] = sample_raw
                                sample_data['unit'] = 'raw'
                                sample_data['description'] = f"{obs_name}: {sample_raw} (raw)"
                            
                            vdm_samples[global_instance] = sample_data
    
    if vdm_observables:
        cmis_data['vdm']['observables'] = vdm_observables
    if vdm_samples:
        cmis_data['vdm']['samples'] = vdm_samples

def output_cmis_page_support(cmis_data):
    """Output CMIS page support information."""
    if not cmis_data.get('page_support'):
        return
    
    print("\n--- Page Support Advertisement ---")
    page_support = cmis_data['page_support']
    
    # Standard pages
    standard_pages = [
        ('page_02h', 'Monitor Thresholds'),
        ('page_03h', 'Module Control'),
        ('page_04h', 'Laser Tuning'),
        ('page_05h', 'Vendor Specific'),
        ('page_10h', 'Lane Control'),
        ('page_11h', 'Lane Status'),
        ('page_12h', 'Tunable Laser'),
        ('page_13h', 'Diagnostics')
    ]
    
    print("Standard Pages:")
    for page_key, page_name in standard_pages:
        if page_key in page_support:
            status = "Supported" if page_support[page_key] else "Not Supported"
            print(f"  {page_name} ({page_key}): {status}")
    
    # Additional pages
    additional_pages = [
        ('page_14h', 'Vendor Specific'),
        ('page_15h', 'Vendor Specific'),
        ('page_16h', 'Vendor Specific'),
        ('page_17h', 'Vendor Specific'),
        ('page_18h', 'Vendor Specific'),
        ('page_19h', 'Vendor Specific'),
        ('page_1Ch', 'Vendor Specific'),
        ('page_1Dh', 'Vendor Specific')
    ]
    
    print("Additional Pages:")
    for page_key, page_name in additional_pages:
        if page_key in page_support:
            status = "Supported" if page_support[page_key] else "Not Supported"
            print(f"  {page_name} ({page_key}): {status}")

def output_cmis_thresholds_complete(cmis_data):
    """Output comprehensive CMIS thresholds information."""
    if not cmis_data.get('thresholds'):
        return
    
    print("\n--- Comprehensive Thresholds ---")
    thresholds = cmis_data['thresholds']
    
    # Module thresholds
    if 'module' in thresholds:
        module_thresh = thresholds['module']
        print("Module Thresholds:")
        
        if 'temperature' in module_thresh:
            temp = module_thresh['temperature']
            print(f"  Temperature High Alarm: {temp['high_alarm']:.1f}°C")
            print(f"  Temperature Low Alarm: {temp['low_alarm']:.1f}°C")
            print(f"  Temperature High Warning: {temp['high_warning']:.1f}°C")
            print(f"  Temperature Low Warning: {temp['low_warning']:.1f}°C")
        
        if 'vcc' in module_thresh:
            vcc = module_thresh['vcc']
            print(f"  VCC High Alarm: {vcc['high_alarm']:.3f}V")
            print(f"  VCC Low Alarm: {vcc['low_alarm']:.3f}V")
            print(f"  VCC High Warning: {vcc['high_warning']:.3f}V")
            print(f"  VCC Low Warning: {vcc['low_warning']:.3f}V")
        
        if 'tx_power' in module_thresh:
            tx_power = module_thresh['tx_power']
            print(f"  TX Power High Alarm: {tx_power['high_alarm']:.2f} mW")
            print(f"  TX Power Low Alarm: {tx_power['low_alarm']:.2f} mW")
            print(f"  TX Power High Warning: {tx_power['high_warning']:.2f} mW")
            print(f"  TX Power Low Warning: {tx_power['low_warning']:.2f} mW")
        
        if 'rx_power' in module_thresh:
            rx_power = module_thresh['rx_power']
            print(f"  RX Power High Alarm: {rx_power['high_alarm']:.2f} mW")
            print(f"  RX Power Low Alarm: {rx_power['low_alarm']:.2f} mW")
            print(f"  RX Power High Warning: {rx_power['high_warning']:.2f} mW")
            print(f"  RX Power Low Warning: {rx_power['low_warning']:.2f} mW")
        
        if 'aux1' in module_thresh:
            aux1 = module_thresh['aux1']
            print(f"  Aux1 High Alarm: {aux1['high_alarm']}")
            print(f"  Aux1 Low Alarm: {aux1['low_alarm']}")
            print(f"  Aux1 High Warning: {aux1['high_warning']}")
            print(f"  Aux1 Low Warning: {aux1['low_warning']}")
        
        if 'aux2' in module_thresh:
            aux2 = module_thresh['aux2']
            print(f"  Aux2 High Alarm: {aux2['high_alarm']}")
            print(f"  Aux2 Low Alarm: {aux2['low_alarm']}")
            print(f"  Aux2 High Warning: {aux2['high_warning']}")
            print(f"  Aux2 Low Warning: {aux2['low_warning']}")
    
    # Lane thresholds
    if 'lanes' in thresholds:
        print("Lane Thresholds:")
        # Get supported lanes from media_info
        supported_lanes = cmis_data.get('media_info', {}).get('supported_lanes', [])
        for lane_name, lane_thresh in thresholds['lanes'].items():
            # Extract lane number from lane_name (e.g., "lane_1" -> 1)
            try:
                lane_num = int(lane_name.split('_')[1])
                if lane_num in supported_lanes:
                    print(f"  {lane_name}:")
                    print(f"    TX Power High Alarm: {lane_thresh['tx_power_high_alarm']:.2f} mW")
                    print(f"    TX Power Low Alarm: {lane_thresh['tx_power_low_alarm']:.2f} mW")
                    print(f"    TX Power High Warning: {lane_thresh['tx_power_high_warning']:.2f} mW")
                    print(f"    TX Power Low Warning: {lane_thresh['tx_power_low_warning']:.2f} mW")
                    print(f"    RX Power High Alarm: {lane_thresh['rx_power_high_alarm']:.2f} mW")
            except (ValueError, IndexError):
                # If lane_name doesn't match expected format, skip it
                continue

def output_cmis_monitoring_complete(cmis_data):
    """Output comprehensive CMIS monitoring information."""
    if not cmis_data.get('monitoring'):
        return
    
    print("\n--- Comprehensive Monitoring ---")
    monitoring = cmis_data['monitoring']
    
    # Module monitoring
    if 'module' in monitoring:
        module_mon = monitoring['module']
        print("Module Monitoring:")
        
        if 'temperature' in module_mon:
            print(f"  Temperature: {module_mon['temperature']:.1f}°C")
        
        if 'vcc' in module_mon:
            print(f"  VCC: {module_mon['vcc']:.3f}V")
        
        if 'tx_power' in module_mon:
            print(f"  TX Power: {module_mon['tx_power']:.2f} mW")
        
        if 'rx_power' in module_mon:
            print(f"  RX Power: {module_mon['rx_power']:.2f} mW")
        
        if 'aux1' in module_mon:
            print(f"  Aux1: {module_mon['aux1']}")
        
        if 'aux2' in module_mon:
            print(f"  Aux2: {module_mon['aux2']}")
    
    # Lane monitoring
    if 'lanes' in monitoring:
        print("Lane Monitoring:")
        # Get supported lanes from media_info
        supported_lanes = cmis_data.get('media_info', {}).get('supported_lanes', [])
        for lane_name, lane_data in monitoring['lanes'].items():
            # Extract lane number from lane_name (e.g., "lane_1" -> 1)
            try:
                lane_num = int(lane_name.split('_')[1])
                if lane_num in supported_lanes:
                    print(f"  {lane_name}:")
                    print(f"    TX Power: {lane_data['tx_power']:.2f} mW")
                    print(f"    RX Power: {lane_data['rx_power']:.2f} mW")
                    print(f"    TX Bias: {lane_data['tx_bias']} mA")
                    print(f"    RX Power Ratio: {lane_data['rx_power_ratio']}")
                    print(f"    TX Power Ratio: {lane_data['tx_power_ratio']}")
            except (ValueError, IndexError):
                # If lane_name doesn't match expected format, skip it
                continue

def output_cmis_vdm_complete(cmis_data):
    """Output comprehensive VDM observables information."""
    if not cmis_data.get('vdm'):
        return
    
    print("\n--- VDM Observables (Complete) ---")
    vdm_data = cmis_data['vdm']
    
    # VDM Observables
    if 'observables' in vdm_data:
        print("VDM Observables:")
        observables = vdm_data['observables']
        samples = vdm_data.get('samples', {})
        
        for instance_id, observable in observables.items():
            print(f"Instance {instance_id}: {observable['name']}")
            print(f"  Type: {observable['type']}")
            print(f"  Instance Type: {observable['instance_type']}")
            print(f"  Threshold Set: {observable['threshold_set']}")
            print(f"  Lane Number: {observable['lane_number']}")
            print(f"  Page: {observable['page']}")
            
            # Display sample value if available
            if instance_id in samples:
                sample = samples[instance_id]
                print(f"  Raw Value: 0x{sample['raw']:04x}")
                print(f"  {sample['description']}")
            else:
                print("  Sample: Not available")
            print()
    
    # Summary of observable types
    if 'observables' in vdm_data:
        observable_types = {}
        for obs in vdm_data['observables'].values():
            obs_type = obs['type']
            if obs_type not in observable_types:
                observable_types[obs_type] = 0
            observable_types[obs_type] += 1
        
        print("Observable Type Summary:")
        for obs_type, count in sorted(observable_types.items()):
            obs_name = VDM_OBSERVABLE_TYPES.get(obs_type, f"Unknown({obs_type})")
            print(f"  Type {obs_type}: {obs_name} ({count} instances)")

def output_cmis_application_descriptors_complete(cmis_data):
    """Output comprehensive application descriptors information."""
    if not cmis_data.get('application_info', {}).get('applications'):
        return
    
    print("\n--- Application Descriptors (Complete) ---")
    applications = cmis_data['application_info']['applications']
    
    for i, app in enumerate(applications):
        print(f"Application {i+1}: {app['name']}")
        print(f"  Code: 0x{app['code']:02x}")
        print(f"  Host Lane Count: {app['host_lane_count']}")
        print(f"  Media Lane Count: {app['media_lane_count']}")
        print(f"  Host Interface ID: 0x{app['code']:02x}")
        print(f"  Media Interface ID: 0x{app.get('media_interface_id', 0):02x}")
        print(f"  Host Assignment: 0x{app['host_lane_assignment']:02x}")
        print(f"  Media Assignment: 0x{app['media_lane_assignment']:02x}")
        # If available, print lane signaling rate and modulation from CDB or vendor fields
        if 'lane_signaling_rate_gbd' in app:
            print(f"    Lane Signaling Rate: {app['lane_signaling_rate_gbd']:.2f} GBd")
        if 'modulation' in app:
            print(f"    Modulation: {app['modulation']}")
        print()
    # Also print Nominal Wavelength and Tolerance if present
    media_info = cmis_data.get('media_info', {})
    if 'nominal_wavelength' in media_info:
        print(f"Nominal Wavelength: {media_info['nominal_wavelength']:.2f} nm")
    if 'wavelength_tolerance' in media_info:
        print(f"Wavelength Tolerance: ±{media_info['wavelength_tolerance']:.3f} nm")
