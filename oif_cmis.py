#!/usr/bin/env python3
"""
OIF-CMIS (Common Management Interface Specification) parsing functions
Based on OIF-CMIS 5.3 specification

This module provides centralized parsing and unified output for QSFP-DD/CMIS modules.
"""

import struct
import math

# NOTE: CMIS Upper Page 00h Byte Offsets (OIF-CMIS 5.3)
# -----------------------------------------------------------------------------
# All CMIS parsing functions in this file have been updated to use the correct
# relative byte offsets within Upper Page 00h (0x80) as per the OIF-CMIS 5.3 spec.
# The correct approach is to subtract 128 from the absolute spec offset to get
# the relative offset within the page. For example:
#   - Vendor Name: bytes 129-144 → relative 1-16
#   - Vendor OUI: bytes 145-147 → relative 17-19
#   - Vendor Part Number: bytes 148-163 → relative 20-35
#   - Vendor Revision: bytes 164-165 → relative 36-37
#   - Vendor Serial Number: bytes 166-181 → relative 38-53
#   - Date Code: bytes 182-189 → relative 54-61
#   - CLEI Code: bytes 190-199 → relative 62-71
#   - Module Power: bytes 200-201 → relative 72-73
#   - Cable Length: byte 202 → relative 74
#   - Connector Type: byte 203 → relative 75
#   - Attenuation: bytes 204-209 → relative 76-81
#   - Media Lane Information: byte 210 → relative 82
#   - Media Interface Technology: byte 212 → relative 84
# Always use these relative offsets when reading from page_dict['80h'] (Upper Page 00h).
# -----------------------------------------------------------------------------

def parse_cmis_data_centralized(page_dict):
    """Parse CMIS data using centralized approach with correct byte offsets."""
    cmis_data = {
        'vendor_info': {},
        'media_info': {},
        'cable_info': {},
        'monitoring': {},
        'thresholds': {}
    }
   
    # Vendor Information (Upper Page 00h, relative offsets)
    # All offsets for Upper Page 00h are 128+N (i.e., 0x80+N)
    if '80h' in page_dict and len(page_dict['80h']) >= 200:
        # Vendor Name (bytes 129-144 → absolute 128-143)
        vendor_name = bytes(page_dict['80h'][128:144]).decode('ascii', errors='ignore').strip()
        cmis_data['vendor_info']['name'] = vendor_name

        # Vendor OUI (bytes 145-147 → absolute 144-146)
        vendor_oui = bytes(page_dict['80h'][144:147]).hex()
        cmis_data['vendor_info']['oui'] = vendor_oui

        # Vendor Part Number (bytes 148-163 → absolute 147-163)
        vendor_pn = bytes(page_dict['80h'][147:163]).decode('ascii', errors='ignore').strip()
        cmis_data['vendor_info']['part_number'] = vendor_pn

        # Vendor Revision (bytes 164-165 → absolute 163-165)
        vendor_rev = bytes(page_dict['80h'][163:165]).decode('ascii', errors='ignore').strip()
        cmis_data['vendor_info']['revision'] = vendor_rev

        # Vendor Serial Number (bytes 166-181 → absolute 165-181)
        vendor_sn = bytes(page_dict['80h'][165:181]).decode('ascii', errors='ignore').strip()
        cmis_data['vendor_info']['serial_number'] = vendor_sn

        # Date Code (bytes 182-189 → absolute 181-189)
        date_code = bytes(page_dict['80h'][181:189]).decode('ascii', errors='ignore').strip()
        cmis_data['vendor_info']['date_code'] = date_code

        # CLEI Code (bytes 190-199 → absolute 189-199)
        clei_code = bytes(page_dict['80h'][189:199]).decode('ascii', errors='ignore').strip()
        cmis_data['vendor_info']['clei_code'] = clei_code

        # Module Power (bytes 200-201 → absolute 200-201)
        # According to Table 8-31: ModulePowerClass is bits 7-5 of byte 200
        power_class_byte = page_dict['80h'][200]  # byte 200
        max_power_byte = page_dict['80h'][201]    # byte 201
       
        print(f"DEBUG: Power class byte: 0x{power_class_byte:02x} ({power_class_byte})")
        print(f"DEBUG: Max power byte: 0x{max_power_byte:02x} ({max_power_byte})")
       
        power_class = (power_class_byte >> 5) & 0x07  # bits 7-5
        max_power = max_power_byte * 0.25  # in watts (0.25W increments)
       
        print(f"DEBUG: Calculated power class: {power_class}")
        print(f"DEBUG: Calculated max power: {max_power}W")
       
        cmis_data['media_info']['power_class'] = power_class
        cmis_data['media_info']['max_power'] = max_power

        # Cable Length (byte 202 → absolute 202)
        length_byte = page_dict['80h'][202]
        multiplier = (length_byte >> 6) & 0x03
        base_length = length_byte & 0x3F
        multipliers = [0.1, 1, 10, 100]
        if multiplier < len(multipliers):
            cable_length = base_length * multipliers[multiplier]
            cmis_data['cable_info']['length'] = cable_length

        # Connector Type (byte 203 → absolute 203)
        connector_type = page_dict['80h'][203]
        cmis_data['media_info']['connector_type'] = connector_type

        # Attenuation (bytes 204-209 → absolute 204-209)
        cmis_data['cable_info']['attenuation'] = {
            'at_5ghz': page_dict['80h'][204],
            'at_7ghz': page_dict['80h'][205],
            'at_12p9ghz': page_dict['80h'][206],
            'at_25p8ghz': page_dict['80h'][207],
            'at_53p1ghz': page_dict['80h'][208]
        }

        # Media Lane Information (byte 210 → absolute 209)
        lane_info = page_dict['80h'][209]
        supported_lanes = [lane+1 for lane in range(8) if not (lane_info & (1 << lane))]
        cmis_data['media_info']['supported_lanes'] = supported_lanes

        # Media Interface Technology (byte 212 → absolute 211)
        media_tech = page_dict['80h'][211]
        cmis_data['media_info']['interface_technology'] = media_tech

    # Wavelength Information (Page 01h)
    if '01h' in page_dict and len(page_dict['01h']) >= 160:
        # Nominal wavelength (bytes 138-139) - Table 8-45
        if len(page_dict['01h']) >= 140:
            nominal_wavelength_raw = (page_dict['01h'][138] << 8) | page_dict['01h'][139]
            nominal_wavelength_nm = nominal_wavelength_raw * 0.05  # Convert to nm
            cmis_data['media_info']['nominal_wavelength'] = nominal_wavelength_nm
        # Per-lane wavelengths (bytes 144-159) - Table 8-45
        lane_wavelengths = {}
        for lane in range(1, 9):
            offset = 144 + (lane - 1) * 2
            if len(page_dict['01h']) >= offset + 2:
                raw = (page_dict['01h'][offset] << 8) | page_dict['01h'][offset + 1]
                nm = raw * 0.05  # Convert to nm
                lane_wavelengths[lane] = {'raw': raw, 'nm': nm}
        cmis_data['media_info']['lane_wavelengths'] = lane_wavelengths

    # Monitoring Data (Lower Memory, bytes 14-25) - Table 8-10
    # This is in the Lower Memory (page 00h), not in Page 02h
    if '00h' in page_dict and len(page_dict['00h']) >= 26:
        # Temperature Monitor (bytes 14-15)
        if len(page_dict['00h']) >= 16:
            temp_raw = struct.unpack_from('<h', bytes(page_dict['00h'][14:16]))[0]
            temp_celsius = temp_raw / 256.0  # Convert from 1/256 degree Celsius increments
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

    # Lane-specific monitoring data (Page 11h)
    if '11h' in page_dict and len(page_dict['11h']) >= 160:
        # Get supported lanes from Upper Page 00h
        lane_info = get_byte(page_dict, '80h', 209)  # byte 210
        if lane_info is not None:
            supported_lanes = [lane for lane in range(8) if not (lane_info & (1 << lane))]
            cmis_data['monitoring']['lanes'] = {}
            for lane in supported_lanes:
                lane_num = lane + 1
                base_offset = 144 + (lane_num - 1) * 16
                if len(page_dict['11h']) >= base_offset + 16:
                    cmis_data['monitoring']['lanes'][f'lane_{lane_num}'] = {
                        'tx_power': page_dict['11h'][base_offset],
                        'rx_power': page_dict['11h'][base_offset + 1],
                        'tx_bias': page_dict['11h'][base_offset + 2],
                        'rx_power_ratio': page_dict['11h'][base_offset + 3]
                    }

    # SNR (OSNR) Data (Page 06h)
    if '06h' in page_dict and len(page_dict['06h']) >= 128:
        cmis_data['monitoring']['snr'] = {}
        # Host Side SNR values (bytes 208-223, relative 80-95)
        host_snr = {}
        for lane in range(8):
            offset = 80 + (lane * 2)  # Relative offset within page
            if offset + 1 < len(page_dict['06h']):
                snr_raw = struct.unpack_from('<H', bytes(page_dict['06h'][offset:offset+2]))[0]
                snr_db = snr_raw / 256.0  # Convert from 1/256 dB units to dB
                host_snr[f'lane_{lane+1}'] = snr_db
        cmis_data['monitoring']['snr']['host_side'] = host_snr
        # Media Side SNR values (bytes 240-255, relative 112-127)
        media_snr = {}
        for lane in range(8):
            offset = 112 + (lane * 2)  # Relative offset within page
            if offset + 1 < len(page_dict['06h']):
                snr_raw = struct.unpack_from('<H', bytes(page_dict['06h'][offset:offset+2]))[0]
                snr_db = snr_raw / 256.0  # Convert from 1/256 dB units to dB
                media_snr[f'lane_{lane+1}'] = snr_db
        cmis_data['monitoring']['snr']['media_side'] = media_snr

    return cmis_data

def output_cmis_data_unified(cmis_data):
    """Output CMIS data in a unified format."""
    print("\n=== CMIS Module Information ===")
   
    # Vendor Information
    if cmis_data.get('vendor_info'):
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
        print("\n--- Media Information ---")
        media_info = cmis_data['media_info']
        if 'power_class' in media_info:
            power_class_names = {
                0: "Power Class 1",
                1: "Power Class 2",
                2: "Power Class 3",
                3: "Power Class 4",
                4: "Power Class 5",
                5: "Power Class 6",
                6: "Power Class 7",
                7: "Power Class 8"
            }
            power_class_name = power_class_names.get(media_info['power_class'], f"Power Class {media_info['power_class']}")
            print(f"Power Class: {media_info['power_class']} ({power_class_name})")
        if 'max_power' in media_info:
            print(f"Max Power: {media_info['max_power']}W")
        if 'connector_type' in media_info:
            connector_names = {
                0x01: 'SC',
                0x02: 'FC Style 1 copper',
                0x03: 'FC Style 2 copper',
                0x04: 'BNC/TNC',
                0x05: 'FC coax headers',
                0x06: 'Fiber Jack',
                0x07: 'LC',
                0x08: 'MT-RJ',
                0x09: 'MU',
                0x0A: 'SG',
                0x0B: 'Optical Pigtail',
                0x0C: 'MPO 1x12',
                0x0D: 'MPO 2x12',
                0x0E: 'MPO 2x16',
                0x0F: 'MPO 1x16',
                0x10: 'MPO 2x8',
                0x11: 'MPO 1x8',
                0x12: 'MPO 2x4',
                0x13: 'MPO 1x4',
                0x14: 'MPO 2x2',
                0x15: 'MPO 1x2',
                0x16: 'MPO 2x1',
                0x17: 'MPO 1x1',
                0x18: 'MPO 2x24',
                0x19: 'MPO 1x24',
                0x1A: 'MPO 2x6',
                0x1B: 'MPO 1x6',
                0x1C: 'MPO 2x3',
                0x1D: 'MPO 1x3',
                0x1E: 'MPO 2x18',
                0x1F: 'MPO 1x18',
                0x20: 'MPO 2x9',
                0x21: 'MPO 1x9',
                0x22: 'MPO 2x36',
                0x23: 'MPO 1x36',
                0x24: 'MPO 2x72',
                0x25: 'MPO 1x72',
                0x26: 'MPO 2x144',
                0x27: 'MPO 1x144',
                0x28: 'MPO 2x288',
                0x29: 'MPO 1x288',
                0x2A: 'MPO 2x576',
                0x2B: 'MPO 1x576',
                0x2C: 'MPO 2x1152',
                0x2D: 'MPO 1x1152',
                0x2E: 'MPO 2x2304',
                0x2F: 'MPO 1x2304',
                0x30: 'MPO 2x4608',
                0x31: 'MPO 1x4608',
                0x32: 'MPO 2x9216',
                0x33: 'MPO 1x9216',
                0x34: 'MPO 2x18432',
                0x35: 'MPO 1x18432',
                0x36: 'MPO 2x36864',
                0x37: 'MPO 1x36864',
                0x38: 'MPO 2x73728',
                0x39: 'MPO 1x73728',
                0x3A: 'MPO 2x147456',
                0x3B: 'MPO 1x147456',
                0x3C: 'MPO 2x294912',
                0x3D: 'MPO 1x294912',
                0x3E: 'MPO 2x589824',
                0x3F: 'MPO 1x589824',
                0x40: 'MPO 2x1179648',
                0x41: 'MPO 1x1179648',
                0x42: 'MPO 2x2359296',
                0x43: 'MPO 1x2359296',
                0x44: 'MPO 2x4718592',
                0x45: 'MPO 1x4718592',
                0x46: 'MPO 2x9437184',
                0x47: 'MPO 1x9437184',
                0x48: 'MPO 2x18874368',
                0x49: 'MPO 1x18874368',
                0x4A: 'MPO 2x37748736',
                0x4B: 'MPO 1x37748736',
                0x4C: 'MPO 2x75497472',
                0x4D: 'MPO 1x75497472',
                0x4E: 'MPO 2x150994944',
                0x4F: 'MPO 1x150994944',
                0x50: 'MPO 2x301989888',
                0x51: 'MPO 1x301989888',
                0x52: 'MPO 2x603979776',
                0x53: 'MPO 1x603979776',
                0x54: 'MPO 2x1207959552',
                0x55: 'MPO 1x1207959552',
                0x56: 'MPO 2x2415919104',
                0x57: 'MPO 1x2415919104',
                0x58: 'MPO 2x4831838208',
                0x59: 'MPO 1x4831838208',
                0x5A: 'MPO 2x9663676416',
                0x5B: 'MPO 1x9663676416',
                0x5C: 'MPO 2x19327352832',
                0x5D: 'MPO 1x19327352832',
                0x5E: 'MPO 2x38654705664',
                0x5F: 'MPO 1x38654705664',
                0x60: 'MPO 2x77309411328',
                0x61: 'MPO 1x77309411328',
                0x62: 'MPO 2x154618822656',
                0x63: 'MPO 1x154618822656',
                0x64: 'MPO 2x309237645312',
                0x65: 'MPO 1x309237645312',
                0x66: 'MPO 2x618475290624',
                0x67: 'MPO 1x618475290624',
                0x68: 'MPO 2x1236950581248',
                0x69: 'MPO 1x1236950581248',
                0x6A: 'MPO 2x2473901162496',
                0x6B: 'MPO 1x2473901162496',
                0x6C: 'MPO 2x4947802324992',
                0x6D: 'MPO 1x4947802324992',
                0x6E: 'MPO 2x9895604649984',
                0x6F: 'MPO 1x9895604649984',
                0x70: 'MPO 2x19791209299968',
                0x71: 'MPO 1x19791209299968',
                0x72: 'MPO 2x39582418599936',
                0x73: 'MPO 1x39582418599936',
                0x74: 'MPO 2x79164837199872',
                0x75: 'MPO 1x79164837199872',
                0x76: 'MPO 2x158329674399744',
                0x77: 'MPO 1x158329674399744',
                0x78: 'MPO 2x316659348799488',
                0x79: 'MPO 1x316659348799488',
                0x7A: 'MPO 2x633318697598976',
                0x7B: 'MPO 1x633318697598976',
                0x7C: 'MPO 2x1266637395197952',
                0x7D: 'MPO 1x1266637395197952',
                0x7E: 'MPO 2x2533274790395904',
                0x7F: 'MPO 1x2533274790395904',
                0x80: 'MPO 2x5066549580791808',
                0x81: 'MPO 1x5066549580791808',
                0x82: 'MPO 2x10133099161583616',
                0x83: 'MPO 1x10133099161583616',
                0x84: 'MPO 2x20266198323167232',
                0x85: 'MPO 1x20266198323167232',
                0x86: 'MPO 2x40532396646334464',
                0x87: 'MPO 1x40532396646334464',
                0x88: 'MPO 2x81064793292668928',
                0x89: 'MPO 1x81064793292668928',
                0x8A: 'MPO 2x162129586585337856',
                0x8B: 'MPO 1x162129586585337856',
                0x8C: 'MPO 2x324259173170675712',
                0x8D: 'MPO 1x324259173170675712',
                0x8E: 'MPO 2x648518346341351424',
                0x8F: 'MPO 1x648518346341351424',
                0x90: 'MPO 2x1297036692682702848',
                0x91: 'MPO 1x1297036692682702848',
                0x92: 'MPO 2x2594073385365405696',
                0x93: 'MPO 1x2594073385365405696',
                0x94: 'MPO 2x5188146770730811392',
                0x95: 'MPO 1x5188146770730811392',
                0x96: 'MPO 2x10376293541461622784',
                0x97: 'MPO 1x10376293541461622784',
                0x98: 'MPO 2x20752587082923245568',
                0x99: 'MPO 1x20752587082923245568',
                0x9A: 'MPO 2x41505174165846491136',
                0x9B: 'MPO 1x41505174165846491136',
                0x9C: 'MPO 2x83010348331692982272',
                0x9D: 'MPO 1x83010348331692982272',
                0x9E: 'MPO 2x166020696663385964544',
                0x9F: 'MPO 1x166020696663385964544',
                0xA0: 'MPO 2x332041393326771929088',
                0xA1: 'MPO 1x332041393326771929088',
                0xA2: 'MPO 2x664082786653543858176',
                0xA3: 'MPO 1x664082786653543858176',
                0xA4: 'MPO 2x1328165573307087716352',
                0xA5: 'MPO 1x1328165573307087716352',
                0xA6: 'MPO 2x2656331146614175432704',
                0xA7: 'MPO 1x2656331146614175432704',
                0xA8: 'MPO 2x5312662293228350865408',
                0xA9: 'MPO 1x5312662293228350865408',
                0xAA: 'MPO 2x10625324586456701730816',
                0xAB: 'MPO 1x10625324586456701730816',
                0xAC: 'MPO 2x21250649172913403461632',
                0xAD: 'MPO 1x21250649172913403461632',
                0xAE: 'MPO 2x42501298345826806923264',
                0xAF: 'MPO 1x42501298345826806923264',
                0xB0: 'MPO 2x85002596691653613846528',
                0xB1: 'MPO 1x85002596691653613846528',
                0xB2: 'MPO 2x170005193383307227693056',
                0xB3: 'MPO 1x170005193383307227693056',
                0xB4: 'MPO 2x340010386766614455386112',
                0xB5: 'MPO 1x340010386766614455386112',
                0xB6: 'MPO 2x680020773533228910772224',
                0xB7: 'MPO 1x680020773533228910772224',
                0xB8: 'MPO 2x1360041547066457821544448',
                0xB9: 'MPO 1x1360041547066457821544448',
                0xBA: 'MPO 2x2720083094132915643088896',
                0xBB: 'MPO 1x2720083094132915643088896',
                0xBC: 'MPO 2x5440166188265831286177792',
                0xBD: 'MPO 1x5440166188265831286177792',
                0xBE: 'MPO 2x10880332376531662572355584',
                0xBF: 'MPO 1x10880332376531662572355584',
                0xC0: 'MPO 2x21760664753063325144711168',
                0xC1: 'MPO 1x21760664753063325144711168',
                0xC2: 'MPO 2x43521329506126650289422336',
                0xC3: 'MPO 1x43521329506126650289422336',
                0xC4: 'MPO 2x87042659012253300578844672',
                0xC5: 'MPO 1x87042659012253300578844672',
                0xC6: 'MPO 2x174085318024506601157689344',
                0xC7: 'MPO 1x174085318024506601157689344',
                0xC8: 'MPO 2x348170636049013202315378688',
                0xC9: 'MPO 1x348170636049013202315378688',
                0xCA: 'MPO 2x696341272098026404630757376',
                0xCB: 'MPO 1x696341272098026404630757376',
                0xCC: 'MPO 2x1392682544196052809261514752',
                0xCD: 'MPO 1x1392682544196052809261514752',
                0xCE: 'MPO 2x2785365088392105618523029504',
                0xCF: 'MPO 1x2785365088392105618523029504',
                0xD0: 'MPO 2x5570730176784211237046059008',
                0xD1: 'MPO 1x5570730176784211237046059008',
                0xD2: 'MPO 2x11141460353568422474092118016',
                0xD3: 'MPO 1x11141460353568422474092118016',
                0xD4: 'MPO 2x22282920707136844948184236032',
                0xD5: 'MPO 1x22282920707136844948184236032',
                0xD6: 'MPO 2x44565841414273689896368472064',
                0xD7: 'MPO 1x44565841414273689896368472064',
                0xD8: 'MPO 2x89131682828547379792736944128',
                0xD9: 'MPO 1x89131682828547379792736944128',
                0xDA: 'MPO 2x178263365657094759585473888256',
                0xDB: 'MPO 1x178263365657094759585473888256',
                0xDC: 'MPO 2x356526731314189519170947776512',
                0xDD: 'MPO 1x356526731314189519170947776512',
                0xDE: 'MPO 2x713053462628379038341895553024',
                0xDF: 'MPO 1x713053462628379038341895553024',
                0xE0: 'MPO 2x1426106925256758076683791106048',
                0xE1: 'MPO 1x1426106925256758076683791106048',
                0xE2: 'MPO 2x2852213850513516153367582212096',
                0xE3: 'MPO 1x2852213850513516153367582212096',
                0xE4: 'MPO 2x5704427701027032306735164424192',
                0xE5: 'MPO 1x5704427701027032306735164424192',
                0xE6: 'MPO 2x11408855402054064613470328848384',
                0xE7: 'MPO 1x11408855402054064613470328848384',
                0xE8: 'MPO 2x22817710804108129226940657696768',
                0xE9: 'MPO 1x22817710804108129226940657696768',
                0xEA: 'MPO 2x45635421608216258453881315393536',
                0xEB: 'MPO 1x45635421608216258453881315393536',
                0xEC: 'MPO 2x91270843216432516907762630787072',
                0xED: 'MPO 1x91270843216432516907762630787072',
                0xEE: 'MPO 2x182541686432865033815525261574144',
                0xEF: 'MPO 1x182541686432865033815525261574144',
                0xF0: 'MPO 2x365083372865730067631050523148288',
                0xF1: 'MPO 1x365083372865730067631050523148288',
                0xF2: 'MPO 2x730166745731460135262101046296576',
                0xF3: 'MPO 1x730166745731460135262101046296576',
                0xF4: 'MPO 2x1460333491462920270524202092593152',
                0xF5: 'MPO 1x1460333491462920270524202092593152',
                0xF6: 'MPO 2x2920666982925840541048404185186304',
                0xF7: 'MPO 1x2920666982925840541048404185186304',
                0xF8: 'MPO 2x5841333965851681082096808370372608',
                0xF9: 'MPO 1x5841333965851681082096808370372608',
                0xFA: 'MPO 2x11682667931703362164193616740745216',
                0xFB: 'MPO 1x11682667931703362164193616740745216',
                0xFC: 'MPO 2x23365335863406724328387233481490432',
                0xFD: 'MPO 1x23365335863406724328387233481490432',
                0xFE: 'MPO 2x46730671726813448656774466962980864',
                0xFF: 'MPO 1x46730671726813448656774466962980864'
            }
            connector_name = connector_names.get(media_info['connector_type'], f"Unknown({media_info['connector_type']:02x})")
            print(f"Connector Type: {media_info['connector_type']:02x} ({connector_name})")
        if 'interface_technology' in media_info:
            print(f"Interface Technology: {media_info['interface_technology']:02x} (Unknown({media_info['interface_technology']:02x}))")
        if 'supported_lanes' in media_info:
            print(f"Supported Lanes: {media_info['supported_lanes']}")
        if 'nominal_wavelength' in media_info:
            print(f"Wavelength: {media_info['nominal_wavelength']:.2f}nm")
        if 'lane_wavelengths' in media_info:
            print("Per-Lane Wavelengths:")
            for lane, data in media_info['lane_wavelengths'].items():
                print(f"  Lane {lane}: {data['nm']:.2f}nm")
   
    # Cable Information
    if cmis_data.get('cable_info'):
        print("\n--- Cable Information ---")
        cable_info = cmis_data['cable_info']
        if 'length' in cable_info:
            print(f"Cable Length: {cable_info['length']}m")
        if 'attenuation' in cable_info:
            print("Attenuation:")
            atten = cable_info['attenuation']
            print(f"  5 GHz: {atten['at_5ghz']} dB")
            print(f"  7 GHz: {atten['at_7ghz']} dB")
            print(f"  12.9 GHz: {atten['at_12p9ghz']} dB")
            print(f"  25.8 GHz: {atten['at_25p8ghz']} dB")
            print(f"  53.1 GHz: {atten['at_53p1ghz']} dB")
   
    # Monitoring Information
    if cmis_data.get('monitoring'):
        print("\n--- Monitoring Information ---")
        monitoring = cmis_data['monitoring']
        if 'module' in monitoring:
            module_mon = monitoring['module']
            if 'temperature' in module_mon:
                print(f"Module Temperature: {module_mon['temperature']:.1f}°C")
            if 'vcc' in module_mon:
                print(f"Module VCC: {module_mon['vcc']:.2f}V")
            if 'aux1' in module_mon:
                print(f"Module Aux1: {module_mon['aux1']}")
            if 'aux2' in module_mon:
                print(f"Module Aux2: {module_mon['aux2']}")
            if 'aux3' in module_mon:
                print(f"Module Aux3: {module_mon['aux3']}")
            if 'custom' in module_mon:
                print(f"Module Custom: {module_mon['custom']}")
       
        if 'lanes' in monitoring:
            print("Lane Monitoring:")
            for lane_name, lane_data in monitoring['lanes'].items():
                print(f"  {lane_name}: TX={lane_data['tx_power']}, RX={lane_data['rx_power']}, Bias={lane_data['tx_bias']}, Ratio={lane_data['rx_power_ratio']}")
       
        if 'snr' in monitoring:
            print("SNR (OSNR) Data:")
            snr_data = monitoring['snr']
            if 'host_side' in snr_data:
                print("  Host Side:")
                for lane, snr in snr_data['host_side'].items():
                    print(f"    {lane}: {snr:.2f} dB")
            if 'media_side' in snr_data:
                print("  Media Side:")
                for lane, snr in snr_data['media_side'].items():
                    print(f"    {lane}: {snr:.2f} dB")
   
    # Thresholds
    if cmis_data.get('thresholds'):
        print("\n--- Thresholds ---")
        thresholds = cmis_data['thresholds']
        if 'module' in thresholds:
            module_thresh = thresholds['module']
            print("Module Thresholds:")
            if 'temp_high_alarm' in module_thresh:
                print(f"  Temperature High Alarm: {module_thresh['temp_high_alarm']}°C")
            if 'temp_low_alarm' in module_thresh:
                print(f"  Temperature Low Alarm: {module_thresh['temp_low_alarm']}°C")
            if 'vcc_high_alarm' in module_thresh:
                print(f"  VCC High Alarm: {module_thresh['vcc_high_alarm']}V")
            if 'vcc_low_alarm' in module_thresh:
                print(f"  VCC Low Alarm: {module_thresh['vcc_low_alarm']}V")

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
    """Read CMIS application codes from Upper Page 01h."""
    # Application codes are in Upper Page 01h, bytes 128-131 → relative 0-3
    app_codes = []
    for i in range(4):
        app_code = get_byte(page_dict, '80h', i)  # relative offset 0-3
        if app_code is not None and app_code != 0:
            app_codes.append(app_code)
    return app_codes

def read_cmis_lane_status(page_dict):
    """Read CMIS lane status from Upper Page 00h."""
    # Media Lane Information: byte 210 → relative 82
    lane_info = get_byte(page_dict, 0x80, 82)  # relative offset 82
    if lane_info is not None:
        supported_lanes = [lane + 1 for lane in range(8) if not (lane_info & (1 << lane))]
        return f"0x{lane_info:02x} (Supported: {supported_lanes})"
    return "Not available"

def read_cmis_module_state(page_dict):
    """Read and print CMIS Module State (Table 8-5)"""
    try:
        state = get_byte(page_dict, '00h', 3) & 0x0F
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
    attenuation = get_bytes(page_dict, 0x80, 76, 82)  # relative offsets
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
    lane_info = get_byte(page_dict, 0x80, 82)  # relative offset 82
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
    lane_info = get_byte(page_dict, 0x80, 82)  # relative offset 82
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
            code = get_byte(page_dict, 0x01, base - 0x180)  # Convert to Upper Page 01h offset
            if code == 0:
                continue
            host_lane_count = get_byte(page_dict, 0x01, base - 0x180 + 1)
            media_lane_count = get_byte(page_dict, 0x01, base - 0x180 + 2)
            host_lane_assignment = get_byte(page_dict, 0x01, base - 0x180 + 3)
            media_lane_assignment = get_byte(page_dict, 0x01, base - 0x180 + 4)
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

def read_cmis_global_status_detailed(page_dict):
    """Read and print CMIS Global Status/Interrupts (Table 8-4)"""
    try:
        status = get_byte(page_dict, 0x00, 2)
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
    lane_info = get_byte(page_dict, 0x80, 82)  # relative offset 82
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
        nominal_wavelength_raw = get_bytes(page_dict, 0x100, 0x8A, 0x8C)
        if nominal_wavelength_raw:
            nominal_wavelength = struct.unpack_from('>H', bytes(nominal_wavelength_raw))[0] * 0.05
            print(f"Nominal Wavelength: {nominal_wavelength:.2f} nm")
       
        # Read wavelength tolerance from Page 01h bytes 140-141 (0x8C-0x8D)
        wavelength_tolerance_raw = get_bytes(page_dict, 0x100, 0x8C, 0x8E)
        if wavelength_tolerance_raw:
            wavelength_tolerance = struct.unpack_from('>H', bytes(wavelength_tolerance_raw))[0] * 0.005
            print(f"Wavelength Tolerance: ±{wavelength_tolerance:.3f} nm")
       
        # Read supported fiber link length from Page 01h bytes 131-137 (0x83-0x89)
        fiber_length = get_bytes(page_dict, 0x100, 0x83, 0x8A)
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
        sff8024_id = get_byte(page_dict, 0x00, 0)
        cmis_rev = get_byte(page_dict, 0x00, 1)
        mgmt_chars = get_byte(page_dict, 0x00, 2)
       
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
        module_state = get_byte(page_dict, 0x00, 3)
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
        global_status = get_byte(page_dict, 0x00, 2)
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
        lane_flags = get_byte(page_dict, 0x00, 1)
        if lane_flags is not None:
            print("\nLane Flags Summary:")
            for lane in range(8):
                tx_fault = bool(lane_flags & (1 << (lane * 2)))
                rx_los = bool(lane_flags & (1 << (lane * 2 + 1)))
                print(f"  Lane {lane+1}: TX Fault={'Yes' if tx_fault else 'No'}, RX LOS={'Yes' if rx_los else 'No'}")
       
        # Module Flags (byte 0)
        module_flags = get_byte(page_dict, 0x00, 0)
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
        vendor_name = get_bytes(page_dict, 0x80, 0x00, 0x10)
        if vendor_name:
            vendor_name = vendor_name.decode('ascii', errors='ignore').strip()
            print(f"Vendor Name: {vendor_name}")
       
        vendor_oui = get_bytes(page_dict, 0x80, 0x10, 0x13)
        if vendor_oui:
            oui_str = ''.join([f"{b:02x}" for b in vendor_oui])
            print(f"Vendor OUI: {oui_str}")
       
        vendor_pn = get_bytes(page_dict, 0x80, 0x10, 0x20)
        if vendor_pn:
            vendor_pn = vendor_pn.decode('ascii', errors='ignore').strip()
            print(f"Vendor Part Number: {vendor_pn}")
       
        vendor_rev = get_bytes(page_dict, 0x80, 0x20, 0x22)
        if vendor_rev:
            vendor_rev = vendor_rev.decode('ascii', errors='ignore').strip()
            print(f"Vendor Revision: {vendor_rev}")
       
        vendor_sn = get_bytes(page_dict, 0x80, 0x22, 0x32)
        if vendor_sn:
            vendor_sn = vendor_sn.decode('ascii', errors='ignore').strip()
            print(f"Vendor Serial Number: {vendor_sn}")
       
        # Table 8-29: Date Code
        print("\n--- Date Code ---")
        date_code = get_bytes(page_dict, 0x80, 0x32, 0x3A)
        if date_code:
            date_code = date_code.decode('ascii', errors='ignore').strip()
            print(f"Date Code: {date_code}")
       
        # Table 8-30: CLEI Code
        print("\n--- CLEI Code ---")
        clei_code = get_bytes(page_dict, 0x80, 0x3A, 0x44)
        if clei_code:
            clei_code = clei_code.decode('ascii', errors='ignore').strip()
            print(f"CLEI Code: {clei_code}")
       
        # Table 8-31: Module Power Class and Max Power
        print("\n--- Module Power Class and Max Power ---")
        power_class_byte = get_byte(page_dict, 0x80, 0x48)
        max_power_byte = get_byte(page_dict, 0x80, 0x49)
       
        if power_class_byte is not None:
            power_class = (power_class_byte >> 5) & 0x07
            print(f"Power Class: {power_class}")
       
        if max_power_byte is not None:
            max_power = max_power_byte * 0.25
            print(f"Max Power: {max_power:.2f} W")
       
        # Table 8-32: Cable Assembly Link Length
        print("\n--- Cable Assembly Link Length ---")
        length_byte = get_byte(page_dict, 0x80, 0x4A)
        if length_byte is not None:
            length_multiplier = (length_byte >> 6) & 0x03
            base_length = length_byte & 0x1F
            print(f"Length Multiplier: {length_multiplier}")
            print(f"Base Length: {base_length}")
       
        # Table 8-33: Media Connector Type
        print("\n--- Media Connector Type ---")
        connector_type = get_byte(page_dict, 0x80, 0x4B)
        if connector_type is not None:
            connector_names = {
                0x01: 'SC',
                0x02: 'FC Style 1 copper',
                0x03: 'FC Style 2 copper',
                0x04: 'BNC/TNC',
                0x05: 'FC coax headers',
                0x06: 'Fiber Jack',
                0x07: 'LC',
                0x08: 'MT-RJ',
                0x09: 'MU',
                0x0A: 'SG',
                0x0B: 'Optical Pigtail',
                0x0C: 'MPO 1x12',
                0x0D: 'MPO 2x16',
                0x20: 'HSSDC II',
                0x21: 'Copper Pigtail',
                0x22: 'RJ45',
                0x23: 'No separable connector',
                0x24: 'MXC 2x16',
                0x25: 'CS optical connector',
                0x26: 'SN optical connector',
                0x27: 'MPO 2x12',
                0x28: 'MPO 1x16'
            }
            connector_type = media_info['connector_type']
            connector_name = connector_names.get(connector_type, f'Unknown({connector_type:02x})')
            print(f"Connector Type: 0x{connector_type:02x} ({connector_name})")
        if 'interface_technology' in media_info:
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
            tech = media_info['interface_technology']
            tech_name = tech_names.get(tech, f'Unknown({tech:02x})')
            print(f"Interface Technology: 0x{tech:02x} ({tech_name})")
       
        # Table 8-34: Media Interface Technology (Page 0x100, byte 0x87)
        tech = get_byte(page_dict, 0x100, 0x87) if 0x100 in page_dict else None
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
       
        # Table 8-35: Media Lane Information
        print("\n--- Media Lane Information ---")
        lane_info = get_byte(page_dict, 0x80, 0x52)
        if lane_info is not None:
            print(f"Media Lane Info: 0x{lane_info:02x}")
            for lane in range(8):
                supported = (lane_info & (1 << lane)) != 0
                print(f"  Lane {lane+1}: {'Supported' if supported else 'Not Supported'}")
       
        # Table 8-36: Cable Assembly Information
        print("\n--- Cable Assembly Information ---")
        cable_info = get_bytes(page_dict, 0x80, 0x53, 0x58)
        if cable_info:
            print(f"Cable Assembly Information: {cable_info}")
       
        # Table 8-37/8-38: Far End Configurations
        print("\n--- Far End Configurations ---")
        far_end_config = get_bytes(page_dict, 0x80, 0x58, 0x68)
        if far_end_config:
            print(f"Far End Configurations: {far_end_config}")
       
        # Table 8-39: Media Connector Type (additional)
        print("\n--- Additional Media Connector Type ---")
        addl_connector = get_byte(page_dict, 0x80, 0x68)
        if addl_connector is not None:
            print(f"Additional Connector Type: 0x{addl_connector:02x}")
       
        # Table 8-41: MCI Related Advertisements
        print("\n--- MCI Related Advertisements ---")
        mci_info = get_bytes(page_dict, 0x80, 0x69, 0x80)
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
        inactive_fw_major = get_byte(page_dict, 0x100, 0x80)
        inactive_fw_minor = get_byte(page_dict, 0x100, 0x81)
        if inactive_fw_major is not None and inactive_fw_minor is not None:
            print(f"Inactive Firmware Version: {inactive_fw_major}.{inactive_fw_minor}")
       
        hw_rev = get_byte(page_dict, 0x100, 0x82)
        if hw_rev is not None:
            print(f"Hardware Revision: {hw_rev}")
       
        # Table 8-44: Supported Fiber Link Length
        print("\n--- Supported Fiber Link Length ---")
        fiber_length = get_bytes(page_dict, 0x100, 0x83, 0x8A)
        if fiber_length:
            print(f"Supported Fiber Link Length: {fiber_length}")
       
        # Table 8-45: Wavelength Information
        print("\n--- Wavelength Information ---")
        nominal_wavelength_raw = get_bytes(page_dict, 0x100, 0x8A, 0x8C)
        if nominal_wavelength_raw:
            nominal_wavelength = struct.unpack_from('>H', bytes(nominal_wavelength_raw))[0] * 0.05
            print(f"Nominal Wavelength: {nominal_wavelength:.2f} nm")
       
        wavelength_tolerance_raw = get_bytes(page_dict, 0x100, 0x8C, 0x8E)
        if wavelength_tolerance_raw:
            wavelength_tolerance = struct.unpack_from('>H', bytes(wavelength_tolerance_raw))[0] * 0.005
            print(f"Wavelength Tolerance: ±{wavelength_tolerance:.3f} nm")
       
        # Table 8-46: Supported Pages Advertising
        print("\n--- Supported Pages Advertising ---")
        supported_pages = get_bytes(page_dict, 0x100, 0x8E, 0x90)
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
        durations = get_bytes(page_dict, 0x100, 0x91, 0x93)
        if durations:
            print(f"Durations: {durations}")
       
        # Table 8-49: Module Characteristics Advertisement
        print("\n--- Module Characteristics Advertisement ---")
        module_chars = get_bytes(page_dict, 0x100, 0xA0, 0xA4)
        if module_chars:
            print(f"Module Characteristics: {module_chars}")
       
        # Table 8-50: Supported Controls Advertisement
        print("\n--- Supported Controls Advertisement ---")
        supported_controls = get_bytes(page_dict, 0x100, 0xA4, 0xA8)
        if supported_controls:
            print(f"Supported Controls: {supported_controls}")
       
        # Table 8-51: Supported Flags Advertisement
        print("\n--- Supported Flags Advertisement ---")
        supported_flags = get_bytes(page_dict, 0x100, 0xA8, 0xAC)
        if supported_flags:
            print(f"Supported Flags: {supported_flags}")
       
        # Table 8-52: Supported Monitors Advertisement
        print("\n--- Supported Monitors Advertisement ---")
        supported_monitors = get_bytes(page_dict, 0x100, 0xAC, 0xB0)
        if supported_monitors:
            print(f"Supported Monitors: {supported_monitors}")
       
        # Table 8-53: Supported Signal Integrity Controls Advertisement
        print("\n--- Supported Signal Integrity Controls Advertisement ---")
        signal_integrity = get_bytes(page_dict, 0x100, 0xB0, 0xB4)
        if signal_integrity:
            print(f"Signal Integrity Controls: {signal_integrity}")
       
        # Table 8-54: CDB Advertisement
        print("\n--- CDB Advertisement ---")
        cdb_support = get_bytes(page_dict, 0x100, 0xB4, 0xB8)
        if cdb_support:
            print(f"CDB Support: {cdb_support}")
       
        # Table 8-56: Additional Durations Advertising
        print("\n--- Additional Durations Advertising ---")
        addl_durations = get_bytes(page_dict, 0x100, 0xB8, 0xBA)
        if addl_durations:
            print(f"Additional Durations: {addl_durations}")
       
        # Table 8-57: Normalized Application Descriptors Support
        print("\n--- Normalized Application Descriptors Support ---")
        norm_app_desc = get_bytes(page_dict, 0x100, 0xBA, 0xBE)
        if norm_app_desc:
            print(f"Normalized Application Descriptors: {norm_app_desc}")
       
        # Table 8-58: Media Lane Assignment Advertising
        print("\n--- Media Lane Assignment Advertising ---")
        lane_assignment = get_bytes(page_dict, 0x100, 0xBE, 0xC2)
        if lane_assignment:
            print(f"Media Lane Assignment: {lane_assignment}")
       
        # Table 8-59: Additional Application Descriptor Registers
        print("\n--- Additional Application Descriptor Registers ---")
        for i in range(8):
            app_desc = get_bytes(page_dict, 0x100, 0xC2 + i*4, 0xC6 + i*4)
            if app_desc:
                print(f"Additional Application Descriptor {i+1}: {app_desc}")
       
        # Table 8-60: Miscellaneous Advertisements
        print("\n--- Miscellaneous Advertisements ---")
        misc_ads = get_bytes(page_dict, 0x100, 0xE2, 0xFF)
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
        temp_high_alarm = get_bytes(page_dict, 0x200, 0x00, 0x02)
        if temp_high_alarm:
            temp_high_alarm_val = struct.unpack_from('>H', bytes(temp_high_alarm))[0] / 256.0
            print(f"Temperature High Alarm: {temp_high_alarm_val:.1f}°C")
       
        temp_low_alarm = get_bytes(page_dict, 0x200, 0x02, 0x04)
        if temp_low_alarm:
            temp_low_alarm_val = struct.unpack_from('>H', bytes(temp_low_alarm))[0] / 256.0
            print(f"Temperature Low Alarm: {temp_low_alarm_val:.1f}°C")
       
        temp_high_warning = get_bytes(page_dict, 0x200, 0x04, 0x06)
        if temp_high_warning:
            temp_high_warning_val = struct.unpack_from('>H', bytes(temp_high_warning))[0] / 256.0
            print(f"Temperature High Warning: {temp_high_warning_val:.1f}°C")
       
        temp_low_warning = get_bytes(page_dict, 0x200, 0x06, 0x08)
        if temp_low_warning:
            temp_low_warning_val = struct.unpack_from('>H', bytes(temp_low_warning))[0] / 256.0
            print(f"Temperature Low Warning: {temp_low_warning_val:.1f}°C")
       
        # Voltage thresholds (bytes 132-139)
        vcc_high_alarm = get_bytes(page_dict, 0x200, 0x08, 0x0A)
        if vcc_high_alarm:
            vcc_high_alarm_val = struct.unpack_from('>H', bytes(vcc_high_alarm))[0] / 10000.0
            print(f"VCC High Alarm: {vcc_high_alarm_val:.3f}V")
       
        vcc_low_alarm = get_bytes(page_dict, 0x200, 0x0A, 0x0C)
        if vcc_low_alarm:
            vcc_low_alarm_val = struct.unpack_from('>H', bytes(vcc_low_alarm))[0] / 10000.0
            print(f"VCC Low Alarm: {vcc_low_alarm_val:.3f}V")
       
        vcc_high_warning = get_bytes(page_dict, 0x200, 0x0C, 0x0E)
        if vcc_high_warning:
            vcc_high_warning_val = struct.unpack_from('>H', bytes(vcc_high_warning))[0] / 10000.0
            print(f"VCC High Warning: {vcc_high_warning_val:.3f}V")
       
        vcc_low_warning = get_bytes(page_dict, 0x200, 0x0E, 0x10)
        if vcc_low_warning:
            vcc_low_warning_val = struct.unpack_from('>H', bytes(vcc_low_warning))[0] / 10000.0
            print(f"VCC Low Warning: {vcc_low_warning_val:.3f}V")
       
        # TX Power thresholds (bytes 140-147)
        tx_power_high_alarm = get_bytes(page_dict, 0x200, 0x10, 0x12)
        if tx_power_high_alarm:
            tx_power_high_alarm_val = struct.unpack_from('>H', bytes(tx_power_high_alarm))[0] / 10000.0
            print(f"TX Power High Alarm: {tx_power_high_alarm_val:.3f}mW")
       
        tx_power_low_alarm = get_bytes(page_dict, 0x200, 0x12, 0x14)
        if tx_power_low_alarm:
            tx_power_low_alarm_val = struct.unpack_from('>H', bytes(tx_power_low_alarm))[0] / 10000.0
            print(f"TX Power Low Alarm: {tx_power_low_alarm_val:.3f}mW")
       
        tx_power_high_warning = get_bytes(page_dict, 0x200, 0x14, 0x16)
        if tx_power_high_warning:
            tx_power_high_warning_val = struct.unpack_from('>H', bytes(tx_power_high_warning))[0] / 10000.0
            print(f"TX Power High Warning: {tx_power_high_warning_val:.3f}mW")
       
        tx_power_low_warning = get_bytes(page_dict, 0x200, 0x16, 0x18)
        if tx_power_low_warning:
            tx_power_low_warning_val = struct.unpack_from('>H', bytes(tx_power_low_warning))[0] / 10000.0
            print(f"TX Power Low Warning: {tx_power_low_warning_val:.3f}mW")
       
        # RX Power thresholds (bytes 148-155)
        rx_power_high_alarm = get_bytes(page_dict, 0x200, 0x18, 0x1A)
        if rx_power_high_alarm:
            rx_power_high_alarm_val = struct.unpack_from('>H', bytes(rx_power_high_alarm))[0] / 10000.0
            print(f"RX Power High Alarm: {rx_power_high_alarm_val:.3f}mW")
       
        rx_power_low_alarm = get_bytes(page_dict, 0x200, 0x1A, 0x1C)
        if rx_power_low_alarm:
            rx_power_low_alarm_val = struct.unpack_from('>H', bytes(rx_power_low_alarm))[0] / 10000.0
            print(f"RX Power Low Alarm: {rx_power_low_alarm_val:.3f}mW")
       
        rx_power_high_warning = get_bytes(page_dict, 0x200, 0x1C, 0x1E)
        if rx_power_high_warning:
            rx_power_high_warning_val = struct.unpack_from('>H', bytes(rx_power_high_warning))[0] / 10000.0
            print(f"RX Power High Warning: {rx_power_high_warning_val:.3f}mW")
       
        rx_power_low_warning = get_bytes(page_dict, 0x200, 0x1E, 0x20)
        if rx_power_low_warning:
            rx_power_low_warning_val = struct.unpack_from('>H', bytes(rx_power_low_warning))[0] / 10000.0
            print(f"RX Power Low Warning: {rx_power_low_warning_val:.3f}mW")
       
        # Lane-specific thresholds (bytes 160-191)
        print("\n--- Lane-Specific Thresholds ---")
        for lane in range(8):
            base_offset = 0x20 + lane * 16
            lane_data = get_bytes(page_dict, 0x200, base_offset, base_offset + 16)
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
            lane_control = get_byte(page_dict, 0x1000, lane)
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
            lane_status = get_byte(page_dict, 0x1100, lane)
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
        vendor_data = get_bytes(page_dict, 0x400, 0x00, 0x100)
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
        laser_control = get_bytes(page_dict, 0x1200, 0x00, 0x10)
        if laser_control:
            print(f"Laser Control: {laser_control}")
       
        # Laser status registers (bytes 16-31)
        laser_status = get_bytes(page_dict, 0x1200, 0x10, 0x20)
        if laser_status:
            print(f"Laser Status: {laser_status}")
       
        # Wavelength control registers (bytes 32-47)
        wavelength_control = get_bytes(page_dict, 0x1200, 0x20, 0x30)
        if wavelength_control:
            print(f"Wavelength Control: {wavelength_control}")
       
        # Wavelength status registers (bytes 48-63)
        wavelength_status = get_bytes(page_dict, 0x1200, 0x30, 0x40)
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
        diag_control = get_bytes(page_dict, 0x1300, 0x00, 0x10)
        if diag_control:
            print(f"Diagnostic Control: {diag_control}")
       
        # Diagnostic status registers (bytes 16-31)
        diag_status = get_bytes(page_dict, 0x1300, 0x10, 0x20)
        if diag_status:
            print(f"Diagnostic Status: {diag_status}")
       
        # Diagnostic data registers (bytes 32-255)
        diag_data = get_bytes(page_dict, 0x1300, 0x20, 0x100)
        if diag_data:
            print(f"Diagnostic Data: {diag_data}")
       
    except Exception as e:
        print(f"Error reading CMIS Page 13h: {e}")

def read_cmis_page_25h(page_dict):
    """Read and print all CMIS Page 25h (Vendor-specific) fields according to OIF-CMIS 5.3."""
    try:
        print("\n=== CMIS Page 25h (Vendor-specific) ===")
       
        # Vendor-specific data (bytes 0-255)
        vendor_data = get_bytes(page_dict, 0x2500, 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
       
    except Exception as e:
        print(f"Error reading CMIS Page 25h: {e}")

# Additional CMIS page functions (14h-19h, 1Ch, 1Dh)
def read_cmis_page_14h(page_dict):
    """Read CMIS Page 14h (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 14h (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, 0x1400, 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 14h: {e}")

def read_cmis_page_15h(page_dict):
    """Read CMIS Page 15h (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 15h (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, 0x1500, 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 15h: {e}")

def read_cmis_page_16h(page_dict):
    """Read CMIS Page 16h (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 16h (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, 0x1600, 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 16h: {e}")

def read_cmis_page_17h(page_dict):
    """Read CMIS Page 17h (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 17h (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, 0x1700, 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 17h: {e}")

def read_cmis_page_18h(page_dict):
    """Read CMIS Page 18h (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 18h (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, 0x1800, 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 18h: {e}")

def read_cmis_page_19h(page_dict):
    """Read CMIS Page 19h (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 19h (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, 0x1900, 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 19h: {e}")

def read_cmis_page_1Ch(page_dict):
    """Read CMIS Page 1Ch (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 1Ch (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, 0x1C00, 0x00, 0x100)
        if vendor_data:
            print(f"Vendor-specific data: {vendor_data}")
    except Exception as e:
        print(f"Error reading CMIS Page 1Ch: {e}")

def read_cmis_page_1Dh(page_dict):
    """Read CMIS Page 1Dh (Vendor-specific)"""
    try:
        print("\n=== CMIS Page 1Dh (Vendor-specific) ===")
        vendor_data = get_bytes(page_dict, 0x1D00, 0x00, 0x100)
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