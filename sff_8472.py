#!/usr/bin/env python3
"""
SFF-8472 (SFP+) parsing functions
Based on SFF-8472 12.4.3 specification

This module provides centralized parsing and unified output for SFP+ modules.
"""

import struct
import math
from curses.ascii import isprint

def parse_sff8472_data_centralized(page_dict):
    """
    Centralized SFF-8472 data parser that reads all relevant pages and returns structured data.
    
    Args:
        page_dict: Dictionary containing page data
        
    Returns:
        dict: Structured SFF-8472 data with all parsed fields
    """
    sff8472_data = {
        'vendor_info': {},
        'module_info': {},
        'monitoring': {},
        'thresholds': {},
        'status': {},
        'compliance': {},
        'distances': {},
        'encoding': {},
        'connector': {},
        'transceiver_codes': []
    }
    
    # Parse Lower Memory (bytes 0-127)
    if 'lower' in page_dict:
        lower_page = page_dict['lower']
        
        # Identifier (byte 0)
        if len(lower_page) > 0:
            identifier = lower_page[0]
            sff8472_data['module_info']['identifier'] = identifier
            sff8472_data['module_info']['identifier_name'] = {
                0x03: 'SFP/SFP+',
                0x0C: 'QSFP',
                0x0D: 'QSFP+',
                0x11: 'QSFP28',
                0x18: 'QSFP-DD'
            }.get(identifier, f'Unknown({identifier:02x})')
        
        # Extended Identifier (byte 1)
        if len(lower_page) > 1:
            ext_identifier = lower_page[1]
            sff8472_data['module_info']['extended_identifier'] = ext_identifier
        
        # Connector Type (byte 2)
        if len(lower_page) > 2:
            connector_type = lower_page[2]
            sff8472_data['connector']['type'] = connector_type
            sff8472_data['connector']['type_name'] = {
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
            }.get(connector_type, f'Unknown({connector_type:02x})')
        
        # Transceiver Codes (bytes 3-10)
        if len(lower_page) >= 11:
            transceiver_codes = lower_page[3:11]
            sff8472_data['transceiver_codes'] = transceiver_codes
        
        # Encoding (byte 11)
        if len(lower_page) > 11:
            encoding = lower_page[11]
            sff8472_data['encoding']['type'] = encoding
            sff8472_data['encoding']['type_name'] = {
                0x01: '8B/10B',
                0x02: '4B/5B',
                0x03: 'NRZ',
                0x04: 'SONET Scrambled',
                0x05: '64B/66B',
                0x06: 'Manchester',
                0x07: 'SONET Scrambled',
                0x08: '256B/257B'
            }.get(encoding, f'Unknown({encoding:02x})')
        
        # Signaling Rate (byte 12)
        if len(lower_page) > 12:
            signaling_rate = lower_page[12]
            sff8472_data['module_info']['signaling_rate'] = signaling_rate
        
        # Rate Identifier (byte 13)
        if len(lower_page) > 13:
            rate_id = lower_page[13]
            sff8472_data['module_info']['rate_identifier'] = rate_id
        
        # Length (bytes 14-19)
        if len(lower_page) >= 20:
            distances = {
                'smf_km': lower_page[14],
                'smf_100m': lower_page[15],
                'om2_10m': lower_page[16],
                'om1_10m': lower_page[17],
                'om4_m': lower_page[18],
                'om4_10m': lower_page[19]
            }
            sff8472_data['distances'] = distances
        
        # Vendor Name (bytes 20-35)
        if len(lower_page) >= 36:
            vendor_name = ''.join([chr(b) for b in lower_page[20:36]]).strip()
            sff8472_data['vendor_info']['name'] = vendor_name
        
        # Extended Transceiver Codes (byte 36)
        if len(lower_page) > 36:
            ext_transceiver = lower_page[36]
            sff8472_data['module_info']['extended_transceiver'] = ext_transceiver
        
        # Vendor OUI (bytes 37-39)
        if len(lower_page) >= 40:
            vendor_oui = lower_page[37:40]
            sff8472_data['vendor_info']['oui'] = f"{vendor_oui[0]:02x}:{vendor_oui[1]:02x}:{vendor_oui[2]:02x}"
        
        # Vendor Part Number (bytes 40-55)
        if len(lower_page) >= 56:
            vendor_pn = ''.join([chr(b) for b in lower_page[40:56]]).strip()
            sff8472_data['vendor_info']['part_number'] = vendor_pn
        
        # Vendor Revision (bytes 56-59)
        if len(lower_page) >= 60:
            vendor_rev = ''.join([chr(b) for b in lower_page[56:60]]).strip()
            sff8472_data['vendor_info']['revision'] = vendor_rev
        
        # Wavelength (bytes 60-61)
        if len(lower_page) >= 62:
            wavelength = struct.unpack_from('>H', bytes(lower_page[60:62]))[0]
            sff8472_data['module_info']['wavelength_nm'] = wavelength
        
        # Vendor Serial Number (bytes 68-83)
        if len(lower_page) >= 84:
            vendor_sn = ''.join([chr(b) for b in lower_page[68:84]]).strip()
            sff8472_data['vendor_info']['serial_number'] = vendor_sn
        
        # Date Code (bytes 84-91)
        if len(lower_page) >= 92:
            date_code = ''.join([chr(b) for b in lower_page[84:92]]).strip()
            sff8472_data['vendor_info']['date_code'] = date_code
        
        # Diagnostic Monitoring Type (byte 92)
        if len(lower_page) > 92:
            monitoring_type = lower_page[92]
            sff8472_data['monitoring']['type'] = monitoring_type
            sff8472_data['monitoring']['type_name'] = {
                0x00: 'No diagnostic monitoring',
                0x01: 'Digital diagnostic monitoring',
                0x02: 'Digital diagnostic monitoring with interrupt',
                0x03: 'Digital diagnostic monitoring with interrupt and threshold'
            }.get(monitoring_type, f'Unknown({monitoring_type:02x})')
        
        # Enhanced Options (byte 93)
        if len(lower_page) > 93:
            enhanced_options = lower_page[93]
            sff8472_data['module_info']['enhanced_options'] = enhanced_options
        
        # SFF-8472 Compliance (byte 94)
        if len(lower_page) > 94:
            compliance = lower_page[94]
            sff8472_data['compliance']['sff8472'] = compliance
        
        # CC_BASE (byte 95)
        if len(lower_page) > 95:
            cc_base = lower_page[95]
            sff8472_data['module_info']['cc_base'] = cc_base
        
        # Temperature (bytes 96-97)
        if len(lower_page) >= 98:
            temp_raw = struct.unpack_from('>h', bytes(lower_page[96:98]))[0]
            temperature = temp_raw / 256.0
            sff8472_data['monitoring']['temperature'] = temperature
        
        # VCC (bytes 98-99)
        if len(lower_page) >= 100:
            vcc_raw = struct.unpack_from('>H', bytes(lower_page[98:100]))[0]
            vcc = vcc_raw / 10000.0
            sff8472_data['monitoring']['vcc'] = vcc
        
        # TX Power (bytes 102-103)
        if len(lower_page) >= 104:
            tx_power_raw = struct.unpack_from('>H', bytes(lower_page[102:104]))[0]
            tx_power = tx_power_raw / 10000.0
            sff8472_data['monitoring']['tx_power'] = tx_power
        
        # RX Power (bytes 104-105)
        if len(lower_page) >= 106:
            rx_power_raw = struct.unpack_from('>H', bytes(lower_page[104:106]))[0]
            rx_power = rx_power_raw / 10000.0
            sff8472_data['monitoring']['rx_power'] = rx_power
        
        # Laser Temperature (bytes 106-107)
        if len(lower_page) >= 108:
            laser_temp_raw = struct.unpack_from('>h', bytes(lower_page[106:108]))[0]
            laser_temperature = laser_temp_raw / 256.0
            sff8472_data['monitoring']['laser_temperature'] = laser_temperature
        
        # Measured Current (bytes 108-109)
        if len(lower_page) >= 110:
            current_raw = struct.unpack_from('>H', bytes(lower_page[108:110]))[0]
            current = current_raw / 10000.0
            sff8472_data['monitoring']['current'] = current
        
        # Status Bits (byte 110)
        if len(lower_page) > 110:
            status_bits = lower_page[110]
            sff8472_data['status']['bits'] = status_bits
            sff8472_data['status']['data_ready'] = bool(status_bits & 0x01)
            sff8472_data['status']['tx_fault'] = bool(status_bits & 0x02)
            sff8472_data['status']['rx_los'] = bool(status_bits & 0x04)
            sff8472_data['status']['signal_detect'] = bool(status_bits & 0x08)
            sff8472_data['status']['tx_disable'] = bool(status_bits & 0x10)
            sff8472_data['status']['rate_select'] = bool(status_bits & 0x20)
            sff8472_data['status']['tx_fault_invert'] = bool(status_bits & 0x40)
            sff8472_data['status']['soft_tx_disable'] = bool(status_bits & 0x80)
    
    return {
        'module_info': sff8472_data['module_info'],
        'vendor_info': sff8472_data['vendor_info'],
        'connector': sff8472_data['connector'],
        'encoding': sff8472_data['encoding'],
        'distances': sff8472_data['distances'],
        'transceiver_codes': sff8472_data['transceiver_codes'],
        'monitoring': sff8472_data['monitoring'],
        'status': sff8472_data['status'],
        'raw_pages': page_dict  # Include raw pages for legacy functions
    }

def output_sff8472_data_unified(sff8472_data):
    """Output SFF-8472 data in a unified format"""
    
    # Basic Module Information
    if sff8472_data['module_info']:
        print("\n=== SFF-8472 Module Information ===")
        module = sff8472_data['module_info']
        if 'identifier' in module:
            print(f"Identifier: 0x{module['identifier']:02x}")
        if 'extended_identifier' in module:
            print(f"Extended Identifier: 0x{module['extended_identifier']:02x}")
        if 'connector' in module:
            print(f"Connector: 0x{module['connector']:02x}")
        if 'wavelength_nm' in module:
            print(f"Wavelength: {module['wavelength_nm']} nm")
        if 'signaling_rate' in module:
            print(f"Signaling Rate: {module['signaling_rate']}")
    
    # Vendor Information
    if sff8472_data['vendor_info']:
        print("\n--- Vendor Information ---")
        vendor = sff8472_data['vendor_info']
        if 'name' in vendor:
            print(f"Vendor: {vendor['name']}")
        if 'oui' in vendor:
            print(f"Vendor OUI: {vendor['oui']}")
        if 'part_number' in vendor:
            print(f"Part Number: {vendor['part_number']}")
        if 'serial_number' in vendor:
            print(f"Serial Number: {vendor['serial_number']}")
        if 'revision' in vendor:
            print(f"Hardware Revision: {vendor['revision']}")
        if 'date_code' in vendor:
            print(f"Date Code: {vendor['date_code']}")
    
    # Connector Information
    if sff8472_data['connector']:
        print("\n--- Connector Information ---")
        connector = sff8472_data['connector']
        if 'type' in connector:
            print(f"Connector Type: 0x{connector['type']:02x} ({connector.get('type_name', 'Unknown')})")
    
    # Encoding Information
    if sff8472_data['encoding']:
        print("\n--- Encoding Information ---")
        encoding = sff8472_data['encoding']
        if 'type' in encoding:
            print(f"Encoding: 0x{encoding['type']:02x} ({encoding.get('type_name', 'Unknown')})")
    
    # Distance Information
    if sff8472_data['distances']:
        print("\n--- Distance Information ---")
        distances = sff8472_data['distances']
        if distances.get('smf_km'):
            print(f"SMF: {distances['smf_km']} km")
        if distances.get('om2_10m'):
            print(f"OM2: {distances['om2_10m'] * 10} m")
        if distances.get('om1_10m'):
            print(f"OM1: {distances['om1_10m'] * 10} m")
        if distances.get('om4_m'):
            print(f"OM4: {distances['om4_m']} m")
    
    # Transceiver Codes
    if sff8472_data['transceiver_codes']:
        print("\n--- Transceiver Codes ---")
        for i, code in enumerate(sff8472_data['transceiver_codes'], 1):
            print(f"Code {i}: 0x{code:02x}")
    
    # Monitoring Data
    if sff8472_data['monitoring']:
        print("\n--- Monitoring Data ---")
        monitoring = sff8472_data['monitoring']
        if 'temperature' in monitoring:
            print(f"Temperature: {monitoring['temperature']:.2f}°C")
        if 'vcc' in monitoring:
            print(f"VCC: {monitoring['vcc']:.3f}V")
        if 'tx_power' in monitoring:
            print(f"TX Power: {monitoring['tx_power']:.2f} dBm")
        if 'rx_power' in monitoring:
            print(f"RX Power: {monitoring['rx_power']:.2f} dBm")
        if 'laser_temperature' in monitoring:
            print(f"Laser Temperature: {monitoring['laser_temperature']:.2f}°C")
        if 'current' in monitoring:
            print(f"Current: {monitoring['current']:.2f} mA")
    
    # Status Information
    if sff8472_data['status']:
        print("\n--- Status Information ---")
        status = sff8472_data['status']
        if 'bits' in status:
            print(f"Status Bits: 0x{status['bits']:02x}")
            if 'data_ready' in status:
                print(f"  Data Ready: {'Yes' if status['data_ready'] else 'No'}")
            if 'tx_fault' in status:
                print(f"  TX Fault: {'Yes' if status['tx_fault'] else 'No'}")
            if 'rx_los' in status:
                print(f"  RX LOS: {'Yes' if status['rx_los'] else 'No'}")
            if 'signal_detect' in status:
                print(f"  Signal Detect: {'Yes' if status['signal_detect'] else 'No'}")
    
    # Call all the working functions for detailed output
    print("\n=== Detailed SFF-8472 Information ===")
    
    # Vendor information
    read_optic_vendor(sff8472_data['raw_pages'])
    read_optic_vendor_oui(sff8472_data['raw_pages'])
    read_sff8472_vendor_partnum(sff8472_data['raw_pages'])
    read_optic_vendor_serialnum(sff8472_data['raw_pages'])
    read_optic_rev(sff8472_data['raw_pages'])
    read_optic_datecode(sff8472_data['raw_pages'])
    
    # Distance information
    read_optic_distances(sff8472_data['raw_pages'])
    
    # Monitoring information
    read_optic_frequency(sff8472_data['raw_pages'])
    read_optic_temperature(sff8472_data['raw_pages'])
    read_optic_vcc(sff8472_data['raw_pages'])
    read_laser_temperature(sff8472_data['raw_pages'])
    read_optic_rxpower(sff8472_data['raw_pages'])
    read_optic_txpower(sff8472_data['raw_pages'])
    read_measured_current(sff8472_data['raw_pages'])
    
    # Status and options
    read_optic_monitoring_type(sff8472_data['raw_pages'])
    read_option_values(sff8472_data['raw_pages'])
    read_enhanced_options(sff8472_data['raw_pages'])
    read_sff_8472_compliance(sff8472_data['raw_pages'])
    read_sfp_status_bits(sff8472_data['raw_pages'])
    
    # Vendor specific area
    dump_vendor(sff8472_data['raw_pages'])

def get_byte(page_dict, page, offset):
    """Helper function to get a byte from page data."""
    if page in page_dict and len(page_dict[page]) > offset:
        return page_dict[page][offset]
    return None

def get_bytes(page_dict, page, start, end):
    """Helper function to get bytes from page data."""
    if page in page_dict and len(page_dict[page]) >= end:
        return page_dict[page][start:end]
    return None

# Legacy functions for backward compatibility
def read_sff8472_vendor_info(page_dict):
    """Read vendor information from SFF-8472 module."""
    sff8472_data = parse_sff8472_data_centralized(page_dict)
    return sff8472_data['vendor_info']

def read_sff8472_module_info(page_dict):
    """Read module information from SFF-8472 module."""
    sff8472_data = parse_sff8472_data_centralized(page_dict)
    return sff8472_data['module_info']

def read_sff8472_monitoring_data(page_dict):
    """Read monitoring data from SFF-8472 module."""
    sff8472_data = parse_sff8472_data_centralized(page_dict)
    return sff8472_data['monitoring'] 

# SFF-8472 Table 5-3, 4-2, 8-3, 9-11, etc. See SFF-8472_12.4.3.txt for details.

def read_optic_transciever(page_dict):
    # SFF-8472 Table 5-3: Bytes 3-9, 36 (compliance codes)
    # TODO: Implement full mapping per spec
    pass

def read_sfp_lengths(page_dict):
    # SFF-8472 Table 4-2: Bytes 14-19 (fiber/copper lengths)
    pass

def read_sfp_extended_info(page_dict):
    # SFF-8472 Table 8-3: Bytes 64-65 (options)
    pass

def read_sfp_vendor_specific(page_dict):
    # SFF-8472 Table 4-1: Vendor-specific area
    pass

def read_sfp_comprehensive(page_dict):
    # SFF-8472: Calls all above for a full SFP+ parse
    pass 

def read_optic_monitoring_type(page_dict):
    # SFF-8472
    # byte 92 - Diagnostic Monitoring Type Table 8-5

    monitoring_byte = get_byte(page_dict, 0x00, 92)
    if monitoring_byte is not None:
        print("Monitoring Types:")
        if (monitoring_byte & 0x80):
            print("\tReserved for legacy diagnostic implementations")
        if (monitoring_byte & 0x40):
            print("\tDDM Supported")
        if (monitoring_byte & 0x20):
            print("\tInternally calibrated")
        if (monitoring_byte & 0x10):
            print("\tExternally calibrated")
        if (monitoring_byte & 0x08):
            print("\tReceived power measurement type: average") # unset this is OMA
        if (monitoring_byte & 0x04):
            print("\tAddress Change Required")
    else:
        print("Monitoring Types: Not available")

def read_option_values(page_dict):
    # SFF-8472, SFF-8431 and SFF-8690 for some undefined bits
    # bytes 64-65

    byte_64 = get_byte(page_dict, 0x00, 64)
    byte_65 = get_byte(page_dict, 0x00, 65)
    
    if byte_64 is not None and byte_65 is not None:
        print("Option Values")

        if (byte_64 & 0x80):
            print("\tUndefined bit 7 set")
        if (byte_64 & 0x40):
            print("\tUndefined bit 6 set")
        if (byte_64 & 0x20):
            print("\tHigh Power Level Required - Level3")
        if (byte_64 & 0x10):
            print("\tPaging Implemented")
        if (byte_64 & 0x08):
            print("\tInternal Retimer")
        if (byte_64 & 0x04):
            print("\tCooled Transciever")
        if (byte_64 & 0x02):
            print("\tPower Level 2")
        if (byte_64 & 0x01):
            print("\tLinear Receiver Output")

        if (byte_65 & 0x80):
            print("\tReceiver decision threshold supported")
        if (byte_65 & 0x40):
            print("\tTunable Optic")
        if (byte_65 & 0x20):
            print("\tRATE_SELECT supported")
        if (byte_65 & 0x10):
            print("\tTX_DISABLE supported")
        if (byte_65 & 0x08):
            print("\tTX_FAULT implemented")
        if (byte_65 & 0x04):
            print("\tSignal Detect implemented")
        if (byte_65 & 0x02):
            print("\tRx_LOS implemented")
        if (byte_65 & 0x01):
            print("\tUnallocated")
    else:
        print("Option Values: Not available")

def read_enhanced_options(page_dict):
    """Read enhanced options and diagnostic information as defined in SFF-8472"""
    try:
        print("\nEnhanced Options:")

        # Check if enhanced options are supported
        options = get_byte(page_dict, 0x00, 92)
        if not options or not (options & 0x04):  # Check if diagnostic monitoring is implemented
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
        opt_diag = get_byte(page_dict, 0x00, 93)

        if opt_diag and opt_diag & 0x80:
            # Read and display received power measurement type
            rx_pwr_type = "Average" if opt_diag & 0x08 else "OMA"
            print(f"- Received Power Measurement Type: {rx_pwr_type}")

        if opt_diag and opt_diag & 0x40:
            # Read and display address change sequence
            addr_chg = get_byte(page_dict, 0x00, 94)
            if addr_chg is not None:
                print(f"- Address Change Sequence: 0x{addr_chg:02x}")

        if opt_diag and opt_diag & 0x20:
            print("- Supports Power Supply Measurements")

        # Read auxiliary monitoring
        if opt_diag and opt_diag & 0x10:
            print("\nAuxiliary Monitoring:")
            print("- Auxiliary monitoring data not available when reading from file")

    except Exception as e:
        print(f"Error reading enhanced options: {str(e)}")

def read_sff_8472_compliance(page_dict):
    # SFF-8472
    # byte 94 Table 8-8

    compliance_byte = get_byte(page_dict, 0x00, 94)
    if compliance_byte is not None:
        if compliance_byte == 0x00:
            sff_8472_compliance_text = ("Unsupported")
        elif compliance_byte == 0x01:
            sff_8472_compliance_text = ("SFF-8472 9.3")
        elif compliance_byte == 0x02:
            sff_8472_compliance_text = ("SFF-8472 9.5")
        elif compliance_byte == 0x03:
            sff_8472_compliance_text = ("SFF-8472 10.2")
        elif compliance_byte == 0x04:
            sff_8472_compliance_text = ("SFF-8472 10.4")
        elif compliance_byte == 0x05:
            sff_8472_compliance_text = ("SFF-8472 11.0")
        elif compliance_byte == 0x06:
            sff_8472_compliance_text = ("SFF-8472 11.3")
        elif compliance_byte == 0x07:
            sff_8472_compliance_text = ("SFF-8472 11.4")
        elif compliance_byte == 0x08:
            sff_8472_compliance_text = ("SFF-8472 12.3")
        elif compliance_byte == 0x09:
            sff_8472_compliance_text = ("SFF-8472 12.4")
        else:
            sff_8472_compliance_text =("Unallocated")
        print("SFF 8472 Compliance:", sff_8472_compliance_text)
    else:
        print("SFF 8472 Compliance: Not available")

def read_extended_compliance_codes(page_dict):
    # SFF-8472 Table 5-4: Byte 36 (Extended compliance codes)
    pass

def read_rate_identifier(page_dict):
    # SFF-8472 Table 5-1/5-6: Byte 13 (Rate identifier)
    pass

def read_application_select(page_dict):
    # SFF-8472: Application select (vendor-specific)
    pass

def read_fibre_channel_link_length(page_dict):
    # SFF-8472: Fibre Channel link length
    pass

def read_fibre_channel_technology(page_dict):
    # SFF-8472: Fibre Channel technology
    pass

def read_sfp_cable_technology(page_dict):
    # SFF-8472: SFP cable technology
    pass

def read_fibre_channel_transmission_media(page_dict):
    # SFF-8472: Fibre Channel transmission media
    pass

def read_optic_frequency(page_dict):
    # SFF-8472
    # Byte 60-61

    wave_msb = get_byte(page_dict, 0x00, 60)
    wave_lsb = get_byte(page_dict, 0x00, 61)
    wave_dec = get_byte(page_dict, 0x00, 62)

    if wave_msb is not None and wave_lsb is not None:
        wavelength = (wave_msb*256)+wave_lsb
        print("Wavelength: %d.%02dnm" % (wavelength, wave_dec or 0))
    else:
        print("Wavelength: Not available")

def read_optic_temperature(page_dict):
    # SFF-8472
    # bytes 96-97 Table 9-2

    temp_msb = get_byte(page_dict, 0x00, 96)
    temp_lsb = get_byte(page_dict, 0x00, 97)

    if temp_msb is not None and temp_lsb is not None:
        print("Optic Temperature: %4.2fC" % (temp_msb + (temp_lsb/256)))
    else:
        print("Optic Temperature: Not available")

def read_optic_vcc(page_dict):
    # SFF-8472
    # bytes 98-99 Table 9-11

    vcc_msb = get_byte(page_dict, 0x00, 98)
    vcc_lsb = get_byte(page_dict, 0x00, 99)

    if vcc_msb is not None and vcc_lsb is not None:
        vcc = (vcc_msb<<8 | vcc_lsb) *0.0001
        print("Optic VCC: %4.2fV msb = %d, lsb = %d" % (vcc, vcc_msb, vcc_lsb))
    else:
        print("Optic VCC: Not available")

def read_laser_temperature(page_dict):
    # SFF-8472
    # bytes 106-107 Table 9-2

    temp_msb = get_byte(page_dict, 0x00, 106)
    temp_lsb = get_byte(page_dict, 0x00, 107)

    if temp_msb is not None and temp_lsb is not None:
        print("Laser Temperature: msb = %d, lsb = %d" % (temp_msb, temp_lsb))
    else:
        print("Laser Temperature: Not available")

def read_optic_rxpower(page_dict):
    # SFF-8472
    # bytes 104, 105

    rx_pwr_msb = get_byte(page_dict, 0x00, 104)
    rx_pwr_lsb = get_byte(page_dict, 0x00, 105)

    if rx_pwr_msb is not None and rx_pwr_lsb is not None:
        # need to convert this from mW to dBm, eg:
        # 10 * math.log10(rx_power)
        # 0 = -40 dBm
        temp_pwr = (rx_pwr_msb<<8|rx_pwr_lsb) *0.0001
        if (temp_pwr > 0):
            rx_pwr = 10 * math.log10((rx_pwr_msb<<8|rx_pwr_lsb) *0.0001)
        else:
            rx_pwr = 0
        print("Rx Power: (%4.2f) dBm  vs mW %f" % (rx_pwr, ((rx_pwr_msb<<8|rx_pwr_lsb) *0.0001)))
    else:
        print("Rx Power: Not available")

def read_optic_txpower(page_dict):
    # SFF-8472
    # bytes 102, 103

    tx_pwr_msb = get_byte(page_dict, 0x00, 102)
    tx_pwr_lsb = get_byte(page_dict, 0x00, 103)

    if tx_pwr_msb is not None and tx_pwr_lsb is not None:
        # need to convert this from mW to dBm, eg:
        # 10 * math.log10(rx_power)
        # 0 = -40 dBm
        temp_pwr = (tx_pwr_msb<<8|tx_pwr_lsb) *0.0001
        if (temp_pwr > 0):
            tx_pwr = 10 * math.log10((tx_pwr_msb<<8|tx_pwr_lsb) *0.0001)
        else:
            tx_pwr = 0
        print("Tx Power: (%4.2f) mW vs mW = %f" % (tx_pwr, ((tx_pwr_msb<<8|tx_pwr_lsb) *0.0001)))
    else:
        print("Tx Power: Not available")

def read_measured_current(page_dict):
    # SFF-8472
    # bytes 108-109

    current_msb = get_byte(page_dict, 0x00, 108)
    current_lsb = get_byte(page_dict, 0x00, 109)
    
    if current_msb is not None and current_lsb is not None:
        bias = (current_msb<<8 | current_lsb) * 0.002
        print("Current Draw: %4.2fmA msb = %d, lsb = %d mA" % (bias, current_msb, current_lsb))
    else:
        print("Current Draw: Not available")

def read_sfp_status_bits(page_dict):
    # SFF-8472
    # byte 110 Table 9-11

    try:
        status_byte = get_byte(page_dict, 0x00, 110)
        if status_byte is not None:
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
        else:
            print("Status Bits: Not available")
    except IndexError:
        print("got IndexError on optic_sff byte 110")

def dump_vendor(page_dict):
    # SFF-8472 Table 4-1
    # bytes 96-127

    vendor_hex = ""
    vendor_isprint = ""

    for byte in range (96, 128):
        vendor_byte = get_byte(page_dict, 0x00, byte)
        if vendor_byte is not None:
            vendor_hex=vendor_hex +('%-2.2x' % vendor_byte)

            v_char = '%c' % vendor_byte

            if (isprint(v_char)):
                vendor_isprint= vendor_isprint + v_char
            else:
                vendor_isprint= vendor_isprint + ' '
        else:
            vendor_hex = vendor_hex + "00"
            vendor_isprint = vendor_isprint + ' '
    
    print(vendor_hex)
    print(vendor_isprint) 

def read_optic_vendor(page_dict):
    # SFF-8472
    # 16 bytes ASCII at bytes 20-35
    vendor_bytes = get_bytes(page_dict, 0x00, 20, 36)
    if vendor_bytes:
        # Convert list of integers to bytes object for decoding
        vendor_bytes_obj = bytes(vendor_bytes)
        vendor = vendor_bytes_obj.decode('ascii', errors='ignore').strip()
        print("Vendor:", vendor)
    else:
        print("Vendor: Not available") 

def read_optic_vendor_oui(page_dict):
    # SFF-8472 4-1
    # 3 bytes 37-39

    vendor_oui=""
    for byte in range (37, 40):
        vendor_byte = get_byte(page_dict, 0x00, byte)
        if vendor_byte is not None:
            vendor_oui = vendor_oui + ("%2.2x" % vendor_byte)
        else:
            vendor_oui = vendor_oui + "00"
    print("vendor_oui: %s" % vendor_oui) 

def read_sff8472_vendor_partnum(page_dict):
    # SFF-8472
    # 16 bytes ASCII at bytes 40-55
    vendor_partnum_bytes = get_bytes(page_dict, 0x00, 40, 56)
    if vendor_partnum_bytes:
        # Convert list of integers to bytes object for decoding
        vendor_partnum_bytes_obj = bytes(vendor_partnum_bytes)
        vendor_partnum = vendor_partnum_bytes_obj.decode('ascii', errors='ignore').strip()
        print("PN:", vendor_partnum)
    else:
        print("PN: Not available") 

def read_optic_vendor_serialnum(page_dict):
    # SFF-8472
    # 16 bytes ASCII at bytes 68-83
    vendor_serialnum = ""

    for byte in range (68, 84):
        vendor_byte = get_byte(page_dict, 0x00, byte)
        if vendor_byte is None or vendor_byte == 0 or vendor_byte == 0xff:
            break
        vendor_serialnum=vendor_serialnum +('%c' % vendor_byte)
    print("SN:", vendor_serialnum) 

def read_optic_datecode(page_dict):
    # SFF-8472
    # 8 bytes ASCII at bytes 84-91
    vendor_datecode = ""

    for byte in range (84, 92):
        vendor_byte = get_byte(page_dict, 0x00, byte)
        if vendor_byte is None or vendor_byte == 0 or vendor_byte == 0xff:
            break
        vendor_datecode = vendor_datecode + ('%c' % vendor_byte)

    print("Date Code:", vendor_datecode) 

def read_optic_rev(page_dict):
    # SFF-8472
    # 4 bytes ASCII at bytes 56-59
    vendor_hwrev = ""

    for byte in range (56, 60):
        vendor_byte = get_byte(page_dict, 0x00, byte)
        if vendor_byte is not None:
            vendor_hwrev=vendor_hwrev +('%c' % vendor_byte)
        else:
            vendor_hwrev=vendor_hwrev +' '
    print("HW Revision:", vendor_hwrev) 

def read_optic_distances(page_dict):
    # SFF-8472
    # bytes 14, 15, 16, 17, 18, 19
    # 14 = SMF in KM
    # 15 = SMF in 100 meter units
    # 16 = 50um OM2 fiber, 10 meter units
    # 17 = 62.5um OM1, 10 meter units
    # 18 = OM4 or DAC cable, units meter
    # 19 = 50um OM4 , 10 meter units

    try:
        smf_km      = get_byte(page_dict, 0x00, 14)
        smf_100m    = get_byte(page_dict, 0x00, 15)
        mmf_om2_10m = get_byte(page_dict, 0x00, 16)
        mmf_om1_10m = get_byte(page_dict, 0x00, 17)
        mmf_om4_m   = get_byte(page_dict, 0x00, 18)
        mmf_om4_10m = get_byte(page_dict, 0x00, 19)
    except Exception:
        print("Distances: Error reading distance data")
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