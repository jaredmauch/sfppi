#!/usr/bin/env python3
"""
SFF-8636 (QSFP+) parsing functions
Based on SFF-8636 2.11 specification

This module provides centralized parsing and unified output for QSFP+ modules.
"""

import struct

def parse_sff8636_data_centralized(page_dict):
    """
    Centralized SFF-8636 data parser that reads all relevant pages and returns structured data.
    
    Args:
        page_dict: Dictionary containing page data
        
    Returns:
        dict: Structured SFF-8636 data with all parsed fields
    """
    sff8636_data = {
        'vendor_info': {},
        'module_info': {},
        'monitoring': {},
        'thresholds': {},
        'status': {},
        'application_codes': [],
        'lane_status': {},
        'config': {}
    }
    
    # Parse Lower Memory (bytes 0-127)
    if 'lower' in page_dict:
        lower_page = page_dict['lower']
        
        # Identifier (byte 0)
        if len(lower_page) > 0:
            identifier = lower_page[0]
            sff8636_data['module_info']['identifier'] = identifier
            sff8636_data['module_info']['identifier_name'] = {
                0x0D: 'QSFP+',
                0x11: 'QSFP28',
                0x18: 'QSFP-DD'
            }.get(identifier, f'Unknown({identifier:02x})')
        
        # Extended Identifier (byte 1)
        if len(lower_page) > 1:
            ext_identifier = lower_page[1]
            sff8636_data['module_info']['extended_identifier'] = ext_identifier
        
        # Connector Type (byte 2)
        if len(lower_page) > 2:
            connector_type = lower_page[2]
            sff8636_data['module_info']['connector_type'] = connector_type
        
        # Transceiver Codes (bytes 3-10)
        if len(lower_page) >= 11:
            transceiver_codes = lower_page[3:11]
            sff8636_data['module_info']['transceiver_codes'] = transceiver_codes
        
        # Encoding (byte 11)
        if len(lower_page) > 11:
            encoding = lower_page[11]
            sff8636_data['module_info']['encoding'] = encoding
        
        # Signaling Rate (byte 12)
        if len(lower_page) > 12:
            signaling_rate = lower_page[12]
            sff8636_data['module_info']['signaling_rate'] = signaling_rate
        
        # Rate Identifier (byte 13)
        if len(lower_page) > 13:
            rate_id = lower_page[13]
            sff8636_data['module_info']['rate_identifier'] = rate_id
        
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
            sff8636_data['module_info']['distances'] = distances
        
        # Vendor Name (bytes 20-35)
        if len(lower_page) >= 36:
            vendor_name = ''.join([chr(b) for b in lower_page[20:36]]).strip()
            sff8636_data['vendor_info']['name'] = vendor_name
        
        # Vendor OUI (bytes 37-39)
        if len(lower_page) >= 40:
            vendor_oui = lower_page[37:40]
            sff8636_data['vendor_info']['oui'] = f"{vendor_oui[0]:02x}:{vendor_oui[1]:02x}:{vendor_oui[2]:02x}"
        
        # Vendor Part Number (bytes 40-55)
        if len(lower_page) >= 56:
            vendor_pn = ''.join([chr(b) for b in lower_page[40:56]]).strip()
            sff8636_data['vendor_info']['part_number'] = vendor_pn
        
        # Vendor Revision (bytes 56-59)
        if len(lower_page) >= 60:
            vendor_rev = ''.join([chr(b) for b in lower_page[56:60]]).strip()
            sff8636_data['vendor_info']['revision'] = vendor_rev
        
        # Wavelength (bytes 60-61)
        if len(lower_page) >= 62:
            wavelength = struct.unpack_from('>H', bytes(lower_page[60:62]))[0]
            sff8636_data['module_info']['wavelength_nm'] = wavelength
        
        # Vendor Serial Number (bytes 68-83)
        if len(lower_page) >= 84:
            vendor_sn = ''.join([chr(b) for b in lower_page[68:84]]).strip()
            sff8636_data['vendor_info']['serial_number'] = vendor_sn
        
        # Date Code (bytes 84-91)
        if len(lower_page) >= 92:
            date_code = ''.join([chr(b) for b in lower_page[84:92]]).strip()
            sff8636_data['vendor_info']['date_code'] = date_code
        
        # Diagnostic Monitoring Type (byte 92)
        if len(lower_page) > 92:
            monitoring_type = lower_page[92]
            sff8636_data['monitoring']['type'] = monitoring_type
        
        # Enhanced Options (byte 93)
        if len(lower_page) > 93:
            enhanced_options = lower_page[93]
            sff8636_data['module_info']['enhanced_options'] = enhanced_options
        
        # SFF-8636 Compliance (byte 94)
        if len(lower_page) > 94:
            compliance = lower_page[94]
            sff8636_data['module_info']['compliance'] = compliance
        
        # CC_BASE (byte 95)
        if len(lower_page) > 95:
            cc_base = lower_page[95]
            sff8636_data['module_info']['cc_base'] = cc_base
        
        # Temperature (bytes 96-97)
        if len(lower_page) >= 98:
            temp_raw = struct.unpack_from('>h', bytes(lower_page[96:98]))[0]
            temperature = temp_raw / 256.0
            sff8636_data['monitoring']['temperature'] = temperature
        
        # VCC (bytes 98-99)
        if len(lower_page) >= 100:
            vcc_raw = struct.unpack_from('>H', bytes(lower_page[98:100]))[0]
            vcc = vcc_raw / 10000.0
            sff8636_data['monitoring']['vcc'] = vcc
        
        # TX Power (bytes 102-103)
        if len(lower_page) >= 104:
            tx_power_raw = struct.unpack_from('>H', bytes(lower_page[102:104]))[0]
            tx_power = tx_power_raw / 10000.0
            sff8636_data['monitoring']['tx_power'] = tx_power
        
        # RX Power (bytes 104-105)
        if len(lower_page) >= 106:
            rx_power_raw = struct.unpack_from('>H', bytes(lower_page[104:106]))[0]
            rx_power = rx_power_raw / 10000.0
            sff8636_data['monitoring']['rx_power'] = rx_power
        
        # Status Bits (byte 110)
        if len(lower_page) > 110:
            status_bits = lower_page[110]
            sff8636_data['status']['bits'] = status_bits
            sff8636_data['status']['data_ready'] = bool(status_bits & 0x01)
            sff8636_data['status']['tx_fault'] = bool(status_bits & 0x02)
            sff8636_data['status']['rx_los'] = bool(status_bits & 0x04)
            sff8636_data['status']['signal_detect'] = bool(status_bits & 0x08)
            sff8636_data['status']['tx_disable'] = bool(status_bits & 0x10)
            sff8636_data['status']['rate_select'] = bool(status_bits & 0x20)
            sff8636_data['status']['tx_fault_invert'] = bool(status_bits & 0x40)
            sff8636_data['status']['soft_tx_disable'] = bool(status_bits & 0x80)
    
    # Parse Page 00h (Application Codes)
    if '00h' in page_dict:
        page_00h = page_dict['00h']
        
        # Application Codes (bytes 128-131)
        if len(page_00h) >= 132:
            app_codes = []
            for i in range(4):
                if len(page_00h) >= 132 + i:
                    app_code = page_00h[128 + i]
                    if app_code != 0:
                        app_codes.append(app_code)
            sff8636_data['application_codes'] = app_codes
    
    # Parse Page 02h (Thresholds)
    if '02h' in page_dict:
        page_02h = page_dict['02h']
        
        # Module-Level Monitor Thresholds (bytes 128-143)
        if len(page_02h) >= 144:
            sff8636_data['thresholds']['module'] = {
                'temp_high_alarm': page_02h[128],
                'temp_low_alarm': page_02h[129],
                'temp_high_warning': page_02h[130],
                'temp_low_warning': page_02h[131],
                'vcc_high_alarm': page_02h[132],
                'vcc_low_alarm': page_02h[133],
                'vcc_high_warning': page_02h[134],
                'vcc_low_warning': page_02h[135],
                'tx_power_high_alarm': page_02h[136],
                'tx_power_low_alarm': page_02h[137],
                'tx_power_high_warning': page_02h[138],
                'tx_power_low_warning': page_02h[139],
                'rx_power_high_alarm': page_02h[140],
                'rx_power_low_alarm': page_02h[141],
                'rx_power_high_warning': page_02h[142],
                'rx_power_low_warning': page_02h[143]
            }
    
    # Parse Page 11h (Monitoring Data)
    if '11h' in page_dict:
        page_11h = page_dict['11h']
        
        # Module-Level Monitor Values (bytes 128-143)
        if len(page_11h) >= 144:
            sff8636_data['monitoring']['module'] = {
                'temperature': page_11h[128],
                'vcc': page_11h[129],
                'tx_power': page_11h[130],
                'rx_power': page_11h[131]
            }
        
        # Lane-Specific Monitors (bytes 144-159 for lane 1)
        if len(page_11h) >= 160:
            sff8636_data['monitoring']['lanes'] = {}
            for lane in range(1, 5):  # QSFP+ has 4 lanes
                base_offset = 144 + (lane - 1) * 16
                if len(page_11h) >= base_offset + 16:
                    sff8636_data['monitoring']['lanes'][f'lane_{lane}'] = {
                        'tx_power': page_11h[base_offset],
                        'rx_power': page_11h[base_offset + 1],
                        'tx_bias': page_11h[base_offset + 2],
                        'rx_power_ratio': page_11h[base_offset + 3]
                    }
    
    return sff8636_data

def output_sff8636_data_unified(sff8636_data):
    """
    Unified output function for SFF-8636 data that produces consistent, non-duplicated output.
    
    Args:
        sff8636_data: Structured SFF-8636 data from parse_sff8636_data_centralized()
    """
    print("\n=== QSFP+ Module Information (SFF-8636) ===")
    
    # Vendor Information
    if sff8636_data['vendor_info']:
        print("\n--- Vendor Information ---")
        vendor = sff8636_data['vendor_info']
        if vendor.get('name'):
            print(f"Vendor Name: {vendor['name']}")
        if vendor.get('oui'):
            print(f"Vendor OUI: {vendor['oui']}")
        if vendor.get('part_number'):
            print(f"Part Number: {vendor['part_number']}")
        if vendor.get('revision'):
            print(f"Revision: {vendor['revision']}")
        if vendor.get('serial_number'):
            print(f"Serial Number: {vendor['serial_number']}")
        if vendor.get('date_code'):
            print(f"Date Code: {vendor['date_code']}")
    
    # Module Information
    if sff8636_data['module_info']:
        print("\n--- Module Information ---")
        module = sff8636_data['module_info']
        if 'identifier' in module:
            print(f"Identifier: 0x{module['identifier']:02x} ({module.get('identifier_name', 'Unknown')})")
        if 'wavelength_nm' in module:
            print(f"Wavelength: {module['wavelength_nm']} nm")
        if 'signaling_rate' in module:
            print(f"Signaling Rate: {module['signaling_rate']}")
        if 'connector_type' in module:
            print(f"Connector Type: 0x{module['connector_type']:02x}")
    
    # Application Codes
    if sff8636_data['application_codes']:
        print("\n--- Application Codes ---")
        for i, code in enumerate(sff8636_data['application_codes'], 1):
            print(f"Application Code {i}: 0x{code:02x}")
    
    # Status Information
    if sff8636_data['status']:
        print("\n--- Status Information ---")
        status = sff8636_data['status']
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
    
    # Monitoring Data
    if sff8636_data['monitoring']:
        print("\n--- Monitoring Data ---")
        monitoring = sff8636_data['monitoring']
        if 'temperature' in monitoring:
            print(f"Temperature: {monitoring['temperature']:.2f}°C")
        if 'vcc' in monitoring:
            print(f"VCC: {monitoring['vcc']:.3f}V")
        if 'tx_power' in monitoring:
            print(f"TX Power: {monitoring['tx_power']:.2f} dBm")
        if 'rx_power' in monitoring:
            print(f"RX Power: {monitoring['rx_power']:.2f} dBm")
        
        if 'lanes' in monitoring:
            print("Lane Monitoring:")
            for lane_name, lane_data in monitoring['lanes'].items():
                print(f"  {lane_name}:")
                if 'tx_power' in lane_data:
                    print(f"    TX Power: {lane_data['tx_power']} dBm")
                if 'rx_power' in lane_data:
                    print(f"    RX Power: {lane_data['rx_power']} dBm")
                if 'tx_bias' in lane_data:
                    print(f"    TX Bias: {lane_data['tx_bias']} mA")
    
    # Thresholds
    if sff8636_data['thresholds']:
        print("\n--- Thresholds ---")
        thresholds = sff8636_data['thresholds']
        if 'module' in thresholds:
            module_thresh = thresholds['module']
            print("Module Thresholds:")
            for key, value in module_thresh.items():
                print(f"  {key}: {value}")

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
def read_sff8636_vendor_info(page_dict):
    """Read vendor information from SFF-8636 module."""
    sff8636_data = parse_sff8636_data_centralized(page_dict)
    return sff8636_data['vendor_info']

def read_sff8636_module_info(page_dict):
    """Read module information from SFF-8636 module."""
    sff8636_data = parse_sff8636_data_centralized(page_dict)
    return sff8636_data['module_info']

def read_sff8636_monitoring_data(page_dict):
    """Read monitoring data from SFF-8636 module."""
    sff8636_data = parse_sff8636_data_centralized(page_dict)
    return sff8636_data['monitoring'] 

# SFF-8636 QSFP+ Functions - Referencing SFF-8636_2.11.txt tables

def read_qsfp_data(page_dict):
    """
    Read QSFP+ specific data according to SFF-8636 Table 6-1 (Common Memory Map), Table 6-2 (Lower Page 00h Memory Map), and Table 6-15 (Upper Page 00h Memory Map).
    Returns a dictionary with key module fields.
    """
    # Lower Page 00h
    identifier = get_byte(page_dict, 0x00, 0)  # Table 6-2, Byte 0
    status = get_bytes(page_dict, 0x00, 1, 3)  # Table 6-2, Bytes 1-2
    # Upper Page 00h
    vendor_name = get_bytes(page_dict, 0x00, 148, 164)  # Table 6-15, Bytes 148-163
    vendor_pn = get_bytes(page_dict, 0x00, 168, 184)    # Table 6-15, Bytes 168-183
    vendor_sn = get_bytes(page_dict, 0x00, 196, 212)    # Table 6-15, Bytes 196-211
    date_code = get_bytes(page_dict, 0x00, 212, 220)    # Table 6-23, Bytes 212-219
    return {
        'identifier': identifier,
        'status': status,
        'vendor_name': vendor_name.decode('ascii', errors='replace').strip() if vendor_name else None,
        'vendor_pn': vendor_pn.decode('ascii', errors='replace').strip() if vendor_pn else None,
        'vendor_sn': vendor_sn.decode('ascii', errors='replace').strip() if vendor_sn else None,
        'date_code': date_code.decode('ascii', errors='replace').strip() if date_code else None,
    }

def read_qsfp_power_control(page_dict):
    """
    Read QSFP+ power control as defined in SFF-8636 Table 6-10 (Control Function Bytes) and Table 6-11 (Truth Table for Enabling Power Classes).
    Returns a dictionary with power control fields.
    """
    # Byte 93: Power control and override
    power_ctrl = get_byte(page_dict, 0x00, 93)
    return {
        'power_override': bool(power_ctrl & 0x04) if power_ctrl is not None else None,  # Table 6-10, bit 2
        'power_set_high': bool(power_ctrl & 0x02) if power_ctrl is not None else None,  # Table 6-10, bit 1
        'low_power_mode': bool(power_ctrl & 0x01) if power_ctrl is not None else None,  # Table 6-10, bit 0
        'raw': power_ctrl
    }

def read_qsfp_page_support(page_dict):
    """
    Read QSFP+ page support as defined in SFF-8636 Table 6-2 (Lower Page 00h Memory Map), Byte 2, and Table 6-15 (Upper Page 00h Memory Map), Byte 195.
    Returns a dictionary indicating which pages are supported.
    """
    # Byte 2, bit 2: Page 03h implemented
    status2 = get_byte(page_dict, 0x00, 2)
    # Byte 195, bit 0: Pages 20h-21h implemented
    options = get_byte(page_dict, 0x00, 195)
    return {
        'page_03h_supported': bool(status2 & 0x04) if status2 is not None else None,
        'pages_20h_21h_supported': bool(options & 0x01) if options is not None else None,
        'raw_status2': status2,
        'raw_options': options
    }

def read_qsfp_thresholds(page_dict):
    """
    Read QSFP+ monitoring thresholds as defined in SFF-8636 Table 6-28 (Page 03h, Bytes 128-223).
    Returns a dictionary with threshold sets (raw bytes).
    """
    # Page 03h, Bytes 128-223: Thresholds
    thresholds = get_bytes(page_dict, 0x03, 128, 224)
    return {
        'thresholds_raw': thresholds
    }

def read_qsfp_extended_status(page_dict):
    """
    Read QSFP+ extended status as defined in SFF-8636 Table 6-16 (Extended Identifier), Table 6-17 (Specification Compliance), and Table 6-19 (Device Technology).
    Returns a dictionary with extended status fields.
    """
    ext_id = get_byte(page_dict, 0x00, 129)
    connector = get_byte(page_dict, 0x00, 130)
    spec_compliance = get_bytes(page_dict, 0x00, 131, 138)
    device_tech = get_byte(page_dict, 0x00, 147)
    return {
        'extended_identifier': ext_id,
        'connector': connector,
        'spec_compliance': spec_compliance,
        'device_technology': device_tech
    }

def read_qsfp_control_status(page_dict):
    """
    Read QSFP+ control and status bytes as defined in SFF-8636 Table 6-10 (Control Function Bytes).
    Returns a dictionary with control/status fields.
    """
    lpmode = get_byte(page_dict, 0x00, 93)
    cdr_control = get_byte(page_dict, 0x00, 98)
    rate_select = get_bytes(page_dict, 0x00, 87, 89)
    status = get_byte(page_dict, 0x00, 85)
    return {
        'low_power_mode': bool(lpmode & 0x01) if lpmode is not None else None,
        'cdr_control': cdr_control,
        'rate_select': rate_select,
        'module_status': status
    }

def read_qsfp_application(page_dict):
    """
    Read QSFP+ application advertisement as defined in SFF-8636 Table 6-9 (Application Codes, bytes 128-131 and following).
    Returns a list of application code dictionaries.
    """
    applications = []
    for i in range(0, 32, 4):  # 8 application entries
        app_code = get_bytes(page_dict, 0x00, 139 + i, 143 + i)
        if not app_code:
            continue
        host_speed, media_type, media_speed, link_length = app_code
        if host_speed == 0 and media_type == 0:
            continue  # Skip empty entries
        applications.append({
            'host_speed': host_speed,
            'media_type': media_type,
            'media_speed': media_speed,
            'link_length': link_length
        })
    return applications

def read_qsfp_per_channel_monitoring(page_dict):
    """
    Read per-channel monitoring data for QSFP+ modules (SFF-8636 Table 6-9, Channel Monitoring Values).
    Returns a dictionary with per-channel RX power, TX bias, and TX power.
    """
    rx_power = []
    tx_bias = []
    tx_power = []
    for lane in range(4):
        rx_power_addr = 34 + lane
        rx_power_raw = get_byte(page_dict, 0x00, rx_power_addr)
        rx_power.append(rx_power_raw)
        tx_bias_addr = 42 + lane
        tx_bias_raw = get_byte(page_dict, 0x00, tx_bias_addr)
        tx_bias.append(tx_bias_raw)
        tx_power_addr = 50 + lane
        tx_power_raw = get_byte(page_dict, 0x00, tx_power_addr)
        tx_power.append(tx_power_raw)
    return {
        'rx_power': rx_power,
        'tx_bias': tx_bias,
        'tx_power': tx_power
    }

def read_qsfp_channel_thresholds(page_dict):
    """
    Read per-channel alarm/warning thresholds for QSFP+ modules (SFF-8636 Table 6-28, Page 03h, Bytes 128-223).
    Returns a dictionary with threshold sets (raw bytes).
    """
    thresholds = get_bytes(page_dict, 0x03, 128, 224)
    return {
        'thresholds_raw': thresholds
    }

def read_qsfp_advanced_controls(page_dict):
    """
    Read advanced control functions for QSFP+ modules (SFF-8636 Table 6-10, Control Function Bytes).
    Returns a dictionary with CDR, rate select, power class, and software reset fields.
    """
    cdr_control = get_byte(page_dict, 0x00, 98)
    rate_select_1 = get_byte(page_dict, 0x00, 87)
    rate_select_2 = get_byte(page_dict, 0x00, 88)
    power_class = get_byte(page_dict, 0x00, 93)
    sw_reset = get_byte(page_dict, 0x00, 94)
    return {
        'cdr_control': cdr_control,
        'rate_select_1': rate_select_1,
        'rate_select_2': rate_select_2,
        'power_class': power_class,
        'software_reset': sw_reset
    }

def read_qsfp_enhanced_status(page_dict):
    """
    Read enhanced status indicators for QSFP+ modules (SFF-8636 Table 6-13, Enhanced Status).
    Returns a dictionary with status indicators, extended identifier, and device technology.
    """
    status = get_byte(page_dict, 0x00, 6)
    ext_id = get_byte(page_dict, 0x00, 129)
    device_tech = get_byte(page_dict, 0x00, 147)
    return {
        'status': status,
        'extended_identifier': ext_id,
        'device_technology': device_tech
    } 