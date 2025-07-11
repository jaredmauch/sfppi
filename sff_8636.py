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
    
    # Parse Lower Memory (bytes 0-127) - Page 0
    if 0 in page_dict:
        lower_page = page_dict[0]
        
        # Identifier (byte 0) - SFF-8636 Table 6-2, Byte 0
        if len(lower_page) > 0:
            identifier = lower_page[0]
            sff8636_data['module_info']['identifier'] = identifier
            sff8636_data['module_info']['identifier_name'] = {
                0x0D: 'QSFP+',
                0x11: 'QSFP28',
                0x18: 'QSFP-DD'
            }.get(identifier, f'Unknown({identifier:02x})')
        
        # Status (bytes 1-2) - SFF-8636 Table 6-2, Bytes 1-2
        if len(lower_page) >= 3:
            status_bytes = lower_page[1:3]
            sff8636_data['status']['bytes'] = status_bytes
        
        # Interrupt Flags (bytes 3-21) - SFF-8636 Table 6-2, Bytes 3-21
        if len(lower_page) >= 22:
            interrupt_flags = lower_page[3:22]
            sff8636_data['status']['interrupt_flags'] = interrupt_flags
        
        # Free Side Device Monitors (bytes 22-33) - SFF-8636 Table 6-2, Bytes 22-33
        if len(lower_page) >= 34:
            # Temperature (bytes 22-23)
            if len(lower_page) >= 24:
                temp_raw = struct.unpack_from('>h', bytes(lower_page[22:24]))[0]
                temperature = temp_raw / 256.0
                sff8636_data['monitoring']['temperature'] = temperature
            
            # VCC (bytes 26-27)
            if len(lower_page) >= 28:
                vcc_raw = struct.unpack_from('>H', bytes(lower_page[26:28]))[0]
                vcc_scaled = vcc_raw / 10000.0
                sff8636_data['monitoring']['vcc'] = vcc_scaled
            
            # TX Power (bytes 34-35)
            if len(lower_page) >= 36:
                tx_power_raw = struct.unpack_from('>H', bytes(lower_page[34:36]))[0]
                tx_power = tx_power_raw / 10000.0
                sff8636_data['monitoring']['tx_power'] = tx_power
            
            # RX Power (bytes 36-37)
            if len(lower_page) >= 38:
                rx_power_raw = struct.unpack_from('>H', bytes(lower_page[36:38]))[0]
                rx_power = rx_power_raw / 10000.0
                sff8636_data['monitoring']['rx_power'] = rx_power
        
        # Channel Monitors (bytes 34-81) - SFF-8636 Table 6-2, Bytes 34-81
        if len(lower_page) >= 82:
            channel_monitors = lower_page[34:82]
            sff8636_data['monitoring']['channel_monitors'] = channel_monitors
        
        # Control (bytes 86-99) - SFF-8636 Table 6-2, Bytes 86-99
        if len(lower_page) >= 100:
            control_bytes = lower_page[86:100]
            sff8636_data['config']['control'] = control_bytes
        
        # Free Side Device and Channel Masks (bytes 100-106) - SFF-8636 Table 6-2, Bytes 100-106
        if len(lower_page) >= 107:
            mask_bytes = lower_page[100:107]
            sff8636_data['config']['masks'] = mask_bytes
        
        # Free Side Device Properties (bytes 107-110) - SFF-8636 Table 6-2, Bytes 107-110
        if len(lower_page) >= 111:
            properties_bytes = lower_page[107:111]
            sff8636_data['config']['properties'] = properties_bytes
        
        # Check for vendor information in Lower Page (some modules store it here)
        # Vendor Name (bytes 20-35) - Alternative location in Lower Page
        if len(lower_page) >= 36 and 'name' not in sff8636_data['vendor_info']:
            vendor_name = ''.join([chr(b) for b in lower_page[20:36]]).strip()
            if vendor_name and vendor_name != '\x00' * 16:
                sff8636_data['vendor_info']['name'] = vendor_name
        
        # Vendor OUI (bytes 37-39) - Alternative location in Lower Page
        if len(lower_page) >= 40 and 'oui' not in sff8636_data['vendor_info']:
            vendor_oui = lower_page[37:40]
            if vendor_oui != [0, 0, 0]:
                sff8636_data['vendor_info']['oui'] = f"{vendor_oui[0]:02x}:{vendor_oui[1]:02x}:{vendor_oui[2]:02x}"
        
        # Vendor Part Number (bytes 40-55) - Alternative location in Lower Page
        if len(lower_page) >= 56 and 'part_number' not in sff8636_data['vendor_info']:
            vendor_pn = ''.join([chr(b) for b in lower_page[40:56]]).strip()
            if vendor_pn and vendor_pn != '\x00' * 16:
                sff8636_data['vendor_info']['part_number'] = vendor_pn
        
        # Vendor Revision (bytes 56-59) - Alternative location in Lower Page
        if len(lower_page) >= 60 and 'revision' not in sff8636_data['vendor_info']:
            vendor_rev = ''.join([chr(b) for b in lower_page[56:60]]).strip()
            if vendor_rev and vendor_rev != '\x00' * 4:
                sff8636_data['vendor_info']['revision'] = vendor_rev
        
        # Vendor Serial Number (bytes 68-83) - Alternative location in Lower Page
        if len(lower_page) >= 84 and 'serial_number' not in sff8636_data['vendor_info']:
            vendor_sn = ''.join([chr(b) for b in lower_page[68:84]]).strip()
            if vendor_sn and vendor_sn != '\x00' * 16:
                sff8636_data['vendor_info']['serial_number'] = vendor_sn
        
        # Date Code (bytes 84-91) - Alternative location in Lower Page
        if len(lower_page) >= 92 and 'date_code' not in sff8636_data['vendor_info']:
            date_code = ''.join([chr(b) for b in lower_page[84:92]]).strip()
            if date_code and date_code != '\x00' * 8:
                sff8636_data['vendor_info']['date_code'] = date_code
    
    # Parse Upper Page 00h (QSFP Vendor Information) - Page 128
    if 128 in page_dict:
        page_80h = page_dict[128]
        
        # Identifier (byte 128) - SFF-8636 Table 6-15, Byte 128
        if len(page_80h) > 0:
            identifier = page_80h[0]
            sff8636_data['module_info']['identifier'] = identifier
            sff8636_data['module_info']['identifier_name'] = {
                0x0D: 'QSFP+',
                0x11: 'QSFP28',
                0x18: 'QSFP-DD'
            }.get(identifier, f'Unknown({identifier:02x})')
        
        # Extended Identifier (byte 129) - SFF-8636 Table 6-15, Byte 129
        if len(page_80h) > 1:
            ext_identifier = page_80h[1]
            sff8636_data['module_info']['extended_identifier'] = ext_identifier
        
        # Connector Type (byte 130) - SFF-8636 Table 6-15, Byte 130
        if len(page_80h) > 2:
            connector_type = page_80h[2]
            sff8636_data['module_info']['connector_type'] = connector_type
        
        # Specification Compliance (bytes 131-138) - SFF-8636 Table 6-15, Bytes 131-138
        if len(page_80h) >= 9:
            spec_compliance = page_80h[3:11]
            sff8636_data['module_info']['specification_compliance'] = spec_compliance
        
        # Encoding (byte 139) - SFF-8636 Table 6-15, Byte 139
        if len(page_80h) > 11:
            encoding = page_80h[11]
            sff8636_data['module_info']['encoding'] = encoding
        
        # Signaling Rate (byte 140) - SFF-8636 Table 6-15, Byte 140
        if len(page_80h) > 12:
            signaling_rate = page_80h[12]
            sff8636_data['module_info']['signaling_rate'] = signaling_rate
        
        # Extended Rate Select Compliance (byte 141) - SFF-8636 Table 6-15, Byte 141
        if len(page_80h) > 13:
            rate_select = page_80h[13]
            sff8636_data['module_info']['rate_select'] = rate_select
        
        # Length fields (bytes 142-146) - SFF-8636 Table 6-15, Bytes 142-146
        if len(page_80h) >= 15:
            lengths = {
                'smf_km': page_80h[14],
                'om3_50um': page_80h[15],
                'om2_50um': page_80h[16],
                'om1_62_5um': page_80h[17],
                'passive_copper_or_om4': page_80h[18]
            }
            sff8636_data['module_info']['lengths'] = lengths
        
        # Device Technology (byte 147) - SFF-8636 Table 6-15, Byte 147
        if len(page_80h) > 19:
            device_tech = page_80h[19]
            sff8636_data['module_info']['device_technology'] = device_tech
        
        # Vendor Name (bytes 148-163) - SFF-8636 Table 6-15, Bytes 148-163
        if len(page_80h) >= 36:
            vendor_name = ''.join([chr(b) for b in page_80h[20:36]]).strip()
            sff8636_data['vendor_info']['name'] = vendor_name
        
        # Extended Module Codes (byte 164) - SFF-8636 Table 6-15, Byte 164
        if len(page_80h) > 36:
            ext_module_codes = page_80h[36]
            sff8636_data['module_info']['extended_module_codes'] = ext_module_codes
        
        # Vendor OUI (bytes 165-167) - SFF-8636 Table 6-15, Bytes 165-167
        if len(page_80h) >= 40:
            vendor_oui = page_80h[37:40]
            sff8636_data['vendor_info']['oui'] = f"{vendor_oui[0]:02x}:{vendor_oui[1]:02x}:{vendor_oui[2]:02x}"
        
        # Vendor Part Number (bytes 168-183) - SFF-8636 Table 6-15, Bytes 168-183
        if len(page_80h) >= 56:
            vendor_pn = ''.join([chr(b) for b in page_80h[40:56]]).strip()
            sff8636_data['vendor_info']['part_number'] = vendor_pn
        
        # Vendor Revision (bytes 184-185) - SFF-8636 Table 6-15, Bytes 184-185
        if len(page_80h) >= 58:
            vendor_rev = ''.join([chr(b) for b in page_80h[56:58]]).strip()
            sff8636_data['vendor_info']['revision'] = vendor_rev
        
        # Wavelength (bytes 186-187) - SFF-8636 Table 6-15, Bytes 186-187
        if len(page_80h) >= 60:
            wavelength_raw = struct.unpack_from('>H', bytes(page_80h[58:60]))[0]
            # According to spec: wavelength=value/20 in nm
            wavelength_nm = wavelength_raw / 20.0
            if 800 <= wavelength_nm <= 1700:  # Reasonable wavelength range
                sff8636_data['module_info']['wavelength_nm'] = wavelength_nm
                print(f"[DEBUG] Found wavelength at bytes 186-187: {wavelength_nm} nm (raw: {wavelength_raw})")
        
        # Wavelength Tolerance (bytes 188-189) - SFF-8636 Table 6-15, Bytes 188-189
        if len(page_80h) >= 62:
            wavelength_tol_raw = struct.unpack_from('>H', bytes(page_80h[60:62]))[0]
            # According to spec: wavelength Tol. =value/200 in nm
            wavelength_tolerance = wavelength_tol_raw / 200.0
            sff8636_data['module_info']['wavelength_tolerance_nm'] = wavelength_tolerance
        
        # Max Case Temperature (byte 190) - SFF-8636 Table 6-15, Byte 190
        if len(page_80h) > 62:
            max_case_temp = page_80h[62]
            sff8636_data['module_info']['max_case_temp'] = max_case_temp
        
        # CC_BASE (byte 191) - SFF-8636 Table 6-15, Byte 191
        if len(page_80h) > 63:
            cc_base = page_80h[63]
            sff8636_data['module_info']['cc_base'] = cc_base
        
        # Link Codes (byte 192) - SFF-8636 Table 6-15, Byte 192
        if len(page_80h) > 64:
            link_codes = page_80h[64]
            sff8636_data['module_info']['link_codes'] = link_codes
        
        # Options (bytes 193-195) - SFF-8636 Table 6-15, Bytes 193-195
        if len(page_80h) >= 68:
            options = page_80h[65:68]
            sff8636_data['module_info']['options'] = options
        
        # Vendor Serial Number (bytes 196-211) - SFF-8636 Table 6-15, Bytes 196-211
        if len(page_80h) >= 84:
            vendor_sn = ''.join([chr(b) for b in page_80h[68:84]]).strip()
            sff8636_data['vendor_info']['serial_number'] = vendor_sn
        
        # Date Code (bytes 212-219) - SFF-8636 Table 6-15, Bytes 212-219
        if len(page_80h) >= 92:
            date_code = ''.join([chr(b) for b in page_80h[84:92]]).strip()
            sff8636_data['vendor_info']['date_code'] = date_code
        
        # Diagnostic Monitoring Type (byte 220) - SFF-8636 Table 6-15, Byte 220
        if len(page_80h) > 92:
            monitoring_type = page_80h[92]
            sff8636_data['monitoring']['type'] = monitoring_type
        
        # Enhanced Options (byte 221) - SFF-8636 Table 6-15, Byte 221
        if len(page_80h) > 93:
            enhanced_options = page_80h[93]
            sff8636_data['module_info']['enhanced_options'] = enhanced_options
        
        # Baud Rate (byte 222) - SFF-8636 Table 6-15, Byte 222
        if len(page_80h) > 94:
            baud_rate = page_80h[94]
            sff8636_data['module_info']['baud_rate'] = baud_rate
        
        # CC_EXT (byte 223) - SFF-8636 Table 6-15, Byte 223
        if len(page_80h) > 95:
            cc_ext = page_80h[95]
            sff8636_data['module_info']['cc_ext'] = cc_ext
    
    # Parse Page 00h (Application Codes) - Use correct page mapping
    if 0x00 in page_dict:
        page_00h = page_dict[0x00]
        
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
    if 0x02 in page_dict:
        page_02h = page_dict[0x02]
        
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
    
    # Module Information
    if sff8636_data['module_info']:
        print("\n--- Module Information ---")
        module = sff8636_data['module_info']
        if 'identifier' in module:
            print(f"Identifier: 0x{module['identifier']:02x} ({module.get('identifier_name', 'Unknown')})")
        if 'extended_identifier' in module:
            print(f"Extended Identifier: 0x{module['extended_identifier']:02x}")
        if 'connector_type' in module:
            connector_names = {0x03: 'LC', 0x07: 'LC', 0x0C: 'MPO 1x12', 0x23: 'No separable connector', 0x24: 'MXC 2x16', 0x25: 'CS optical connector', 0x26: 'SN optical connector', 0x27: 'MPO 2x12', 0x28: 'MPO 1x16'}
            print(f"Connector Type: 0x{module['connector_type']:02x} ({connector_names.get(module['connector_type'], 'Unknown')})")
        if 'encoding' in module:
            encoding_names = {0x01: '8B/10B', 0x02: '4B/5B', 0x03: 'NRZ', 0x04: 'SONET Scrambled', 0x05: '64B/66B', 0x06: 'Manchester', 0x07: 'SONET Scrambled', 0x08: '256B/257B'}
            print(f"Encoding: 0x{module['encoding']:02x} ({encoding_names.get(module['encoding'], 'Unknown')})")
        if 'signaling_rate' in module:
            print(f"Signaling Rate: {module['signaling_rate']} (x100 Mbps)")
        if 'rate_identifier' in module:
            print(f"Rate Identifier: 0x{module['rate_identifier']:02x}")
        if 'wavelength_nm' in module:
            print(f"Wavelength: {module['wavelength_nm']} nm")
        if 'enhanced_options' in module:
            print(f"Enhanced Options: 0x{module['enhanced_options']:02x}")
        if 'compliance' in module:
            print(f"Compliance: 0x{module['compliance']:02x}")
        if 'cc_base' in module:
            print(f"CC_BASE: 0x{module['cc_base']:02x}")
        # Distance decoding (QSFP: bytes 14-19, same as SFP)
        if 'distances' in module:
            print("\n--- Distance Information ---")
            distances = module['distances']
            if distances.get('smf_km') and distances['smf_km'] != 0xFF:
                print(f"SMF: {distances['smf_km']} km")
            if distances.get('smf_100m') and distances['smf_100m'] != 0xFF:
                print(f"SMF: {distances['smf_100m']*100} meters")
            if distances.get('om2_10m') and distances['om2_10m'] != 0xFF:
                print(f"OM2: {distances['om2_10m']*10} meters")
            if distances.get('om1_10m') and distances['om1_10m'] != 0xFF:
                print(f"OM1: {distances['om1_10m']*10} meters")
            if distances.get('om4_m') and distances['om4_m'] != 0xFF:
                print(f"OM4/DAC: {distances['om4_m']} meter(s)")
            if distances.get('om4_10m') and distances['om4_10m'] != 0xFF:
                print(f"OM4: {distances['om4_10m']*10} meters")
    # Vendor Information
    if sff8636_data['vendor_info']:
        print("\n--- Vendor Information ---")
        vendor = sff8636_data['vendor_info']
        if vendor.get('name'):
            print(f"Vendor: {vendor['name']}")
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
            if 'tx_disable' in status:
                print(f"  TX Disable: {'Yes' if status['tx_disable'] else 'No'}")
            if 'rate_select' in status:
                print(f"  Rate Select: {'Yes' if status['rate_select'] else 'No'}")
            if 'tx_fault_invert' in status:
                print(f"  TX Fault Invert: {'Yes' if status['tx_fault_invert'] else 'No'}")
            if 'soft_tx_disable' in status:
                print(f"  Soft TX Disable: {'Yes' if status['soft_tx_disable'] else 'No'}")
    
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
    
    # Transceiver Codes
    if sff8636_data['module_info'].get('transceiver_codes'):
        print("\n--- Transceiver Codes ---")
        codes = sff8636_data['module_info']['transceiver_codes']
        print(f"Transceiver Codes: {codes}")
        # Decode transceiver codes similar to SFP modules
        if len(codes) >= 8:
            print(f"  Byte 3: 0x{codes[0]:02x}")
            print(f"  Byte 4: 0x{codes[1]:02x}")
            print(f"  Byte 5: 0x{codes[2]:02x}")
            print(f"  Byte 6: 0x{codes[3]:02x}")
            print(f"  Byte 7: 0x{codes[4]:02x}")
            print(f"  Byte 8: 0x{codes[5]:02x}")
            print(f"  Byte 9: 0x{codes[6]:02x}")
            print(f"  Byte 10: 0x{codes[7]:02x}")
    
    # Distances
    if sff8636_data['module_info'].get('distances'):
        print("\n--- Distance Information ---")
        distances = sff8636_data['module_info']['distances']
        print(f"SMF (km): {distances.get('smf_km', 0)}")
        print(f"SMF (100m): {distances.get('smf_100m', 0)}")
        print(f"OM2 (10m): {distances.get('om2_10m', 0)}")
        print(f"OM1 (10m): {distances.get('om1_10m', 0)}")
        print(f"OM4 (m): {distances.get('om4_m', 0)}")
        print(f"OM4 (10m): {distances.get('om4_10m', 0)}")
    
    # Configuration
    if sff8636_data['config']:
        print("\n--- Configuration ---")
        config = sff8636_data['config']
        for key, value in config.items():
            print(f"  {key}: {value}")
    
    # Lane Status
    if sff8636_data['lane_status']:
        print("\n--- Lane Status ---")
        for lane_name, lane_data in sff8636_data['lane_status'].items():
            print(f"  {lane_name}: {lane_data}")

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