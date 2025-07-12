#!/usr/bin/env python3
"""
SFF-8636 (QSFP+) parsing functions
Based on SFF-8636 2.11 specification

This module provides centralized parsing and unified output for QSFP+ modules.
"""

import struct
import math

# Import VERBOSE from read-optic.py if available, otherwise default to False
try:
    from read_optic import VERBOSE
except ImportError:
    VERBOSE = False

def parse_sff8636_data_centralized(page_dict):
    """
    Centralized SFF-8636 data parser that reads all relevant pages and returns structured data.
    Args:
        page_dict: Dictionary containing page data (string-based keys, e.g., '00h', '80h')
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

    # Parse Lower Memory (bytes 0-127) - Page '00h'
    lower_page = page_dict['00h'] if '00h' in page_dict else []
    if lower_page:
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
            
            # Parse Power Class 8 maximum power consumption (byte 107)
            # According to SFF-8636 Table 6-14, Byte 107 indicates max power in 0.1 W increments
            if len(lower_page) > 107:
                max_power_raw = lower_page[107]
                if VERBOSE:
                    print(f"Debug: Byte 107 (Power Class 8 max power) = 0x{max_power_raw:02x} ({max_power_raw})")
                if max_power_raw != 0:  # Only add if not zero
                    max_power_watts = max_power_raw * 0.1  # Convert from 0.1 W increments to W
                    sff8636_data['module_info']['max_power_consumption'] = max_power_watts
                else:
                    # Power Class 8 is implemented but no specific power value provided
                    sff8636_data['module_info']['power_class_8_no_value'] = True
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

    # Parse Upper Page 00h (QSFP Vendor Information) - Page '80h'
    if '80h' in page_dict:
        page_80h = page_dict['80h']
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
            distances = {
                'smf_km': page_80h[14],
                'om3_50um': page_80h[15],
                'om2_50um': page_80h[16],
                'om1_62_5um': page_80h[17],
                'passive_copper_or_om4': page_80h[18]
            }
            sff8636_data['module_info']['distances'] = distances
        # Device Technology (byte 147) - SFF-8636 Table 6-15, Byte 147
        if len(page_80h) > 19:
            device_tech = page_80h[19]
            sff8636_data['module_info']['device_technology'] = device_tech
        # Vendor Name (bytes 148-163) - SFF-8636 Table 6-15, Bytes 148-163
        if len(page_80h) >= 164:
            vendor_name = ''.join([chr(b) for b in page_80h[148-128:164-128]]).strip()
            if vendor_name and vendor_name != '\x00' * 16:
                sff8636_data['vendor_info']['name'] = vendor_name
        # Vendor OUI (bytes 165-167) - SFF-8636 Table 6-15, Bytes 165-167
        if len(page_80h) >= 168:
            vendor_oui = page_80h[165-128:168-128]
            if vendor_oui != [0, 0, 0]:
                sff8636_data['vendor_info']['oui'] = f"{vendor_oui[0]:02x}:{vendor_oui[1]:02x}:{vendor_oui[2]:02x}"
        # Vendor Part Number (bytes 168-183) - SFF-8636 Table 6-15, Bytes 168-183
        if len(page_80h) >= 184:
            vendor_pn = ''.join([chr(b) for b in page_80h[168-128:184-128]]).strip()
            if vendor_pn and vendor_pn != '\x00' * 16:
                sff8636_data['vendor_info']['part_number'] = vendor_pn
        # Vendor Revision (bytes 184-185) - SFF-8636 Table 6-15, Bytes 184-185
        if len(page_80h) >= 186:
            vendor_rev = ''.join([chr(b) for b in page_80h[184-128:186-128]]).strip()
            if vendor_rev and vendor_rev != '\x00' * 2:
                sff8636_data['vendor_info']['revision'] = vendor_rev
        # Vendor Serial Number (bytes 196-211) - SFF-8636 Table 6-15, Bytes 196-211
        if len(page_80h) >= 212:
            vendor_sn = ''.join([chr(b) for b in page_80h[196-128:212-128]]).strip()
            if vendor_sn and vendor_sn != '\x00' * 16:
                sff8636_data['vendor_info']['serial_number'] = vendor_sn
        # Date Code (bytes 212-219) - SFF-8636 Table 6-15, Bytes 212-219
        if len(page_80h) >= 220:
            date_code = ''.join([chr(b) for b in page_80h[212-128:220-128]]).strip()
            if date_code and date_code != '\x00' * 8:
                sff8636_data['vendor_info']['date_code'] = date_code
        
        # Wavelength Information (bytes 186-189) - SFF-8636 Table 6-15, Bytes 186-189
        if len(page_80h) >= 190:
            # Bytes 186-187: Wavelength or Copper Cable Attenuation
            wavelength_raw = struct.unpack_from('>H', bytes(page_80h[186-128:188-128]))[0]
            if wavelength_raw != 0:  # Only parse if not zero
                # For optical modules: wavelength = value/20 in nm
                wavelength_nm = wavelength_raw / 20.0
                sff8636_data['module_info']['wavelength_nm'] = wavelength_nm
            
            # Bytes 188-189: Wavelength Tolerance or Copper Cable Attenuation
            wavelength_tol_raw = struct.unpack_from('>H', bytes(page_80h[188-128:190-128]))[0]
            if wavelength_tol_raw != 0:  # Only parse if not zero
                # For optical modules: wavelength tolerance = value/200 in nm
                wavelength_tolerance_nm = wavelength_tol_raw / 200.0
                sff8636_data['module_info']['wavelength_tolerance_nm'] = wavelength_tolerance_nm
        
        # Channel Implementation (byte 113 bits 3-0) - SFF-8636 Table 6-14, Byte 113 bits 3-0
        if len(lower_page) >= 114:
            channel_impl_byte = lower_page[113]
            # Bits 3-0 indicate which channels are implemented (0=implemented, 1=not implemented)
            active_channels = 0
            for i in range(4):
                if not (channel_impl_byte & (1 << i)):  # Bit is 0 = channel implemented
                    active_channels += 1
            sff8636_data['module_info']['active_channels'] = active_channels
            sff8636_data['module_info']['channel_implementation'] = channel_impl_byte

    # Parse Application Codes (bytes 3-10 in lower page)
    if len(lower_page) >= 11:
        transceiver_codes = lower_page[3:11]
        sff8636_data['module_info']['transceiver_codes'] = transceiver_codes
        
        # Parse application codes from transceiver codes
        application_codes = []
        for i, code in enumerate(transceiver_codes):
            if code != 0:  # Only add non-zero codes
                application_codes.append(code)
        sff8636_data['application_codes'] = application_codes

    # Parse Lane Status from monitoring data according to SFF-8636 Table 6-9
    if 'monitoring' in sff8636_data and 'channel_monitors' in sff8636_data['monitoring']:
        channel_monitors = sff8636_data['monitoring']['channel_monitors']
        lane_status = {}
        
        # According to SFF-8636 Table 6-9, Channel Monitoring Values (Page 00h Bytes 34-81):
        # Bytes 34-35: Rx1 Power MSB/LSB
        # Bytes 36-37: Rx2 Power MSB/LSB  
        # Bytes 38-39: Rx3 Power MSB/LSB
        # Bytes 40-41: Rx4 Power MSB/LSB
        # Bytes 42-43: Tx1 Bias MSB/LSB
        # Bytes 44-45: Tx2 Bias MSB/LSB
        # Bytes 46-47: Tx3 Bias MSB/LSB
        # Bytes 48-49: Tx4 Bias MSB/LSB
        # Bytes 50-51: Tx1 Power MSB/LSB
        # Bytes 52-53: Tx2 Power MSB/LSB
        # Bytes 54-55: Tx3 Power MSB/LSB
        # Bytes 56-57: Tx4 Power MSB/LSB
        
        # Parse lane data - handle partial data gracefully
        available_lanes = min(4, len(channel_monitors) // 12)  # Each lane needs 12 bytes
        if available_lanes == 0 and len(channel_monitors) >= 8:
            # Try to parse at least RX power data (first 8 bytes)
            available_lanes = min(4, len(channel_monitors) // 2)
        
        if available_lanes > 0:
            for i in range(available_lanes):
                lane_data = {}
                
                # RX Power (bytes 34-41, 2 bytes per lane)
                rx_power_offset = i * 2  # 0, 2, 4, 6 for lanes 1-4
                if rx_power_offset + 1 < len(channel_monitors):
                    rx_power_raw = struct.unpack_from('>H', bytes(channel_monitors[rx_power_offset:rx_power_offset+2]))[0]
                    # Convert from raw value to mW, then to dBm
                    rx_power_mw = rx_power_raw * 0.0001  # LSB = 0.1 µW = 0.0001 mW
                    rx_power_dbm = 10 * math.log10(rx_power_mw) if rx_power_mw > 0 else -40
                    lane_data['rx_power'] = rx_power_dbm
                    lane_data['rx_power_raw'] = rx_power_raw
                
                # TX Bias (bytes 42-49, 2 bytes per lane)
                tx_bias_offset = 8 + (i * 2)  # 8, 10, 12, 14 for lanes 1-4
                if tx_bias_offset + 1 < len(channel_monitors):
                    tx_bias_raw = struct.unpack_from('>H', bytes(channel_monitors[tx_bias_offset:tx_bias_offset+2]))[0]
                    tx_bias_ma = tx_bias_raw * 0.002  # LSB = 2 µA = 0.002 mA
                    lane_data['tx_bias'] = tx_bias_ma
                    lane_data['tx_bias_raw'] = tx_bias_raw
                
                # TX Power (bytes 50-57, 2 bytes per lane)
                tx_power_offset = 16 + (i * 2)  # 16, 18, 20, 22 for lanes 1-4
                if tx_power_offset + 1 < len(channel_monitors):
                    tx_power_raw = struct.unpack_from('>H', bytes(channel_monitors[tx_power_offset:tx_power_offset+2]))[0]
                    # Convert from raw value to mW, then to dBm
                    tx_power_mw = tx_power_raw * 0.0001  # LSB = 0.1 µW = 0.0001 mW
                    tx_power_dbm = 10 * math.log10(tx_power_mw) if tx_power_mw > 0 else -40
                    lane_data['tx_power'] = tx_power_dbm
                    lane_data['tx_power_raw'] = tx_power_raw
                
                if lane_data:  # Only add lane if we have some data
                    lane_status[f'lane_{i+1}'] = lane_data
        else:
            # Debug: If we don't have enough data, try to parse what we have
            if VERBOSE:
                print(f"Warning: Channel monitors data length ({len(channel_monitors)}) is insufficient for lane parsing")
        
        sff8636_data['lane_status'] = lane_status

    # Parse Thresholds (if available in upper page)
    if '80h' in page_dict and len(page_dict['80h']) >= 256:
        page_80h = page_dict['80h']
        thresholds = {}
        
        # Temperature thresholds (bytes 128-131)
        if len(page_80h) >= 132:
            temp_high_alarm = struct.unpack_from('>h', bytes(page_80h[128:130]))[0] / 256.0
            temp_low_alarm = struct.unpack_from('>h', bytes(page_80h[130:132]))[0] / 256.0
            thresholds['temperature'] = {
                'high_alarm': temp_high_alarm,
                'low_alarm': temp_low_alarm
            }
        
        # VCC thresholds (bytes 132-135)
        if len(page_80h) >= 136:
            vcc_high_alarm = struct.unpack_from('>H', bytes(page_80h[132:134]))[0] / 10000.0
            vcc_low_alarm = struct.unpack_from('>H', bytes(page_80h[134:136]))[0] / 10000.0
            thresholds['vcc'] = {
                'high_alarm': vcc_high_alarm,
                'low_alarm': vcc_low_alarm
            }
        
        # TX Power thresholds (bytes 136-139)
        if len(page_80h) >= 140:
            tx_power_high_alarm = struct.unpack_from('>H', bytes(page_80h[136:138]))[0] / 10000.0
            tx_power_low_alarm = struct.unpack_from('>H', bytes(page_80h[138:140]))[0] / 10000.0
            thresholds['tx_power'] = {
                'high_alarm': tx_power_high_alarm,
                'low_alarm': tx_power_low_alarm
            }
        
        # RX Power thresholds (bytes 140-143)
        if len(page_80h) >= 144:
            rx_power_high_alarm = struct.unpack_from('>H', bytes(page_80h[140:142]))[0] / 10000.0
            rx_power_low_alarm = struct.unpack_from('>H', bytes(page_80h[142:144]))[0] / 10000.0
            thresholds['rx_power'] = {
                'high_alarm': rx_power_high_alarm,
                'low_alarm': rx_power_low_alarm
            }
        
        if thresholds:
            sff8636_data['thresholds'] = thresholds

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
        # print("\n--- Module Information ---")
        module = sff8636_data['module_info']
        if 'identifier' in module:
            print(f"Identifier: 0x{module['identifier']:02x} ({module.get('identifier_name', 'Unknown')})")
        if 'extended_identifier' in module:
            print(f"Extended Identifier: 0x{module['extended_identifier']:02x}")
            decoded_ext_id = decode_extended_identifier(module['extended_identifier'])
            if decoded_ext_id:
                print("  Decoded Extended Identifier:")
                print(f"    Power Class (bits 7-6): {decoded_ext_id['power_class_7_6']}")
                print(f"    Power Class 8 (bit 5): {decoded_ext_id['power_class_8']}")
                print(f"    CLEI Code (bit 4): {decoded_ext_id['clei_code']}")
                print(f"    CDR in Tx (bit 3): {decoded_ext_id['cdr_tx']}")
                print(f"    CDR in Rx (bit 2): {decoded_ext_id['cdr_rx']}")
                print(f"    Power Class (bits 1-0): {decoded_ext_id['power_class_1_0']}")
        if 'connector_type' in module:
            connector_names = {0x03: 'LC', 0x07: 'LC', 0x0C: 'MPO 1x12', 0x23: 'No separable connector', 0x24: 'MXC 2x16', 0x25: 'CS optical connector', 0x26: 'SN optical connector', 0x27: 'MPO 2x12', 0x28: 'MPO 1x16'}
            print(f"Connector Type: 0x{module['connector_type']:02x} ({connector_names.get(module['connector_type'], 'Unknown')})")
        if 'encoding' in module:
            encoding_names = {0x01: '8B/10B', 0x02: '4B/5B', 0x03: 'NRZ', 0x04: 'SONET Scrambled', 0x05: '64B/66B', 0x06: 'Manchester', 0x07: 'SONET Scrambled', 0x08: '256B/257B'}
            print(f"Encoding: 0x{module['encoding']:02x} ({encoding_names.get(module['encoding'], 'Unknown')})")
        if 'signaling_rate' in module:
            # SFF-8636: signaling_rate is in units of 100 Mbps
            per_lane_rate_mbps = module['signaling_rate'] * 100
            per_lane_rate_gbps = per_lane_rate_mbps / 1000.0
            
            # Get actual number of active channels from module data
            num_lanes = module.get('active_channels', 4)  # Default to 4 if not available
            total_rate_mbps = per_lane_rate_mbps * num_lanes
            total_rate_gbps = total_rate_mbps / 1000.0
            
            print(f"Signaling Rate: {module['signaling_rate']} (x100 Mbps)")
            print(f"  Per-lane: {per_lane_rate_mbps} Mbps ({per_lane_rate_gbps:.2f} Gbps)")
            print(f"  Active Channels: {num_lanes}")
            print(f"  Total: {num_lanes} × {per_lane_rate_mbps} Mbps = {total_rate_mbps} Mbps ({total_rate_gbps:.2f} Gbps)")
        if 'rate_identifier' in module:
            print(f"Rate Identifier: 0x{module['rate_identifier']:02x}")
        if 'wavelength_nm' in module:
            print(f"Wavelength: {module['wavelength_nm']} nm")
        if 'wavelength_tolerance_nm' in module:
            print(f"Wavelength Tolerance: ±{module['wavelength_tolerance_nm']} nm")
        if 'enhanced_options' in module:
            print(f"Enhanced Options: 0x{module['enhanced_options']:02x}")
        if 'compliance' in module:
            print(f"Compliance: 0x{module['compliance']:02x}")
        if 'cc_base' in module:
            print(f"CC_BASE: 0x{module['cc_base']:02x}")
        if 'max_power_consumption' in module:
            print(f"Maximum Power Consumption: {module['max_power_consumption']:.1f} W")
        elif 'power_class_8_no_value' in module:
            print("Power Class 8: Implemented (no specific power value provided)")
        # Distance decoding (QSFP: bytes 14-19, same as SFP)
        if 'distances' in module:
            # print("\n--- Distance Information ---")
            distances = module['distances']
            if distances.get('smf_km') and distances['smf_km'] not in (0xFF, 0x00):
                print(f"SMF: {distances['smf_km']} km")
            if distances.get('smf_100m') and distances['smf_100m'] not in (0xFF, 0x00):
                print(f"SMF: {distances['smf_100m']*100} meters")
            if distances.get('om2_10m') and distances['om2_10m'] not in (0xFF, 0x00):
                print(f"OM2: {distances['om2_10m']*10} meters")
            if distances.get('om1_10m') and distances['om1_10m'] not in (0xFF, 0x00):
                print(f"OM1: {distances['om1_10m']*10} meters")
            if distances.get('om4_m') and distances['om4_m'] not in (0xFF, 0x00):
                print(f"OM4/DAC: {distances['om4_m']} meter(s)")
            if distances.get('om4_10m') and distances['om4_10m'] not in (0xFF, 0x00):
                print(f"OM4: {distances['om4_10m']*10} meters")
        if 'device_technology' in module:
            print(f"Device Technology: 0x{module['device_technology']:02x}")
            decoded_tech = decode_device_technology(module['device_technology'])
            for k, v in decoded_tech.items():
                print(f"  {k}: {v}")
    # Vendor Information
    if sff8636_data['vendor_info']:
        # print("\n--- Vendor Information ---")
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
        # print("\n--- Application Codes ---")
        for i, code in enumerate(sff8636_data['application_codes'], 1):
            print(f"Application Code {i}: 0x{code:02x}")
   
    # Status Information
    if sff8636_data['status']:
        print("\n--- Status Information ---")
        status = sff8636_data['status']
        if 'bytes' in status and len(status['bytes']) >= 2:
            decoded_status = decode_status_bytes(status['bytes'])
            for k, v in decoded_status.items():
                print(f"  {k}: {v}")
        if 'interrupt_flags' in status:
            decoded_interrupts = decode_interrupt_flags(status['interrupt_flags'])
            for k, v in decoded_interrupts.items():
                print(f"  {k}: {v}")
        if VERBOSE:
            if 'bytes' in status:
                print(f"  (raw) status bytes: {status['bytes']}")
            if 'interrupt_flags' in status:
                print(f"  (raw) interrupt flags: {status['interrupt_flags']}")
    # Monitoring Data
    if sff8636_data['monitoring']:
        # print("\n--- Monitoring Data ---")
        monitoring = sff8636_data['monitoring']
        if 'temperature' in monitoring:
            print(f"Temperature: {monitoring['temperature']:.2f}°C")
        if 'vcc' in monitoring:
            print(f"VCC: {monitoring['vcc']:.3f}V")
        if 'tx_power' in monitoring:
            print(f"TX Power: {monitoring['tx_power']:.2f} dBm")
        if 'rx_power' in monitoring:
            print(f"RX Power: {monitoring['rx_power']:.2f} dBm")
       
        # Enhanced Lane Monitoring Display
        if 'lane_status' in sff8636_data and sff8636_data['lane_status']:
            print("\n--- Per-Lane Monitoring (SFF-8636 Standard) ---")
            for lane_name, lane_data in sff8636_data['lane_status'].items():
                print(f"  {lane_name.upper()}:")
                if 'tx_power' in lane_data:
                    print(f"    TX Power: {lane_data['tx_power']:.2f} dBm")
                if 'rx_power' in lane_data:
                    print(f"    RX Power: {lane_data['rx_power']:.2f} dBm")
                if 'tx_bias' in lane_data:
                    print(f"    TX Bias: {lane_data['tx_bias']:.2f} mA")
   
    # Thresholds
    if sff8636_data['thresholds']:
        # print("\n--- Thresholds ---")
        thresholds = sff8636_data['thresholds']
        if 'module' in thresholds:
            module_thresh = thresholds['module']
            print("Module Thresholds:")
            for key, value in module_thresh.items():
                print(f"  {key}: {value}")
   
    # Transceiver Codes
    if sff8636_data['module_info'].get('transceiver_codes'):
        codes = sff8636_data['module_info']['transceiver_codes']
        print(f"Transceiver Codes: {codes}")
        
        # Decode transceiver codes according to SFF-8636 Table 6-17
        if len(codes) >= 8:
            decoded_codes = decode_transceiver_codes_sff8636(codes)
            
            # Display raw bytes for reference
            for i, code in enumerate(codes):
                print(f"  Byte {131+i}: 0x{code:02x}")
            
            # Display decoded compliance codes
            print("\n--- Decoded Transceiver Compliance Codes (SFF-8636 Table 6-17) ---")
            
            if decoded_codes.get('ethernet_compliance'):
                print("  10/40G/100G Ethernet Compliance:")
                for compliance in decoded_codes['ethernet_compliance']:
                    print(f"    - {compliance}")
            
            if decoded_codes.get('sonet_compliance'):
                print("  SONET Compliance:")
                for compliance in decoded_codes['sonet_compliance']:
                    print(f"    - {compliance}")
            
            if decoded_codes.get('sas_sata_compliance'):
                print("  SAS/SATA Compliance:")
                for compliance in decoded_codes['sas_sata_compliance']:
                    print(f"    - {compliance}")
            
            if decoded_codes.get('gigabit_ethernet_compliance'):
                print("  Gigabit Ethernet Compliance:")
                for compliance in decoded_codes['gigabit_ethernet_compliance']:
                    print(f"    - {compliance}")
            
            if decoded_codes.get('fibre_channel_link_length'):
                print("  Fibre Channel Link Length:")
                for compliance in decoded_codes['fibre_channel_link_length']:
                    print(f"    - {compliance}")
            
            if decoded_codes.get('fibre_channel_transmitter_technology'):
                print("  Fibre Channel Transmitter Technology:")
                for compliance in decoded_codes['fibre_channel_transmitter_technology']:
                    print(f"    - {compliance}")
            
            if decoded_codes.get('fibre_channel_transmission_media'):
                print("  Fibre Channel Transmission Media:")
                for compliance in decoded_codes['fibre_channel_transmission_media']:
                    print(f"    - {compliance}")
            
            if decoded_codes.get('fibre_channel_speed'):
                print("  Fibre Channel Speed:")
                for compliance in decoded_codes['fibre_channel_speed']:
                    print(f"    - {compliance}")
            
            # Check if no compliance codes were found
            all_empty = all(not codes_list for codes_list in decoded_codes.values())
            if all_empty:
                print("    - No specific compliance codes detected")
   
    # Configuration
    if sff8636_data['config']:
        print("\n--- Configuration ---")
        config = sff8636_data['config']
        # Decode and print control bytes
        if 'control' in config:
            print("  Control:")
            decoded_control = decode_control_bytes(config['control'])
            for k, v in decoded_control.items():
                print(f"    {k}: {v}")
        # Decode and print mask bytes
        if 'masks' in config:
            print("  Masks:")
            decoded_masks = decode_mask_bytes(config['masks'])
            for k, v in decoded_masks.items():
                print(f"    {k}: {v}")
        # Decode and print properties bytes
        if 'properties' in config:
            print("  Properties:")
            decoded_props = decode_properties_bytes(config['properties'])
            for k, v in decoded_props.items():
                print(f"    {k}: {v}")
        # Only show raw values if VERBOSE is set
        if VERBOSE:
            for key, value in config.items():
                print(f"  (raw) {key}: {value}")

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
    identifier = get_byte(page_dict, '00h', 0)  # Table 6-2, Byte 0
    status = get_bytes(page_dict, '00h', 1, 3)  # Table 6-2, Bytes 1-2
    # Upper Page 00h
    vendor_name = get_bytes(page_dict, '80h', 148, 164)  # Table 6-15, Bytes 148-163
    vendor_pn = get_bytes(page_dict, '80h', 168, 184)    # Table 6-15, Bytes 168-183
    vendor_sn = get_bytes(page_dict, '80h', 196, 212)    # Table 6-15, Bytes 196-211
    date_code = get_bytes(page_dict, '00h', 84, 92)    # Table 6-23, Bytes 212-219
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
    power_ctrl = get_byte(page_dict, '00h', 93)
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
    status2 = get_byte(page_dict, '00h', 2)
    # Byte 195, bit 0: Pages 20h-21h implemented
    options = get_byte(page_dict, '00h', 195)
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
    thresholds = get_bytes(page_dict, '03h', 128, 224)
    return {
        'thresholds_raw': thresholds
    }

def read_qsfp_extended_status(page_dict):
    """
    Read QSFP+ extended status as defined in SFF-8636 Table 6-16 (Extended Identifier), Table 6-17 (Specification Compliance), and Table 6-19 (Device Technology).
    Returns a dictionary with extended status fields.
    """
    ext_id = get_byte(page_dict, '00h', 129)
    connector = get_byte(page_dict, '00h', 130)
    spec_compliance = get_bytes(page_dict, '00h', 131, 138)
    device_tech = get_byte(page_dict, '00h', 147)
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
    lpmode = get_byte(page_dict, '00h', 93)
    cdr_control = get_byte(page_dict, '00h', 98)
    rate_select = get_bytes(page_dict, '00h', 87, 89)
    status = get_byte(page_dict, '00h', 85)
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
        app_code = get_bytes(page_dict, '00h', 139 + i, 143 + i)
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
        rx_power_raw = get_byte(page_dict, '00h', rx_power_addr)
        rx_power.append(rx_power_raw)
        tx_bias_addr = 42 + lane
        tx_bias_raw = get_byte(page_dict, '00h', tx_bias_addr)
        tx_bias.append(tx_bias_raw)
        tx_power_addr = 50 + lane
        tx_power_raw = get_byte(page_dict, '00h', tx_power_addr)
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
    thresholds = get_bytes(page_dict, '03h', 128, 224)
    return {
        'thresholds_raw': thresholds
    }

def read_qsfp_advanced_controls(page_dict):
    """
    Read advanced control functions for QSFP+ modules (SFF-8636 Table 6-10, Control Function Bytes).
    Returns a dictionary with CDR, rate select, power class, and software reset fields.
    """
    cdr_control = get_byte(page_dict, '00h', 98)
    rate_select_1 = get_byte(page_dict, '00h', 87)
    rate_select_2 = get_byte(page_dict, '00h', 88)
    power_class = get_byte(page_dict, '00h', 93)
    sw_reset = get_byte(page_dict, '00h', 94)
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
    status = get_byte(page_dict, '00h', 6)
    ext_id = get_byte(page_dict, '00h', 129)
    device_tech = get_byte(page_dict, '00h', 147)
    return {
        'status': status,
        'extended_identifier': ext_id,
        'device_technology': device_tech
    }

def decode_status_bytes(status_bytes):
    """
    Decode SFF-8636 Status Bytes (bytes 1-2).
    Returns a dict of status indicators and their values.
    """
    # Table 6-3: Status Indicators
    decoded = {}
    if len(status_bytes) >= 2:
        # Byte 1: Status Indicators
        decoded['Data Ready'] = bool(status_bytes[0] & 0x80)
        decoded['Tx Fault'] = bool(status_bytes[0] & 0x40)
        decoded['Rx LOS'] = bool(status_bytes[0] & 0x20)
        decoded['Signal Detect'] = bool(status_bytes[0] & 0x10)
        decoded['Tx Disable'] = bool(status_bytes[0] & 0x08)
        decoded['Rate Select'] = bool(status_bytes[0] & 0x04)
        decoded['Tx Fault Invert'] = bool(status_bytes[0] & 0x02)
        decoded['Soft Tx Disable'] = bool(status_bytes[0] & 0x01)
        # Byte 2: Status Indicators (continued)
        decoded['Rx4 LOS'] = bool(status_bytes[1] & 0x80)
        decoded['Rx3 LOS'] = bool(status_bytes[1] & 0x40)
        decoded['Rx2 LOS'] = bool(status_bytes[1] & 0x20)
        decoded['Rx1 LOS'] = bool(status_bytes[1] & 0x10)
        decoded['Tx4 Fault'] = bool(status_bytes[1] & 0x08)
        decoded['Tx3 Fault'] = bool(status_bytes[1] & 0x04)
        decoded['Tx2 Fault'] = bool(status_bytes[1] & 0x02)
        decoded['Tx1 Fault'] = bool(status_bytes[1] & 0x01)
    return decoded

def decode_interrupt_flags(interrupt_bytes):
    """
    Decode SFF-8636 Interrupt Flags (bytes 3-21).
    Returns a dict of interrupt flags and their values.
    """
    # Table 6-4: Interrupt Flags
    decoded = {}
    if len(interrupt_bytes) >= 19:
        # Bytes 3-10: Interrupt Flags for various conditions
        # Byte 3: Temperature, Vcc, Tx Power, Rx Power
        decoded['Temp High Alarm'] = bool(interrupt_bytes[0] & 0x80)
        decoded['Temp Low Alarm'] = bool(interrupt_bytes[0] & 0x40)
        decoded['Temp High Warning'] = bool(interrupt_bytes[0] & 0x20)
        decoded['Temp Low Warning'] = bool(interrupt_bytes[0] & 0x10)
        decoded['Vcc High Alarm'] = bool(interrupt_bytes[0] & 0x08)
        decoded['Vcc Low Alarm'] = bool(interrupt_bytes[0] & 0x04)
        decoded['Vcc High Warning'] = bool(interrupt_bytes[0] & 0x02)
        decoded['Vcc Low Warning'] = bool(interrupt_bytes[0] & 0x01)
        # Byte 4: Tx Power, Rx Power
        decoded['Tx4 Power High Alarm'] = bool(interrupt_bytes[1] & 0x80)
        decoded['Tx3 Power High Alarm'] = bool(interrupt_bytes[1] & 0x40)
        decoded['Tx2 Power High Alarm'] = bool(interrupt_bytes[1] & 0x20)
        decoded['Tx1 Power High Alarm'] = bool(interrupt_bytes[1] & 0x10)
        decoded['Tx4 Power Low Alarm'] = bool(interrupt_bytes[1] & 0x08)
        decoded['Tx3 Power Low Alarm'] = bool(interrupt_bytes[1] & 0x04)
        decoded['Tx2 Power Low Alarm'] = bool(interrupt_bytes[1] & 0x02)
        decoded['Tx1 Power Low Alarm'] = bool(interrupt_bytes[1] & 0x01)
        # Byte 5: Rx Power
        decoded['Rx4 Power High Alarm'] = bool(interrupt_bytes[2] & 0x80)
        decoded['Rx3 Power High Alarm'] = bool(interrupt_bytes[2] & 0x40)
        decoded['Rx2 Power High Alarm'] = bool(interrupt_bytes[2] & 0x20)
        decoded['Rx1 Power High Alarm'] = bool(interrupt_bytes[2] & 0x10)
        decoded['Rx4 Power Low Alarm'] = bool(interrupt_bytes[2] & 0x08)
        decoded['Rx3 Power Low Alarm'] = bool(interrupt_bytes[2] & 0x04)
        decoded['Rx2 Power Low Alarm'] = bool(interrupt_bytes[2] & 0x02)
        decoded['Rx1 Power Low Alarm'] = bool(interrupt_bytes[2] & 0x01)
        # Continue with other interrupt bytes as needed...
    return decoded

def decode_extended_identifier(ext_id):
    """
    Decode extended identifier according to SFF-8636 Table 6-16.
    
    Args:
        ext_id: Extended identifier byte value
        
    Returns:
        Dictionary with decoded bit fields
    """
    if ext_id is None:
        return None
    
    # Power Class (bits 7-6)
    power_class_bits = (ext_id >> 6) & 0x03
    power_classes = {
        0: "Power Class 1 (1.5 W max.)",
        1: "Power Class 2 (2.0 W max.)", 
        2: "Power Class 3 (2.5 W max.)",
        3: "Power Class 4 (3.5 W max.) and Power Classes 5, 6 or 7"
    }
    power_class = power_classes.get(power_class_bits, f"Unknown Power Class ({power_class_bits})")
    
    # Power Class 8 (bit 5)
    power_class_8 = bool(ext_id & 0x20)
    power_class_8_text = "Power Class 8 implemented (Max power declared in byte 107)" if power_class_8 else "Power Class 8 not implemented"
    
    # CLEI Code (bit 4)
    clei_code = bool(ext_id & 0x10)
    clei_code_text = "CLEI code present in Page 02h" if clei_code else "No CLEI code present in Page 02h"
    
    # CDR in Tx (bit 3)
    cdr_tx = bool(ext_id & 0x08)
    cdr_tx_text = "CDR present in Tx" if cdr_tx else "No CDR in Tx"
    
    # CDR in Rx (bit 2)
    cdr_rx = bool(ext_id & 0x04)
    cdr_rx_text = "CDR present in Rx" if cdr_rx else "No CDR in Rx"
    
    # Power Classes 5-7 (bits 1-0)
    power_class_5_7_bits = ext_id & 0x03
    power_class_5_7 = {
        0: "Power Classes 1 to 4",
        1: "Power Class 5 (4.0 W max.) See Byte 93 bit 2 to enable.",
        2: "Power Class 6 (4.5 W max.) See Byte 93 bit 2 to enable.",
        3: "Power Class 7 (5.0 W max.) See Byte 93 bit 2 to enable."
    }
    power_class_5_7_text = power_class_5_7.get(power_class_5_7_bits, f"Unknown Power Class 5-7 ({power_class_5_7_bits})")
    
    return {
        'raw_value': ext_id,
        'power_class_7_6': power_class,
        'power_class_8': power_class_8_text,
        'clei_code': clei_code_text,
        'cdr_tx': cdr_tx_text,
        'cdr_rx': cdr_rx_text,
        'power_class_1_0': power_class_5_7_text
    }

def decode_transceiver_codes_sff8636(transceiver_codes):
    """
    Decode transceiver codes according to SFF-8636 Table 6-17 Specification Compliance Codes.
    
    Args:
        transceiver_codes: List of 8 bytes (bytes 131-138 from SFF-8636)
    
    Returns:
        dict: Decoded transceiver codes with human-readable descriptions
    """
    if len(transceiver_codes) < 8:
        return {"error": "Insufficient transceiver codes data"}
    
    decoded = {
        "ethernet_compliance": [],
        "sonet_compliance": [],
        "sas_sata_compliance": [],
        "gigabit_ethernet_compliance": [],
        "fibre_channel_link_length": [],
        "fibre_channel_transmitter_technology": [],
        "fibre_channel_transmission_media": [],
        "fibre_channel_speed": []
    }
    
    # Byte 131: 10/40G/100G Ethernet Compliance Codes
    byte_131 = transceiver_codes[0]
    if byte_131 & 0x80:
        decoded["ethernet_compliance"].append("Extended: See SFF-8024 Transceiver Management")
    if byte_131 & 0x40:
        decoded["ethernet_compliance"].append("10GBASE-LRM")
    if byte_131 & 0x20:
        decoded["ethernet_compliance"].append("10GBASE-LR")
    if byte_131 & 0x10:
        decoded["ethernet_compliance"].append("10GBASE-SR")
    if byte_131 & 0x08:
        decoded["ethernet_compliance"].append("40GBASE-CR4")
    if byte_131 & 0x04:
        decoded["ethernet_compliance"].append("40GBASE-SR4")
    if byte_131 & 0x02:
        decoded["ethernet_compliance"].append("40GBASE-LR4")
    if byte_131 & 0x01:
        decoded["ethernet_compliance"].append("40G Active Cable (XLPPI)")
    
    # Byte 132: SONET Compliance Codes
    byte_132 = transceiver_codes[1]
    if byte_132 & 0x04:
        decoded["sonet_compliance"].append("OC 48, long reach")
    if byte_132 & 0x02:
        decoded["sonet_compliance"].append("OC 48, intermediate reach")
    if byte_132 & 0x01:
        decoded["sonet_compliance"].append("OC 48 short reach")
    
    # Byte 133: SAS/SATA Compliance Codes
    byte_133 = transceiver_codes[2]
    if byte_133 & 0x80:
        decoded["sas_sata_compliance"].append("SAS 24.0 Gbps")
    if byte_133 & 0x40:
        decoded["sas_sata_compliance"].append("SAS 12.0 Gbps")
    if byte_133 & 0x20:
        decoded["sas_sata_compliance"].append("SAS 6.0 Gbps")
    if byte_133 & 0x10:
        decoded["sas_sata_compliance"].append("SAS 3.0 Gbps")
    
    # Byte 134: Gigabit Ethernet Compliance Codes
    byte_134 = transceiver_codes[3]
    if byte_134 & 0x08:
        decoded["gigabit_ethernet_compliance"].append("1000BASE-T")
    if byte_134 & 0x04:
        decoded["gigabit_ethernet_compliance"].append("1000BASE-CX")
    if byte_134 & 0x02:
        decoded["gigabit_ethernet_compliance"].append("1000BASE-LX")
    if byte_134 & 0x01:
        decoded["gigabit_ethernet_compliance"].append("1000BASE-SX")
    
    # Byte 135: Fibre Channel Link Length and Transmitter Technology
    byte_135 = transceiver_codes[4]
    # Link Length (bits 7-4)
    if byte_135 & 0x80:
        decoded["fibre_channel_link_length"].append("Very long distance (V)")
    if byte_135 & 0x40:
        decoded["fibre_channel_link_length"].append("Short distance (S)")
    if byte_135 & 0x20:
        decoded["fibre_channel_link_length"].append("Intermediate distance (I)")
    if byte_135 & 0x10:
        decoded["fibre_channel_link_length"].append("Long distance (L)")
    if byte_135 & 0x08:
        decoded["fibre_channel_link_length"].append("Medium (M)")
    
    # Transmitter Technology (bits 1-0)
    if byte_135 & 0x02:
        decoded["fibre_channel_transmitter_technology"].append("Longwave laser (LC)")
    if byte_135 & 0x01:
        decoded["fibre_channel_transmitter_technology"].append("Electrical inter-enclosure (EL)")
    
    # Byte 136: Fibre Channel Transmission Media
    byte_136 = transceiver_codes[5]
    if byte_136 & 0x80:
        decoded["fibre_channel_transmission_media"].append("Electrical intra-enclosure")
    if byte_136 & 0x40:
        decoded["fibre_channel_transmission_media"].append("Shortwave laser w/o OFC (SN)")
    if byte_136 & 0x20:
        decoded["fibre_channel_transmission_media"].append("Shortwave laser w OFC (SL)")
    if byte_136 & 0x10:
        decoded["fibre_channel_transmission_media"].append("Longwave Laser (LL)")
    
    # Byte 137: Fibre Channel Transmission Media (continued)
    byte_137 = transceiver_codes[6]
    if byte_137 & 0x80:
        decoded["fibre_channel_transmission_media"].append("Twin Axial Pair (TW)")
    if byte_137 & 0x40:
        decoded["fibre_channel_transmission_media"].append("Shielded Twisted Pair (TP)")
    if byte_137 & 0x20:
        decoded["fibre_channel_transmission_media"].append("Miniature Coax (MI)")
    if byte_137 & 0x10:
        decoded["fibre_channel_transmission_media"].append("Video Coax (TV)")
    if byte_137 & 0x08:
        decoded["fibre_channel_transmission_media"].append("Multi-mode 62.5 um (M6)")
    if byte_137 & 0x04:
        decoded["fibre_channel_transmission_media"].append("Multi-mode 50 um (M5)")
    if byte_137 & 0x02:
        decoded["fibre_channel_transmission_media"].append("Multi-mode 50 um (OM3)")
    if byte_137 & 0x01:
        decoded["fibre_channel_transmission_media"].append("Single Mode (SM)")
    
    # Byte 138: Fibre Channel Speed
    byte_138 = transceiver_codes[7]
    if byte_138 & 0x80:
        decoded["fibre_channel_speed"].append("1200 MBps (per channel)")
    if byte_138 & 0x40:
        decoded["fibre_channel_speed"].append("800 MBps")
    if byte_138 & 0x20:
        decoded["fibre_channel_speed"].append("1600 MBps (per channel)")
    if byte_138 & 0x10:
        decoded["fibre_channel_speed"].append("400 MBps")
    if byte_138 & 0x08:
        decoded["fibre_channel_speed"].append("3200 MBps (per channel)")
    if byte_138 & 0x04:
        decoded["fibre_channel_speed"].append("200 MBps")
    if byte_138 & 0x02:
        decoded["fibre_channel_speed"].append("Extended: See SFF-8024 Transceiver Management")
    if byte_138 & 0x01:
        decoded["fibre_channel_speed"].append("100 MBps")
    
    return decoded

def decode_control_bytes(control_bytes):
    """
    Decode SFF-8636 Control Function Bytes (bytes 86-99).
    Returns a dict of control functions and their values.
    """
    # Table 6-10: Control Function Bytes
    decoded = {}
    if len(control_bytes) >= 14:
        # Byte 86: Tx Disable (bits 3-0)
        decoded['Tx4 Disable'] = bool(control_bytes[0] & 0x08)
        decoded['Tx3 Disable'] = bool(control_bytes[0] & 0x04)
        decoded['Tx2 Disable'] = bool(control_bytes[0] & 0x02)
        decoded['Tx1 Disable'] = bool(control_bytes[0] & 0x01)
        # Byte 87: Rx Rate Select (bits 7-0)
        decoded['Rx4 Rate Select'] = (control_bytes[1] >> 6) & 0x03
        decoded['Rx3 Rate Select'] = (control_bytes[1] >> 4) & 0x03
        decoded['Rx2 Rate Select'] = (control_bytes[1] >> 2) & 0x03
        decoded['Rx1 Rate Select'] = control_bytes[1] & 0x03
        # Byte 88: Tx Rate Select (bits 7-0)
        decoded['Tx4 Rate Select'] = (control_bytes[2] >> 6) & 0x03
        decoded['Tx3 Rate Select'] = (control_bytes[2] >> 4) & 0x03
        decoded['Tx2 Rate Select'] = (control_bytes[2] >> 2) & 0x03
        decoded['Tx1 Rate Select'] = control_bytes[2] & 0x03
        # Bytes 89-92: Reserved (skip)
        # Byte 93: Power/Reset/Override
        decoded['Software Reset'] = bool(control_bytes[7] & 0x80)
        decoded['High Power Class 8 Enable'] = bool(control_bytes[7] & 0x08)
        decoded['High Power Class 5-7 Enable'] = bool(control_bytes[7] & 0x04)
        decoded['Power Set'] = bool(control_bytes[7] & 0x02)
        decoded['Power Override'] = bool(control_bytes[7] & 0x01)
        # Bytes 94-97: Reserved (skip)
        # Byte 98: CDR Control (bits 7-0)
        decoded['Tx4 CDR Control'] = bool(control_bytes[12] & 0x80)
        decoded['Tx3 CDR Control'] = bool(control_bytes[12] & 0x40)
        decoded['Tx2 CDR Control'] = bool(control_bytes[12] & 0x20)
        decoded['Tx1 CDR Control'] = bool(control_bytes[12] & 0x10)
        decoded['Rx4 CDR Control'] = bool(control_bytes[12] & 0x08)
        decoded['Rx3 CDR Control'] = bool(control_bytes[12] & 0x04)
        decoded['Rx2 CDR Control'] = bool(control_bytes[12] & 0x02)
        decoded['Rx1 CDR Control'] = bool(control_bytes[12] & 0x01)
        # Byte 99: Hardware Signal Configuration Controls
        decoded['LP/TxDis ctrl'] = bool(control_bytes[13] & 0x02)
        decoded['IntL/LOSL ctrl'] = bool(control_bytes[13] & 0x01)
    return decoded

def decode_mask_bytes(mask_bytes):
    """
    Decode SFF-8636 Mask Bytes (bytes 100-106).
    Returns a dict of mask functions and their values.
    """
    # Table 6-13: Hardware Interrupt Pin Masking Bits
    decoded = {}
    if len(mask_bytes) >= 7:
        # Byte 100: LOS Masks
        decoded['M-Tx4 LOS Mask'] = bool(mask_bytes[0] & 0x80)
        decoded['M-Tx3 LOS Mask'] = bool(mask_bytes[0] & 0x40)
        decoded['M-Tx2 LOS Mask'] = bool(mask_bytes[0] & 0x20)
        decoded['M-Tx1 LOS Mask'] = bool(mask_bytes[0] & 0x10)
        decoded['M-Rx4 LOS Mask'] = bool(mask_bytes[0] & 0x08)
        decoded['M-Rx3 LOS Mask'] = bool(mask_bytes[0] & 0x04)
        decoded['M-Rx2 LOS Mask'] = bool(mask_bytes[0] & 0x02)
        decoded['M-Rx1 LOS Mask'] = bool(mask_bytes[0] & 0x01)
        # Byte 101: Tx Fault/Adapt EQ Fault Masks
        decoded['M-Tx4 Adapt EQ Fault Mask'] = bool(mask_bytes[1] & 0x80)
        decoded['M-Tx3 Adapt EQ Fault Mask'] = bool(mask_bytes[1] & 0x40)
        decoded['M-Tx2 Adapt EQ Fault Mask'] = bool(mask_bytes[1] & 0x20)
        decoded['M-Tx1 Adapt EQ Fault Mask'] = bool(mask_bytes[1] & 0x10)
        decoded['M-Tx4 Transmitter Fault Mask'] = bool(mask_bytes[1] & 0x08)
        decoded['M-Tx3 Transmitter Fault Mask'] = bool(mask_bytes[1] & 0x04)
        decoded['M-Tx2 Transmitter Fault Mask'] = bool(mask_bytes[1] & 0x02)
        decoded['M-Tx1 Transmitter Fault Mask'] = bool(mask_bytes[1] & 0x01)
        # Byte 102: CDR LOL Masks
        decoded['M-Tx4 CDR LOL Mask'] = bool(mask_bytes[2] & 0x80)
        decoded['M-Tx3 CDR LOL Mask'] = bool(mask_bytes[2] & 0x40)
        decoded['M-Tx2 CDR LOL Mask'] = bool(mask_bytes[2] & 0x20)
        decoded['M-Tx1 CDR LOL Mask'] = bool(mask_bytes[2] & 0x10)
        decoded['M-Rx4 CDR LOL Mask'] = bool(mask_bytes[2] & 0x08)
        decoded['M-Rx3 CDR LOL Mask'] = bool(mask_bytes[2] & 0x04)
        decoded['M-Rx2 CDR LOL Mask'] = bool(mask_bytes[2] & 0x02)
        decoded['M-Rx1 CDR LOL Mask'] = bool(mask_bytes[2] & 0x01)
        # Byte 103: Temperature Alarm/Warning Masks
        decoded['M-Temp High Alarm'] = bool(mask_bytes[3] & 0x80)
        decoded['M-Temp Low Alarm'] = bool(mask_bytes[3] & 0x40)
        decoded['M-Temp High Warning'] = bool(mask_bytes[3] & 0x20)
        decoded['M-Temp Low Warning'] = bool(mask_bytes[3] & 0x10)
        decoded['M-TC readiness flag'] = bool(mask_bytes[3] & 0x02)
        # Byte 104: Vcc Alarm/Warning Masks
        decoded['M-Vcc High alarm'] = bool(mask_bytes[4] & 0x80)
        decoded['M-Vcc Low alarm'] = bool(mask_bytes[4] & 0x40)
        decoded['M-Vcc High Warning'] = bool(mask_bytes[4] & 0x20)
        decoded['M-Vcc Low Warning'] = bool(mask_bytes[4] & 0x10)
        # Bytes 105-106: Vendor Specific (skip)
    return decoded

def decode_properties_bytes(properties_bytes):
    """
    Decode SFF-8636 Free Side Device Properties (bytes 107-110).
    Returns a dict of property fields and their values.
    """
    # Table 6-14: Free Side Device Properties
    decoded = {}
    if len(properties_bytes) >= 4:
        # Byte 107: Max Power Consumption (0.1W increments)
        decoded['Max Power Consumption (W)'] = properties_bytes[0] * 0.1
        # Bytes 108-109: Propagation Delay (16-bit, 10ns units)
        prop_delay = (properties_bytes[1] << 8) | properties_bytes[2]
        decoded['Propagation Delay (ns)'] = prop_delay * 10
        # Byte 110: Advanced Low Power Mode (bits 7-4), Far Side Managed (bit 3), Min Operating Voltage (bits 2-0)
        adv_low_power_mode = (properties_bytes[3] >> 4) & 0x0F
        far_side_managed = bool(properties_bytes[3] & 0x08)
        min_operating_voltage = properties_bytes[3] & 0x07
        adv_low_power_mode_map = {
            0x0: '1.5W or higher',
            0x1: 'no more than 1W',
            0x2: 'no more than 0.75W',
            0x3: 'no more than 0.5W',
        }
        min_operating_voltage_map = {
            0x0: '3.3V',
            0x1: '2.5V',
            0x2: '1.8V',
        }
        decoded['Advanced Low Power Mode'] = adv_low_power_mode_map.get(adv_low_power_mode, f'Unknown ({adv_low_power_mode})')
        decoded['Far Side Managed'] = far_side_managed
        decoded['Min Operating Voltage'] = min_operating_voltage_map.get(min_operating_voltage, f'Unknown ({min_operating_voltage})')
    return decoded

def decode_device_technology(device_tech_byte):
    """
    Decode SFF-8636 Device Technology (byte 147).
    Returns a dict of device technology fields and their values.
    """
    # Table 6-19: Device Technology
    decoded = {}
    if device_tech_byte is not None:
        # Bits 7-4: Transmitter technology
        tx_tech = (device_tech_byte >> 4) & 0x0F
        tx_tech_map = {
            0x0: '850 nm VCSEL',
            0x1: '1310 nm VCSEL',
            0x2: '1550 nm VCSEL',
            0x3: '1310 nm FP',
            0x4: '1310 nm DFB',
            0x5: '1550 nm DFB',
            0x6: '1310 nm EML',
            0x7: '1550 nm EML',
            0x8: 'Other / Undefined',
            0x9: '1490 nm DFB',
            0xA: 'Copper cable unequalized',
            0xB: 'Copper cable passive equalized',
            0xC: 'Copper cable, near and far end limiting active equalizers',
            0xD: 'Copper cable, far end limiting active equalizers',
            0xE: 'Copper cable, near end limiting active equalizers',
            0xF: 'Copper cable, linear active equalizers',
        }
        decoded['Transmitter Technology'] = tx_tech_map.get(tx_tech, f'Unknown ({tx_tech})')
        # Bit 3: Wavelength control
        decoded['Wavelength Control'] = bool(device_tech_byte & 0x08)
        # Bit 2: Cooled transmitter
        decoded['Cooled Transmitter'] = bool(device_tech_byte & 0x04)
        # Bit 1: Detector type
        decoded['APD Detector'] = bool(device_tech_byte & 0x02)
        # Bit 0: Tunable transmitter
        decoded['Tunable Transmitter'] = bool(device_tech_byte & 0x01)
    return decoded
