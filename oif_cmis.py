#!/usr/bin/env python3
"""
OIF-CMIS (Common Management Interface Specification) parsing functions
Based on OIF-CMIS 5.3 specification

This module provides centralized parsing and unified output for QSFP-DD/CMIS modules.
"""

import struct

def parse_cmis_data_centralized(page_dict):
    """
    Centralized CMIS data parser that reads all relevant pages and returns structured data.
    This eliminates duplication and ensures consistency across all CMIS functions.
    
    Args:
        page_dict: Dictionary containing page data
        
    Returns:
        dict: Structured CMIS data with all parsed fields
    """
    cmis_data = {
        'vendor_info': {},
        'module_info': {},
        'power_info': {},
        'cable_info': {},
        'media_info': {},
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
        
        # Module State (byte 3)
        if len(lower_page) > 3:
            module_state = lower_page[3]
            cmis_data['module_info']['state'] = module_state
            cmis_data['module_info']['state_name'] = {
                0: 'ModuleLowPwr',
                1: 'ModulePwrUp',
                2: 'ModuleReady',
                3: 'ModulePwrDn',
                4: 'ModuleFault',
                5: 'ModuleTxTurnOn',
                6: 'ModuleTxTurnOff',
                7: 'ModuleTxFault'
            }.get(module_state, f'Unknown({module_state})')
        
        # Global Status (byte 2)
        if len(lower_page) > 2:
            global_status = lower_page[2]
            cmis_data['status']['global'] = {
                'data_path_ready': bool(global_status & 0x01),
                'module_ready': bool(global_status & 0x02),
                'module_fault': bool(global_status & 0x04),
                'module_pwr_good': bool(global_status & 0x08),
                'tx_fault': bool(global_status & 0x10),
                'rx_los': bool(global_status & 0x20),
                'tx_cdr_lol': bool(global_status & 0x40),
                'rx_cdr_lol': bool(global_status & 0x80)
            }
        
        # Lane Flags Summary (byte 1)
        if len(lower_page) > 1:
            lane_flags = lower_page[1]
            cmis_data['status']['lane_flags'] = {
                'lane1_tx_fault': bool(lane_flags & 0x01),
                'lane1_rx_los': bool(lane_flags & 0x02),
                'lane2_tx_fault': bool(lane_flags & 0x04),
                'lane2_rx_los': bool(lane_flags & 0x08),
                'lane3_tx_fault': bool(lane_flags & 0x10),
                'lane3_rx_los': bool(lane_flags & 0x20),
                'lane4_tx_fault': bool(lane_flags & 0x40),
                'lane4_rx_los': bool(lane_flags & 0x80)
            }
        
        # Module Flags (byte 0)
        if len(lower_page) > 0:
            module_flags = lower_page[0]
            cmis_data['status']['module_flags'] = {
                'data_path_ready': bool(module_flags & 0x01),
                'module_ready': bool(module_flags & 0x02),
                'module_fault': bool(module_flags & 0x04),
                'module_pwr_good': bool(module_flags & 0x08),
                'tx_fault': bool(module_flags & 0x10),
                'rx_los': bool(module_flags & 0x20),
                'tx_cdr_lol': bool(module_flags & 0x40),
                'rx_cdr_lol': bool(module_flags & 0x80)
            }
    
    # Parse Page 00h (Vendor Information)
    if '00h' in page_dict:
        page_00h = page_dict['00h']
        
        # Vendor Name (bytes 129-144) - Table 8-28
        if len(page_00h) >= 145:
            vendor_name = ''.join([chr(b) for b in page_00h[129:145]]).strip()
            cmis_data['vendor_info']['name'] = vendor_name
        
        # Vendor OUI (bytes 145-147) - Table 8-28
        if len(page_00h) >= 148:
            vendor_oui = page_00h[145:148]
            cmis_data['vendor_info']['oui'] = f"{vendor_oui[0]:02x}:{vendor_oui[1]:02x}:{vendor_oui[2]:02x}"
        
        # Vendor Part Number (bytes 148-163) - Table 8-28
        if len(page_00h) >= 164:
            vendor_pn = ''.join([chr(b) for b in page_00h[148:164]]).strip()
            cmis_data['vendor_info']['part_number'] = vendor_pn
        
        # Vendor Revision (bytes 164-165) - Table 8-28
        if len(page_00h) >= 166:
            vendor_rev = ''.join([chr(b) for b in page_00h[164:166]]).strip()
            cmis_data['vendor_info']['revision'] = vendor_rev
        
        # Vendor Serial Number (bytes 166-181) - Table 8-28
        if len(page_00h) >= 182:
            vendor_sn = ''.join([chr(b) for b in page_00h[166:182]]).strip()
            cmis_data['vendor_info']['serial_number'] = vendor_sn
        
        # Date Code (bytes 182-189) - Table 8-29
        if len(page_00h) >= 190:
            date_code = ''.join([chr(b) for b in page_00h[182:190]]).strip()
            cmis_data['vendor_info']['date_code'] = date_code
        
        # CLEI Code (bytes 190-199) - Table 8-30
        if len(page_00h) >= 200:
            clei_code = ''.join([chr(b) for b in page_00h[190:200]]).strip()
            cmis_data['vendor_info']['clei_code'] = clei_code
        
        # Module Power Class and Max Power (bytes 200-201) - Table 8-31
        if len(page_00h) >= 202:
            power_class = (page_00h[200] >> 5) & 0x07
            max_power = page_00h[201] * 0.25  # Convert to watts
            
            cmis_data['power_info']['power_class'] = power_class
            cmis_data['power_info']['max_power_watts'] = max_power
            cmis_data['power_info']['power_class_name'] = {
                0: 'Power class 1',
                1: 'Power class 2',
                2: 'Power class 3',
                3: 'Power class 4',
                4: 'Power class 5',
                5: 'Power class 6',
                6: 'Power class 7',
                7: 'Power class 8'
            }.get(power_class, f'Unknown({power_class})')
        
        # Cable Assembly Link Length (byte 202) - Table 8-32
        if len(page_00h) >= 203:
            length_byte = page_00h[202]
            length_multiplier = (length_byte >> 6) & 0x03
            base_length = length_byte & 0x3F
            
            multipliers = {0: 0.1, 1: 1, 2: 10, 3: 100}
            actual_length = base_length * multipliers.get(length_multiplier, 0)
            
            cmis_data['cable_info']['link_length_meters'] = actual_length
            cmis_data['cable_info']['length_multiplier'] = length_multiplier
            cmis_data['cable_info']['base_length'] = base_length
        
        # Media Connector Type (byte 203) - Table 8-33
        if len(page_00h) >= 204:
            connector_type = page_00h[203]
            cmis_data['media_info']['connector_type'] = connector_type
        
        # Copper Cable Attenuation (bytes 204-209) - Table 8-34
        if len(page_00h) >= 210:
            cmis_data['cable_info']['attenuation'] = {
                'at_5ghz': page_00h[204],
                'at_7ghz': page_00h[205],
                'at_12p9ghz': page_00h[206],
                'at_25p8ghz': page_00h[207],
                'at_53p1ghz': page_00h[208]
            }
        
        # Media Lane Information (byte 210) - Table 8-35
        if len(page_00h) >= 211:
            media_lane_byte = page_00h[210]
            cmis_data['media_info']['lane_support'] = {
                'lane1_supported': not bool(media_lane_byte & 0x01),
                'lane2_supported': not bool(media_lane_byte & 0x02),
                'lane3_supported': not bool(media_lane_byte & 0x04),
                'lane4_supported': not bool(media_lane_byte & 0x08),
                'lane5_supported': not bool(media_lane_byte & 0x10),
                'lane6_supported': not bool(media_lane_byte & 0x20),
                'lane7_supported': not bool(media_lane_byte & 0x40),
                'lane8_supported': not bool(media_lane_byte & 0x80)
            }
    
    # Parse Page 01h (Module Information)
    if '01h' in page_dict:
        page_01h = page_dict['01h']
        
        # Application Codes (bytes 128-131) - Table 8-23
        if len(page_01h) >= 132:
            app_codes = []
            for i in range(4):
                if len(page_01h) >= 132 + i:
                    app_code = page_01h[128 + i]
                    if app_code != 0:
                        app_codes.append(app_code)
            cmis_data['application_codes'] = app_codes
        
        # Supported Fiber Link Length (bytes 132-133) - Table 8-44
        if len(page_01h) >= 134:
            cmis_data['media_info']['supported_fiber_length'] = {
                'smf_km': page_01h[132],
                'om2_10m': page_01h[133]
            }
        
        # Wavelength Information (bytes 134-135) - Table 8-45
        if len(page_01h) >= 136:
            cmis_data['media_info']['wavelength'] = {
                'min_nm': page_01h[134],
                'max_nm': page_01h[135]
            }
    
    # Parse Page 02h (Thresholds)
    if '02h' in page_dict:
        page_02h = page_dict['02h']
        
        # Module-Level Monitor Thresholds (bytes 128-143) - Table 8-62
        if len(page_02h) >= 144:
            cmis_data['thresholds']['module'] = {
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
        
        # Module-Level Monitor Values (bytes 128-143) - Table 8-10
        if len(page_11h) >= 144:
            cmis_data['monitoring']['module'] = {
                'temperature': page_11h[128],
                'vcc': page_11h[129],
                'tx_power': page_11h[130],
                'rx_power': page_11h[131]
            }
        
        # Lane-Specific Monitors (bytes 144-159 for lane 1) - Table 8-89
        if len(page_11h) >= 160:
            cmis_data['monitoring']['lanes'] = {}
            for lane in range(1, 9):
                base_offset = 144 + (lane - 1) * 16
                if len(page_11h) >= base_offset + 16:
                    cmis_data['monitoring']['lanes'][f'lane_{lane}'] = {
                        'tx_power': page_11h[base_offset],
                        'rx_power': page_11h[base_offset + 1],
                        'tx_bias': page_11h[base_offset + 2],
                        'rx_power_ratio': page_11h[base_offset + 3]
                    }
    
    return cmis_data

def output_cmis_data_unified(cmis_data):
    """
    Unified output function for CMIS data that produces consistent, non-duplicated output.
    
    Args:
        cmis_data: Structured CMIS data from parse_cmis_data_centralized()
    """
    print("\n=== QSFP-DD/CMIS Module Information ===")
    
    # Vendor Information
    if cmis_data['vendor_info']:
        print("\n--- Vendor Information ---")
        vendor = cmis_data['vendor_info']
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
        if vendor.get('clei_code'):
            print(f"CLEI Code: {vendor['clei_code']}")
    
    # Module Information
    if cmis_data['module_info']:
        print("\n--- Module Information ---")
        module = cmis_data['module_info']
        if 'state' in module:
            print(f"Module State: {module['state']} ({module.get('state_name', 'Unknown')})")
    
    # Power Information
    if cmis_data['power_info']:
        print("\n--- Power Information ---")
        power = cmis_data['power_info']
        if 'power_class' in power:
            print(f"Power Class: {power['power_class']} ({power.get('power_class_name', 'Unknown')})")
        if 'max_power_watts' in power:
            print(f"Maximum Power: {power['max_power_watts']:.2f}W")
    
    # Cable Information
    if cmis_data['cable_info']:
        print("\n--- Cable Information ---")
        cable = cmis_data['cable_info']
        if 'link_length_meters' in cable:
            print(f"Link Length: {cable['link_length_meters']:.1f}m")
        if 'attenuation' in cable:
            atten = cable['attenuation']
            print("Cable Attenuation:")
            if atten.get('at_5ghz') is not None:
                print(f"  At 5 GHz: {atten['at_5ghz']} dB")
            if atten.get('at_7ghz') is not None:
                print(f"  At 7 GHz: {atten['at_7ghz']} dB")
            if atten.get('at_12p9ghz') is not None:
                print(f"  At 12.9 GHz: {atten['at_12p9ghz']} dB")
            if atten.get('at_25p8ghz') is not None:
                print(f"  At 25.8 GHz: {atten['at_25p8ghz']} dB")
            if atten.get('at_53p1ghz') is not None:
                print(f"  At 53.125 GHz: {atten['at_53p1ghz']} dB")
    
    # Media Information
    if cmis_data['media_info']:
        print("\n--- Media Information ---")
        media = cmis_data['media_info']
        if 'connector_type' in media:
            print(f"Connector Type: {media['connector_type']}")
        if 'wavelength' in media:
            wave = media['wavelength']
            if wave.get('min_nm') and wave.get('max_nm'):
                print(f"Wavelength Range: {wave['min_nm']}-{wave['max_nm']} nm")
        if 'lane_support' in media:
            lanes = media['lane_support']
            supported_lanes = [f"Lane{i}" for i in range(1, 9) if lanes.get(f'lane{i}_supported', False)]
            if supported_lanes:
                print(f"Supported Lanes: {', '.join(supported_lanes)}")
    
    # Application Codes
    if cmis_data['application_codes']:
        print("\n--- Application Codes ---")
        for i, code in enumerate(cmis_data['application_codes'], 1):
            print(f"Application Code {i}: 0x{code:02x}")
    
    # Status Information
    if cmis_data['status']:
        print("\n--- Status Information ---")
        status = cmis_data['status']
        if 'global' in status:
            global_status = status['global']
            print("Global Status:")
            for key, value in global_status.items():
                print(f"  {key}: {'Yes' if value else 'No'}")
    
    # Monitoring Data
    if cmis_data['monitoring']:
        print("\n--- Monitoring Data ---")
        monitoring = cmis_data['monitoring']
        if 'module' in monitoring:
            module_mon = monitoring['module']
            print("Module Monitoring:")
            if 'temperature' in module_mon:
                print(f"  Temperature: {module_mon['temperature']}°C")
            if 'vcc' in module_mon:
                print(f"  VCC: {module_mon['vcc']}V")
            if 'tx_power' in module_mon:
                print(f"  TX Power: {module_mon['tx_power']} dBm")
            if 'rx_power' in module_mon:
                print(f"  RX Power: {module_mon['rx_power']} dBm")
        
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
    if cmis_data['thresholds']:
        print("\n--- Thresholds ---")
        thresholds = cmis_data['thresholds']
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