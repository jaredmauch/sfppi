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

# Core CMIS functions moved from read-optic.py
def read_cmis_application_codes(page_dict):
    """Read CMIS Application Codes according to OIF-CMIS 5.3 Table 8-23"""
    try:
        print("CMIS Application Codes:")
        # Application descriptors are in bytes 128-131 for the first 4 descriptors
        # according to Table 8-23 (Application Descriptor Registers)
        for i in range(4):
            app_code = get_bytes(page_dict, 0x00, 128 + i, 131 + i)
            if app_code and any(b != 0 for b in app_code):
                print(f"  Application {i}: {app_code.hex().upper()}")
        return True
    except Exception as e:
        print(f"Error reading CMIS application codes: {e}")
        return False

def read_cmis_lane_status(page_dict):
    """Read CMIS Lane Status according to OIF-CMIS 5.3 Table 8-35"""
    try:
        print("CMIS Lane Status:")
        # Media lane support is in byte 210 according to Table 8-35
        lane_info = get_byte(page_dict, 0x00, 210)
        if lane_info is not None:
            for lane in range(8):
                supported = (lane_info & (1 << lane)) != 0
                status = "Supported" if supported else "Not Supported"
                print(f"  Lane {lane}: {status}")
            return lane_info
        else:
            print("  Lane Status: Not available")
            return None
    except Exception as e:
        print(f"Error reading CMIS lane status: {e}")
        return None

def read_cmis_module_state(page_dict):
    """Read and print CMIS Module State (Table 8-5)"""
    try:
        state = get_byte(page_dict, 0x00, 3) & 0x0F
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
    """Read CMIS module power according to OIF-CMIS 5.3 Table 8-31"""
    try:
        print("\nCMIS Module Power:")
        # Power class is in byte 200 bits 7-5, max power is in byte 201 according to Table 8-31
        power_class_byte = get_byte(page_dict, 0x00, 200)
        max_power_byte = get_byte(page_dict, 0x00, 201)
        
        if power_class_byte is not None:
            power_class = (power_class_byte >> 5) & 0x07
            print(f"Module Power Class: {power_class}")
        else:
            power_class = None
            print("Module Power Class: Not available")
            
        if max_power_byte is not None:
            max_power = max_power_byte * 0.25  # Units of 0.25W
            print(f"Module Max Power: {max_power:.2f}W")
        else:
            max_power = None
            print("Module Max Power: Not available")
            
        # Current power consumption is in bytes 18-19 according to Table 8-10
        if get_byte(page_dict, 0x00, 19) is not None:
            power = (get_byte(page_dict, 0x00, 18) << 8) | get_byte(page_dict, 0x00, 19)
            power = power / 10000.0  # Convert to watts (units of 0.0001W)
            print(f"Current Power Consumption: {power:.3f}W")
            
        return power_class, max_power
    except Exception as e:
        print(f"Error reading CMIS module power: {e}")
        return None, None

def read_cmis_module_config(page_dict):
    """Read CMIS module configuration according to OIF-CMIS 5.3 Table 8-5"""
    try:
        print("\nCMIS Module Configuration:")
        
        # Management characteristics are in bytes 0-2 according to Table 8-5
        sff8024_id = get_byte(page_dict, 0x00, 0)
        cmis_rev = get_byte(page_dict, 0x00, 1)
        mgmt_chars = get_byte(page_dict, 0x00, 2)
        
        if sff8024_id is not None:
            print(f"SFF8024 Identifier: 0x{sff8024_id:02x}")
        
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
        
        return sff8024_id, cmis_rev, mgmt_chars
    except Exception as e:
        print(f"Error reading CMIS module configuration: {e}")
        return None, None, None

def read_cmis_copper_attenuation(page_dict):
    """Read CMIS copper attenuation data (CMIS 5.0)"""
    try:
        print("\nCopper Attenuation:")
        print(f"5GHz: {get_byte(page_dict, 0x00, 204)} dB")
        print(f"7GHz: {get_byte(page_dict, 0x00, 205)} dB")
        print(f"12.9GHz: {get_byte(page_dict, 0x00, 206)} dB")
        print(f"25.8GHz: {get_byte(page_dict, 0x00, 207)} dB")
    except Exception as e:
        print(f"Error reading copper attenuation: {str(e)}")

def read_cmis_media_lane_info(page_dict):
    """Read CMIS media lane information (CMIS 5.0)"""
    try:
        # Use the same fallback logic as other functions
        lane_info_lower = get_byte(page_dict, 0x00, 210) if get_byte(page_dict, 0x00, 210) is not None else 0
        lane_info_upper = get_byte(page_dict, 0x80, 210) if get_byte(page_dict, 0x80, 210) is not None else 0
        
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

def get_cmis_supported_lanes(page_dict):
    """Return a list of supported lane indices (0-based) according to the Media Lane Support bitmap."""
    # Media lane information is in Upper Page 00h (0x80), byte 0x52
    # According to OIF-CMIS 5.3 Table 8-35
    lane_info = get_byte(page_dict, 0x80, 0x52)
    if lane_info is None:
        lane_info = 0
    return [lane for lane in range(8) if lane_info & (1 << lane)]

def read_cmis_monitoring_data(page_dict):
    """Read CMIS monitoring data for QSFP-DD modules"""
    try:
        # Read module temperature (bytes 14-15)
        temp = (get_byte(page_dict, 0x00, 14) << 8) | get_byte(page_dict, 0x00, 15)
        temp = temp / 256.0  # Convert to Celsius
        print(f"Module Temperature: {temp:.1f}°C")

        # Read module voltage (bytes 16-17)
        voltage = (get_byte(page_dict, 0x00, 16) << 8) | get_byte(page_dict, 0x00, 17)
        voltage = voltage / 10000.0  # Convert to V
        print(f"Module Voltage: {voltage:.3f}V")

        # Read module power consumption (bytes 18-19)
        power = (get_byte(page_dict, 0x00, 18) << 8) | get_byte(page_dict, 0x00, 19)
        power = power / 10000.0  # Convert to W
        print(f"Module Power: {power:.3f}W")

        # Only print for supported lanes
        supported_lanes = get_cmis_supported_lanes(page_dict)
        if not supported_lanes:
            print("No supported lanes found for monitoring data.")
            return
        # Read lane-specific data (bytes 20-31)
        for lane in supported_lanes:
            # Read RX power (bytes 20+2*lane, 21+2*lane)
            rx_power = (get_byte(page_dict, 0x00, 20+2*lane) << 8) | get_byte(page_dict, 0x00, 21+2*lane)
            rx_power = rx_power / 10000.0  # Convert to mW
            if rx_power > 0:
                print(f"Lane {lane+1} RX Power: {rx_power:.3f}mW")

            # Read TX power (bytes 36+2*lane, 37+2*lane)
            tx_power = (get_byte(page_dict, 0x00, 36+2*lane) << 8) | get_byte(page_dict, 0x00, 37+2*lane)
            tx_power = tx_power / 10000.0  # Convert to mW
            if tx_power > 0:
                print(f"Lane {lane+1} TX Power: {tx_power:.3f}mW")

            # Read bias current (bytes 52+2*lane, 53+2*lane)
            bias = (get_byte(page_dict, 0x00, 52+2*lane) << 8) | get_byte(page_dict, 0x00, 53+2*lane)
            bias = bias / 500.0  # Convert to mA
            if bias > 0:
                print(f"Lane {lane+1} Bias Current: {bias:.2f}mA")
            
    except Exception as e:
        print(f"Error reading CMIS monitoring data: {e}")

def read_cmis_thresholds(page_dict):
    """Read CMIS threshold values for QSFP-DD modules"""
    try:
        # Read temperature thresholds (bytes 128-131)
        temp_high_alarm = (get_byte(page_dict, 0x00, 128) << 8) | get_byte(page_dict, 0x00, 129)
        temp_high_alarm = temp_high_alarm / 256.0  # Convert to Celsius
        temp_low_alarm = (get_byte(page_dict, 0x00, 130) << 8) | get_byte(page_dict, 0x00, 131)
        temp_low_alarm = temp_low_alarm / 256.0
        print(f"Temperature Thresholds - High Alarm: {temp_high_alarm:.1f}°C, Low Alarm: {temp_low_alarm:.1f}°C")

        # Read voltage thresholds (bytes 132-135)
        voltage_high_alarm = (get_byte(page_dict, 0x00, 132) << 8) | get_byte(page_dict, 0x00, 133)
        voltage_high_alarm = voltage_high_alarm / 10000.0  # Convert to V
        voltage_low_alarm = (get_byte(page_dict, 0x00, 134) << 8) | get_byte(page_dict, 0x00, 135)
        voltage_low_alarm = voltage_low_alarm / 10000.0
        print(f"Voltage Thresholds - High Alarm: {voltage_high_alarm:.3f}V, Low Alarm: {voltage_low_alarm:.3f}V")

        # Read power thresholds (bytes 136-139)
        power_high_alarm = (get_byte(page_dict, 0x00, 136) << 8) | get_byte(page_dict, 0x00, 137)
        power_high_alarm = power_high_alarm / 10000.0  # Convert to W
        power_low_alarm = (get_byte(page_dict, 0x00, 138) << 8) | get_byte(page_dict, 0x00, 139)
        power_low_alarm = power_low_alarm / 10000.0
        print(f"Power Thresholds - High Alarm: {power_high_alarm:.3f}W, Low Alarm: {power_low_alarm:.3f}W")

        # Only print for supported lanes
        supported_lanes = get_cmis_supported_lanes(page_dict)
        if not supported_lanes:
            print("No supported lanes found for threshold data.")
            return
        # Read lane-specific thresholds (bytes 140-191)
        for lane in supported_lanes:
            # RX power thresholds
            rx_power_high_alarm = (get_byte(page_dict, 0x00, 140+6*lane) << 8) | get_byte(page_dict, 0x00, 141+6*lane)
            rx_power_high_alarm = rx_power_high_alarm / 10000.0  # Convert to mW
            rx_power_low_alarm = (get_byte(page_dict, 0x00, 142+6*lane) << 8) | get_byte(page_dict, 0x00, 143+6*lane)
            rx_power_low_alarm = rx_power_low_alarm / 10000.0
            print(f"Lane {lane+1} RX Power Thresholds - High Alarm: {rx_power_high_alarm:.3f}mW, Low Alarm: {rx_power_low_alarm:.3f}mW")

            # TX power thresholds
            tx_power_high_alarm = (get_byte(page_dict, 0x00, 144+6*lane) << 8) | get_byte(page_dict, 0x00, 145+6*lane)
            tx_power_high_alarm = tx_power_high_alarm / 10000.0  # Convert to mW
            tx_power_low_alarm = (get_byte(page_dict, 0x00, 146+6*lane) << 8) | get_byte(page_dict, 0x00, 147+6*lane)
            tx_power_low_alarm = tx_power_low_alarm / 10000.0
            print(f"Lane {lane+1} TX Power Thresholds - High Alarm: {tx_power_high_alarm:.3f}mW, Low Alarm: {tx_power_low_alarm:.3f}mW")

    except Exception as e:
        print(f"Error reading CMIS thresholds: {e}")

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
    """Read advanced CMIS monitoring data including OSNR, CD, BER, etc."""
    try:
        print("\nAdvanced CMIS Monitoring:")
        
        # Get media lane support information
        # Try both Lower Page and Upper Page 00h for lane info
        lane_info_lower = get_byte(page_dict, 0x00, 210) if get_byte(page_dict, 0x00, 210) is not None else 0
        lane_info_upper = get_byte(page_dict, 0x80, 210) if get_byte(page_dict, 0x80, 210) is not None else 0
        
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
        media_tech = get_byte(page_dict, 0x80, 0x87) if get_byte(page_dict, 0x80, 0x87) is not None else 0  # Upper Page 00h byte 135
        coherent_techs = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27]  # Coherent technologies
        
        # --- OSNR ---
        osnr_pages = []
        if media_tech in coherent_techs:
            if get_byte(page_dict, 0x20, 0) is not None:
                osnr_pages.append((0x20, "Upper Page 20h"))
            if get_byte(page_dict, 0x1280, 0) is not None:
                osnr_pages.append((0x1280, "Upper Page 25h"))
        if osnr_pages:
            for page, label in osnr_pages:
                print(f"\nOSNR Data ({label}):")
                for lane in supported_lanes:
                    osnr_offset = lane * 4
                    osnr_raw = (get_byte(page_dict, page, osnr_offset) << 8) | get_byte(page_dict, page, osnr_offset + 1)
                    if osnr_raw > 0:
                        osnr_db = osnr_raw / 100.0  # Convert to dB
                        print(f"Lane {lane+1} OSNR: {osnr_db:.2f} dB")
        else:
            print("\nOSNR Data: Not supported (non-coherent module or no OSNR page present)")

        # --- Chromatic Dispersion ---
        cd_pages = []
        if media_tech in coherent_techs:
            if get_byte(page_dict, 0x20, 0x40) is not None:
                cd_pages.append((0x20, "Upper Page 20h"))
            if get_byte(page_dict, 0x1280, 0x40) is not None:
                cd_pages.append((0x1280, "Upper Page 25h"))
        if cd_pages:
            for page, label in cd_pages:
                print(f"\nChromatic Dispersion Data ({label}):")
                for lane in supported_lanes:
                    cd_offset = 0x40 + lane * 4
                    cd_bytes = get_bytes(page_dict, page, cd_offset, cd_offset + 4)
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
            if get_byte(page_dict, 0x20, 0x80) is not None:
                ber_pages.append((0x20, "Upper Page 20h"))
            if get_byte(page_dict, 0x1280, 0x80) is not None:
                ber_pages.append((0x1280, "Upper Page 25h"))
        if ber_pages:
            for page, label in ber_pages:
                print(f"\nBER Data ({label}):")
                for lane in supported_lanes:
                    ber_offset = 0x80 + lane * 8
                    pre_fec_bytes = get_bytes(page_dict, page, ber_offset, ber_offset + 8)
                    if pre_fec_bytes:
                        pre_fec_ber_raw = struct.unpack_from('>Q', bytes(pre_fec_bytes))[0]
                        if pre_fec_ber_raw > 0:
                            pre_fec_ber = pre_fec_ber_raw / 1e15
                            print(f"Lane {lane+1} Pre-FEC BER: {pre_fec_ber:.2e}")
                    post_fec_offset = ber_offset + 8
                    post_fec_bytes = get_bytes(page_dict, page, post_fec_offset, post_fec_offset + 8)
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
            if get_byte(page_dict, 0x20, 0x100) is not None:
                q_pages.append((0x20, "Upper Page 20h"))
            if get_byte(page_dict, 0x1280, 0x100) is not None:
                q_pages.append((0x1280, "Upper Page 25h"))
        if q_pages:
            for page, label in q_pages:
                print(f"\nQ-Factor Data ({label}):")
                for lane in supported_lanes:
                    q_offset = 0x100 + lane * 2
                    q_raw = (get_byte(page_dict, page, q_offset) << 8) | get_byte(page_dict, page, q_offset + 1)
                    if q_raw > 0:
                        q_factor = q_raw / 100.0  # Convert to dB
                        print(f"Lane {lane+1} Q-Factor: {q_factor:.2f} dB")
        else:
            print("\nQ-Factor Data: Not supported (non-coherent module or no Q-Factor page present)")
        
        # Laser wavelength (for tunable modules)
        # According to CMIS 5.0, wavelength info is in Upper Page 01h at specific offsets
        # For tunable modules, this is typically in the Media Interface Technology section
        if get_byte(page_dict, 0x01, 0) is not None:
            print("\nLaser Wavelength Data (if supported):")
            for lane in supported_lanes:
                # Try different wavelength locations based on CMIS specification
                # Primary wavelength location for tunable modules
                wavelength_offset = 0x88 + lane * 2  # Upper Page 01h, byte 136+ (0x188+)
                wavelength_raw = (get_byte(page_dict, 0x01, wavelength_offset) << 8) | get_byte(page_dict, 0x01, wavelength_offset + 1)
                if wavelength_raw > 0:
                    wavelength_nm = wavelength_raw * 0.05  # Convert to nm (CMIS spec)
                    print(f"Lane {lane+1} Wavelength: {wavelength_nm:.2f} nm")
                
                # Alternative wavelength location for coherent modules
                alt_wavelength_offset = 0x90 + lane * 4  # Upper Page 01h, byte 144+ (0x190+)
                alt_wavelength_bytes = get_bytes(page_dict, 0x01, alt_wavelength_offset, alt_wavelength_offset + 4)
                if alt_wavelength_bytes:
                    alt_wavelength_raw = struct.unpack_from('>I', bytes(alt_wavelength_bytes))[0]
                    if alt_wavelength_raw > 0 and alt_wavelength_raw != wavelength_raw:
                        alt_wavelength_nm = alt_wavelength_raw / 1000.0  # Convert to nm
                        print(f"Lane {lane+1} Alt Wavelength: {alt_wavelength_nm:.3f} nm")
        
        # Laser temperature (for wavelength stability)
        if get_byte(page_dict, 0x01, 0x60) is not None:
            print("\nLaser Temperature Data (if supported):")
            for lane in supported_lanes:
                laser_temp_offset = 0x60 + lane * 2
                laser_temp_bytes = get_bytes(page_dict, 0x01, laser_temp_offset, laser_temp_offset + 2)
                if laser_temp_bytes:
                    laser_temp_raw = struct.unpack_from('>h', bytes(laser_temp_bytes))[0]
                    if laser_temp_raw != 0:
                        laser_temp_c = laser_temp_raw / 256.0  # Convert to Celsius
                        print(f"Lane {lane+1} Laser Temperature: {laser_temp_c:.2f}°C")
        
        # Check for data in higher pages (10h, 11h, 12h, 13h, 25h)
        # These pages contain advanced monitoring data for coherent modules
        if get_byte(page_dict, 0x10, 0) is not None:
            print("\nAdvanced Monitoring Data from Higher Pages:")
            # Check for data in Upper Page 10h (0x400-0x4FF)
            for lane in supported_lanes:
                # Look for coherent monitoring data
                coherent_offset = lane * 16
                coherent_bytes = get_bytes(page_dict, 0x10, coherent_offset, coherent_offset + 16)
                if coherent_bytes:
                    # Check for non-zero data
                    data_sum = sum(coherent_bytes)
                    if data_sum > 0:
                        print(f"Lane {lane+1} has coherent monitoring data at offset 0x{coherent_offset:04x}")
            
            # Check for data in Upper Page 11h (0x480-0x4FF)
            for lane in supported_lanes:
                coherent_offset = lane * 16
                coherent_bytes = get_bytes(page_dict, 0x11, coherent_offset, coherent_offset + 16)
                if coherent_bytes:
                    # Check for non-zero data
                    data_sum = sum(coherent_bytes)
                    if data_sum > 0:
                        print(f"Lane {lane+1} has coherent monitoring data at offset 0x{coherent_offset:04x}")
        
    except Exception as e:
        print(f"Error reading advanced CMIS monitoring: {e}")

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
            print(f"SFF8024 Identifier: 0x{sff8024_id:02x}")
        
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
            print(f"Connector Type: 0x{connector_type:02x}")
        
        # Table 8-34: Copper Cable Attenuation (only for copper modules)
        # Check media interface technology to determine if it's copper
        tech = get_byte(page_dict, 0x100, 0x87) if 0x100 in page_dict else 0  # Media Interface Technology
        copper_techs = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x30, 0x31, 0x32, 0x33, 0x34]  # Copper technologies
        if tech in copper_techs:
            print("\n--- Copper Cable Attenuation ---")
            attenuation = get_bytes(page_dict, 0x80, 0x4C, 0x52)
            if attenuation:
                print(f"Copper Cable Attenuation: {attenuation}")
                # Parse attenuation values for different frequencies
                if len(attenuation) >= 6:
                    att_5ghz = attenuation[0]
                    att_7ghz = attenuation[1]
                    att_12_9ghz = attenuation[2]
                    att_25_8ghz = attenuation[3]
                    print(f"  Attenuation at 5GHz: {att_5ghz} dB")
                    print(f"  Attenuation at 7GHz: {att_7ghz} dB")
                    print(f"  Attenuation at 12.9GHz: {att_12_9ghz} dB")
                    print(f"  Attenuation at 25.8GHz: {att_25_8ghz} dB")
        
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