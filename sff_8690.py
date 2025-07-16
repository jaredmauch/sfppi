# SFF-8690 Rev 1.5 field definitions and decoding utilities
# Copyright (c) 2024 SNIA, see SFF-8690 for full legal notice

from typing import Dict, Any
import struct

# --- Byte/offset definitions (A2h, Page 02h) ---
A2H_PAGE_02 = {
    'FEATURES_ADVERTISEMENT': 128,
    'MODULE_CAPABILITIES': 132,  # 132-141
    'CHANNEL_NUMBER_SET': 144,   # 144-145
    'WAVELENGTH_SET': 146,       # 146-147
    'CONTROL': 151,
    'FREQ_ERROR': 152,            # 152-153
    'WAVELENGTH_ERROR': 154,     # 154-155
    'CURRENT_STATUS': 168,
    'LATCHED_STATUS': 172,
}

# --- Bit definitions for key fields ---
FEATURES_ADVERTISEMENT_BITS = {
    0: 'Tunable DWDM (channel number)',
    1: 'Tunable DWDM (50pm steps)',
    2: 'Tx Dither Supported',
    3: 'Self Tuning via Smart Tunable MSA Supported',
    4: 'Vendor defined tunability/self-tunability',
    5: 'Reserved',
    6: 'Reserved',
    7: 'Reserved',
}

CONTROL_BITS = {
    0: 'Tx Dither (1=disable, 0=enable)',
    1: 'Enable Self Tuning',
    2: 'Disable Self Tuning Restart on LOS Timer Timeout',
    3: 'Reserved',
    4: 'Reserved',
    5: 'Reserved',
    6: 'Reserved',
    7: 'Reserved',
}

CURRENT_STATUS_BITS = {
    4: 'TxTune (Tx not ready due to tuning)',
    5: 'Wavelength Unlocked',
    6: 'TC (Temperature Control) Fault',
    7: 'Self Tuning (1=In Progress, 0=Idle/Locked)',
}

LATCHED_STATUS_BITS = {
    2: 'L-Unsupported TX Dither Request',
    3: 'L-New Channel Acquired',
    4: 'L-Bad Channel Requested',
    5: 'L-Wavelength Unlocked',
    6: 'L-TEC Fault',
    7: 'L-Self Tune (1=In Progress, 0=Locked/Manual)',
}

# --- Decoding functions ---
def decode_features_advertisement(byte: int) -> Dict[str, bool]:
    return {desc: bool(byte & (1 << bit)) for bit, desc in FEATURES_ADVERTISEMENT_BITS.items()}

def decode_control(byte: int) -> Dict[str, bool]:
    return {desc: bool(byte & (1 << bit)) for bit, desc in CONTROL_BITS.items()}

def decode_current_status(byte: int) -> Dict[str, bool]:
    return {desc: bool(byte & (1 << bit)) for bit, desc in CURRENT_STATUS_BITS.items()}

def decode_latched_status(byte: int) -> Dict[str, bool]:
    return {desc: bool(byte & (1 << bit)) for bit, desc in LATCHED_STATUS_BITS.items()}

# --- Module Capabilities (all 2-byte fields, MSB first) ---
def parse_module_capabilities(data: bytes) -> Dict[str, Any]:
    # data: 10 bytes (132-141)
    if len(data) != 10:
        raise ValueError('Module Capabilities must be 10 bytes')
    lfl1 = struct.unpack('>H', data[0:2])[0]  # THz
    lfl2 = struct.unpack('>H', data[2:4])[0]  # GHz*10
    lfh1 = struct.unpack('>H', data[4:6])[0]  # THz
    lfh2 = struct.unpack('>H', data[6:8])[0]  # GHz*10
    lgrid = struct.unpack('>h', data[8:10])[0]  # signed, 0.1 GHz
    return {
        'LFL1_THz': lfl1,
        'LFL2_GHz_x10': lfl2,
        'LFH1_THz': lfh1,
        'LFH2_GHz_x10': lfh2,
        'LGrid_0.1GHz': lgrid,
    }

# --- Channel/Wavelength Set (2 bytes, MSB first) ---
def parse_channel_number_set(data: bytes) -> int:
    if len(data) != 2:
        raise ValueError('Channel Number Set must be 2 bytes')
    return struct.unpack('>H', data)[0]

def parse_wavelength_set(data: bytes) -> float:
    if len(data) != 2:
        raise ValueError('Wavelength Set must be 2 bytes')
    # Units: 0.05 nm
    return struct.unpack('>H', data)[0] * 0.05

# --- Frequency/Wavelength Error (2 bytes, signed, MSB first) ---
def parse_frequency_error(data: bytes) -> float:
    if len(data) != 2:
        raise ValueError('Frequency Error must be 2 bytes')
    return struct.unpack('>h', data)[0] * 0.1  # GHz

def parse_wavelength_error(data: bytes) -> float:
    if len(data) != 2:
        raise ValueError('Wavelength Error must be 2 bytes')
    return struct.unpack('>h', data)[0] * 0.005  # nm

# --- Utility: pretty print for status bits ---
def pretty_status(bits: Dict[str, bool]) -> str:
    return ', '.join(f'{k}: {"Yes" if v else "No"}' for k, v in bits.items())

# --- Main decode entry point (for a dict of page 02h bytes) ---
def decode_sff_8690(page02: Dict[int, int]) -> Dict[str, Any]:
    out = {}
    # Features Advertisement
    if 128 in page02:
        out['Features Advertisement'] = decode_features_advertisement(page02[128])
    # Module Capabilities
    if all(x in page02 for x in range(132, 142)):
        cap_bytes = bytes([page02[x] for x in range(132, 142)])
        out['Module Capabilities'] = parse_module_capabilities(cap_bytes)
    # Channel Number Set
    if 144 in page02 and 145 in page02:
        out['Channel Number Set'] = parse_channel_number_set(bytes([page02[144], page02[145]]))
    # Wavelength Set
    if 146 in page02 and 147 in page02:
        out['Wavelength Set (nm)'] = parse_wavelength_set(bytes([page02[146], page02[147]]))
    # Control
    if 151 in page02:
        out['Control'] = decode_control(page02[151])
    # Frequency Error
    if 152 in page02 and 153 in page02:
        out['Frequency Error (GHz)'] = parse_frequency_error(bytes([page02[152], page02[153]]))
    # Wavelength Error
    if 154 in page02 and 155 in page02:
        out['Wavelength Error (nm)'] = parse_wavelength_error(bytes([page02[154], page02[155]]))
    # Current Status
    if 168 in page02:
        out['Current Status'] = decode_current_status(page02[168])
    # Latched Status
    if 172 in page02:
        out['Latched Status'] = decode_latched_status(page02[172])
    return out 