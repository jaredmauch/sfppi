# sff_8024.py
"""
SFF-8024: Centralized definitions for Identifiers and Connector Types
Based on SFF-8024 Rev 4.12 (2023-10-31)
"""

# Table 3-1: Identifier Values
IDENTIFIERS = {
    0x00: "Unknown or unspecified",
    0x01: "GBIC",
    0x02: "Module/connector soldered to motherboard",
    0x03: "SFP/SFP+/SFP28/SFP56/SFP-DD/SFP112/SFP-DD112",
    0x04: "300 pin XBI",
    0x05: "XENPAK",
    0x06: "XFP",
    0x07: "XFF",
    0x08: "XFP-E",
    0x09: "XPAK",
    0x0A: "X2",
    0x0B: "DWDM-SFP/SFP+ (not using SFF-8472)",
    0x0C: "QSFP (INF-8438)",
    0x0D: "QSFP+ or later with SFF-8636 or SFF-8436 management interface",
    0x0E: "CXP or later",
    0x0F: "Shielded Mini Multilane HD 4X",
    0x10: "Shielded Mini Multilane HD 8X",
    0x11: "QSFP28/QSFP56",
    0x12: "CXP2 (CXP28)",
    0x13: "CDFP (Style 1/2)",
    0x14: "Shielded Mini Multilane HD 4X Fanout Cable",
    0x15: "Shielded Mini Multilane HD 8X Fanout Cable",
    0x16: "CDFP (Style 3) INF-TA-1003",
    0x17: "microQSFP",
    0x18: "QSFP-DD Double Density 8X Pluggable Transceiver",
    0x19: "OSFP 8X Pluggable Transceiver",
    0x1A: "SFP-DD Double Density 2X Pluggable Transceiver with SFP-DD Management Interface Specification",
    0x1B: "DSFP Dual Small Form Factor Pluggable Transceiver",
    0x1C: "x4 MiniLink/OcuLink",
    0x1D: "x8 MiniLink",
    0x1E: "QSFP+ or later with Common Management Interface Specification (CMIS)",
    0x1F: "SFP-DD Double Density 2X Pluggable Transceiver with Common Management Interface Specification (CMIS)",
    0x20: "SFP+ and later with Common Management Interface Specification (CMIS)",
    0x21: "OSFP-XD with Common Management interface Specification (CMIS)",
    0x22: "OIF-ELSFP with Common Management interface Specification (CMIS)",
    0x23: "CDFP (x4 PCIe) SFF-TA-1032 with Common Management interface Specification (CMIS)",
    0x24: "CDFP (x8 PCIe) SFF-TA-1032 with Common Management interface Specification (CMIS)",
    0x25: "CDFP (x16 PCIe) SFF-TA-1032 with Common Management interface Specification (CMIS)",
    # 0x26-0x7F: Reserved
}

# Table 4-3: Connector Types (complete per SFF-8024 Rev 4.12)
CONNECTOR_TYPES = {
    0x00: "Unknown or unspecified",
    0x01: "SC",
    0x02: "Fibre Channel Style 1 copper",
    0x03: "Fibre Channel Style 2 copper",
    0x04: "BNC/TNC",
    0x05: "Fibre Channel coaxial headers",
    0x06: "FiberJack",
    0x07: "LC",
    0x08: "MT-RJ",
    0x09: "MU",
    0x0A: "SG",
    0x0B: "Optical pigtail",
    0x0C: "MPO 1x12",
    0x0D: "MPO 2x16",
    0x0E: "HSSDC II",
    0x0F: "Copper pigtail",
    0x10: "RJ45",
    0x11: "No separable connector",
    0x12: "MXC 2x16",
    0x13: "CS optical connector",
    0x14: "SN optical connector (Mini CS)",
    0x15: "MPO 2x12",
    0x16: "MPO 1x16",
    0x17: "MPO 24",
    0x18: "MPO 48",
    0x19: "MPO 72",
    0x1A: "MPO 96",
    0x1B: "MPO 144",
    0x1C: "MPO 288",
    # 0x1D-0x1F Reserved
    0x1D: "Reserved",
    0x1E: "Reserved",
    0x1F: "Reserved",
    0x20: "HSSDC II (High Speed Serial Data Connector)",
    0x21: "Copper pigtail",
    0x22: "RJ45 (Registered Jack)",
    0x23: "No separable connector",
    0x24: "MXC 2x16",
    0x25: "CS optical connector",
    0x26: "SN (previously Mini CS) optical connector",
    0x27: "MPO 2x12",
    0x28: "MPO 1x16",
    # 0x29-0x7F Reserved
}
# Add reserved and vendor-specific ranges for completeness
def connector_type_name(code):
    if code in CONNECTOR_TYPES:
        return CONNECTOR_TYPES[code]
    elif 0x0E <= code <= 0x1F or 0x29 <= code <= 0x7F:
        return "Reserved"
    elif 0x80 <= code <= 0xFF:
        return "Vendor specific"
    else:
        return f"Unknown (0x{code:02X})"

# Add reserved and vendor-specific ranges for completeness
def identifier_name(code):
    if code in IDENTIFIERS:
        return IDENTIFIERS[code]
    elif 0x26 <= code <= 0x7F:
        return "Reserved"
    elif 0x80 <= code <= 0xFF:
        return "Vendor Specific"
    else:
        return f"Unknown (0x{code:02X})" 

# Table 4-2: Encoding Values (complete per SFF-8024 Rev 4.12)
ENCODING_VALUES = {
    0x00: "Unspecified",
    0x01: "8B/10B",
    0x02: "4B/5B",
    0x03: "NRZ",
    0x04: "Manchester",
    0x05: "SONET Scrambled",
    0x06: "64B/66B",
    0x07: "256B/257B (transcoded FEC-enabled data)",
    0x08: "PAM4",
    # 0x09-0xFF: Reserved
}
def encoding_value_name(code):
    if code in ENCODING_VALUES:
        return ENCODING_VALUES[code]
    elif 0x09 <= code <= 0xFF:
        return "Reserved"
    else:
        return f"Unknown (0x{code:02X})" 

# Table 4-12: Fiber Face Type Codes (per SFF-8024 Rev 4.12)
FIBER_FACE_TYPE_CODES = {
    0x00: "Unknown or unspecified",
    0x01: "PC/UPC (Physical/Ultra Physical contact)",
    0x02: "APC (Angled Physical Contact)",
}
def fiber_face_type_name(code):
    if code in FIBER_FACE_TYPE_CODES:
        return FIBER_FACE_TYPE_CODES[code]
    else:
        return f"Unknown (0x{code:02X})" 

# Table 4-6 to 4-10: Media Interface Codes (sample, per SFF-8024 Rev 4.12)
MEDIA_INTERFACE_CODES = {
    0x00: "Undefined",
    0x01: "Copper cable",
    0x02: "Reserved",
    0x07: "50GBASE-SR",
    0x0C: "100GBASE-SR2",
    0x0E: "200GBASE-SR4",
    0x10: "400GBASE-SR8",
    0x14: "100GBASE-DR",
    0x17: "200GBASE-DR4",
    0x18: "200GBASE-FR4",
    0x19: "200GBASE-LR4",
    0x1A: "400GBASE-FR8",
    0x1C: "400GBASE-DR4",
    0x2A: "128GFC (FC-PI-6P)",
    0x2B: "256GFC (FC-PI-7P)",
    0x31: "4I1-4D1F (G.959.1)",
    0x32: "8R1-4D1F (G.959.1)",
    0x33: "8I1-4D1F (G.959.1)",
    0x38: "10G-SR",
    0x39: "10G-LR",
    0x41: "200GBASE-ER4",
    0x44: "100GBASE-ZR",
    0x4A: "100G-LR1-20 MSA",
    0x4B: "100G-ER1-30 MSA",
    0x4C: "100G-ER1-40 MSA",
    0x51: "FOIC1.4-DO (G.709.3/Y.1331.3)",
    0x52: "FOIC2.8-DO (G.709.3/Y.1331.3)",
    0x53: "FOIC4.8-DO (G.709.3/Y.1331.3)",
    0x54: "FOIC2.4-DO (G.709.3/Y.1331.3)",
    0x70: "1I1-5D1F (G.959.1)",
    0x71: "1R1-5D1F (G.959.1)",
    0x72: "FOIC1.1-RS (G.709.1/Y.1331.58)",
    0x73: "200GBASE-DR1 (Clause 180)",
    0x74: "200GBASE-DR1-2 (Clause 181)",
    0xBF: "Passive Loopback module",
    0xC0: "Linear active copper loopback module",
    0xFF: "Vendor Specific/Custom",
    # ... (add more as needed from SFF-8024 Table 4-6, 4-7, 4-8, 4-9, 4-10)
}
def media_interface_code_name(code):
    if code in MEDIA_INTERFACE_CODES:
        return MEDIA_INTERFACE_CODES[code]
    elif 0x02 <= code <= 0xBE:
        return "Reserved"
    elif 0xC1 <= code <= 0xFE:
        return "Vendor Specific/Custom"
    else:
        return f"Unknown (0x{code:02X})" 

# Table 4-5: Host Electrical Interface IDs (sample, per SFF-8024 Rev 4.12)
HOST_ELECTRICAL_INTERFACE_IDS = {
    0x00: "Undefined",
    0x01: "1000BASE-CX (Clause 39)",
    0x02: "XAUI (Clause 47)",
    0x03: "XFI (SFF INF-8071i)",
    0x04: "SFI (SFF-8431)",
    0x05: "25GAUI C2M (Annex 109B)",
    0x06: "XLAUI C2M (Annex 83B)",
    0x07: "XLPPI (Annex 86A)",
    0x08: "LAUI-2 C2M (Annex 135C)",
    0x09: "50GAUI-2 C2M (Annex 135E)",
    0x0A: "50GAUI-1 C2M (Annex 135G)",
    0x0B: "CAUI-4 C2M (Annex 83E)",
    0x0C: "100GAUI-4 C2M (Annex 135E)",
    0x0D: "100GAUI-2 C2M (Annex 135G)",
    0x0E: "200GAUI-8 C2M (Annex 120C)",
    0x0F: "200GAUI-4 C2M (Annex 120E)",
    0x10: "400GAUI-16 C2M (Annex 120C)",
    0x11: "400GAUI-8 C2M (Annex 120E)",
    0x13: "10GBASE-CX4 (Clause 54)",
    0x14: "25GBASE-CR CA-25G-L (Clause 110)",
    0x15: "25GBASE-CR or 25GBASE-CR-S CA-25G-S (Clause 110)",
    0x16: "25GBASE-CR or 25GBASE-CR-S CA-25G-N (Clause 110)",
    0x17: "40GBASE-CR4 (Clause 85)",
    0x18: "50GBASE-CR (Clause 136)",
    0x19: "100GBASE-CR10 (Clause 85)",
    0x1A: "100GBASE-CR4 (Clause 92)",
    0x1B: "100GBASE-CR2 (Clause 136)",
    0x1C: "200GBASE-CR4 (Clause 136)",
    0x1D: "400G CR8 (Ethernet Technology Consortium)",
    0x1E: "200GBASE-CR1 (Clause179)",
    0x1F: "400GBASE-CR2 (Clause179)",
    0x20: "LEI-100G-PAM4-1 (LPO MSA)",
    0x21: "LEI-200G-PAM4-2 (LPO MSA)",
    0x22: "LEI-400G-PAM4-4 (LPO MSA)",
    0x23: "LEI-800G-PAM4-8 (LPO MSA)",
    0x24: "Reserved",
    0x25: "8GFC (FC-PI-4)",
    0x26: "10GFC (10GFC)",
    0x27: "16GFC (FC-PI-5)",
    0x28: "32GFC (FC-PI-6)",
    0x29: "64GFC (FC-PI-7)",
    0x2A: "128GFC (FC-PI-6P)",
    0x2B: "256GFC (FC-PI-7P)",
    0x2C: "IB SDR (Arch.Spec.Vol.2)",
    0x2D: "IB DDR (Arch.Spec.Vol.2)",
    0x2E: "IB QDR (Arch.Spec.Vol.2)",
    0x2F: "IB FDR (Arch.Spec.Vol.2)",
    0x30: "IB EDR (Arch.Spec.Vol.2)",
    0x31: "IB HDR (Arch.Spec.Vol.2)",
    0x32: "IB NDR (Arch.Spec.Vol.2)",
    0x33: "E.96 (CPRI Specification V7.0)",
    0x34: "E.99 (CPRI Specification V7.0)",
    0x35: "E.119 (CPRI Specification V7.0)",
    0x36: "E.238 (CPRI Specification V7.0)",
    0x37: "OTL3.4 (ITU-T G.709/Y.1331 G.Sup58)",
    0x38: "OTL4.10 (ITU-T G.709/Y.1331 G.Sup58)",
    0x39: "OTL4.4 (ITU-T G.709/Y.1331 G.Sup58)",
    0x3A: "OTLC.4 (ITU-T G.709.1/Y.1331 G.Sup58)",
    0x3B: "FOIC1.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x3C: "FOIC1.2-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x3D: "FOIC2.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x3E: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x3F: "FOIC4.16-MFI (ITU-T G.709.5/Y1331 G.Sup58)",
    0x40: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x41: "CAUI-4 C2M (Annex 83E) without FEC",
    0x42: "CAUI-4 C2M (Annex 83E) with RS (528,514) FEC",
    0x43: "50GBASE-CR2 (Ethernet Technology Consortium) with RS (528,514) (Clause 91) FEC",
    0x44: "50GBASE-CR2 (Ethernet Technology Consortium) with BASE-R (Clause 74), Fire code FEC",
    0x45: "50GBASE-CR2 (Ethernet Technology Consortium) with no FEC",
    0x46: "100GBASE-CR1 (Clause 162)",
    0x47: "200GBASE-CR2 (Clause 162)",
    0x48: "400GBASE-CR4 (Clause 162)",
    0x49: "800G-ETC-CR8 or 800GBASE-CR8",
    0x4A: "128GFC (FC-PI-8)",
    0x51: "800GAUI-8 S C2M (Annex 120G)",
    0x52: "800GAUI-8 L C2M (Annex 120G)",
    0x53: "OTL4.2",
    0x54: "FOIC2.4-DO (G.709.3/Y.1331.3)",
    0x55: "1.6TAUI-16-S C2M (Annex 120G)",
    0x56: "1.6TAUI-16-L C2M (Annex 120G)",
    0x70: "PCIe 4.0",
    0x71: "PCIe 5.0",
    0x72: "PCIe 6.0",
    0x73: "PCIe 7.0 (placeholder)",
    0x74: "CEI-112G-LINEAR-PAM4",
    0x80: "200GAUI-1 (Annex176E)",
    0x81: "400GAUI-2 (Annex176E)",
    0x82: "800GAUI-4 (Annex176E)",
    0x83: "1.6TAUI-8 (Annex176E)",
    0x90: "EEI-100G-RTLR-1-S",
    0x91: "EEI-100G-RTLR-1-L",
    0x92: "EEI-200G-RTLR-2-S",
    0x93: "EEI-200G-RTLR-2-L",
    0x94: "EEI-400G-RTLR-4-S",
    0x95: "EEI-400G-RTLR-4-L",
    0x96: "EEI-800G-RTLR-8-S",
    0x97: "EEI-800G-RTLR-8-L",
    0xA0: "IB XDR (placeholder)",
    0xB0: "FOIC1.1-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB1: "FOIC4.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB2: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB7: "ITU-T G.9804.3",
    0xBF: "Passive Loopback module",
    0xC0: "Linear active copper loopback module",
    0xFF: "Vendor Specific/Custom",
    # ... (add more as needed from SFF-8024 Table 4-5)
}
def host_electrical_interface_name(code):
    if code in HOST_ELECTRICAL_INTERFACE_IDS:
        return HOST_ELECTRICAL_INTERFACE_IDS[code]
    else:
        return f"Unknown (0x{code:02X})" 