#!/usr/bin/python3
"""
Code Mappings for SFF/CMIS Specifications
Extracted from SFF-8024, OIF-CMIS, and other SFF specifications
"""

# Host Electrical Interface IDs from SFF-8024 Table 4-5
HOST_INTERFACE_CODES = {
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
    0x12: "Reserved for Ethernet active modules",
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
    0x3F: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
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
    0x4B: "100GAUI-1-S C2M (Annex 120G)",
    0x4C: "100GAUI-1-L C2M (Annex 120G)",
    0x4D: "200GAUI-2-S C2M (Annex 120G)",
    0x4E: "200GAUI-2-L C2M (Annex 120G)",
    0x4F: "400GAUI-4-S C2M (Annex 120G)",
    0x50: "400GAUI-4-L C2M (Annex 120G)",
    0x51: "800GAUI-8 S C2M (Annex 120G)",
    0x52: "800GAUI-8 L C2M (Annex 120G)",
    0x53: "OTL4.2",
    0x55: "1.6TAUI-16-S C2M (Annex 120G)",
    0x56: "1.6TAUI-16-L C2M (Annex 120G)",
    0x57: "800GBASE-CR4 (Clause179)",
    0x58: "1.6TBASE-CR8 (Clause179)",
    0x59: "400GAUI-4-S C2M (Annex 120G)",
    0x60: "Reserved for future Fibre Channel codes",
    0x70: "PCIe 4.0",
    0x71: "PCIe 5.0",
    0x72: "PCIe 6.0",
    0x73: "PCIe 7.0 (placeholder)",
    0x74: "CEI-112G-LINEAR-PAM4",
    0x80: "200GAUI-1 (Annex176E)",
    0x81: "400GAUI-2 (Annex176E)",
    0x82: "800GAUI-4 (Annex176E)",
    0x83: "1.6TAUI-8 (Annex176E)",
    0x84: "Reserved for Ethernet active modules",
    0x90: "EEI-100G-RTLR-1-S",
    0xA0: "IB XDR (placeholder)",
    0xA1: "Reserved for future InfiniBand codes",
    0xB0: "FOIC1.1-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB1: "FOIC4.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB2: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB7: "ITU-T G.9804.3",
    0xFF: "Unused/Empty Application Descriptor"
}

# MMF Media Interface IDs from SFF-8024 Table 4-6
MMF_MEDIA_INTERFACE_CODES = {
    0x00: "Undefined",
    0x01: "10GBASE-SW (Clause 52)",
    0x02: "10GBASE-SR (Clause 52)",
    0x03: "25GBASE-SR (Clause 112)",
    0x04: "40GBASE-SR4 (Clause 86)",
    0x05: "40GE SWDM4 MSA Spec",
    0x06: "40GE BiDi",
    0x07: "50GBASE-SR (Clause 138)",
    0x08: "100GBASE-SR10 (Clause 86)",
    0x09: "100GBASE-SR4 (Clause 95)",
    0x0A: "100GE SWDM4 MSA Spec",
    0x0B: "100GE BiDi",
    0x0C: "100GBASE-SR2 (Clause 138)",
    0x0D: "100GBASE-SR1 (Clause 167)",
    0x0E: "200GBASE-SR4 (Clause 138)",
    0x0F: "400GBASE-SR16 (Clause 123)",
    0x10: "400GBASE-SR8 (Clause 138)",
    0x11: "400GBASE-SR4 (Clause 167)",
    0x12: "800GBASE-SR8 (Clause 167)",
    0x13: "8GFC-MM (FC-PI-4)",
    0x14: "10GFC-MM (10GFC)",
    0x15: "16GFC-MM (FC-PI-5)",
    0x16: "32GFC-MM (FC-PI-6)",
    0x17: "64GFC-MM (FC-PI-7)",
    0x18: "128GFC-MM4 (FC-PI-6P)",
    0x19: "256GFC-MM4 (FC-PI-7P)",
    0x1A: "400GBASE-SR4.2 (Clause 150) (400GE BiDi)",
    0x1B: "100GBASE-VR1 (Clause 167)",
    0x1C: "128GFC-MM (FC-PI-8)",
    0x1D: "100GBASE-VR1 (Clause 167)",
    0x1E: "200GBASE-VR2 (Clause 167)",
    0x1F: "400GBASE-VR4 (Clause 167)",
    0x20: "800GBASE-VR8 (Clause 167)",
    0x21: "800G-VR4.2",
    0x22: "800G-SR4.2",
    0x23: "1.6T-VR8.2",
    0x24: "1.6T-SR8.2",
    0x25: "Reserved",
    0xC0: "Vendor Specific/Custom"
}

# SMF Media Interface IDs from SFF-8024 Table 4-7
SMF_MEDIA_INTERFACE_CODES = {
    0x00: "Undefined",
    0x01: "10GBASE-LW (Clause 52)",
    0x02: "10GBASE-EW (Clause 52)",
    0x03: "10G-ZW",
    0x04: "10GBASE-LR (Clause 52)",
    0x05: "10GBASE-ER (Clause 52)",
    0x06: "10G-ZR",
    0x07: "25GBASE-LR (Clause 114)",
    0x08: "25GBASE-ER (Clause 114)",
    0x09: "40GBASE-LR4 (Clause 87)",
    0x0A: "40GBASE-FR (Clause 89)",
    0x0B: "50GBASE-FR (Clause 139)",
    0x0C: "50GBASE-LR (Clause 139)",
    0x0D: "100GBASE-LR4 (Clause 88)",
    0x0E: "100GBASE-ER4 (Clause 88)",
    0x0F: "100G PSM4 MSA Spec",
    0x10: "100G CWDM4 MSA Spec",
    0x11: "100G 4WDM-10 MSA Spec",
    0x12: "100G 4WDM-20 MSA Spec",
    0x13: "100G 4WDM-40 MSA Spec",
    0x14: "100GBASE-DR (Clause 140)",
    0x15: "100G-FR MSA spec2/100GBASE-FR1 (Clause 140)",
    0x16: "100G-LR MSA spec2/100GBASE-LR1 (Clause 140)",
    0x17: "200GBASE-DR4 (Clause 121)",
    0x18: "200GBASE-FR4 (Clause 122)",
    0x19: "200GBASE-LR4 (Clause 122)",
    0x1A: "400GBASE-FR8 (Clause 122)",
    0x1B: "400GBASE-LR8 (Clause 122)",
    0x1C: "400GBASE-DR4 (Clause 124)",
    0x1D: "400G-FR4 MSA spec2/400GBASE-FR4 (Clause 151)",
    0x1E: "400G-LR4-10 MSA Spec2",
    0x1F: "8GFC-SM (FC-PI-4)",
    0x20: "10GFC-SM (10GFC)",
    0x21: "16GFC-SM (FC-PI-5)",
    0x22: "32GFC-SM (FC-PI-6)",
    0x23: "64GFC-SM (FC-PI-7)",
    0x24: "128GFC-PSM4 (FC-PI-6P)",
    0x26: "128GFC-CWDM4 (FC-PI-6P)",
    0x34: "100G CWDM4-OCP",
    0x38: "10G-SR",
    0x39: "10G-LR",
    0x3A: "25G-SR",
    0x3B: "25G-LR",
    0x3C: "10G-LR-BiDi",
    0x3D: "25G-LR-BiDi",
    0x3E: "400ZR (0x01, 0x03), DWDM, amplified",
    0x3F: "400ZR (0x02), Single Wavelength, Unamplified",
    0x40: "50GBASE-ER (Clause 139)",
    0x41: "200GBASE-ER4 (Clause 122)",
    0x42: "400GBASE-ER8 (Clause 122)",
    0x44: "100GBASE-ZR (Clause 154)",
    0x45: "128GFC-SM (FC-PI-8)",
    0x4A: "100G-LR1-20 MSA Spec2",
    0x4B: "100G-ER1-30 MSA Spec 2",
    0x4C: "100G-ER1-40 MSA Spec2",
    0x4D: "400GBASE-ZR (Clause 156)",
    0x4E: "10GBASE-BR (Clause 158)",
    0x4F: "25GBASE-BR (Clause 159)",
    0x50: "50GBASE-BR (Clause 160)",
    0x51: "FOIC1.4-DO (G.709.3/Y.1331.3)",
    0x52: "FOIC2.8-DO (G.709.3/Y.1331.3)",
    0x53: "FOIC4.8-DO (G.709.3/Y.1331.3)",
    0x54: "FOIC2.4-DO (G.709.3/Y.1331.3)",
    0x55: "400GBASE-DR4-2 (Clause 124)",
    0x56: "800GBASE-DR8 (Clause 124)",
    0x57: "800GBASE-DR8-2 (Clause 124)",
    0x6F: "400G-ER4-30 MSA Spec2",
    0x70: "1I1-5D1F (G.959.1)",
    0x71: "1R1-5D1F (G.959.1)",
    0x72: "FOIC1.1-RS (G.709.1/Y.1331.58)",
    0x73: "4I1-9D1F (G.959.1)",
    0x74: "4L1-9C1F (G.959.1)",
    0x75: "4L1-9D1F (G.959.1)",
    0x76: "C4S1-9D1F (G.695)",
    0x77: "4I1-4D1F (G.959.1)",
    0x78: "8R1-4D1F (G.959.1)",
    0x79: "8I1-4D1F (G.959.1)",
    0x7A: "800GBASE-FR4-500 (Clause 183)",
    0x7B: "800GBASE-FR4 (Clause 183)",
    0x7C: "800GBASE-LR4 (Clause 183)",
    0x7D: "800GBASE-ER1-20 (Clause 187)",
    0x7E: "800GBASE-ER1 (Clause 187)",
    0x7F: "1.6TBASE-DR8 (Clause 180)",
    0x80: "1.6TBASE-DR8-2 (Clause 181)",
    0x81: "FOIC1.1-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x82: "FOIC4.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x83: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x84: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x85: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x86: "FOIC2.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x87: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x88: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x89: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x8A: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x8B: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x8C: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x8D: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x8E: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x8F: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x90: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x91: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x92: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x93: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x94: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x95: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x96: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x97: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x98: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x99: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x9A: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x9B: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x9C: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x9D: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x9E: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0x9F: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xA0: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xA1: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xA2: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xA3: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xA4: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xA5: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xA6: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xA7: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xA8: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xA9: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xAA: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xAB: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xAC: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xAD: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xAE: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xAF: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB0: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB1: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB2: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB3: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB4: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB5: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB6: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB7: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB8: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xB9: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xBA: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xBB: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xBC: "FOIC4.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xBD: "FOIC2.4-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xBE: "FOIC8.8-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xBF: "FOIC4.16-MFI (ITU-T G.709.5/Y.1331 G.Sup58)",
    0xC0: "Vendor Specific/Custom"
}

# BASE-T Media Interface IDs from SFF-8024 Table 4-10 (referenced)
BASE_T_MEDIA_INTERFACE_CODES = {
    0x00: "Undefined",
    0x01: "1000BASE-T",
    0x02: "2.5GBASE-T",
    0x03: "5GBASE-T",
    0x04: "10GBASE-T",
    0x05: "25GBASE-T",
    0x06: "40GBASE-T",
    0x07: "50GBASE-T",
    0x08: "100GBASE-T",
    0x09: "200GBASE-T",
    0x0A: "400GBASE-T",
    0x0B: "800GBASE-T",
    0x0C: "1.6TBASE-T"
}

# Copper Cable Media Interface IDs (referenced in SFF-8024)
COPPER_MEDIA_INTERFACE_CODES = {
    0x00: "Undefined",
    0x01: "10GBASE-CX4",
    0x02: "25GBASE-CR",
    0x03: "40GBASE-CR4",
    0x04: "50GBASE-CR2",
    0x05: "100GBASE-CR10",
    0x06: "100GBASE-CR4",
    0x07: "100GBASE-CR2",
    0x08: "200GBASE-CR4",
    0x09: "400G CR8",
    0x0A: "800G-ETC-CR8",
    0x0B: "200GBASE-CR1",
    0x0C: "400GBASE-CR2",
    0x0D: "800GBASE-CR4",
    0x0E: "1.6TBASE-CR8"
}

# Active Cable Media Interface IDs (referenced in SFF-8024)
ACTIVE_CABLE_MEDIA_INTERFACE_CODES = {
    0x00: "Undefined",
    0x01: "Active Copper Cable",
    0x02: "Active Optical Cable",
    0x03: "Active Loopback",
    0x04: "Passive Loopback"
}

# Application Types (derived from CMIS specification)
APPLICATION_TYPES = {
    0x00: "Undefined/Unknown",
    0x01: "Ethernet",
    0x02: "Fibre Channel",
    0x03: "Infiniband",
    0x04: "CPRI",
    0x05: "OTN (ITU-T)",
    0x06: "PON",
    0x07: "PCIe",
    0x08: "OIF",
    0x09: "Custom/Vendor Specific"
}

# Domain Types (derived from CMIS and SFF specifications)
DOMAIN_TYPES = {
    0x00: "Undefined/Unknown",
    0x01: "Host Domain",
    0x02: "Media Domain",
    0x03: "Module Domain",
    0x04: "System Domain",
    0x05: "Network Domain",
    0x06: "Client Domain",
    0x07: "Line Domain",
    0x08: "Custom/Vendor Specific"
}

def get_host_interface_name(code):
    """Get human-readable name for host interface code"""
    if code in HOST_INTERFACE_CODES:
        return HOST_INTERFACE_CODES[code]
    elif 0x25 <= code <= 0xBF:
        return "Reserved for future Fibre Channel codes"
    elif 0x60 <= code <= 0x67:
        return "Reserved for future Fibre Channel codes"
    elif 0x96 <= code <= 0x103:
        return "Reserved for future Fibre Channel codes"
    elif 0x132 <= code <= 0x143:
        return "Reserved for Ethernet active modules"
    elif 0x176 <= code <= 0x17F:
        return "Reserved for future InfiniBand codes"
    elif 0x1A1 <= code <= 0x1A7:
        return "Reserved for future InfiniBand codes"
    elif 0x1B0 <= code <= 0x1BF:
        return "Reserved for future CPRI codes"
    elif 0x1C0 <= code <= 0x1FF:
        return "Reserved for future OTN codes"
    elif 0x200 <= code <= 0x2FF:
        return "Reserved for future PON codes"
    elif 0x300 <= code <= 0x3FF:
        return "Reserved for future PCIe codes"
    elif 0x400 <= code <= 0x4FF:
        return "Reserved for future OIF codes"
    elif 0x500 <= code <= 0x7FF:
        return "Reserved for future use"
    elif 0x800 <= code <= 0xFFF:
        return "Vendor Specific/Custom"
    else:
        return f"Unknown/Reserved (0x{code:02x})"

def get_media_interface_name(code, media_type=0x00):
    """Get human-readable name for media interface code based on media type"""
    if media_type == 0x00:  # Undefined
        return "Undefined"
    elif media_type == 0x01:  # Optical - MMF
        if code in MMF_MEDIA_INTERFACE_CODES:
            return MMF_MEDIA_INTERFACE_CODES[code]
        elif 0x25 <= code <= 0xBF:
            return "Reserved"
        elif 0xC0 <= code <= 0xFF:
            return "Vendor Specific/Custom"
        else:
            return f"Unknown MMF Media Interface (0x{code:02x})"
    elif media_type == 0x02:  # Optical - SMF
        if code in SMF_MEDIA_INTERFACE_CODES:
            return SMF_MEDIA_INTERFACE_CODES[code]
        elif 0x25 <= code <= 0xBF:
            return "Reserved"
        elif 0xC0 <= code <= 0xFF:
            return "Vendor Specific/Custom"
        else:
            return f"Unknown SMF Media Interface (0x{code:02x})"
    elif media_type == 0x03:  # Copper Cable
        if code in COPPER_MEDIA_INTERFACE_CODES:
            return COPPER_MEDIA_INTERFACE_CODES[code]
        else:
            return f"Unknown Copper Media Interface (0x{code:02x})"
    elif media_type == 0x04:  # BASE-T
        if code in BASE_T_MEDIA_INTERFACE_CODES:
            return BASE_T_MEDIA_INTERFACE_CODES[code]
        else:
            return f"Unknown BASE-T Media Interface (0x{code:02x})"
    elif media_type == 0x05:  # Active Cable
        if code in ACTIVE_CABLE_MEDIA_INTERFACE_CODES:
            return ACTIVE_CABLE_MEDIA_INTERFACE_CODES[code]
        else:
            return f"Unknown Active Cable Media Interface (0x{code:02x})"
    else:
        return f"Unknown Media Type {media_type} Interface (0x{code:02x})"

def get_application_type_name(code):
    """Get human-readable name for application type code"""
    if code in APPLICATION_TYPES:
        return APPLICATION_TYPES[code]
    else:
        return f"Unknown Application Type (0x{code:02x})"

def get_domain_type_name(code):
    """Get human-readable name for domain type code"""
    if code in DOMAIN_TYPES:
        return DOMAIN_TYPES[code]
    else:
        return f"Unknown Domain Type (0x{code:02x})"

def decode_application_descriptor(host_id, media_id, host_lanes, media_lanes, media_type=0x00):
    """Decode a complete application descriptor"""
    result = {
        'host_interface': {
            'code': host_id,
            'name': get_host_interface_name(host_id),
            'lanes': host_lanes
        },
        'media_interface': {
            'code': media_id,
            'name': get_media_interface_name(media_id, media_type),
            'lanes': media_lanes
        }
    }
    
    # Add application type inference
    if host_id in [0x01, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F]:
        result['application_type'] = "Ethernet"
    elif host_id in [0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B]:
        result['application_type'] = "Fibre Channel"
    elif host_id in [0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32]:
        result['application_type'] = "Infiniband"
    elif host_id in [0x33, 0x34, 0x35, 0x36]:
        result['application_type'] = "CPRI"
    elif host_id in [0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40]:
        result['application_type'] = "OTN (ITU-T)"
    elif host_id in [0x70, 0x71, 0x72, 0x73]:
        result['application_type'] = "PCIe"
    elif host_id in [0x74, 0x90]:
        result['application_type'] = "OIF"
    else:
        result['application_type'] = "Unknown/Custom"
    
    return result

def print_application_descriptor(host_id, media_id, host_lanes, media_lanes, media_type=0x00, app_sel=None):
    """Print a formatted application descriptor"""
    decoded = decode_application_descriptor(host_id, media_id, host_lanes, media_lanes, media_type)
    
    if app_sel is not None:
        print(f"Application {app_sel}:")
    else:
        print("Application Descriptor:")
    
    print(f"  Host Interface: 0x{host_id:02x} - {decoded['host_interface']['name']}")
    print(f"    Lanes: {decoded['host_interface']['lanes']}")
    print(f"  Media Interface: 0x{media_id:02x} - {decoded['media_interface']['name']}")
    print(f"    Lanes: {decoded['media_interface']['lanes']}")
    print(f"  Application Type: {decoded['application_type']}")
    print()

def print_all_codes():
    """Print all available code mappings for reference"""
    print("=== Host Interface Codes ===")
    for code, name in sorted(HOST_INTERFACE_CODES.items()):
        print(f"0x{code:02x}: {name}")
    
    print("\n=== MMF Media Interface Codes ===")
    for code, name in sorted(MMF_MEDIA_INTERFACE_CODES.items()):
        print(f"0x{code:02x}: {name}")
    
    print("\n=== SMF Media Interface Codes ===")
    for code, name in sorted(SMF_MEDIA_INTERFACE_CODES.items()):
        print(f"0x{code:02x}: {name}")
    
    print("\n=== BASE-T Media Interface Codes ===")
    for code, name in sorted(BASE_T_MEDIA_INTERFACE_CODES.items()):
        print(f"0x{code:02x}: {name}")
    
    print("\n=== Copper Media Interface Codes ===")
    for code, name in sorted(COPPER_MEDIA_INTERFACE_CODES.items()):
        print(f"0x{code:02x}: {name}")
    
    print("\n=== Active Cable Media Interface Codes ===")
    for code, name in sorted(ACTIVE_CABLE_MEDIA_INTERFACE_CODES.items()):
        print(f"0x{code:02x}: {name}")

if __name__ == "__main__":
    # Example usage
    print("Code Mappings Module")
    print("===================")
    
    # Example: Decode a 400ZR application
    print("Example: 400ZR Application")
    print_application_descriptor(
        host_id=0x50,  # 400GAUI-4 C2M
        media_id=0x3E,  # 400ZR (0x01, 0x03), DWDM, amplified
        host_lanes=4,
        media_lanes=1,
        media_type=0x02,  # SMF
        app_sel=1
    )
    
    # Example: Decode a 100G SR4 application
    print("Example: 100G SR4 Application")
    print_application_descriptor(
        host_id=0x0C,  # 100GAUI-4 C2M
        media_id=0x09,  # 100GBASE-SR4
        host_lanes=4,
        media_lanes=4,
        media_type=0x01,  # MMF
        app_sel=2
    )
