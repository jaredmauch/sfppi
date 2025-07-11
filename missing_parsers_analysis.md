# Missing Parsers and Values Analysis for Optic Data Parsing

## Overview
Based on analysis of SFF-8472, SFF-8636, and other SFF specifications, several parsers and values are missing from the current implementation that could significantly enhance the optic data parsing capabilities.

## ✅ COMPLETED ITEMS



## 9. Functions Needing Review/Update for SFF-8472/SFP+ Byte Offset Compliance

The following functions in read-optic.py should be reviewed and updated for strict compliance with SFF-8472 Rev 12.4.3 (and INF-8074_1.0 where relevant). These were identified as potentially ambiguous, incomplete, or using offsets that may not match the latest spec:

- `read_optic_transciever()`: Only decodes a subset of Table 5-3 (bytes 3-9, 36), and does not handle all compliance codes or new/extended fields. Needs a more systematic mapping to spec tables.
- `read_sfp_lengths()`: The field names/descriptions (e.g., "Length (9m)") are unclear and may not match the spec's definitions for bytes 14-19. Should be cross-checked with SFF-8472 Table 4-2 and updated for OM2/OM3/OM4/copper.
- `read_sfp_extended_info()`: The logic for options bytes (64-65) and bit meanings should be checked against Table 8-3 and SFF-8431/SFF-8690 for undefined bits. Some option bits may be outdated or missing.
- `read_sfp_vendor_specific()`: Only prints raw data; could be improved to decode known vendor-specific fields if any are standardized.
- `read_sfp_comprehensive()`: Relies on the above functions; will need update if any of those are changed for spec compliance.

**Action:**
- Review and update these functions to ensure all byte offsets, field names, and bit meanings match the latest SFF-8472 and related specs. Add comments referencing the exact table/section for each field.
- Consider adding more robust/complete parsing for compliance codes, options, and vendor-specific fields. 

- `read_optic_monitoring_type()`: Bit meanings for byte 92 should be checked against Table 8-5; ensure all bits are handled and descriptions are up to date.
- `read_option_values()`: Option bits for bytes 64-65 should be cross-checked with Table 8-3 and SFF-8431/SFF-8690; some bits are marked as undefined or may be outdated.
- `read_enhanced_options()`: Logic for enhanced options and auxiliary monitoring should be reviewed for completeness and spec compliance (Table 9-11 and related tables).
- `read_sff_8472_compliance()`: Compliance code mapping for byte 94 should be checked against Table 8-8; ensure all possible values are handled.
- `read_extended_compliance_codes()`: Byte 36 logic should be cross-checked with Table 5-4; ensure all extended compliance codes are parsed and described.
- `read_rate_identifier()`: Byte 13 logic should be checked against Table 5-1/5-6; ensure all rate identifier codes are handled.
- `read_application_select()`: Application select logic is vendor-specific and may need clarification or expansion for spec compliance.
- `read_fibre_channel_link_length()`, `read_fibre_channel_technology()`, `read_sfp_cable_technology()`, `read_fibre_channel_transmission_media()`: These functions reference Fibre Channel fields and should be checked for correct byte/bit usage and completeness per spec.
- `read_optic_frequency()`, `read_optic_temperature()`, `read_optic_vcc()`, `read_laser_temperature()`, `read_optic_rxpower()`, `read_optic_txpower()`, `read_measured_current()`: All DDM/monitoring fields (bytes 96-109) should be checked for correct scaling, byte order, and field mapping per Table 9-2 and related tables.
- `read_sfp_status_bits()`: Byte 110 logic should be checked against Table 9-11; ensure all status/control bits are handled.
- `dump_vendor()`: Vendor-specific area (bytes 96-127) could be improved to decode any standardized vendor fields if present. 

## 10. Functions Needing Review/Update for QSFP (SFF-8636) and QSFP-DD/CMIS (OIF-CMIS) Byte Offset Compliance

The following functions in read-optic.py should be reviewed and updated for strict compliance with SFF-8636 (QSFP/QSFP+) and OIF-CMIS (QSFP-DD/CMIS) specifications. These were identified as potentially using incorrect, ambiguous, or outdated byte offsets/field mappings:

### OIF-CMIS 5.3 Specific Issues:

**COMPLETED FIXES (Updated to use correct byte offsets per OIF-CMIS 5.3):**
- ✅ `read_qsfpdd_vendor()`: Fixed to read from bytes 129-144 according to Table 8-28
- ✅ `read_qsfpdd_vendor_oui()`: Fixed to read from bytes 145-147 according to Table 8-28  
- ✅ `read_qsfpdd_vendor_partnum()`: Fixed to read from bytes 148-163 according to Table 8-28
- ✅ `read_qsfpdd_vendor_rev()`: Fixed to read from bytes 164-165 according to Table 8-28
- ✅ `read_qsfpdd_vendor_sn()`: Fixed to read from bytes 166-181 according to Table 8-28
- ✅ `read_qsfpdd_date()`: Fixed to read from bytes 182-189 according to Table 8-29
- ✅ `read_qsfpdd_clei_code()`: Fixed to read from bytes 190-199 according to Table 8-30
- ✅ `read_qsfpdd_mod_power()`: Fixed to read from bytes 200-201 according to Table 8-31
- ✅ `read_qsfpdd_cable_len()`: Fixed to read from byte 202 according to Table 8-32
- ✅ `read_qsfpdd_connector_type()`: Fixed to read from byte 203 according to Table 8-33
- ✅ `read_qsfpdd_copper_attenuation()`: Fixed to read from bytes 204-209 according to Table 8-34
- ✅ `read_qsfpdd_media_lane_info()`: Fixed to read from byte 210 according to Table 8-35
- ✅ `read_cmis_application_codes()`: Fixed to read from bytes 128-131 according to Table 8-23
- ✅ `read_cmis_lane_status()`: Fixed to read from byte 210 according to Table 8-35
- ✅ `read_cmis_module_power()`: Fixed to read from bytes 200-201 according to Table 8-31
- ✅ `read_cmis_module_config()`: Fixed to read from bytes 0-2 according to Table 8-5

**REMAINING FUNCTIONS NEEDING UPDATES:**

- `read_cmis_copper_attenuation()`: Uses bytes 204-207 for attenuation, which matches Table 8-34. This function appears to be correct.

- `read_cmis_media_lane_info()`: Uses byte 210 for media lane info, which matches Table 8-35. This function appears to be correct.

- `read_cmis_monitoring_data()`: Uses bytes 14-19 for temperature/voltage/power, which matches Table 8-10. However, the lane-specific monitoring offsets (20+2*lane, 36+2*lane, 52+2*lane) need verification against the correct page structure.

- `read_cmis_thresholds()`: Uses bytes 128-191 for thresholds, but needs verification against the correct threshold table structure.

**QSFP (SFF-8636) Functions:**
- All `read_qsfp_*` functions need verification against SFF-8636 tables for correct byte offsets
- Per-channel monitoring and threshold functions likely have incorrect offsets
- Vendor info, OUI, part number, revision, serial, and date code offsets need verification
- Advanced/extended status/control fields need careful review

**Implementation Priority:**
1. ✅ Fix vendor information functions (most critical - wrong offsets) - COMPLETED
2. ✅ Fix power and configuration functions - COMPLETED  
3. ✅ Fix application codes and lane status functions - COMPLETED
4. Verify monitoring and threshold functions
5. Review all QSFP functions against SFF-8636 