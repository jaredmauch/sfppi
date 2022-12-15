#!/usr/bin/python

# (c) 2015 Jared Mauch jared@puck.nether.net
# (c) 2015 WhiteBoxOptical LLC
# 
# Unauthorized copying Prohibited
# 
# Raspberry PI 2 setup details:
# % # echo dtparam=i2c_arm=on >> /boot/config.txt
# % # echo dtparam=i2c_vc=on >> /boot/config.txt
# % # apt-get install python-smbus
# % # modprobe i2c_dev ; echo i2c_dev >> /etc/modules
# % ** append  bcm2708.vc_i2c_override=1 to /boot/cmdline.txt
#
from __future__ import division
from __future__ import print_function

# some optics (eg: GLC-T) come soft-disabled for some reason
# added code to soft-enable them

from builtins import chr
from builtins import range
real_hardware = False
if real_hardware:
   import smbus
import time
import json
import math
from curses.ascii import isprint
usleep = lambda x: time.sleep(x/1000000.0)

# globals
address_one = 0x50 # A0
address_two = 0x51 # A2 DDM and SFF-8690 Tunable support

tmp102_address = 0x48
#tmp102_address = 0x4e

optic_sff = bytearray.fromhex("030401000000000000000003196414c800000000465320202020202020202020202020200000000058472d5346502d32352d32304e322020312e302004f600fe000a141443323230363336373231352020202020323230373036202068f005e500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
optic_sff_read = 255;
optic_ddm = bytearray.fromhex("5a00d3005500d8008ca0753088b8791888b801f4753003e8ffff312df6783de909d0000807cb000a000000000000000000000000000000000000000000000000000000003f80000000000000010000000100000001000000010000000000003122ac7fde06d671f1024956b800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
optic_ddm_read = 255;
optic_dwdm =[];
optic_dwdm_read = -1;

def reset_muxes(busno):
    mcp23017_bus = smbus.SMBus(busno)
    for mcp23017 in [0x20, 0x21, 0x22, 0x23]:
        try:
            optic_bus.write_byte_data(mcp23017, 0, 0)
            usleep(20)
            optic_bus.write_byte_data(mcp23017, 0, 0xff);
        except IOError:
            usleep(0)

def fetch_psu_data(busno):
    psu_bus = smbus.SMBus(busno)

    for psu_address in [0x40, 0x47]:
        psu=[]
        psu_read = -1;
    #   psu_address= 0x40;
        while psu_read < 128:
            try:
                if (psu_read == -1):
                    psu_tmp = psu_bus.read_i2c_block_data(psu_address, 0, 32);
                else:
                    psu_tmp = psu_bus.read_i2c_block_data(psu_address, psu_read, 32);
                for member in psu_tmp:
                    psu.append(member);
                psu_read = len(psu);
    #			print("psu_read=%d, %d" % (psu_read, len(psu));
            except IOError:
                break;

#		print("PSU_ADDRESS: 0x%x" % psu_address
        if psu_read >= 128:
            psu_model=""
            psu_sn=""
            psu_rev=""
            psu_mfg=""
    #		print("PSU: %d bytes in model#" % psu[0]
            for byte in range (1, 16):
                if (isprint(chr(psu[byte]))):
                    psu_model += "%c" % psu[byte]
            for byte in range (17, 26):
                if (isprint(chr(psu[byte]))):
                    psu_sn += "%c" % psu[byte]
            for byte in range (27, 29):
                if (isprint(chr(psu[byte]))):
                    psu_rev += "%c" % psu[byte]
            for byte in range (33, 42):
                if (isprint(chr(psu[byte]))):
                    psu_mfg += "%c" % psu[byte]

            psu_date = "%4.4d-%-2.2d-%2.2d" % (psu[29]+2000, psu[30], psu[31])
            print("PSU_MODEL: %s" % psu_model)
            print("PSU_SN: %s" % psu_sn)
            print("PSU_DATE: %s" % psu_date)
            print("PSU_MFG: %s" % psu_mfg)
            print("PSU_MFG_LOC: %d" % psu[42])
            print("PSU_SPEC_VOLTAGE: %d" % ((psu[43]*256)+psu[44]))
            print("PSU_SPEC_CURRENT: %d" % ((psu[46]*256)+psu[47]))
            print("PSU_SPEC_POWER: %d" % ((psu[49]*256)+psu[50]))
            print("PSU_SPEC_MIN_AC: %d" % ((psu[51]*256)+psu[52]))
            print("PSU_SPEC_MAX_AC: %d" % ((psu[53]*256)+psu[54]))
            print("PSU_CHECKSUM: %d" % psu[55])
            print("PSU_FAULT: 0x%x" % psu[56])
    #		if (psu[56] & 0x80): # 0b10000000
    #		if (psu[56] & 0x40): # 0b01000000
    #		if (psu[56] & 0x20): # 0b00100000
            if (psu[56] & 0x10): # 0b00010000
                print("PSU_FAULT: OVER_TEMP")
            if (psu[56] & 0x08): # 
                print("PSU_FAULT: FAN_FAIL")
            if (psu[56] & 0x04): # 
                print("PSU_FAULT: DC_OUTPUT_FAIL")
            if (psu[56] & 0x02): # 
                print("PSU_FAULT: AC_INPUT_FAIL")
            if (psu[56] & 0x01): # 
                print("PSU_FAULT: SEATED_IMPROPERLY")
            print("PSU_FAN_SPEED: %d RPM" % (psu[57]*100))
            if (psu[58] & 0x80):
                print("PSU_TEMP: OUT_OF_RANGE")
            else:
                psu_temp = (psu[58] & 0b01111111)-34;
                print("PSU_TEMP: %d C" % psu_temp)
            print("PSU_ROHS_BYTE: %c" % psu[59])

def fetch_optic_data(optic_bus):
    # import as globals
    global optic_sff;
    global optic_sff_read;
    #
    global optic_ddm;
    global optic_ddm_read;
    #
    global optic_dwdm;
    global optic_dwdm_read;

    # initalize them
    optic_sff =[];
    optic_sff_read = -1;
    optic_ddm =[];
    optic_ddm_read = -1;
    optic_dwdm =[];
    optic_dwdm_read = -1;


    # read SFF data
    while optic_sff_read < 256:
        try:
            if (optic_sff_read == -1):
                optic_sff_tmp = optic_bus.read_i2c_block_data(address_one, 0, 32);
            else:
                optic_sff_tmp = optic_bus.read_i2c_block_data(address_one, optic_sff_read, 32);
            for member in optic_sff_tmp:
                optic_sff.append(member);
            optic_sff_read = len(optic_sff);
#			print("optic_sff_read=%d, %d" % (optic_sff_read, len(optic_sff));
        except IOError:
            break;

    # regular page
    try:
        # write data to set to default page
#		print("Switching optic to page 0";
        optic_bus.write_byte_data(address_two, 127, 0x0);
    except IOError:
        # error switching to dwdm data page
#		print("IOError while trying to switch optic page";
        a=0;

    # read DDM data
#	for byte in range (0, 256):
#		try:
#			value = optic_bus.read_byte_data(address_two, byte);
#			optic_ddm.insert(byte, value);
#			optic_ddm_read = byte+1;
#		# IOError reading DDM data
#		except IOError:
#			a=0;

    while optic_ddm_read < 256:
        try:
            if (optic_ddm_read == -1):
                optic_ddm_tmp = optic_bus.read_i2c_block_data(address_two, 0, 32);
            else:
                optic_ddm_tmp = optic_bus.read_i2c_block_data(address_two, optic_ddm_read, 32);
            for member in optic_ddm_tmp:
                optic_ddm.append(member);
            optic_ddm_read = len(optic_ddm);
#		       print("optic_ddm_read=%d, %d" % (optic_ddm_read, len(optic_ddm));
        except IOError:
            break;


#	print("optic_ddm_read=%d" % optic_ddm_read;

    # if dwdm optic value
    if (optic_sff_read > 65):
        if (optic_sff[65] & 0x40):
            # switch to page with DWDM dwdm data
            try:
                # write data
#				print("Switching to page 2"
                optic_bus.write_byte_data(address_two, 127, 0x2);
            except IOError:
                # error switching to dwdm data page
                a=0;

    # read DWDM-DDM data
    while optic_dwdm_read < 256:
        try:
            if (optic_dwdm_read == -1):
                optic_dwdm_tmp = optic_bus.read_i2c_block_data(address_two, 0, 32);
            else:
                optic_dwdm_tmp = optic_bus.read_i2c_block_data(address_two, optic_dwdm_read, 32);
            for member in optic_dwdm_tmp:
                optic_dwdm.append(member);
            optic_dwdm_read = len(optic_dwdm);
#		      print("optic_dwdm_read=%d, %d" % (optic_dwdm_read, len(optic_dwdm));
        except IOError:
            break;

#	print("optic_dwdm(PAGE2)_read=%d" % optic_dwdm_read;




def read_optic_type():
    # defined in SFF-8024
    # updated 2015-05-15

    if optic_sff[0] == 0x00:
        sff_type_text = ("Unknown or unspecified")
    elif optic_sff[0] == 0x01:
        sff_type_text = ("GBIC")
    elif optic_sff[0] == 0x02:
        sff_type_text = ("Module soldered to motherboard")
    elif optic_sff[0] == 0x03:
        sff_type_text = ("SFP/SFP+/SFP28")
    elif optic_sff[0] == 0x04:
        sff_type_text = ("300 pin XBI")
    elif optic_sff[0] == 0x05:
        sff_type_text = ("XENPAK")
    elif optic_sff[0] == 0x06:
        sff_type_text = ("XFP") # INF-8077i, SFF-8477
    elif optic_sff[0] == 0x07:
        sff_type_text = ("XFF")
    elif optic_sff[0] == 0x08:
        sff_type_text = ("XFP-E")
    elif optic_sff[0] == 0x09:
        sff_type_text = ("XPAK")
    elif optic_sff[0] == 0x0A:
        sff_type_text = ("X2")
    elif optic_sff[0] == 0x0B:
        sff_type_text = ("DWDM-SFP/SFP+")
    elif optic_sff[0] == 0x0C:
        sff_type_text = ("QSFP")
    elif optic_sff[0] == 0x0D:
        sff_type_text = ("QSFP+")
    elif optic_sff[0] == 0x0E:
        sff_type_text = ("CXP")
    elif optic_sff[0] == 0x0F:
        sff_type_text = ("Shielded Mini Multilane HD 4X")
    elif optic_sff[0] == 0x10:
        sff_type_text = ("Shielded Mini Multilane HD 8X")
    elif optic_sff[0] == 0x11:
        sff_type_text = ("QSFP28") # SFF-8636
    elif optic_sff[0] == 0x12:
        sff_type_text = ("CXP2/CFP28")
    elif optic_sff[0] == 0x13:
        sff_type_text = ("CDFP") #style 1/2
    elif optic_sff[0] == 0x14:
        sff_type_text = ("Shielded Mini Multilane HD 4X Fanout")
    elif optic_sff[0] == 0x15:
        sff_type_text = ("Shielded Mini Multilane HD 8X Fanout")
    elif optic_sff[0] == 0x16:
        sff_type_text = ("CDFP Style 3")
    elif optic_sff[0] == 0x17:
        sff_type_text = ("microQSFP")
    elif optic_sff[0] == 0x18:
        sff_type_text = ("QSFP-DD") # INF-8628
    elif optic_sff[0] >= 0x80:
        sff_type_text = ("Vendor Specific")
    else:
        sff_type_text = ("Not yet specified value (%d) check SFF-8024" % optic_sff[0])
    print("SFF Type:", sff_type_text)

    return int(optic_sff[0]);


def read_optic_mod_def():
    # SFF-8472 Physical Device Extended Identifer Values
    # Byte 1 Table 5-2

    if optic_sff[1] == 0x00:
        mod_def_text = ("Not Specified")
    elif optic_sff[1] == 0x01:
        mod_def_text = ("MOD_DEF 1")
    elif optic_sff[1] == 0x02:
        mod_def_text = ("MOD_DEF 2")
    elif optic_sff[1] == 0x03:
        mod_def_text = ("MOD_DEF 3")
    elif optic_sff[1] == 0x04:
        mod_def_text = ("function defined by i2c ID only")
    elif optic_sff[1] == 0x05:
        mod_def_text = ("MOD_DEF 5")
    elif optic_sff[1] == 0x06:
        mod_def_text = ("MOD_DEF 6")
    elif optic_sff[1] == 0x07:
        mod_def_text = ("MOD_DEF 7")
    else:
        mod_def_text = ("Unallocated")

    print("Extended Identifier Value:", mod_def_text)

    return

def read_optic_connector_type(connector_type):
    # defined in SFF-8024 4-3, INF-8077 Table 48

#	connector_type = optic_sff[2]
#	if (optic_sff[0] == 0x06): # XFP
#		connector_type = optic_sff[130];

    if connector_type == 0x00:
        connector_type_text = "Unknown or unspecified"
    elif connector_type == 0x01:
       connector_type_text = "SC"
    elif connector_type == 0x02:
        connector_type_text ="Fibre Channel Style 1 copper connector"
    elif connector_type == 0x03:
        connector_type_text ="Fibre Channel Style 2 copper connector"
    elif connector_type == 0x04:
        connector_type_text ="BNC/TNC"
    elif connector_type == 0x05:
        connector_type_text ="Fiber Channel coax headers"
    elif connector_type == 0x06:
        connector_type_text ="Fiber Jack"
    elif connector_type == 0x07:
        connector_type_text ="LC"
    elif connector_type == 0x08:
        connector_type_text ="MT-RJ"
    elif connector_type == 0x09:
        connector_type_text ="MU"
    elif connector_type == 0x0A:
        connector_type_text ="SG"
    elif connector_type == 0x0B:
        connector_type_text ="Optical Pigtail"
    elif connector_type == 0x0C:
        connector_type_text ="MPO 1x12"
    elif connector_type == 0x0D:
        connector_type_text ="MPO 2x16"
    elif connector_type == 0x20:
        connector_type_text ="HSSDC II"
    elif connector_type == 0x21:
        connector_type_text =("Copper Pigtail")
    elif connector_type == 0x22:
        connector_type_text =("RJ45")
    elif connector_type == 0x23:
        connector_type_text =("No separable connector")
    elif connector_type == 0x24:
        connector_type_text =("MXC 2x16")
    elif connector_type == 0x25:
        connector_type_text =("CS optical connector")
    elif connector_type == 0x26:
        connector_type_text =("SN optical connector (Mini CS)")
    elif connector_type == 0x27:
        connector_type_text =("MPO 2x12")
    elif connector_type == 0x28:
        connector_type_text =("MPO 1x16")
    elif connector_type >= 0x80:
        connector_type_text =("Vendor Specific") # sff-8024 4.3
    else:
        connector_type_text =("Not yet specified value (%d) check SFF-8024" % connector_type)
    print("Connector Type:", connector_type_text)


    return

def read_sff_optic_encoding():
    # SFF 8472 11
    # SFF 8024 4-2


    if optic_sff[11] == 0x00:
        encoding_type_text = ("Unspecified")
    elif optic_sff[11] == 0x01:
        encoding_type_text = ("8B/10B")
    elif optic_sff[11] == 0x02:
        encoding_type_text = ("4B/5B")
    elif optic_sff[11] == 0x03:
        encoding_type_text = ("NRZ")
    elif optic_sff[11] == 0x04:
        encoding_type_text = ("Manchester")
    elif optic_sff[11] == 0x05:
        encoding_type_text = ("SONET Scrambled")
    elif optic_sff[11] == 0x06:
        encoding_type_text = ("64B/66B")
    elif optic_sff[11] == 0x07:
        encoding_type_text = ("256B/257B")
    elif optic_sff[11] == 0x08:
        encoding_type_text = ("PAM-4")
    else:
        encoding_type_text = ("Not yet specified value (%d) check SFF-8024" % optic_sff[11])
    print("Encoding Type:", encoding_type_text)


    return

def read_xfp_encoding():
    # INF-8077 Table 50 Byte 139
    xfp_encoding= [];
    if (optic_sff[139] & 0x80): # bit 7
        xfp_encoding.append('64B/66B');
    if (optic_sff[139] & 0x40): # bit 6
        xfp_encoding.append('8B10B');
    if (optic_sff[139] & 0x20): # bit 5
        xfp_encoding.append('SONET Scrambled');
    if (optic_sff[139] & 0x10): # bit 4
        xfp_encoding.append('NRZ');
    if (optic_sff[139] & 0x8):  # bit 3
        xfp_encoding.append('RZ');
    if (optic_sff[139] & 0x4):  # bit 2
        xfp_encoding.append('139-2-Reserved');
    if (optic_sff[139] & 0x2):  # bit 1
        xfp_encoding.append('139-1-Reserved');
    if (optic_sff[139] & 0x1):  # bit 0
        xfp_encoding.append('139-0-Reserved');
    
    comma=",";
    print("XFP Encoding:", comma.join(xfp_encoding))

def read_xfp_br():
    xfp_min_br = optic_sff[140]*100;
    xfp_max_br = optic_sff[141]*100;
    print("XFP Min-Bitrate = %d Mbps" % xfp_min_br)
    print("XFP Max-Bitrate = %d Mbps" % xfp_max_br)

def read_xfp_lengths():
    xfp_len_km_smf = optic_sff[142];
    xfp_len_om2_mmf = optic_sff[143] *2; # convert to meters
    xfp_len_mmf = optic_sff[144];
    xfp_len_om1_mmf = optic_sff[145];
    xfp_len_copper = optic_sff[146]; # meters
    
    print("XFP Distances:")
    print("\tSMF %d KM" % xfp_len_km_smf)
    print("\tOM2 MMF %d meters" % xfp_len_om2_mmf)
    print("\tOM2 MMF %d meters" % xfp_len_mmf)
    print("\tOM1 MMF %d meters" % xfp_len_om1_mmf)
    print("\tCopper %d meters" % xfp_len_copper)

def read_xfp_technology():
    xfp_device_technology = [];
    if (optic_sff[147] & 0x8): # bit 3
        xfp_device_technology.append('Active Wavelength Control');
    else:
        xfp_device_technology.append('No Wavelength Control');
    if (optic_sff[147] & 0x4): # bit 2
        xfp_device_technology.append('Cooled transmitter');
    else:
        xfp_device_technology.append('Uncooled transmitter');
    if (optic_sff[147] & 0x2): # bit 1
        xfp_device_technology.append('APD Detector');
    else:
        xfp_device_technology.append('PIN detector');
    if (optic_sff[147] & 0x1): # bit 0
        xfp_device_technology.append('Transmitter Tunable');
    else:
        xfp_device_technology.append('Transmitter not Tunable');
    comma=",";
    print("XFP Technology:", comma.join(xfp_device_technology))

    xfp_technology_bits = optic_sff[147] >> 4;
    print("XFP Transmitter Technology:")
    if (xfp_technology_bits == 0x0):
        print("\t850 nm VCSEL")
    elif (xfp_technology_bits == 0x1):
        print("\t1310 nm VCSEL")
    elif (xfp_technology_bits == 0x2):
        print("\t1550 nm VCSEL")
    elif (xfp_technology_bits == 0x3):
        print("\t1310 nm FP")
    elif (xfp_technology_bits == 0x4):
        print("\t1310 nm DFB")
    elif (xfp_technology_bits == 0x5):
        print("\t1550 nm DFB")
    elif (xfp_technology_bits == 0x6):
        print("\t1310 nm EML")
    elif (xfp_technology_bits == 0x7):
        print("\t1550 nm EML")
    elif (xfp_technology_bits == 0x8):
        print("\tCopper")
    else:
        print("\tReserved (%x)" % xfp_technology_bits)

def read_xfp_vendor():
    # INF-8077 5.XX
    # 16 bytes ASCII at bytes 148-163
    vendor = ""

    for byte in range (148, 164):
        vendor=vendor +('%c' % optic_sff[byte])
    print("Vendor:", vendor)

def read_xfp_vendor_pn():
    # INF-8077 5.31
    vendor_pn = ""
    for byte in range (168, 184):
        vendor_pn = vendor_pn + ('%c' % optic_sff[byte])
    print("Vendor PN:", vendor_pn)

def read_xfp_vendor_rev():
    # INF-8077 5.32 (184-185)
    vendor_rev = ""
    for byte in range (184, 186):
        vendor_rev = vendor_rev + ('%c' % optic_sff[byte])
    print("Vendor REV:", vendor_rev)

def read_xfp_wavelength():
    # INF-8077 5.33 (186,187)
    xfp_wavelength = ((optic_sff[186]*256)+optic_sff[187])*.05;

    print("XFP Wavelength: %d nm" % xfp_wavelength)
    # INF-8077 5.34
    print("XFP Wavelength Tolerance: %d nm" % (((optic_sff[188]*256)+optic_sff[189]) *.005))

def read_xfp_max_temp():
    # INF-8077 5.35
    xfp_max_temp_c = optic_sff[190]
    print("XFP Max Temp: %d C" % xfp_max_temp_c)

def read_xfp_cc_base():
    # INF-8077 5.36
    # checksum of bytes 128-190
    calc_cc_base = 0
    for byte in range (128, 191):
        calc_cc_base = calc_cc_base + optic_sff[byte];
    print("XFP CC Base = %x, Calc = %x" % (optic_sff[191], calc_cc_base & 0xff))

def read_xfp_power_supply():
    # INF-8077 5.37
    # 192-195
    xfp_max_power_disp = optic_sff[192] * 20;
    xfp_total_power_disp = optic_sff[193] * 10
    xfp_max_current_5v = (optic_sff[194] >> 4) * 50;
    xfp_max_current_3v = (optic_sff[194] & 0xf) * 100;
    xfp_max_current_1v = (optic_sff[195] >> 4) * 100;
    xfp_max_current_neg5v = (optic_sff[195] & 0xf) * 50;
    print("Maximum Power Dissipation: %d mW" % xfp_max_power_disp)
    print("Maximum Total Power Dissipation (P_Down): %d mW" % xfp_total_power_disp)
    print("Maximum current required 5V: %d mA" % xfp_max_current_5v)
    print("Maximum current required 3V3: %d mA" % xfp_max_current_3v)
    print("Maximum current required 1V8: %d mA" % xfp_max_current_1v)
    print("Maximum current required -5.2V: %d mA" % xfp_max_current_neg5v)

def read_xfp_ext_ddm_type():
    # INF-8077 5.40 Byte 220
    xfp_ddm_type=[];

    if (optic_sff[220] & 0x10): # bit 4
        xfp_ddm_type.append('BER Support');
    else:
        xfp_ddm_type.append('No BER Support');
    if (optic_sff[220] & 0x8): # bit 3
        xfp_ddm_type.append('OMA');
    else:
        xfp_ddm_type.append('Average Power');
    comma=',';
    print("XFP DDM Type:", comma.join(xfp_ddm_type))

def read_xfp_ext_enh_monitoring():
    # INF-8077 5.41 Table 57 Byte 221
    xfp_enh_options=[];
    if (optic_sff[221] & 0x80): # bit 7
        xfp_enh_options.append('VPS supported');
    if (optic_sff[221] & 0x40): # bit 6
        xfp_enh_options.append('Soft TX_DISABLE supported');
    if (optic_sff[221] & 0x20): # bit 5
        xfp_enh_options.append('Soft P_Down supported');
    if (optic_sff[221] & 0x10): # bit 4
        xfp_enh_options.append('VPS LV regulator supported');
    if (optic_sff[221] & 0x8): # bit 3
        xfp_enh_options.append('VPS bypassed regulator modes supported');
    if (optic_sff[221] & 0x4): # bit 2
        xfp_enh_options.append('Active FEC control functions supported');
    if (optic_sff[221] & 0x2): # bit 1
        xfp_enh_options.append('Wavelength tunable supported');
    if (optic_sff[221] & 0x1): # bit 0
        xfp_enh_options.append('CMU Support Mode Supported');
    comma=',';
    print("XFP Enhanced Options:", comma.join(xfp_enh_options))


def read_xfp_cdr():
    xfp_cdr_support=[];
    if (optic_sff[164] & 0x80): # bit 7
        xfp_cdr_support.append('9.95Gb/s');
    if (optic_sff[164] & 0x40): # bit 6
        xfp_cdr_support.append('10.3Gb/s');
    if (optic_sff[164] & 0x20): # bit 5
        xfp_cdr_support.append('10.5Gb/s');
    if (optic_sff[164] & 0x10): # bit 4
        xfp_cdr_support.append('10.7Gb/s');
    if (optic_sff[164] & 0x8): # bit 3
        xfp_cdr_support.append('11.1Gb/s');
    if (optic_sff[164] & 0x4): # bit 2
        xfp_cdr_support.append('Reserved');
    if (optic_sff[164] & 0x2): # bit 1
        xfp_cdr_support.append('Lineside Loopback Mode Supported');
    if (optic_sff[164] & 0x1): # bit 0
        xfp_cdr_support.append('XFP Loopback Mode Supported');
    comma=',';
    print("XFP CDR Support:", comma.join(xfp_cdr_support))

def read_optic_signaling_rate():
    # SFF-8472 12 
    print("Optic Sigaling Rate: %d Mbit" % (optic_sff[12] *100))

def read_optic_rate_identifier():
    # SFF-8472 13

    print("Optic Rate Identifier: %d" % optic_sff[13])

def read_optic_vendor():
    # SFF-8472
    # 16 bytes ASCII at bytes 20-35
    vendor = ""

    for byte in range (20, 36):
        vendor=vendor +('%c' % optic_sff[byte])
    print("Vendor:", vendor)

def read_optic_transciever():
    # SFF-8472 Table 5-3
    # Bytes 3-9
    # Extended 1 byte 36
    #
    # XXX This code is a hack
    # XXX

    # Decode Table 5-3
    if (optic_sff[3] & 0x80):
        print("10G-Base-ER")
    if (optic_sff[3] & 0x40):
        print("10G-Base-LRM")
    if (optic_sff[3] & 0x20):
        print("10G-Base-LR")
    if (optic_sff[3] & 0x10):
        print("10G-Base-SR")
    if (optic_sff[3] & 0x08):
        print("Infiniband 1X SX")
    if (optic_sff[3] & 0x04):
        print("Infiniband 1X LX")
    if (optic_sff[3] & 0x02):
        print("infiniband 1X Copper Active")
    if (optic_sff[3] & 0x01):
        print("Infiniband 1X Copper Passive")

    if (optic_sff[6] & 0x80):
        print("Base-PX")
    if (optic_sff[6] & 0x40):
        print("Base-BX10")
    if (optic_sff[6] & 0x20):
        print("100Base-FX")
    if (optic_sff[6] & 0x10):
        print("100Base-LX/LX10")
    if (optic_sff[6] & 0x08):
        print("1000Base-T")
    if (optic_sff[6] & 0x04):
        print("1000Base-CX")
    if (optic_sff[6] & 0x02):
        print("1000Base-LX")
    if (optic_sff[6] & 0x01):
        print("1000Base-SX")


    print("extended compliance_code %d" % optic_sff[36])


def read_optic_vendor_oui():
    # SFF-8472 4-1
    # 3 bytes 37-39

    vendor_oui=""
    for byte in range (37, 40):
        vendor_oui = vendor_oui + ("%2.2x" % optic_sff[byte])
    print("vendor_oui: %s" % vendor_oui)

def read_xfp_vendor_oui():
    # INF-8077 5.30
    # 3 bytes 165-167

    vendor_oui=""
    for byte in range (165, 168):
        vendor_oui = vendor_oui + ("%2.2x" % optic_sff[byte])
    print("vendor_oui: %s" % vendor_oui)

def read_optic_vendor_partnum():
    # SFF-8472
    # 16 bytes ASCII at bytes 40-55
    vendor_partnum = ""

    for byte in range (40, 56):
        vendor_partnum=vendor_partnum +('%c' % optic_sff[byte])
    print("PN:", vendor_partnum)

def read_optic_vendor_serialnum():
    # SFF-8472
    # 16 bytes ASCII at bytes 68-83
    vendor_serialnum = ""

    for byte in range (68, 84):
        if (optic_sff[byte] == 0 or optic_sff[byte] == 0xff):
            break;
        vendor_serialnum=vendor_serialnum +('%c' % optic_sff[byte])
    print("SN:", vendor_serialnum)

def read_xfp_ext_vendor_sn():
    # INF-8077 5.38 196-211
    vendor_serialnum = ""

    for byte in range (196, 212):
        if (optic_sff[byte] == 0 or optic_sff[byte] == 0xff):
            break;
        vendor_serialnum=vendor_serialnum +('%c' % optic_sff[byte])
    print("Vendor SN:", vendor_serialnum)

def read_optic_datecode():
    # SFF-8472
    # 8 bytes ASCII at bytes 84-91
    vendor_datecode = ""

    for byte in range (84, 92):
        if (optic_sff[byte] == 0 or optic_sff[byte] == 0xff):
            break;
        vendor_datecode = vendor_datecode + ('%c' % optic_sff[byte])

    print("Date Code:", vendor_datecode)

def read_xfp_datecode():
    # INF-8077
    # 8 Bytes ASCII at 212-219
    vendor_datecode = ""
    
    for byte in range (212, 220): 
        if (optic_sff[byte] == 0 or optic_sff[byte] == 0xff):
            break;
        vendor_datecode = vendor_datecode + ('%c' % optic_sff[byte])

    print("Date Code:", vendor_datecode)


def read_optic_rev():
    # SFF-8472
    # 4 bytes ASCII at bytes 56-59
    vendor_hwrev = ""

    for byte in range (56, 60):
        vendor_hwrev=vendor_hwrev +('%c' % optic_sff[byte])
    print("HW Revision:", vendor_hwrev)

def read_optic_distances():
    # SFF-8472
    # bytes 14, 15, 16, 17, 18, 19
    # 14 = SMF in KM
    # 15 = SMF in 100 meter units
    # 16 = 50um OM2 fiber, 10 meter units
    # 17 = 62.5um OM1, 10 meter units
    # 18 = OM4 or DAC cable, units meter
    # 19 = 50um OM4 , 10 meter units

    try:
        smf_km      = optic_sff[14];
        smf_100m    = optic_sff[15];
        mmf_om2_10m = optic_sff[16];
        mmf_om1_10m = optic_sff[17];
        mmf_om4_m   = optic_sff[18];
        mmf_om4_10m = optic_sff[19];
    except IOError:
        return;

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


def read_optic_monitoring_type():
    # SFF-8472
    # byte 92 - Diagnostic Monitoring Type Table 8-5

    print("Monitoring Types:")
    if (optic_sff[92] & 0x80):
        print("\tReserved for legacy diagnostic implementations")
    if (optic_sff[92] & 0x40):
        print("\tDDM Supported")
    if (optic_sff[92] & 0x20):
        print("\tInternally calibrated")
    if (optic_sff[92] & 0x10):
        print("\tExternally calibrated")
    if (optic_sff[92] & 0x08):
        print("\tReceived power measurement type: average") # unset this is OMA
    if (optic_sff[92] & 0x04):
        print("\tAddress Change Required")

    return

def read_option_values():
    # SFF-8472, SFF-8431 and SFF-8690 for some undefined bits
    # bytes 64-65

    print("Option Values")

    if (optic_sff[64] & 0x80):
        print("\tUndefined bit 7 set")
    if (optic_sff[64] & 0x40):
        print("\tUndefined bit 6 set")
    if (optic_sff[64] & 0x20):
        print("\tHigh Power Level Required - Level3")
    if (optic_sff[64] & 0x10):
        print("\tPaging Implemented")
    if (optic_sff[64] & 0x08):
        print("\tInternal Retimer")
    if (optic_sff[64] & 0x04):
        print("\tCooled Transciever")
    if (optic_sff[64] & 0x02):
        print("\tPower Level 2")
    if (optic_sff[64] & 0x01):
        print("\tLinear Receiver Output")

    if (optic_sff[65] & 0x80):
        print("\tReceiver decision threshold supported")
    if (optic_sff[65] & 0x40):
        print("\tTunable Optic")
    if (optic_sff[65] & 0x20):
        print("\tRATE_SELECT supported")
    if (optic_sff[65] & 0x10):
        print("\tTX_DISABLE supported")
    if (optic_sff[65] & 0x08):
        print("\tTX_FAULT implemented")
    if (optic_sff[65] & 0x04):
        print("\tSignal Detect implemented")
    if (optic_sff[65] & 0x02):
        print("\tRx_LOS implemented")
    if (optic_sff[65] & 0x01):
        print("\tUnallocated")


def read_enhanced_options():
    # SFF-8472
    # byte 93 Table 8-6

    if (optic_sff[93] & 0x80):
        print("Optional Alarm/warning flags implemented for all monitored quantities") # table 9-12
    if (optic_sff[93] & 0x40):
        print("Optional soft TX_DISABLE control and monitoring implemented")
    if (optic_sff[93] & 0x20):
        print("Optional soft TX_FAULT monitoring implemented")
    if (optic_sff[93] & 0x10):
        print("Optional soft RX_LOS monitoring implemented")
    if (optic_sff[93] & 0x08):
        print("Optional soft RATE_SELECT control and monitoring implemented")
    if (optic_sff[93] & 0x04):
        print("Optional Application Select control implemented") # SFF-8079
    if (optic_sff[93] & 0x02):
        print("Optional soft Rate Select control implemented") # SFF-8431
    if (optic_sff[93] & 0x01):
        print("Unallocated") # SFF-8472

    return

def read_sff_8472_compliance():
    # SFF-8472
    # byte 94 Table 8-8

    if optic_sff[94] == 0x00:
        sff_8472_compliance_text = ("Unsupported")
    elif optic_sff[94] == 0x01:
        sff_8472_compliance_text = ("SFF-8472 9.3")
    elif optic_sff[94] == 0x02:
        sff_8472_compliance_text = ("SFF-8472 9.5")
    elif optic_sff[94] == 0x03:
        sff_8472_compliance_text = ("SFF-8472 10.2")
    elif optic_sff[94] == 0x04:
        sff_8472_compliance_text = ("SFF-8472 10.4")
    elif optic_sff[94] == 0x05:
        sff_8472_compliance_text = ("SFF-8472 11.0")
    elif optic_sff[94] == 0x06:
        sff_8472_compliance_text = ("SFF-8472 11.3")
    elif optic_sff[94] == 0x07:
        sff_8472_compliance_text = ("SFF-8472 11.4")
    elif optic_sff[94] == 0x08:
        sff_8472_compliance_text = ("SFF-8472 12.3")
    elif optic_sff[94] == 0x09:
        sff_8472_compliance_text = ("SFF-8472 12.4")
    else:
        sff_8472_compliance_text =("Unallocated")
    print("SFF 8472 Compliance:", sff_8472_compliance_text)


def read_optic_frequency():
    # SFF-8472
    # Byte 60-61

    wave_msb = optic_sff[60];
    wave_lsb = optic_sff[61];
    wave_dec = optic_sff[62];

    wavelength = (wave_msb*256)+wave_lsb;
    print("Wavelength: %d.%02dnm" % (wavelength, wave_dec))

def read_xfp_status_bits():
    # XFP MSA INF-8077
    # byte 110 Table 42

    try:
        print("Status Bits:")

        if (optic_sff[110] & 0x80): # bit 7
            print("\tTX_Disable Set")
        if (optic_sff[110] & 0x40): # bit 6
            print("\tSoft TX Disable Selected")
        if (optic_sff[110] & 0x20): # bit 5
            print("\tMOD_NR State set")
        if (optic_sff[110] & 0x10): # bit 4
            print("\tP_Down Set")
        if (optic_sff[110] & 0x08): # bit 3
            print("\tSoft P_Down set")
        if (optic_sff[110] & 0x04): # bit 2
            print("\tInterrupt")
        if (optic_sff[110] & 0x02): # bit 1
            print("\tRX_LOS")
        if (optic_sff[110] & 0x01): # bit 0
            print("\tData NOT Ready")

    except IndexError:
        print("got IndexError on optic_sff byte 110")


def read_sfp_status_bits():
    # SFF-8472
    # byte 110 Table 9-11

    try:
        print("Status Bits:")

        if (optic_sff[110] & 0x80): # bit 7
            print("\tTX_Disable Set")
        if (optic_sff[110] & 0x40): # bit 6
            print("\tSoft TX Disable Selected")
        if (optic_sff[110] & 0x20): # bit 5
            print("\tRS(1) State set")
        if (optic_sff[110] & 0x10): # bit 4
            print("\tRate_Select State")
        if (optic_sff[110] & 0x08): # bit 3
            print("\tSoft Rate_Select selected")
        if (optic_sff[110] & 0x04): # bit 2
            print("\tTX_Fault")
        if (optic_sff[110] & 0x02): # bit 1
            print("\tRX_LOS")
        if (optic_sff[110] & 0x01): # bit 0
            print("\tData Ready")

    except IndexError:
        print("got IndexError on optic_sff byte 110")




def read_optic_temperature():
    # SFF-8472
    # bytes 96-97 Table 9-2

    temp_msb = optic_ddm[96];
    temp_lsb = optic_ddm[97];

    print("Optic Temperature: %4.2fC" % (temp_msb + (temp_lsb/256)))

def read_optic_vcc():
    # SFF-8472
    # bytes 98-99 Table 9-11

    vcc_msb = optic_ddm[98];
    vcc_lsb = optic_ddm[99];

    vcc = (vcc_msb<<8 | vcc_lsb) *0.0001;
    print("Optic VCC: %4.2fV msb = %d, lsb = %d" % (vcc, vcc_msb, vcc_lsb))

def read_laser_temperature():
    # SFF-8472
    # bytes 106-107 Table 9-2

    temp_msb = optic_ddm[106];
    temp_lsb = optic_ddm[107];

    print("Laser Temperature: msb = %d, lsb = %d" % (temp_msb, temp_lsb))


def read_optic_rxpower():
    # SFF-8472
    # bytes 104, 105

    rx_pwr_msb = optic_ddm[104];
    rx_pwr_lsb = optic_ddm[105];

    # need to convert this from mW to dBm, eg:
    # 10 * math.log10(rx_power)
    # 0 = -40 dBm
    temp_pwr = (rx_pwr_msb<<8|rx_pwr_lsb) *0.0001;
    if (temp_pwr > 0):
        rx_pwr = 10 * math.log10((rx_pwr_msb<<8|rx_pwr_lsb) *0.0001);
    else:
        rx_pwr = 0;
    print("Rx Power: (%4.2f) dBm  vs mW %f" % (rx_pwr, ((rx_pwr_msb<<8|rx_pwr_lsb) *0.0001)))

def read_optic_txpower():
    # SFF-8472
    # bytes 102, 103

    tx_pwr_msb = optic_ddm[102];
    tx_pwr_lsb = optic_ddm[103];

    # need to convert this from mW to dBm, eg:
    # 10 * math.log10(rx_power)
    # 0 = -40 dBm
    temp_pwr = (tx_pwr_msb<<8|tx_pwr_lsb) *0.0001;
    if (temp_pwr > 0):
        tx_pwr = 10 * math.log10((tx_pwr_msb<<8|tx_pwr_lsb) *0.0001);
    else:
        tx_pwr = 0;
    print("Tx Power: (%4.2f) mW vs mW = %f" % (tx_pwr, ((tx_pwr_msb<<8|tx_pwr_lsb) *0.0001)))

def read_measured_current():
    # SFF-8472
    # bytes 108-109

    current_msb = optic_ddm[108];
    current_lsb = optic_ddm[109];
    bias = (current_msb<<8 | current_lsb) * 0.002;

    print("Current Draw: %4.2fmA msb = %d, lsb = %d mA" % (bias, current_msb, current_lsb))



def dump_vendor():
    # SFF-8472 Table 4-1
    # bytes 96-127

    vendor_hex = ""
    vendor_isprint = ""

    for byte in range (96, 128):
        vendor_hex=vendor_hex +('%-2.2x' % optic_sff[byte])

        v_char = '%c' % optic_sff[byte]

        if (isprint(v_char)):
            vendor_isprint= vendor_isprint + v_char
        else:
            vendor_isprint= vendor_isprint + ' '
    print(vendor_hex)
    print(vendor_isprint)

def decode_dwdm_data():

    if (optic_dwdm[128] & 0x4):
        print("\tTx Dither Supported")
    if (optic_dwdm[128] & 0x2):
        print("\tTunable DWDM selection by channel number")
    if (optic_dwdm[128] & 0x1):
        print("\tTunable DWDM selection by 50pm steps")

    laser_first_freq_thz = (optic_dwdm[132]*256)+optic_dwdm[133];
    print("\tLaser First Frequency %d THz, (%d, %d)" % (laser_first_freq_thz, optic_dwdm[132], optic_dwdm[133]))

    laser_first_freq_ghz = (optic_dwdm[134]*256)+optic_dwdm[133];
    print("\tLaser First Frequency %d GHz, (%d, %d)" % (laser_first_freq_ghz, optic_dwdm[134], optic_dwdm[135]))

    laser_last_freq_thz = (optic_dwdm[136]*256)+optic_dwdm[137];
    print("\tLaser Last Frequency %d THz, (%d, %d)" % (laser_last_freq_thz, optic_dwdm[136], optic_dwdm[137]))

    laser_last_freq_ghz = (optic_dwdm[138]*256)+optic_dwdm[139];
    print("\tLaser Last Frequency %d GHz, (%d, %d)" % (laser_last_freq_ghz, optic_dwdm[138], optic_dwdm[139]))

    laser_min_grid = (optic_dwdm[140]*256)+optic_dwdm[141];
    print("\tLasers minimum grid: %d Ghz, (%d, %d)" % (laser_min_grid,optic_dwdm[140], optic_dwdm[141]))

    channel_set = (optic_dwdm[144]*256)+optic_dwdm[145];
    print("\tDWDM Channel set: %d (%d, %d)" % (channel_set, optic_dwdm[144], optic_dwdm[145]))

    wavelength_set = (optic_dwdm[146]*256)+optic_dwdm[147];
    print("\tDWDM wavelength set: %2.02f nm (%d, %d)" % (wavelength_set, optic_dwdm[146], optic_dwdm[147]))

    # SFF 8690 Table 4-5
    print("\tDWDM frequency error (152, 153) = %d (%d, %d)" % ((optic_dwdm[152]*256)+optic_dwdm[153],optic_dwdm[152], optic_dwdm[153]))

    print("\tDWDM wavelength error (154, 155) = %d (%d, %d)" % ((optic_dwdm[154]*256)+optic_dwdm[155],optic_dwdm[154], optic_dwdm[155]))

    # SFF 8690 Table 4-6
    if (optic_dwdm[168] & 0x80):
        print("\tDWDM Reserved bit set")
    if (optic_dwdm[168] & 0x40):
        print("\tTEC Fault")
    if (optic_dwdm[168] & 0x20):
        print("\tWavelength Unlocked")
    if (optic_dwdm[168] & 0x10):
        print("\tTxTune - Transmit not ready due to tuning")

    # SFF 8690 Table 4-7
    if (optic_dwdm[172] & 0x40):
        print("\tL-TEC Fault")
    if (optic_dwdm[172] & 0x20):
        print("\tL-Wavelength-Unlocked")
    if (optic_dwdm[172] & 0x10):
        print("\tL-Bad Channel")
    if (optic_dwdm[172] & 0x8):
        print("\tL-New Channel")
    if (optic_dwdm[172] & 0x4):
        print("\tL-Unsupported TX Dither")


# read the board type
# 0x00-0f = Board Name
# 0x10-1f = Board Sub-type
# 0x20-2f = Mfg date
# 0x30-3f = Board Test Time
# 0x40-4f = Board port types
#  0x40 = SFP ports
#  0x41 = QSFP ports
#  0x42 = XFP ports
#  0x43 = CFP ports
#  0x44 = CFP2 ports
#  0x45 = CFP4 ports
#  0x46 = microQSFP ports
# 0x50-5f = board serial number
#      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f    0123456789abcdef
# 00: 57 42 4f 2d 53 49 58 76 31 ff ff ff ff ff ff ff    WBO-SIXv1.......
# 10: 48 57 52 45 56 2d 30 2e 31 41 ff ff ff ff ff ff    HWREV-0.1A......
# 20: 32 30 31 35 31 31 31 37 ff ff ff ff ff ff ff ff    20151117........
# 30: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
# 40: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
# 50: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
# 60: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
# 70: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................

def read_board_id(bus, i2cbus, mux, mux_val):
#	print("Should read 0x57 to ID the board type")
    board_type=[];
    board_type_read = -1;

    while board_type_read < 128:
        try:
            if (board_type_read == -1):
                board_type_tmp = bus.read_i2c_block_data(0x57, 0, 32);
            else:
                board_type_tmp = bus.read_i2c_block_data(0x57, board_type_read, 32);
            for member in board_type_tmp:
                board_type.append(member);
            board_type_read = len(board_type);
#		      print("board_type_read=%d, %d" % (board_type_read, len(board_type)))
        except IOError:
#			print("Error reading board ID")
            break;

#	print("Read %d bytes checking board_type" % board_type_read)
    if (board_type_read >= 128):
        board_name ="";
        board_sub_type ="";
        board_mfg_date="";
        board_test_time="";
        board_sn="";
        for byte in range (0, 0x10):
            if (isprint(chr(board_type[byte]))):
                board_name += "%c" % board_type[byte];
        for byte in range (0x10, 0x20):
            if (isprint(chr(board_type[byte]))):
                board_sub_type += "%c" % board_type[byte];
        for byte in range (0x20, 0x30):
            if (isprint(chr(board_type[byte]))):
                board_mfg_date += "%c" % board_type[byte];
        for byte in range (0x30, 0x40):
            if (isprint(chr(board_type[byte]))):
                board_test_time += "%c" % board_type[byte];
        for byte in range (0x50, 0x60):
            if (isprint(chr(board_type[byte]))):
                board_sn += "%c" % board_type[byte];

        print("--> BOARD INFO <--")
        print("NAME: %s" % board_name)
        print("SUB_TYPE: %s" % board_sub_type)
        print("MFG_DATE: %s" % board_mfg_date)
        print("TEST_TIME: %s" % board_test_time)
        print("SERIAL: %s" % board_sn)


def read_optic_xfp_signal_conditioner_control():
    # FIXME check bitwise operator
    xfp_speed = optic_sff[1]
    if (xfp_speed > 0):
        xfp_speed = optic_sff[1] >> 4;
        print("XFP Speed = %d, %x" % (xfp_speed, optic_sff[1]))

def read_optic_xfp_thresholds():
    # INF-8077
    print("FIXME: read_optic_xfp_thresholds Unimplemented")

def read_optic_xfp_vps_control_registers():
    # INF-8077 Table 33 Bytes 58-59
    print("XFP: Lowest Voltage Supported: %d" % (optic_sff[58]>>4))
    print("XFP: Voltage Supplied on VCC2: %d" % (optic_sff[58] & 0xf))
    print("XFP: Voltage Supported with Bypasss regulator: %d" % (optic_sff[59]<<4))
    print("XFP: Regulator bypass mode: %d" % (optic_sff[59] & 0x1))

def read_xfp_transciever():
    # INF-8077 Table 49
    #
    
    transciever_type=[];
    if (optic_sff[131] & 0x80): # bit 7
        transciever_type.append('10Gbase-SR')
    if (optic_sff[131] & 0x40): # bit 6
        transciever_type.append('10GBase-LR')
    if (optic_sff[131] & 0x20): # bit 5
        transciever_type.append('10Gbase-ER');
    if (optic_sff[131] & 0x10): # bit 4
        transciever_type.append('10Gbase-LRM');
    if (optic_sff[131] & 0x8): # bit 3
        transciever_type.append('10Gbase-SW');
    if (optic_sff[131] & 0x4): # bit 2
        transciever_type.append('10Gbase-LW');
    if (optic_sff[131] & 0x2): # bit 1
        transciever_type.append('10Gbase-EW');
    if (optic_sff[131] & 0x1): # bit 0
        transciever_type.append('131-0-Reserved');

    if (optic_sff[132] & 0x80): # bit 7
        transciever_type.append('1200-MX-SN-I');
    if (optic_sff[132] & 0x40): # bit 6
        transciever_type.append('1200-SM-LL-L');
    if (optic_sff[132] & 0x20): # bit 5
        transciever_type.append('132-5-Reserved');
    if (optic_sff[132] & 0x10): # bit 4
        transciever_type.append('132-4-Reserved');
    if (optic_sff[132] & 0x8):  # bit 3
        transciever_type.append('132-3-Reserved');
    if (optic_sff[132] & 0x4):  # bit 2
        transciever_type.append('132-2-Reserved');
    if (optic_sff[132] & 0x2):  # bit 1
        transciever_type.append('132-1-Reserved');
    if (optic_sff[132] & 0x1):  # bit 0
        transciever_type.append('132-0-Reserved');

    if (optic_sff[133] & 0x80): # bit 7
        transciever_type.append('133-Reserved');
    if (optic_sff[133] & 0x40): # bit 6
        transciever_type.append('133-Reserved');
    if (optic_sff[133] & 0x20): # bit 5
        transciever_type.append('133-Reserved');
    if (optic_sff[133] & 0x10): # bit 4
        transciever_type.append('133-Reserved');
    if (optic_sff[133] & 0x8):  # bit 3
        transciever_type.append('133-Reserved');
    if (optic_sff[133] & 0x4):  # bit 2
        transciever_type.append('133-Reserved');
    if (optic_sff[133] & 0x2):  # bit 1
        transciever_type.append('133-Reserved');
    if (optic_sff[133] & 0x1):  # bit 0
        transciever_type.append('133-Reserved');

    if (optic_sff[134] & 0x80): # bit 7
        transciever_type.append('1000Base-SX/1xFC MMF');
    if (optic_sff[134] & 0x40): # bit 6
        transciever_type.append('1000Base-LX/1xFC SMF');
    if (optic_sff[134] & 0x20): # bit 5
        transciever_type.append('2xFC MMF');
    if (optic_sff[134] & 0x10): # bit 4
        transciever_type.append('2xFC SMF');
    if (optic_sff[134] & 0x8):  # bit 3
        transciever_type.append('OC-48-SR');
    if (optic_sff[134] & 0x4):  # bit 2
        transciever_type.append('OC-48-IR');
    if (optic_sff[134] & 0x2):  # bit 1
        transciever_type.append('OC-48-LR');
    if (optic_sff[134] & 0x1):  # bit 0
        transciever_type.append('134-Reserved');

    if (optic_sff[135] & 0x80): # bit 7
        transciever_type.append('I-64.1r');
    if (optic_sff[135] & 0x40): # bit 6
        transciever_type.append('I-64.1');
    if (optic_sff[135] & 0x20): # bit 5
        transciever_type.append('I-64.2r');
    if (optic_sff[135] & 0x10): # bit 4
        transciever_type.append('I-64.2');
    if (optic_sff[135] & 0x8):  # bit 3
        transciever_type.append('I-64.3');
    if (optic_sff[135] & 0x4):  # bit 2
        transciever_type.append('I-64.5');
    if (optic_sff[135] & 0x2):  # bit 1
        transciever_type.append('135-1-Reserved');
    if (optic_sff[135] & 0x1):  # bit 0
        transciever_type.append('135-0-Reserved');

    if (optic_sff[136] & 0x80): # bit 7
        transciever_type.append('S-64.1');
    if (optic_sff[136] & 0x40): # bit 6
        transciever_type.append('S-64.2a');
    if (optic_sff[136] & 0x20): # bit 5
        transciever_type.append('S-64.2b');
    if (optic_sff[136] & 0x10): # bit 4
        transciever_type.append('S-64.3a');
    if (optic_sff[136] & 0x8):  # bit 3
        transciever_type.append('S-64.3b');
    if (optic_sff[136] & 0x4):  # bit 2
        transciever_type.append('S-64.5a');
    if (optic_sff[136] & 0x2):  # bit 1
        transciever_type.append('S-64.5b');
    if (optic_sff[136] & 0x1):  # bit 0
        transciever_type.append('136-0-Reserved');

    if (optic_sff[137] & 0x80): # bit 7
        transciever_type.append('L-64.1');
    if (optic_sff[137] & 0x40): # bit 6
        transciever_type.append('L-64.2a');
    if (optic_sff[137] & 0x20): # bit 5
        transciever_type.append('L-64.2b');
    if (optic_sff[137] & 0x10): # bit 4
        transciever_type.append('L-64.2c');
    if (optic_sff[137] & 0x8):  # bit 3
        transciever_type.append('L-64.3');
    if (optic_sff[137] & 0x4):  # bit 2
        transciever_type.append('G.959.1 P1L1-2D2');
    if (optic_sff[137] & 0x2):  # bit 1
        transciever_type.append('137-1-Reserved');
    if (optic_sff[137] & 0x1):  # bit 0
        transciever_type.append('137-0-Reserved');

    if (optic_sff[138] & 0x80): # bit 7
        transciever_type.append('V-64.2a');
    if (optic_sff[138] & 0x40): # bit 6
        transciever_type.append('V-64-2b');
    if (optic_sff[138] & 0x20): # bit 5
        transciever_type.append('V-64-3');
    if (optic_sff[138] & 0x10): # bit 4
        transciever_type.append('138-Reserved');
    if (optic_sff[138] & 0x8):  # bit 3
        transciever_type.append('138-Reserved');
    if (optic_sff[138] & 0x4):  # bit 2
        transciever_type.append('138-Reserved');
    if (optic_sff[138] & 0x2):  # bit 1
        transciever_type.append('138-Reserved');
    if (optic_sff[138] & 0x1):  # bit 0
        transciever_type.append('138-Reserved');

    comma=',';
    print("Transciever Type:", comma.join(transciever_type))

def read_optic_xfp_fec_control_registers():
    # INF-8077 I Table 38 
    xfp_amplitude_adustment = optic_sff[76];
    xfp_phase_adjustment = optic_sff[77];
    print("XFP Amplitude Adustment: %d" % xfp_amplitude_adustment)
    print("XFP Phase Adjustment: %d" % xfp_phase_adjustment)

def read_optic_xfp_flags():
    # INF-8077 I Table 39 Bytes 80-95
    xfp_flags =[];

    if (optic_sff[80] & 0x80): # bit 7
        xfp_flags.append('L-Temp High Alarm');
    if (optic_sff[80] & 0x40): # bit 6
        xfp_flags.append('L-Temp Low Alarm');
    if (optic_sff[80] & 0x20): # bit 5
        xfp_flags.append('80-5-Reserved');
    if (optic_sff[80] & 0x10): # bit 4
        xfp_flags.append('80-4-Reserved');
    if (optic_sff[80] & 0x8):  # bit 3
        xfp_flags.append('L-TX Bias High Alarm');
    if (optic_sff[80] & 0x4):  # bit 2
        xfp_flags.append('L-TX Biase Low Alarm');
    if (optic_sff[80] & 0x2):  # bit 1
        xfp_flags.append('L-TX Power High Alarm');
    if (optic_sff[80] & 0x1):  # bit 0
        xfp_flags.append('L-TX Power Low Alarm');

    if (optic_sff[81] & 0x80): # bit 7
        xfp_flags.append('L-RX Power High Alarm');
    if (optic_sff[81] & 0x40): # bit 6
        xfp_flags.append('L-RX Power Low Alarm');
    if (optic_sff[81] & 0x20): # bit 5
        xfp_flags.append('L-AUX-1 High Alarm');
    if (optic_sff[81] & 0x10): # bit 4
        xfp_flags.append('L-AUX-1 Low Alarm');
    if (optic_sff[81] & 0x8):  # bit 3
        xfp_flags.append('L-AUX-2 High Alarm');
    if (optic_sff[81] & 0x4):  # bit 2
        xfp_flags.append('L-AUX-2 Low Alarm');
    if (optic_sff[81] & 0x2):  # bit 1
        xfp_flags.append('81-1-Reserved');
    if (optic_sff[81] & 0x1):  # bit 0
        xfp_flags.append('81-0-Reserved');

    if (optic_sff[82] & 0x80): # bit 7
        xfp_flags.append('L-Temp High Warning');
    if (optic_sff[82] & 0x40): # bit 6
        xfp_flags.append('L-Temp Low Warning');
    if (optic_sff[82] & 0x20): # bit 5
        xfp_flags.append('Reserved')
    if (optic_sff[82] & 0x10): # bit 4
        xfp_flags.append('Reserved')
    if (optic_sff[82] & 0x8):  # bit 3
        xfp_flags.append('L-TX Bias High Warning');
    if (optic_sff[82] & 0x4):  # bit 2
        xfp_flags.append('L-TX Bias Low Warning');
    if (optic_sff[82] & 0x2):  # bit 1
        xfp_flags.append('L-TX Power High Warning');
    if (optic_sff[82] & 0x1):  # bit 0
        xfp_flags.append('L-TX Power Low Warning');

    if (optic_sff[83] & 0x80): # bit 7
        xfp_flags.append('L-RX Power High Warning');
    if (optic_sff[83] & 0x40): # bit 6
        xfp_flags.append('L-RX Power Low Warning');
    if (optic_sff[83] & 0x20): # bit 5
        xfp_flags.append('L-AUX-1 High Warning');
    if (optic_sff[83] & 0x10): # bit 4
        xfp_flags.append('L-AUX-1 Low Warning');
    if (optic_sff[83] & 0x8):  # bit 3
        xfp_flags.append('L-AUX-2 High Warning');
    if (optic_sff[83] & 0x4):  # bit 2
        xfp_flags.append('L-AUX-2 Low Warning');
    if (optic_sff[83] & 0x2):  # bit 1
        xfp_flags.append('Reserved');
    if (optic_sff[83] & 0x1):  # bit 0
        xfp_flags.append('Reserved');

    if (optic_sff[84] & 0x80): # bit 7
        xfp_flags.append('L-TX Not Ready');
    if (optic_sff[84] & 0x40): # bit 6
        xfp_flags.append('L-TX Fault');
    if (optic_sff[84] & 0x20): # bit 5
        xfp_flags.append('L-TX CDR not Locked');
    if (optic_sff[84] & 0x10): # bit 4
        xfp_flags.append('L-RX Not Ready');
    if (optic_sff[84] & 0x8):  # bit 3
        xfp_flags.append('L-RX LOS');
    if (optic_sff[84] & 0x4):  # bit 2
        xfp_flags.append('L-RX CDR not Locked');
    if (optic_sff[84] & 0x2):  # bit 1
        xfp_flags.append('L-Module Not Ready');
    if (optic_sff[84] & 0x1):  # bit 0
        xfp_flags.append('L-Reset Complete');

    if (optic_sff[85] & 0x80): # bit 7
        xfp_flags.append('L-APD Supply Fault');
    if (optic_sff[85] & 0x40): # bit 6
        xfp_flags.append('L-TEC Fault');
    if (optic_sff[85] & 0x20): # bit 5
        xfp_flags.append('L-Wavelength Unlocked');
    if (optic_sff[85] & 0x10): # bit 4
        xfp_flags.append('Reserved');
    if (optic_sff[85] & 0x8):  # bit 3
        xfp_flags.append('Reserved');
    if (optic_sff[85] & 0x4):  # bit 2
        xfp_flags.append('Reserved');
    if (optic_sff[85] & 0x2):  # bit 1
        xfp_flags.append('Reserved');
    if (optic_sff[85] & 0x1):  # bit 0
        xfp_flags.append('Reserved');

    if (optic_sff[86] & 0x80): # bit 7
        xfp_flags.append('L-VCC5 High Alarm');
    if (optic_sff[86] & 0x40): # bit 6
        xfp_flags.append('L-VCC5 Low Alarm');
    if (optic_sff[86] & 0x20): # bit 5
        xfp_flags.append('L-VCC3 High Alarm');
    if (optic_sff[86] & 0x10): # bit 4
        xfp_flags.append('L-VCC3 Low Alarm');
    if (optic_sff[86] & 0x8):  # bit 3
        xfp_flags.append('L-VCC2 High Alarm');
    if (optic_sff[86] & 0x4):  # bit 2
        xfp_flags.append('L-VCC2 Low Alarm');
    if (optic_sff[86] & 0x2):  # bit 1
        xfp_flags.append('L-Vee5 High Alarm');
    if (optic_sff[86] & 0x1):  # bit 0
        xfp_flags.append('L-Vee5 Low Alarm');

    if (optic_sff[87] & 0x80): # bit 7
        xfp_flags.append('L-VCC5 High Warning');
    if (optic_sff[87] & 0x40): # bit 6
        xfp_flags.append('L-VCC5 Low Warning');
    if (optic_sff[87] & 0x20): # bit 5
        xfp_flags.append('L-VCC3 High Warning');
    if (optic_sff[87] & 0x10): # bit 4
        xfp_flags.append('L-VCC3 Low Warning');
    if (optic_sff[87] & 0x8):  # bit 3
        xfp_flags.append('L-VCC2 High Warning');
    if (optic_sff[87] & 0x4):  # bit 2
        xfp_flags.append('L-VCC2 Low Warning');
    if (optic_sff[87] & 0x2):  # bit 1
        xfp_flags.append('L-Vee5 High Warning');
    if (optic_sff[87] & 0x1):  # bit 0
        xfp_flags.append('L-Vee5 Low Warning');

    if (optic_sff[88] & 0x80): # bit 7
        xfp_flags.append('M-Temp High Alarm');
    if (optic_sff[88] & 0x40): # bit 6
        xfp_flags.append('M-Temp Low Alarm');
    if (optic_sff[88] & 0x20): # bit 5
        xfp_flags.append('Reserved');
    if (optic_sff[88] & 0x10): # bit 4
        xfp_flags.append('Reserved');
    if (optic_sff[88] & 0x8):  # bit 3
        xfp_flags.append('M-TX Bias High Alarm');
    if (optic_sff[88] & 0x4):  # bit 2
        xfp_flags.append('M-TX Bias Low Alarm');
    if (optic_sff[88] & 0x2):  # bit 1
        xfp_flags.append('M-TX Power High Alarm');
    if (optic_sff[88] & 0x1):  # bit 0
        xfp_flags.append('M-TX Power Low Alarm');

    if (optic_sff[89] & 0x80): # bit 7
        xfp_flags.append('M-RX Power High Alarm');
    if (optic_sff[89] & 0x40): # bit 6
        xfp_flags.append('M-RX Power Low Alarm');
    if (optic_sff[89] & 0x20): # bit 5
        xfp_flags.append('M-AUX-1 High Alarm');
    if (optic_sff[89] & 0x10): # bit 4
        xfp_flags.append('M-AUX-1 Low Alarm');
    if (optic_sff[89] & 0x8):  # bit 3
        xfp_flags.append('M-AUX-2 High Alarm');
    if (optic_sff[89] & 0x4):  # bit 2
        xfp_flags.append('M-AUX-2 Low Alarm');
    if (optic_sff[89] & 0x2):  # bit 1
        xfp_flags.append('Reserved');
    if (optic_sff[89] & 0x1):  # bit 0
        xfp_flags.append('Reserved');

    if (optic_sff[90] & 0x80): # bit 7
        xfp_flags.append('M-Temp High Warning');
    if (optic_sff[90] & 0x40): # bit 6
        xfp_flags.append('M-Temp Low Warning');
    if (optic_sff[90] & 0x20): # bit 5
        xfp_flags.append('Reserved');
    if (optic_sff[90] & 0x10): # bit 4
        xfp_flags.append('Reserved');
    if (optic_sff[90] & 0x8):  # bit 3
        xfp_flags.append('M-TX Bias High Warning');
    if (optic_sff[90] & 0x4):  # bit 2
        xfp_flags.append('M-TX Bias Low Warning');
    if (optic_sff[90] & 0x2):  # bit 1
        xfp_flags.append('M-Tx Power High Warning');
    if (optic_sff[90] & 0x1):  # bit 0
        xfp_flags.append('M-Tx Power Low Warning');

    if (optic_sff[91] & 0x80): # bit 7
        xfp_flags.append('M-Rx Power High Warning');
    if (optic_sff[91] & 0x40): # bit 6
        xfp_flags.append('M-Rx Power Low Warning');
    if (optic_sff[91] & 0x20): # bit 5
        xfp_flags.append('M-AUX-1 High Warning');
    if (optic_sff[91] & 0x10): # bit 4
        xfp_flags.append('M-AUX-1 Low Warning');
    if (optic_sff[91] & 0x8):  # bit 3
        xfp_flags.append('M-AUX-2 High Warning');
    if (optic_sff[91] & 0x4):  # bit 2
        xfp_flags.append('M-AUX-2 Low Warning');
    if (optic_sff[91] & 0x2):  # bit 1
        xfp_flags.append('Reserved');
    if (optic_sff[91] & 0x1):  # bit 0
        xfp_flags.append('Reserved');

    if (optic_sff[92] & 0x80): # bit 7
        xfp_flags.append('M-TX Not Ready');
    if (optic_sff[92] & 0x40): # bit 6
        xfp_flags.append('M-TX Fault');
    if (optic_sff[92] & 0x20): # bit 5
        xfp_flags.append('M-TX CDR not Locked');
    if (optic_sff[92] & 0x10): # bit 4
        xfp_flags.append('M-RX not Ready');
    if (optic_sff[92] & 0x8):  # bit 3
        xfp_flags.append('M-RX LOS');
    if (optic_sff[92] & 0x4):  # bit 2
        xfp_flags.append('M-RX CDR not Locked');
    if (optic_sff[92] & 0x2):  # bit 1
        xfp_flags.append('M-Module not Ready');
    if (optic_sff[92] & 0x1):  # bit 0
        xfp_flags.append('M-Reset Complete');

    if (optic_sff[93] & 0x80): # bit 7
        xfp_flags.append('M-APD Supply Fault');
    if (optic_sff[93] & 0x40): # bit 6
        xfp_flags.append('M-TEC Fault');
    if (optic_sff[93] & 0x20): # bit 5
        xfp_flags.append('M-Wavelength Unlocked');
    if (optic_sff[93] & 0x10): # bit 4
        xfp_flags.append('Reserved');
    if (optic_sff[93] & 0x8):  # bit 3
        xfp_flags.append('Reserved');
    if (optic_sff[93] & 0x4):  # bit 2
        xfp_flags.append('Reserved');
    if (optic_sff[93] & 0x2):  # bit 1
        xfp_flags.append('Reserved');
    if (optic_sff[93] & 0x1):  # bit 0
        xfp_flags.append('Reserved');

    if (optic_sff[94] & 0x80): # bit 7
        xfp_flags.append('M-VCC5 High Alarm');
    if (optic_sff[94] & 0x40): # bit 6
        xfp_flags.append('M-VCC5 Low Alarm');
    if (optic_sff[94] & 0x20): # bit 5
        xfp_flags.append('M-VCC3 High Alarm');
    if (optic_sff[94] & 0x10): # bit 4
        xfp_flags.append('M-VCC3 Low Alarm');
    if (optic_sff[94] & 0x8):  # bit 3
        xfp_flags.append('M-VCC2 High Alarm');
    if (optic_sff[94] & 0x4):  # bit 2
        xfp_flags.append('M-VCC2 Low Alarm');
    if (optic_sff[94] & 0x2):  # bit 1
        xfp_flags.append('M-Vee5 High Alarm');
    if (optic_sff[94] & 0x1):  # bit 0
        xfp_flags.append('M-Vee5 Low Alarm');

    if (optic_sff[95] & 0x80): # bit 7
        xfp_flags.append('M-VCC5 High Warning');
    if (optic_sff[95] & 0x40): # bit 6
        xfp_flags.append('M-VCC5 Low Warning');
    if (optic_sff[95] & 0x20): # bit 5
        xfp_flags.append('M-VCC3 High Warning');
    if (optic_sff[95] & 0x10): # bit 4
        xfp_flags.append('M-VCC3 Low Warning');
    if (optic_sff[95] & 0x8):  # bit 3
        xfp_flags.append('M-VCC2 High Warning');
    if (optic_sff[95] & 0x4):  # bit 2
        xfp_flags.append('M-VCC2 Low Warning');
    if (optic_sff[95] & 0x2):  # bit 1
        xfp_flags.append('M-Vee5 High Warning');
    if (optic_sff[95] & 0x1):  # bit 0
        xfp_flags.append('M-Vee5 Low Warning');

    comma=',';
    print("XFP Flags:", comma.join(xfp_flags))

def read_optic_xfp_ad_readout():
    # INF-8077 I Table 41
    xfp_temp = (optic_sff[96]<<8)+optic_sff[97];
    xfp_tx_bias = (optic_sff[100]<<8)+optic_sff[101]
    xfp_tx_power = (optic_sff[102]<<8)+optic_sff[103]
    xfp_rx_power = (optic_sff[104]<<8)+optic_sff[105]
    xfp_aux1 = (optic_sff[106]<<8)+optic_sff[107]
    xfp_aux2 = (optic_sff[108]<<8)+optic_sff[109]
    print("XFP Temp: %d" % xfp_temp)
    print("XFP TX Bias: %d" % xfp_tx_bias)
    print("XFP TX Power: %d" % xfp_tx_power)
    print("XFP RX Power: %d" % xfp_rx_power)
    print("XFP Aux1: %d" % xfp_aux1)
    print("XFP Aux2: %d" % xfp_aux2)

# actually read data from the optic at this location
def process_optic_data(bus, i2cbus, mux, mux_val, hash_key):
    # read SFF and DDM data
    if real_hardware: 
        fetch_optic_data(bus)

#	print("Read %d bytes of SFF data" % optic_sff_read;
#	print("Read %d bytes of DDM data" % optic_ddm_read;
#	print("Read %d bytes of DWDM data" % optic_dwdm_read;

    if (optic_sff_read == -1):
#		print("No optic in slot (bus %d, mux 0x%x, muxval %d)" % (i2cbus, mux, mux_val);
        return;
    if (optic_sff_read < 128):
        print("Error reading optic bus %d mux_val %d, read %d bytes and %d bytes" % (i2cbus, mux_val, optic_sff_read, optic_ddm_read))
        return;

    if (optic_sff_read >=128):
        optic_type = read_optic_type() # SFF
        if (optic_type == 0x06): # XFP
            read_optic_xfp_signal_conditioner_control()
            read_optic_xfp_thresholds()
            read_optic_xfp_vps_control_registers()
            #read_optic_xfp_ber_reporting()
            #read_optic_xfp_wavelength_control_registers()
            read_optic_xfp_fec_control_registers()
            read_optic_xfp_flags()
            read_optic_xfp_ad_readout()
            read_xfp_status_bits()
            if (optic_sff[127] == 0x01):
                read_optic_connector_type(optic_sff[130])
                read_xfp_transciever()
                read_xfp_encoding()
                read_xfp_br()
                read_xfp_lengths()
                read_xfp_technology()
                read_xfp_vendor()
                read_xfp_cdr()
                read_xfp_vendor_oui()
                read_xfp_vendor_pn()
                read_xfp_vendor_rev()
                read_xfp_wavelength()
                read_xfp_max_temp()
                read_xfp_cc_base()
#				# extended id fields
                read_xfp_power_supply()
                read_xfp_ext_vendor_sn() # 
                read_xfp_datecode() # table 55
                read_xfp_ext_ddm_type() # table 56
                read_xfp_ext_enh_monitoring() # Table 57
                #
                # FIXME do this
                #read_xfp_aux_types()
            #
#			dump_vendor()
        else:
            read_optic_mod_def();
            read_optic_connector_type(optic_sff[2])
            read_sff_optic_encoding()
            read_optic_signaling_rate()
            read_optic_rate_identifier()
            read_optic_vendor()
            read_optic_vendor_oui()
            read_optic_vendor_partnum()
            read_optic_vendor_serialnum()
            read_optic_rev()
            read_optic_datecode()
            read_optic_transciever()
            read_optic_distances()
            read_optic_frequency()
    
            read_optic_monitoring_type()
            read_option_values()
    
            read_enhanced_options();
            read_sff_8472_compliance();
            read_sfp_status_bits()
    
            # if optic is disabled re-enable it
            if ((optic_sff[110] & 0x40) | (optic_sff[110] & 0x80)):
                print("%x would be %x" % (optic_sff[110], (optic_sff[110]&~(0x80 + 0x40))))
                try:
                    bus.write_byte_data(address_one, 110, optic_sff[110]&~(0x80 + 0x40))
                except IOError:
                    print("Unable to set optic to Soft-TX-Enable")
    
            if (optic_ddm_read >=128):
                read_optic_temperature()
                read_optic_rxpower()
                read_optic_txpower();
    
                read_laser_temperature()
                read_optic_vcc()
                read_measured_current()
                # if the optic is dwdm
                if (optic_sff[65] & 0x40):
                    print("Reading/decoding dwdm")
                    if (optic_dwdm_read >= 128):
                        decode_dwdm_data()


#		dump_vendor()

    return optic_sff_read;
## end process_optic_data



## main()

def poll_busses():

    optics_exist = { };
    temps = { };
    retval = -1;

    # iterate through i2c busses
    for busno in range (0, 2):

        print("Optic(s) on slot(Bus) number %d:" % busno)
        bus = smbus.SMBus(busno)

        for mux_loc in range (0x70, 0x77):
            mux_exist = 0
            any_mux_exist = 0
            ## detect if PCA9547 is there by reading 0x70-0x77
            # perhaps also 0x70 - 0x77
            try:
                mux = bus.read_byte_data(mux_loc, 0x4)
                mux_exist = 1
                any_mux_exist = 1
#				print("Found pca954x at i2c %d at %-2x" % (busno, mux_loc))
            except IOError:
                mux_exist=0;

            if (mux_exist == 1):
                for i2csel in range (8, 16):
#					print("---- > Switching i2c(%d) to %d-0x%-2x" % (busno, (mux_loc-0x70), i2csel))
                    key = "%d-%d-%d" % (busno, mux_loc-0x70, i2csel - 0x9);
#					print("HASH KEY = %s" % key)
                    try:
                        bus.write_byte_data(mux_loc,0x04,i2csel)
                    except IOError:
                        print("i2c switch failed for bus %d location 0x%-2x" % (busno, i2csel))

                    retval = process_optic_data(bus, busno, mux_loc, i2csel, key);
                    if (retval > 0):
                        optics_exist[key] = 1;
                    if ((i2csel == 15) or (i2csel == 9)):
                        try:
                            # read the flash chip that says what board it is
#							print("Should read 0x57")
                            read_board_id(bus, busno, mux_loc, i2csel);
                        except IOError:
                            # Error reading flash chip
                            print("Error reading board ID via i2c, reseat board?")

                        try:
                            # try to read TMP102 sensor

                            msb = bus.read_byte_data(tmp102_address, 0x0);
                            lsb = bus.read_byte_data(tmp102_address, 0x1);

                            temp = ((msb << 8) | lsb);
                            temp >>=4;
                            if(temp & (1<<11)):
                                temp |= 0xf800;

                            tempC = temp*0.0625;
                            tempF = (1.8* tempC) + 32;
                            print("PCB Temperature appears to be %2.2fC or %2.2fF msb %d lsb %d" % (tempC, tempF, msb, lsb))
                            temps[key] = tempF;

                        except IOError:
                            temp = -1;
                        # end try TMP102

                # end i2csel

                # reset the i2c mux back to the first channel to avoid address conflicts
                try:
                    bus.write_byte_data(mux_loc, 0x04, 8);
                except IOError:
                    print("Unable to set mux back to first channel")
        # end for mux_loc

        if (any_mux_exist == 0):
            try:
                msb = bus.read_byte_data(tmp102_address, 0x0);
                lsb = bus.read_byte_data(tmp102_address, 0x1);

                temp = ((msb << 8) | lsb);
                temp >>=4;
                if(temp & (1<<11)):
                    temp |= 0xf800;

                tempC = temp*0.0625;
                tempF = (1.8* tempC) + 32;
                print("PCB Temperature appears to be %2.2fC or %2.2fF msb %d lsb %d" % (tempC, tempF, msb, lsb))
                temps["0"] = tempF;
            except IOError:
                temp = -1;


        # handle any optics not on a mux
        process_optic_data(bus, busno, 0, 0, "nomux");

    # end for busno
    print("Optics exist in these slots:")
    for k in sorted(optics_exist.keys()):
        print(k)

    print("Board Temps:")
    for k in sorted(temps.keys()):
        print("%s %s" % (k, temps[k]))

## main

while 1 == 1:

    if real_hardware:
        # poll the busses
        poll_busses()
        # fetch power supply data
        fetch_psu_data(0)

    else:
        process_optic_data(0,0,0,0,0)
#	break;
    time.sleep(2)


