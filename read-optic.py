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

import smbus
import time
import json
import math
from curses.ascii import isprint

# globals
address_one = 0x50 # A0
address_two = 0x51 # A2


def read_optic_type():
	# defined in SFF-8024
	# updated 2015-05-15
	try:
		value = bus.read_byte_data(address_one, 0x0)
	except IOError:
		return;

	print "SFF Type:",
	if value == 0x00:
		print "Unknown or unspecified"
	elif value == 0x01:
		print "GBIC"
	elif value == 0x02:
		print "Module soldered to motherboard"
	elif value == 0x03:
		print "SFP/SFP+/SFP28"
	elif value == 0x04:
		print "300 pin XBI"
	elif value == 0x05:
		print "XENPAK"
	elif value == 0x06:
		print "XFP"
	elif value == 0x07:
		print "XFF"
	elif vlaue == 0x08:
		print "XFP-E"
	elif value == 0x09:
		print "XPAK"
	elif value == 0x0A:
		print "X2"
	elif value == 0x0B:
		print "DWDM-SFP/SFP+"
	elif value == 0x0C:
		print "QSFP";
	elif value == 0x0D:
		print "QSFP+";
	elif value == 0x0E:
		print "CXP";
	elif value == 0x0F:
		print "Shielded Mini Multilane HD 4X";
	elif value == 0x10:
		print "Shielded Mini Multilane HD 8X";
	elif value == 0x11:
		print "QSFP28"; # SFF=8636
	elif value == 0x12:
		print "CXP2/CFP28";
	elif value == 0x13:
		print "CDFP"; #style 1/2
	elif value == 0x14:
		print "Shielded Mini Multilane HD 4X Fanout";
	elif value == 0x15:
		print "Shielded Mini Multilane HD 8X Fanout";
	elif value == 0x16:
		print "CDFP Style 3";
	else:
		print "Not yet specified value (%d) check SFF-8024" % value
	return


def read_optic_mod_def():
	# SFF-8472 Physical Device Extended Identifer Values
	# Byte 1 Table 5-2

	try:
		value = bus.read_byte_data(address_one, 1);
	except IOError:
		return;

	print "Extended Identifier Value:",
	if value == 0x00:
		print "Not Specified";
	elif value == 0x01:
		print "MOD_DEF 1";
	elif value == 0x02:
		print "MOD_DEF 2";
	elif value == 0x03:
		print "MOD_DEF 3";
	elif value == 0x04:
		print "function defined by i2c ID only";
	elif value == 0x05:
		print "MOD_DEF 5";
	elif value == 0x06:
		print "MOD_DEF 6";
	elif value == 0x07:
		print "MOD_DEF 7";
	else:
		print "Unallocated";

	return

def read_optic_connector_type():
        # defined in SFF-8024 4-3
	try:
		value = bus.read_byte_data(address_one, 0x2)
	except IOError:
		return;

	print "Connector Type:",
	if value == 0x00:
		print "Unknown or unspecified"
	elif value == 0x01:
		print "SC"
	elif value == 0x02:
		print "Fibre Channel Style 1 copper connector";
	elif value == 0x03:
		print "Fibre Channel Style 2 copper connector";
	elif value == 0x04:
		print "BNC/TNC";
	elif value == 0x05:
		print "Fiber Channel coax headers";
	elif value == 0x06:
		print "Fiber Jack";
	elif value == 0x07:
		print "LC";
	elif value == 0x08:
		print "MT-RJ";
	elif value == 0x09:
		print "MU";
	elif value == 0x0A:
		print "SG";
	elif value == 0x0B:
		print "Optical Pigtail";
	elif value == 0x0C:
		print "MPO 1x12";
	elif value == 0x0D:
		print "MPO 2x16";
	elif value == 0x20:
		print "HSSDC II";
	elif value == 0x21:
		print "Copper Pigtail";
	elif value == 0x22:
		print "RJ45";
	elif value == 0x23:
		print "No separable connector";
	elif value == 0x24:
		print "MXC 2x16";
	else:
		print "Not yet specified value (%d) check SFF-8024" % value

	return

def read_optic_encoding():
	# SFF 8472 11
	# SFF 8024 4-2
	try:
		value = bus.read_byte_data(address_one, 11)
	except IOError:
		return;

	print "Encoding Type:",

	if value == 0x00:
		print "Unspecified";
	elif value == 0x01:
		print "8B/10B";
	elif value == 0x02:
		print "4B/5B";
	elif value == 0x03:
		print "NRZ";
	elif value == 0x04:
		print "Manchester";
	elif value == 0x05:
		print "SONET Scrambled";
	elif value == 0x06:
		print "64B/66B";
	elif value == 0x07:
		print "256B/257B";
	else:
		print "Not yet specified value (%d) check SFF-8024" % value

	return

def read_optic_signaling_rate():
	# SFF-8472 12 
	try:
		value = bus.read_byte_data(address_one, 12)
	except IOError:
		return;

	print "Optic Sigaling Rate: %d Mbit" % (value *100)

def read_optic_rate_identifier():
	# SFF-8472 13
        try:
                value = bus.read_byte_data(address_one, 13)
        except IOError:
                return;

        print "Optic Rate Identifier: %d" % value;

	
def read_optic_vendor():
	# SFF-8472
	# 16 bytes ASCII at bytes 20-35
	vendor = ""

	for byte in range (20, 36):
		try:
			value = bus.read_byte_data(address_one, byte);
		except IOError:
			return;
		vendor=vendor +('%c' % value)
	print "Vendor:",
	print vendor

def read_optic_transciever():
	# SFF-8472 Table 5-3
	# Bytes 3-9
	# Extended 1 byte 36
	#
	# XXX This code is a hack
	# XXX

	try:
		value3 = bus.read_byte_data(address_one, 3)
		value4 = bus.read_byte_data(address_one, 4)
		value5 = bus.read_byte_data(address_one, 5)
		value6 = bus.read_byte_data(address_one, 6)
		value7 = bus.read_byte_data(address_one, 7)
		value8 = bus.read_byte_data(address_one, 8)
		value9 = bus.read_byte_data(address_one, 9)
	except IOError:
		return;

	# Decode Table 5-3
	if (value3 & 0x80):
		print "10G-Base-ER";
	if (value3 & 0x40):
		print "10G-Base-LRM";
	if (value3 & 0x20):
		print "10G-Base-LR";
	if (value3 & 0x10):
		print "10G-Base-SR";
	if (value3 & 0x08):
		print "Infiniband 1X SX";
	if (value3 & 0x04):
		print "Infiniband 1X LX";
	if (value3 & 0x02):
		print "infiniband 1X Copper Active";
	if (value3 & 0x01):
		print "Infiniband 1X Copper Passive";
		
	if (value6 & 0x80):
		print "Base-PX";
	if (value6 & 0x40):
		print "Base-BX10";
	if (value6 & 0x20):
		print "100Base-FX";
	if (value6 & 0x10):
		print "100Base-LX/LX10";
	if (value6 & 0x08):
		print "1000Base-T";
	if (value6 & 0x04):
		print "1000Base-CX";
	if (value6 & 0x02):
		print "1000Base-LX";
	if (value6 & 0x01):
		print "1000Base-SX";


	try:
		value = bus.read_byte_data(address_one, 36)
	except IOError:
		return;

	print "extended compliance_code %d" % value;


def read_optic_vendor_oui():
	# SFF-8472 4-1
	# 3 bytes 37-39

	vendor_oui=""
	for byte in range (37, 40):
		try:
			value = bus.read_byte_data(address_one, byte);
		except IOError:
			return;
		vendor_oui = vendor_oui + ("%2.2x" % value)
	print "vendor_oui: %s" % vendor_oui;


def read_optic_vendor_partnum():
        # SFF-8472
        # 16 bytes ASCII at bytes 40-55
        vendor_partnum = ""

        for byte in range (40, 56):
		try:
	                value = bus.read_byte_data(address_one, byte);
		except IOError:
			return;
                vendor_partnum=vendor_partnum +('%c' % value)
        print "PN:", 
	print vendor_partnum

def read_optic_vendor_serialnum():
        # SFF-8472
        # 16 bytes ASCII at bytes 68-83
        vendor_serialnum = ""

        for byte in range (68, 84):
		try:
	                value = bus.read_byte_data(address_one, byte);
		except IOError:
			return
                vendor_serialnum=vendor_serialnum +('%c' % value)
	print "SN:", 
        print vendor_serialnum

def read_optic_datecode():
	# SFF-8472
	# 8 bytes ASCII at bytes 84-91
	vendor_datecode = ""

	for byte in range (84, 92):
		try:
			value = bus.read_byte_data(address_one, byte);
		except IOError:
			return
		vendor_datecode = vendor_datecode + ('%c' % value)

	print "Date Code:",
	print vendor_datecode

def read_optic_rev():
        # SFF-8472
        # 4 bytes ASCII at bytes 56-59
        vendor_hwrev = ""

        for byte in range (56, 60):
		try:
	                value = bus.read_byte_data(address_one, byte);
		except IOError:
			return;
                vendor_hwrev=vendor_hwrev +('%c' % value)
	print "HW Revision:",
        print vendor_hwrev

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
		smf_km      = bus.read_byte_data(address_one, 14);
		smf_100m    = bus.read_byte_data(address_one, 15);
		mmf_om2_10m = bus.read_byte_data(address_one, 16);
		mmf_om1_10m = bus.read_byte_data(address_one, 17);
		mmf_om4_m   = bus.read_byte_data(address_one, 18);
		mmf_om4_10m = bus.read_byte_data(address_one, 19);
	except IOError:
		return;

	print "Distances:";
	if smf_km:
		print "\tSMF - %d km" % smf_km;
	if smf_100m:
		print "\tSMF - %d meters" % (smf_100m *100);
	if mmf_om2_10m:
		print "\tOM2 - %d meters" % (mmf_om2_10m * 10);
	if mmf_om1_10m:
		print "\tOM1 - %d meters" % (mmf_om1_10m * 10);
	if mmf_om4_m:
		print "\tOM4/DAC - %d meter(s)" % (mmf_om4_m);
	if mmf_om4_10m:
		print "\tOM4 - %d meters" % (mmf_om4_10m * 10);

	
def read_optic_monitoring_type():
	# SFF-8472
	# byte 92 - Diagnostic Monitoring Type Table 8-5

	try:
		value = bus.read_byte_data(address_one, 92);
	except IOError:
		return;
 
	print "Monitoring Types:"
	if (value & 0x80):
		print "\tReserved for legacy diagnostic implementations";
	if (value & 0x40):
		print "\tDDM Supported";
	if (value & 0x20):
		print "\tInternally calibrated";
	if (value & 0x10):
		print "\tExternally calibrated";
	if (value & 0x08):
		print "\tReceived power measurement type: average"; # unset this is OMA
	if (value & 0x04):
		print "\tAddress Change Required";

	return

def read_option_values():
	# SFF-8472, SFF-8431 and SFF-8690 for some undefined bits
	# bytes 64-65

	try:
		value64 = bus.read_byte_data(address_one, 64);
		value65 = bus.read_byte_data(address_one, 65);
	except IOError:
		return;

	print "Option Values";

	if (value64 & 0x80):
		print "\tUndefined bit 7 set";
	if (value64 & 0x40):
		print "\tUndefined bit 6 set";
	if (value64 & 0x20):
		print "\tHigh Power Level Required - Level3";
	if (value64 & 0x10):
		print "\tPaging Implemented";
	if (value64 & 0x08):
		print "\tInternal Retimer";
	if (value64 & 0x04):
		print "\tCooled Transciever";
	if (value64 & 0x02):
		print "\tPower Level 2";
	if (value64 & 0x01):
		print "\tLinear Receiver Output";

	if (value65 & 0x80):
		print "\tReceiver decision threshold supported";
	if (value65 & 0x40):
		print "\tTunable Optic";
	if (value65 & 0x20):
		print "\tRATE_SELECT supported";
	if (value65 & 0x10):
		print "\tTX_DISABLE supported";
	if (value65 & 0x08):
		print "\tTX_FAULT implemented";
	if (value65 & 0x04):
		print "\tSignal Detect implemented";
	if (value65 & 0x02):
		print "\tRx_LOS implemented";
	if (value65 & 0x01):
		print "\tUnallocated";

	
def read_enhanced_options():
	# SFF-8472
	# byte 93 Table 8-6

	try:
		value = bus.read_byte_data(address_one, 93);
	except IOError:
		return;

	if (value & 0x80):
		print "Optional Alarm/warning flags implemented for all monitored quantities"; # table 9-12
	if (value & 0x40):
		print "Optional soft TX_DISABLE control and monitoring implemented";
	if (value & 0x20):
		print "Optional soft TX_FAULT monitoring implemented";
	if (value & 0x10):
		print "Optional soft RX_LOS monitoring implemented";
	if (value & 0x08):
		print "Optional soft RATE_SELECT control and monitoring implemented";
	if (value & 0x04):
		print "Optional Application Select control implemented"; # SFF-8079
	if (value & 0x02):
		print "Optional soft Rate Select control implemented"; # SFF-8431
	if (value & 0x01):
		print "Unallocated"; # SFF-8472

	return

def read_sff_8472_compliance():
	# SFF-8472
	# byte 94 Table 8-8

	try:
		value = bus.read_byte_data(address_one, 94);
	except IOError:
		return;

	print "SFF 8472 Compliance:",

	if value == 0x00:
		print "Unsupported";
	elif value == 0x01:
		print "SFF-8472 9.3";
	elif value == 0x02:
		print "SFF-8472 9.5";
	elif value == 0x03:
		print "SFF-8472 10.2";
	elif value == 0x04:
		print "SFF-8472 10.4";
	elif value == 0x05:
		print "SFF-8472 11.0";
	elif value == 0x06:
		print "SFF-8472 11.3";
	elif value == 0x07:
		print "SFF-8472 11.4";
	elif value == 0x08:
		print "SFF-8472 12.0";
	else:
		print "Unallocated";

def read_optic_frequency():
	# SFF-8472
	# Byte 60-61

	try:
		wave_msb = bus.read_byte_data(address_one, 60);
		wave_lsb = bus.read_byte_data(address_one, 61);
		wave_dec = bus.read_byte_data(address_one, 62);
	except IOError:
		return;

	
	wavelength = (wave_msb*256)+wave_lsb;
	print "Wavelength: %d.%dnm" % (wavelength, wave_dec);

def read_status_bits():
	# SFF-8472
	# byte 110 Table 9-11

	try:
		value = bus.read_byte_data(address_two, 110);
	except IOError:
		return;

	print "Status Bits:"

	if (value & 0x80):
		print "\tTX_Disable Set";
	if (value & 0x40):
		print "\tSoft TX Disable Selected";
	if (value & 0x20):
		print "\tRS(1) State set";
	if (value & 0x10):
		print "\tRate_Select State";
	if (value & 0x08):
		print "\tSoft Rate_Select selected";
	if (value & 0x04):
		print "\tTX_Fault";
	if (value & 0x02):
		print "\tRX_LOS";
	if (value & 0x01):
		print "\tData Ready";


def read_optic_temperature():
	# SFF-8472
	# bytes 96-97 Table 9-2

	try:
		temp_msb = bus.read_byte_data(address_two, 96);
		temp_lsb = bus.read_byte_data(address_two, 97);
	except IOError:
		return;

	print "Optic Temperature: %4.2fC" % (temp_msb + (temp_lsb/256));

def read_optic_vcc():
	# SFF-8472
	# bytes 98-99 Table 9-11

	try:
		vcc_msb = bus.read_byte_data(address_two, 98);
		vcc_lsb = bus.read_byte_data(address_two, 99);
	except IOError:
		return;

	vcc = (vcc_msb<<8 | vcc_lsb) *0.0001;
	print "Optic VCC: %4.2fV msb = %d, lsb = %d" % (vcc, vcc_msb, vcc_lsb);

def read_laser_temperature():
        # SFF-8472
        # bytes 106-107 Table 9-2

	try:
	        temp_msb = bus.read_byte_data(address_two, 106);
	        temp_lsb = bus.read_byte_data(address_two, 107);
	except IOError:
		return;

        print "Laser Temperature: msb = %d, lsb = %d" % (temp_msb, temp_lsb)


def read_optic_rxpower():
	# SFF-8472
	# bytes 104, 105

	try:
		rx_pwr_msb = bus.read_byte_data(address_two, 104)
		rx_pwr_lsb = bus.read_byte_data(address_two, 105)
	except IOError:
		return;

	# need to convert this from mW to dBm, eg:
	# 10 * math.log10(rx_power)
	# 0 = -40 dBm
	temp_pwr = (rx_pwr_msb<<8|rx_pwr_lsb) *0.0001;
	if (temp_pwr > 0):
	        rx_pwr = 10 * math.log10((rx_pwr_msb<<8|rx_pwr_lsb) *0.0001);
	else:
		rx_pwr = 0;
	print "Rx Power: (%4.2f) dBm  vs mW %f" % (rx_pwr, ((rx_pwr_msb<<8|rx_pwr_lsb) *0.0001));

def read_optic_txpower():
        # SFF-8472
        # bytes 104, 105

        try:
                tx_pwr_msb = bus.read_byte_data(address_two, 102)
                tx_pwr_lsb = bus.read_byte_data(address_two, 103)
        except IOError:
                return;

        # need to convert this from mW to dBm, eg:
        # 10 * math.log10(rx_power)
        # 0 = -40 dBm
        temp_pwr = (tx_pwr_msb<<8|tx_pwr_lsb) *0.0001;
        if (temp_pwr > 0):
                tx_pwr = 10 * math.log10((tx_pwr_msb<<8|tx_pwr_lsb) *0.0001);
        else:
                tx_pwr = 0;
        print "Tx Power: (%4.2f) mW vs mW = %f" % (tx_pwr, ((tx_pwr_msb<<8|tx_pwr_lsb) *0.0001));

def read_measured_current():
        # SFF-8472
        # bytes 108-109


	try:
		current_msb = bus.read_byte_data(address_two, 108)
		current_lsb = bus.read_byte_data(address_two, 109)
	except IOError:
		return;
	bias = (current_msb<<8 | current_lsb) * 0.002;

	print "Current Draw: %4.2fmA msb = %d, lsb = %d mA" % (bias, current_msb, current_lsb)



def dump_vendor():
	# SFF-8472 Table 4-1
	# bytes 96-127


        vendor_hex = ""
	vendor_isprint = ""

        for byte in range (96, 128):
                try:
                        value = bus.read_byte_data(address_one, byte);
                except IOError:
                        return;
                vendor_hex=vendor_hex +('%-2.2x' % value)

		v_char = '%c' % value;

		if (isprint(v_char)):
			vendor_isprint = vendor_isprint + v_char;
		else:
			vendor_isprint = vendor_isprint + ' ';
        print vendor_hex
	print vendor_isprint



## main()

# read first optic

#
for busno in range (0, 2):

	print "Optic in slot number %d:" % busno
	bus = smbus.SMBus(busno)

	read_optic_type()
	read_optic_mod_def();
	read_optic_connector_type()
	read_optic_encoding()
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
	read_optic_temperature()
	read_optic_rxpower()
	read_optic_txpower();

#	read_laser_temperature()
	read_optic_vcc()
	read_measured_current()

	read_status_bits()

	#dump_vendor()

#
	



