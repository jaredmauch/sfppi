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
address_two = 0x51 # A2 DDM and SFF-8690 Tunable support

optic_sff =[];
optic_sff_read = -1;
optic_ddm =[];
optic_ddm_read = -1;


def fetch_optic_data(optic_bus):
	# import as globals
	global optic_sff;
	global optic_sff_read;
	#
	global optic_ddm;
	global optic_ddm_read;

	# initalize them
	optic_sff =[];
	optic_sff_read = -1;
	optic_ddm =[];
	optic_ddm_read = -1;

	# read SFF data
	for byte in range (0, 128):
		try:
			value = optic_bus.read_byte_data(address_one, byte);
			optic_sff.insert(byte, value);
			optic_sff_read = (byte+1);
		except IOError:
			break;

	# read DDM data
	for byte in range (0, 128):
		try:
			value = optic_bus.read_byte_data(address_two, byte);
			optic_ddm.insert(byte, value);
			optic_ddm_read = byte+1;
		except IOError:
			break;


def read_optic_type():
	# defined in SFF-8024
	# updated 2015-05-15

	print "SFF Type:",
	if optic_sff[0] == 0x00:
		print "Unknown or unspecified"
	elif optic_sff[0] == 0x01:
		print "GBIC"
	elif optic_sff[0] == 0x02:
		print "Module soldered to motherboard"
	elif optic_sff[0] == 0x03:
		print "SFP/SFP+/SFP28"
	elif optic_sff[0] == 0x04:
		print "300 pin XBI"
	elif optic_sff[0] == 0x05:
		print "XENPAK"
	elif optic_sff[0] == 0x06:
		print "XFP"
	elif optic_sff[0] == 0x07:
		print "XFF"
	elif vlaue == 0x08:
		print "XFP-E"
	elif optic_sff[0] == 0x09:
		print "XPAK"
	elif optic_sff[0] == 0x0A:
		print "X2"
	elif optic_sff[0] == 0x0B:
		print "DWDM-SFP/SFP+"
	elif optic_sff[0] == 0x0C:
		print "QSFP";
	elif optic_sff[0] == 0x0D:
		print "QSFP+";
	elif optic_sff[0] == 0x0E:
		print "CXP";
	elif optic_sff[0] == 0x0F:
		print "Shielded Mini Multilane HD 4X";
	elif optic_sff[0] == 0x10:
		print "Shielded Mini Multilane HD 8X";
	elif optic_sff[0] == 0x11:
		print "QSFP28"; # SFF=8636
	elif optic_sff[0] == 0x12:
		print "CXP2/CFP28";
	elif optic_sff[0] == 0x13:
		print "CDFP"; #style 1/2
	elif optic_sff[0] == 0x14:
		print "Shielded Mini Multilane HD 4X Fanout";
	elif optic_sff[0] == 0x15:
		print "Shielded Mini Multilane HD 8X Fanout";
	elif optic_sff[0] == 0x16:
		print "CDFP Style 3";
	else:
		print "Not yet specified value (%d) check SFF-8024" % optic_sff[0]
	return


def read_optic_mod_def():
	# SFF-8472 Physical Device Extended Identifer Values
	# Byte 1 Table 5-2

	print "Extended Identifier Value:",
	if optic_sff[1] == 0x00:
		print "Not Specified";
	elif optic_sff[1] == 0x01:
		print "MOD_DEF 1";
	elif optic_sff[1] == 0x02:
		print "MOD_DEF 2";
	elif optic_sff[1] == 0x03:
		print "MOD_DEF 3";
	elif optic_sff[1] == 0x04:
		print "function defined by i2c ID only";
	elif optic_sff[1] == 0x05:
		print "MOD_DEF 5";
	elif optic_sff[1] == 0x06:
		print "MOD_DEF 6";
	elif optic_sff[1] == 0x07:
		print "MOD_DEF 7";
	else:
		print "Unallocated";

	return

def read_optic_connector_type():
	# defined in SFF-8024 4-3

	print "Connector Type:",
	if optic_sff[2] == 0x00:
		print "Unknown or unspecified"
	elif optic_sff[2] == 0x01:
		print "SC"
	elif optic_sff[2] == 0x02:
		print "Fibre Channel Style 1 copper connector";
	elif optic_sff[2] == 0x03:
		print "Fibre Channel Style 2 copper connector";
	elif optic_sff[2] == 0x04:
		print "BNC/TNC";
	elif optic_sff[2] == 0x05:
		print "Fiber Channel coax headers";
	elif optic_sff[2] == 0x06:
		print "Fiber Jack";
	elif optic_sff[2] == 0x07:
		print "LC";
	elif optic_sff[2] == 0x08:
		print "MT-RJ";
	elif optic_sff[2] == 0x09:
		print "MU";
	elif optic_sff[2] == 0x0A:
		print "SG";
	elif optic_sff[2] == 0x0B:
		print "Optical Pigtail";
	elif optic_sff[2] == 0x0C:
		print "MPO 1x12";
	elif optic_sff[2] == 0x0D:
		print "MPO 2x16";
	elif optic_sff[2] == 0x20:
		print "HSSDC II";
	elif optic_sff[2] == 0x21:
		print "Copper Pigtail";
	elif optic_sff[2] == 0x22:
		print "RJ45";
	elif optic_sff[2] == 0x23:
		print "No separable connector";
	elif optic_sff[2] == 0x24:
		print "MXC 2x16";
	else:
		print "Not yet specified value (%d) check SFF-8024" % optic_sff[2]

	return

def read_optic_encoding():
	# SFF 8472 11
	# SFF 8024 4-2

	print "Encoding Type:",

	if optic_sff[11] == 0x00:
		print "Unspecified";
	elif optic_sff[11] == 0x01:
		print "8B/10B";
	elif optic_sff[11] == 0x02:
		print "4B/5B";
	elif optic_sff[11] == 0x03:
		print "NRZ";
	elif optic_sff[11] == 0x04:
		print "Manchester";
	elif optic_sff[11] == 0x05:
		print "SONET Scrambled";
	elif optic_sff[11] == 0x06:
		print "64B/66B";
	elif optic_sff[11] == 0x07:
		print "256B/257B";
	else:
		print "Not yet specified value (%d) check SFF-8024" % optic_sff[11]

	return

def read_optic_signaling_rate():
	# SFF-8472 12 
	print "Optic Sigaling Rate: %d Mbit" % (optic_sff[12] *100)

def read_optic_rate_identifier():
	# SFF-8472 13

	print "Optic Rate Identifier: %d" % optic_sff[13];
	
def read_optic_vendor():
	# SFF-8472
	# 16 bytes ASCII at bytes 20-35
	vendor = ""

	for byte in range (20, 36):
		vendor=vendor +('%c' % optic_sff[byte])
	print "Vendor:",
	print vendor

def read_optic_transciever():
	# SFF-8472 Table 5-3
	# Bytes 3-9
	# Extended 1 byte 36
	#
	# XXX This code is a hack
	# XXX

	# Decode Table 5-3
	if (optic_sff[3] & 0x80):
		print "10G-Base-ER";
	if (optic_sff[3] & 0x40):
		print "10G-Base-LRM";
	if (optic_sff[3] & 0x20):
		print "10G-Base-LR";
	if (optic_sff[3] & 0x10):
		print "10G-Base-SR";
	if (optic_sff[3] & 0x08):
		print "Infiniband 1X SX";
	if (optic_sff[3] & 0x04):
		print "Infiniband 1X LX";
	if (optic_sff[3] & 0x02):
		print "infiniband 1X Copper Active";
	if (optic_sff[3] & 0x01):
		print "Infiniband 1X Copper Passive";
		
	if (optic_sff[6] & 0x80):
		print "Base-PX";
	if (optic_sff[6] & 0x40):
		print "Base-BX10";
	if (optic_sff[6] & 0x20):
		print "100Base-FX";
	if (optic_sff[6] & 0x10):
		print "100Base-LX/LX10";
	if (optic_sff[6] & 0x08):
		print "1000Base-T";
	if (optic_sff[6] & 0x04):
		print "1000Base-CX";
	if (optic_sff[6] & 0x02):
		print "1000Base-LX";
	if (optic_sff[6] & 0x01):
		print "1000Base-SX";


	print "extended compliance_code %d" % optic_sff[36]


def read_optic_vendor_oui():
	# SFF-8472 4-1
	# 3 bytes 37-39

	vendor_oui=""
	for byte in range (37, 40):
		vendor_oui = vendor_oui + ("%2.2x" % optic_sff[byte])
	print "vendor_oui: %s" % vendor_oui;


def read_optic_vendor_partnum():
	# SFF-8472
	# 16 bytes ASCII at bytes 40-55
	vendor_partnum = ""

	for byte in range (40, 56):
		vendor_partnum=vendor_partnum +('%c' % optic_sff[byte])
	print "PN:", 
	print vendor_partnum

def read_optic_vendor_serialnum():
	# SFF-8472
	# 16 bytes ASCII at bytes 68-83
	vendor_serialnum = ""

	for byte in range (68, 84):
		if (optic_sff[byte] == 0 or optic_sff[byte] == 0xff):
			break;
		vendor_serialnum=vendor_serialnum +('%c' % optic_sff[byte])
	print "SN:", 
	print vendor_serialnum

def read_optic_datecode():
	# SFF-8472
	# 8 bytes ASCII at bytes 84-91
	vendor_datecode = ""

	for byte in range (84, 92):
		if (optic_sff[byte] == 0 or optic_sff[byte] == 0xff):
			break;
		vendor_datecode = vendor_datecode + ('%c' % optic_sff[byte])

	print "Date Code:",
	print vendor_datecode

def read_optic_rev():
	# SFF-8472
	# 4 bytes ASCII at bytes 56-59
	vendor_hwrev = ""

	for byte in range (56, 60):
		vendor_hwrev=vendor_hwrev +('%c' % optic_sff[byte])
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
		smf_km      = optic_sff[14];
		smf_100m    = optic_sff[15];
		mmf_om2_10m = optic_sff[16];
		mmf_om1_10m = optic_sff[17];
		mmf_om4_m   = optic_sff[18];
		mmf_om4_10m = optic_sff[19];
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

	print "Monitoring Types:"
	if (optic_sff[92] & 0x80):
		print "\tReserved for legacy diagnostic implementations";
	if (optic_sff[92] & 0x40):
		print "\tDDM Supported";
	if (optic_sff[92] & 0x20):
		print "\tInternally calibrated";
	if (optic_sff[92] & 0x10):
		print "\tExternally calibrated";
	if (optic_sff[92] & 0x08):
		print "\tReceived power measurement type: average"; # unset this is OMA
	if (optic_sff[92] & 0x04):
		print "\tAddress Change Required";

	return

def read_option_values():
	# SFF-8472, SFF-8431 and SFF-8690 for some undefined bits
	# bytes 64-65

	print "Option Values";

	if (optic_sff[64] & 0x80):
		print "\tUndefined bit 7 set";
	if (optic_sff[64] & 0x40):
		print "\tUndefined bit 6 set";
	if (optic_sff[64] & 0x20):
		print "\tHigh Power Level Required - Level3";
	if (optic_sff[64] & 0x10):
		print "\tPaging Implemented";
	if (optic_sff[64] & 0x08):
		print "\tInternal Retimer";
	if (optic_sff[64] & 0x04):
		print "\tCooled Transciever";
	if (optic_sff[64] & 0x02):
		print "\tPower Level 2";
	if (optic_sff[64] & 0x01):
		print "\tLinear Receiver Output";

	if (optic_sff[65] & 0x80):
		print "\tReceiver decision threshold supported";
	if (optic_sff[65] & 0x40):
		print "\tTunable Optic";
	if (optic_sff[65] & 0x20):
		print "\tRATE_SELECT supported";
	if (optic_sff[65] & 0x10):
		print "\tTX_DISABLE supported";
	if (optic_sff[65] & 0x08):
		print "\tTX_FAULT implemented";
	if (optic_sff[65] & 0x04):
		print "\tSignal Detect implemented";
	if (optic_sff[65] & 0x02):
		print "\tRx_LOS implemented";
	if (optic_sff[65] & 0x01):
		print "\tUnallocated";

	
def read_enhanced_options():
	# SFF-8472
	# byte 93 Table 8-6

	if (optic_sff[93] & 0x80):
		print "Optional Alarm/warning flags implemented for all monitored quantities"; # table 9-12
	if (optic_sff[93] & 0x40):
		print "Optional soft TX_DISABLE control and monitoring implemented";
	if (optic_sff[93] & 0x20):
		print "Optional soft TX_FAULT monitoring implemented";
	if (optic_sff[93] & 0x10):
		print "Optional soft RX_LOS monitoring implemented";
	if (optic_sff[93] & 0x08):
		print "Optional soft RATE_SELECT control and monitoring implemented";
	if (optic_sff[93] & 0x04):
		print "Optional Application Select control implemented"; # SFF-8079
	if (optic_sff[93] & 0x02):
		print "Optional soft Rate Select control implemented"; # SFF-8431
	if (optic_sff[93] & 0x01):
		print "Unallocated"; # SFF-8472

	return

def read_sff_8472_compliance():
	# SFF-8472
	# byte 94 Table 8-8

	print "SFF 8472 Compliance:",

	if optic_sff[94] == 0x00:
		print "Unsupported";
	elif optic_sff[94] == 0x01:
		print "SFF-8472 9.3";
	elif optic_sff[94] == 0x02:
		print "SFF-8472 9.5";
	elif optic_sff[94] == 0x03:
		print "SFF-8472 10.2";
	elif optic_sff[94] == 0x04:
		print "SFF-8472 10.4";
	elif optic_sff[94] == 0x05:
		print "SFF-8472 11.0";
	elif optic_sff[94] == 0x06:
		print "SFF-8472 11.3";
	elif optic_sff[94] == 0x07:
		print "SFF-8472 11.4";
	elif optic_sff[94] == 0x08:
		print "SFF-8472 12.0";
	else:
		print "Unallocated";

def read_optic_frequency():
	# SFF-8472
	# Byte 60-61

	wave_msb = optic_sff[60];
	wave_lsb = optic_sff[61];
	wave_dec = optic_sff[62];
	
	wavelength = (wave_msb*256)+wave_lsb;
	print "Wavelength: %d.%02dnm" % (wavelength, wave_dec);

def read_status_bits():
	# SFF-8472
	# byte 110 Table 9-11

	print "Status Bits:"

	if (optic_sff[110] & 0x80):
		print "\tTX_Disable Set";
	if (optic_sff[110] & 0x40):
		print "\tSoft TX Disable Selected";
	if (optic_sff[110] & 0x20):
		print "\tRS(1) State set";
	if (optic_sff[110] & 0x10):
		print "\tRate_Select State";
	if (optic_sff[110] & 0x08):
		print "\tSoft Rate_Select selected";
	if (optic_sff[110] & 0x04):
		print "\tTX_Fault";
	if (optic_sff[110] & 0x02):
		print "\tRX_LOS";
	if (optic_sff[110] & 0x01):
		print "\tData Ready";


def read_optic_temperature():
	# SFF-8472
	# bytes 96-97 Table 9-2

	temp_msb = optic_ddm[96];
	temp_lsb = optic_ddm[97];

	print "Optic Temperature: %4.2fC" % (temp_msb + (temp_lsb/256));

def read_optic_vcc():
	# SFF-8472
	# bytes 98-99 Table 9-11

	vcc_msb = optic_ddm[98];
	vcc_lsb = optic_ddm[99];

	vcc = (vcc_msb<<8 | vcc_lsb) *0.0001;
	print "Optic VCC: %4.2fV msb = %d, lsb = %d" % (vcc, vcc_msb, vcc_lsb);

def read_laser_temperature():
	# SFF-8472
	# bytes 106-107 Table 9-2

	temp_msb = optic_ddm[106];
	temp_lsb = optic_ddm[107];

	print "Laser Temperature: msb = %d, lsb = %d" % (temp_msb, temp_lsb)


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
	print "Rx Power: (%4.2f) dBm  vs mW %f" % (rx_pwr, ((rx_pwr_msb<<8|rx_pwr_lsb) *0.0001));

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
	print "Tx Power: (%4.2f) mW vs mW = %f" % (tx_pwr, ((tx_pwr_msb<<8|tx_pwr_lsb) *0.0001));

def read_measured_current():
	# SFF-8472
	# bytes 108-109

	current_msb = optic_ddm[108];
	current_lsb = optic_ddm[109];
	bias = (current_msb<<8 | current_lsb) * 0.002;

	print "Current Draw: %4.2fmA msb = %d, lsb = %d mA" % (bias, current_msb, current_lsb)



def dump_vendor():
	# SFF-8472 Table 4-1
	# bytes 96-127

	vendor_hex = ""
	vendor_isprint = ""

	for byte in range (96, 128):
		vendor_hex=vendor_hex +('%-2.2x' % sff_data[byte])

		v_char = '%c' % sff_data[byte];

		if (isprint(v_char)):
			vendor_isprint = vendor_isprint + v_char;
		else:
			vendor_isprint = vendor_isprint + ' ';
	print vendor_hex
	print vendor_isprint



## main()

# read first optic



def poll_busses():
# iterate through i2c busses
	for busno in range (0, 2):

		print "Optic(s) on slot(Bus) number %d:" % busno
		bus = smbus.SMBus(busno)

		try:
			# try to read TMP102 sensor

			msb = bus.read_byte_data(0x48, 0x0);
			lsb = bus.read_byte_data(0x48, 0x1);


			temp = ((msb << 8) | lsb);
			temp >>=4;
			if(temp & (1<<11)):
				temp |= 0xf800;
				
			tempC = temp*0.0625;
			tempF = (1.8* tempC) + 32;
			print "Temperature appears to be %2.2fC or %2.2fF msb %d lsb %d" % (tempC, tempF, msb, lsb);
			
		except IOError:
			temp = -1;
	
		## detect if PCA9547 is there by reading 0x70
		# perhaps also 0x70 - 0x77
		try:
			mux = bus.read_byte_data(0x70, 0x4);
			mux_exist=1;
			print "Found pca954x at i2c %d at %-2x" % (busno, 0x70);
		except IOError:
			mux_exist=0;
	
		for i2csel in range (8, 16):
			if (mux_exist == 1):
				print "---- > Switching i2c to 0x%-2x" % (i2csel)
				try:
					bus.write_byte_data(0x70,0x04,i2csel)
				except IOError:
					print "i2c switch failed for bus %d location 0x%-2x" % (busno, i2csel)
	
#		fetch_optic_data(bus,address_one,sff_data)
#		fetch_optic_data(bus,address_two,ddm_data)

			# read SFF and DDM data
			fetch_optic_data(bus);
#			print "Read %d bytes of SFF data" % optic_sff_read;
#			print "Read %d bytes of DDM data" % optic_ddm_read;

			if (optic_sff_read >=128):
				read_optic_type() # SFF
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
	
			if (optic_ddm_read >=128):
				read_optic_temperature()
				read_optic_rxpower()
				read_optic_txpower();
	
#				read_laser_temperature()
				read_optic_vcc()
				read_measured_current()

				read_status_bits()
			# if not part of a mux, skip the 8-16 channel selection process
			if (mux_exist == 0):
				break;


		#dump_vendor()
		# end for i2csel

	# end for busno
	


while 1 == 1:
	poll_busses()
	time.sleep(6)

