#!/usr/bin/env perl

##################
# Purpose:	Get Dell Warranty for Dell Gear
# Changelog:
#       * 1/10/2022 - Initial Release
#	* 2/14/2024 - Update to Resolve Dell Token and Format Changes
##############################
my $prog_author	 = "Brandon McCorkle";
my $prog_date	 = "February 14th, 2024";
my $prog_name	 = "check_dellwarranty.pl";
my $prog_version = "1.1";

#
# Copyright (c) 2022, Brandon McCorkle <brandon.mccorkle@gmail.com>
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above copyright
#         notice, this list of conditions and the following disclaimer in the
#         documentation and/or other materials provided with the distribution.
#       * Neither the name of the <organization> nor the
#         names of its contributors may be used to endorse or promote products
#         derived from this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use warnings;
use strict;
use Net::SNMP;
use Getopt::Long;
Getopt::Long::config('auto_abbrev');
use Time::Piece;
use WWW::Curl::Easy;
use feature 'fc';



#####
#USER CONFIGURABLE VARIABLES:
#####
my $debug               = 0;            #Set to 1 to Debug

## YOUR client id and secret from Dell (https://techdirect.dell.com) 
my $client_id="INFO_NEEDED";
my $client_secret="INFO_NEEDED";
my $grant_type="client_credentials";

## Hashes Containing Dell SNMP OIDs
my %hash_chassis        = ( "oid_servicetag"  => "1.3.6.1.4.1.674.10892.2.1.1.6.0" );           	#Untested OID, Might need changed
my %hash_idrac		= ( "oid_servicetag"  => "1.3.6.1.4.1.674.10892.5.1.3.2.990" );		
my %hash_server         = ( "oid_servicetag"  => "1.3.6.1.4.1.674.10892.2.1.1.11.0" );			#Untested OID, Might need changed
my %hash_switch  	= ( "oid_servicetag"  => "1.3.6.1.4.1.674.10895.3000.1.2.100.8.1.4.1" );	#Untested OID, Might need changed
 


#####
# VARIABLES
#####

## Dell Websites to obtain OAuth 2.0 token and retrieve warranty information:
my $url_token="https://apigtwb2c.us.dell.com/auth/oauth/v2/token";
my $url_warranty1="https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements/";
my $url_warranty2="https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/assets/";

## Option Variables
my $CRIT_THRESHOLD	= 10;		#Default (Days)
my $WARN_THRESHOLD	= 20;		#Default (Days)
my $stag		= "";
my $custom_display	= "";
my $line1_format	= 1;
my $date_format         = 0;
my $hide_exit_status    = 0;
my $type                = "server";	#Default
my $print_help          = 0;
my $print_version       = 0;
my $curl = WWW::Curl::Easy->new;

## SNMP Variables
my $snmp_community		= "";
my $snmp_host;
my $snmp_port                   = 161;		
my $snmp_timeout                = 5;		#Seconds
my $snmp_version                = 3;		#Default
my $snmp_username;
my $snmp_seclevel		= "authpriv";	#Default
my $snmp_authprotocol		= "sha";	#Default
my $snmp_authpassword;
my $snmp_privprotocol		= "aes";	#Default
my $snmp_privpassword;
my $session;
my $error;

## Declare Multidimension Array to Hold Warranty Information
## X#=Warranty, Y0=Start, Y1=End, Y2=Entitlement, Y3=Level
my (@columns);
my @warranties = ( \@columns);

## Dell Site Related Variables
my $access_token;
my $warranty_count;
my $warranty_output;
my $shipdate;
my $sysdesc;

## Program Variables
my $warranty_expiration;
my $warranty_daysleft;
my $current_epoch;
my $crit_epoch;
my $warn_epoch;
my $flag_warn		= 0;
my $flag_crit		= 0;
my $EXIT_STATE;

## Icinga2 Status Codes:
my $STATE_OK            = 0;
my $STATE_WARNING       = 1;
my $STATE_CRITICAL      = 2;
my $STATE_UNKNOWN       = 3;




#####
# HELP MESSAGE
#####
sub display_help(){
        system("clear");
        print "scriptname [options]\n";
        print "\t-h\tHelp\n";
        print "\t-V\tVersion\n";
        print "\t-H\tHostname or Address\n";
        print "\t-C\tSNMP: Community\n";
        print "\t-p\tSNMP: Port (Default: 161)\n";
        print "\t-t\tSNMP: Timeout (Default 5 sec)\n";
	print "\t-v\tSNMP: Version [1|2|3]  (Default: 3)\n";
        print "\t-c\tCRIT: Number of days remaining (Default: 10)\n";
        print "\t-w\tWARN: Number of days remaining (Default: 20)\n";
        print "\t-T\tType: [chassis|idrac|server|switch|tag]\n";
        print "\t-S\tService Tag (Type='tag')\n";
	print "\t-d\tDisplay Multiline Output [m|v]\n";
	print "\t\t   m = Show All Warranties\n";
        print "\t\t   v = Show Only Valid Warranties\n";
        print "\t-x\tLine 1 Display Format [1|2|3]\n";
        print "\t\t   1 = Use Days Remaining (Default)\n";
        print "\t\t   2 = Use Expiration Date\n";
        print "\t\t   3 = Use Days Remaining & Expiration Date\n";
        print "\t-y\tUse %Y-%m-%d for dates (Default: %m/%d\/%y)\n";
	print "\t-z\tDON'T Print exit status on Line 1 (Hate duplication)\n";
	print "\t--un\tSNMPv3: Username\n";
	print "\t--sl\tSNMPv3: Security Level [noauthnopriv|authnopriv|authpriv] (Default: authpriv)\n";
	print "\t--ap\tSNMPv3: Auth Protocol [md5|sha] (Default: sha)\n";
	print "\t--ak\tSNMPv3: Auth Password\n";
	print "\t--pp\tSNMPv3: Privacy Protocol [des|aes] (Default: aes)\n";
        print "\t--pk\tSNMPv3: Privacy Password\n";
        print "\n";
        print "\tExample 1: ./check_dellwarranty.pl -T tag -S SERVICETAG -w 20 -c 10\n";
        print "\tExample 2: ./check_dellwarranty.pl -T server -H 10.0.0.1 -v 1 -C public -w 20 -c 10 -d m\n";
	print "\tExample 3: ./check_dellwarranty.pl -T server -H 10.0.0.1 --un USERNAME --ak AUTHPASS --pk PRIVPASS -w 20 -c 10 -d m\n";
        print "\n\n";
}



#####
# Retrieve Options
#####
Getopt::Long::Configure('bundling');
my $status = GetOptions
        ("h+"           =>      \$print_help,
         "V+"           =>      \$print_version,
         "C=s"          =>      \$snmp_community,
         "H=s"          =>      \$snmp_host,
         "p=i"          =>      \$snmp_port,
         "t=i"          =>      \$snmp_timeout,
	 "v=i"		=>	\$snmp_version,
	 "d=s"		=>	\$custom_display,
         "w=i"          =>      \$WARN_THRESHOLD,
         "c=i"          =>      \$CRIT_THRESHOLD,
         "T=s"          =>      \$type,
         "S=s"          =>      \$stag,
         "x=i"          =>      \$line1_format,
         "y!"           =>      \$date_format,
	 "z!"		=>	\$hide_exit_status,
	 "un=s"		=>	\$snmp_username,
	 "sl=s"		=>	\$snmp_seclevel,
	 "ap=s"		=>	\$snmp_authprotocol,
	 "ak=s"		=>	\$snmp_authpassword,
	 "pp=s"		=>	\$snmp_privprotocol,
         "y!"           =>      \$date_format,         "y!"           =>      \$date_format,	 "pk=s"		=>	\$snmp_privpassword,)
        or exit $STATE_WARNING;

if ($print_help != 0) {
        display_help;
        exit;
}
elsif ($print_version !=0) {
        print "\n$prog_name by $prog_author | Released: $prog_date | Version: $prog_version\n\n";
        exit;
}



#####
# SANITIZE OPTIONS
#####
sub sub_sanitize() {
	#Verify: Dell API Variable
	if ($client_id eq "INFO_NEEDED" || $client_secret eq "INFO_NEEDED") {
		print "Dell API Information Missing!\n";
		print "Apply/Obtain an API Key from https://techdirect.dell.com\n";
		print "Then enter Client ID & Client Secret into the USER Section tied to your API Key\n";
		exit $STATE_WARNING;	
	}

        #Verify: Warning Threshold
        if ( (defined $WARN_THRESHOLD && $WARN_THRESHOLD < -365) || (defined $WARN_THRESHOLD && $WARN_THRESHOLD > 3650) ) {
                print "Option -w: Invalid Days Remaining (-365 to 3650)\n\n";
                exit $STATE_WARNING;
        }

	#Verify: Critical Threshold
        if ( (defined $CRIT_THRESHOLD && $CRIT_THRESHOLD < -365 || defined $CRIT_THRESHOLD && $CRIT_THRESHOLD > 3650) ) {
                print "Option -c: Invalid Days Remaining (-365 to 3650)\n\n";
                exit $STATE_WARNING;
        }

        #Verify: Device Type
        if (defined $type) {

		#Type Uses SNMP...
		if (fc($type) eq "server" || fc($type) eq "chassis" || fc($type) eq "idrac" || fc($type) eq "switch") {

			#SNMPv3
        	        if ($snmp_version == 3) {

                	        #snmp_username required
                        	if ($snmp_seclevel eq "noauthnopriv") {
                                	if (!defined $snmp_username) {
                                        	print "Missing SNMPv3 Option for 'noauthnopriv' Security\n\n";
	                                        exit $STATE_WARNING;
        	                        }
                	        }
                        	#snmp_username & snmp_authpassword required
	                        elsif ($snmp_seclevel eq "authnopriv") {
        	                        if (!defined $snmp_username || !defined $snmp_authpassword) {
                	                        print "Missing SNMPv3 Option for 'authnopriv' Security\n\n";
                        	                exit $STATE_WARNING;
                                	}
	                        }
        	                #snmp_username & snmp_authpassword & snmp_privpassword required
                	        elsif ($snmp_seclevel eq "authpriv") {
                        	        if ( !defined($snmp_username) || !defined($snmp_authpassword) || !defined($snmp_privpassword) ) {
                                	        print "Missing SNMPv3 Option for 'authpriv' Security\n\n";
                                        	exit $STATE_WARNING;
	                                }
        	                }
                	        else {
                        	        print "Option --sl: Invalid Option\n\n";
                                	exit $STATE_WARNING;
	                        }

        	        }
			#SNMPv1 or SNMPv2
        	        elsif ( ($snmp_version == 1 || $snmp_version == 2) && $snmp_community eq "" ) {
                	        print "Option -C: Missing but SNMP version 1 or 2 set\n\n";
                        	exit $STATE_WARNING;
	                }
		}
		#Type Tag
		elsif (fc($type) eq "tag") {
                        if (fc($type) eq "tag" && $stag eq "") {
                                        print "Option -S: Type 'tag' but No Service Tag was Specified\n\n";
                                        exit $STATE_WARNING;
                        }
                }
		#Invalid Type
		else {
                        print "Option -t: Invalid Type (server, chassis, idrac, switch, tag)\n\n";
                        exit $STATE_WARNING;
		}

        }

        #Verify: Line 1 Format
        if ($line1_format != 1 && $line1_format != 2 && $line1_format != 3) {
                print "Option -x: Invalid Option [1|2|3]\n\n";
                exit $STATE_WARNING;
        }

	#Verify: Display Multiine Output
	if ($custom_display ne "m" && $custom_display ne "v" && $custom_display ne "") {
		print "Option -d: Invalid Option [m|v]\n\n";
		exit $STATE_WARNING;
	}

	if ($debug == 1) {
                print "\n\n";
                print "DEBUG: OPTIONS...\n";
		print "DEBUG: Type:  $type\n";
		if (fc($type) eq "tag") {
			print "DEBUG: Service Tag (if Type=tag): $stag\n";
		}
                print "DEBUG: Warn Threshold (Days):  $WARN_THRESHOLD\n";	
		print "DEBUG: Crit Threshold (Days):  $CRIT_THRESHOLD\n";
		if ($custom_display eq "m" || $custom_display eq "v") {
	                print "DEBUG: Display Option:  $custom_display\n";
		}
	}

	return;
}



#####
# GET SERVICE TAG FROM SNMP
#####
sub sub_get_snmp() {
        my ($err, $result, @oids);

        #Debug
        if ($debug == 1) {
                print "\n\n";
                print "DEBUG: Getting SNMP Service Tag...\n";
        }

	# Establish Connection Depending on Version Used
        if ($snmp_version == 3) {
                ($session,$error) = Net::SNMP->session(
                        -hostname       =>      $snmp_host,
                        -port           =>      $snmp_port,
                        -version        =>      $snmp_version,
                        -timeout        =>      $snmp_timeout,
                        -username       =>      $snmp_username,
                        -authprotocol   =>      $snmp_authprotocol,
                        -authpassword   =>      $snmp_authpassword,
                        -privprotocol   =>      $snmp_privprotocol,
                        -privpassword   =>      $snmp_privpassword
                );
	}
	elsif ($snmp_version == 1 || $snmp_version == 2) {
	        ($session,$error) = Net::SNMP->session(
        	        Hostname        =>      $snmp_host,
                	Port            =>      $snmp_port,
	                Version         =>      $snmp_version,
        	        Timeout         =>      $snmp_timeout,
                	Community       =>      $snmp_community,
                );
	}

        # Close Connection if Error
        if (!defined($session)){
		printf ("ERROR: %s.\n", $error);
                exit $STATE_CRITICAL;
        }

	#Set Which OID to Retreive
        if ($type eq "chassis") {
		@oids = sort values %hash_chassis;
	}
	elsif ($type eq "idrac") {
                @oids = sort values %hash_server;
        }
	elsif ($type eq "switch") {
		@oids = sort values %hash_switch;
	}
	else {
		@oids = sort values %hash_server;
	}

	$result = $session->get_request( -varbindlist => \@oids );	

	$err = $session->error;
        if ($err) {
		print "$err\n";
		exit $STATE_CRITICAL;
	}

	#Debug
	if ($debug == 1) {
		print "DEBUG: Retrieved Service Tag: $result->{ $hash_server{ 'oid_servicetag'}}\n";
	}

	$session->close();

	$stag = $result->{ $hash_server{ 'oid_servicetag'}};

	#Exit if no Service Tag Found
	if (!defined($stag) || fc($stag) eq "") {
		print "No Service Tag was Retrieved over SNMP!\n\n";
		exit $STATE_CRITICAL;
	}

	return;
}




#####
# RETRIEVE ACCESS TOKEN
#####
sub sub_get_token() {
	my $retcode;
	my $arg="client_id=$client_id&client_secret=$client_secret&grant_type=$grant_type";
 	my $raw_data;

	# Setup Curl Options
	$curl->setopt(CURLOPT_POST(),1);
	$curl->setopt(CURLOPT_POSTFIELDS, $arg);
	$curl->setopt(CURLOPT_URL, $url_token);
	$curl->setopt(CURLOPT_WRITEDATA,\$raw_data);

	# Execute Request
	$retcode = $curl->perform;

	# Return Error if unable to get Results
	if ($retcode != 0) {
        	# Error code, type of error, error message
	        print("An error happened: $retcode ".$curl->strerror($retcode)." ".$curl->errbuf."\n");
	}

	# Parse out Token from Returned Data
	$access_token = $raw_data =~ m/([a-z0-9]+\-[a-z0-9]+\-[a-z0-9]+\-[a-z0-9]+\-[a-z0-9]+\-[a-z0-9]+)/;
	$access_token = $1;

	#Debug
	if ($debug == 1) {
                print "DEBUG: RAW DATA...\n";
                print "DEBUG: $raw_data\n\n";
		print "DEBUG: RETRIEVED ACCESS TOKEN...\n";
		print "DEBUG: $access_token\n\n";
	}

	return;
}



#####
# RETRIEVE WARRANTY INFO FROM DELL
#####
sub sub_get_warrantyinfo() {
	my $retcode;
	my $url = "$url_warranty1?servicetags=$stag";

	# Setup Curl Options
	$curl->setopt(CURLOPT_HTTPAUTH,CURLAUTH_BEARER);
	$curl->setopt(CURLOPT_XOAUTH2_BEARER,$access_token);
	$curl->setopt(CURLOPT_HTTPGET,1);
	$curl->setopt(CURLOPT_URL, $url);
	$curl->setopt(CURLOPT_WRITEDATA,\$warranty_output);
	#$curl->setopt(CURLOPT_HEADER,1);		# Set if you want to include headers
	# Also Works instead of first two CURLOPT lines but not as refined (uses headers)
	# my @headers  = ("Authorization: Bearer $access_token");
	# $curl->setopt(CURLOPT_HTTPHEADER, \@headers);

	# Execute Request
	$retcode = $curl->perform;

	# Return Error if unable to get Results
	if ($retcode != 0) {
        	# Error code, type of error, error message
	        print("An error happened: $retcode ".$curl->strerror($retcode)." ".$curl->errbuf."\n");
	}

	#Debug
	if ($debug == 1) {
		print "DEBUG: RETRIEVED WARRANTY OUTPUT...:\n";
		print "DEBUG: $warranty_output\n\n";
	}

	return;
}



#####
# PARSE WARRANTY INFO
#####
sub sub_parse_info {
	my ($i, $k, @warranty_list, @splitdata);
	my ($sdate,$edate,$entitle,$level);

	#Get Warranty List & Number of Warranties
	@warranty_list = $warranty_output =~ m/(<entitlement><itemNumber>[[:digit:]]+\-[[:digit:]]+<\/itemNumber><startDate>\d{4}\-\d{1,2}\-\d{1,2}[TZ:\.[:digit:]\-]+<\/startDate><endDate>\d{4}\-\d{1,2}\-\d{1,2}[TZ:\.[:digit:]\-]+<\/endDate><entitlementType>[[:alpha:]]+<\/entitlementType><serviceLevelCode>[[:alnum:]\+]+<\/serviceLevelCode><serviceLevelDescription>[[:alnum:][:space:]\/]+<\/serviceLevelDescription><serviceLevelGroup>[[:digit:]]+<\/serviceLevelGroup><\/entitlement>)/g;
	$warranty_count = $#warranty_list + 1;

	#Get Ship Date
	$shipdate = $warranty_output =~ m/(<shipDate>\d{4}\-(0[1-9]|1[0-2])\-\d{1,2}[TZ:\.[:digit:]\-]+<\/shipDate>|<shipDate><\/shipDate>)/;
	$shipdate = $1;
	if ($shipdate eq "<shipDate><\/shipDate>") {
		$shipdate = "null";
	}
	else {
		$shipdate =~ m/(\d{4}\-(0[1-9]|1[0-2])\-\d{1,2})/;
		$shipdate = $1;
		$shipdate = Time::Piece->strptime($shipdate, '%F')->strftime('%s');
	}

	#Get System Description
	$sysdesc = $warranty_output =~ m/(<productLineDescription>([[:alnum:]]+|\s)+<\/productLineDescription>|<productLineDescription><\/productLineDescription>)/;
	$sysdesc = $1;
	if ($sysdesc eq "<productLineDescription><\/productLineDescription>") {
		$sysdesc = "null";
	}
        else {
		$sysdesc =~ s /<productLineDescription>//;
		$sysdesc =~ s /<\/productLineDescription>//;
	}

        #Debug
        if ($debug == 1) {
		print "DEBUG: WARRANTY SUMMARY...\n";
		print "DEBUG: Ship Date: $shipdate\n";
		print "DEBUG: System Desc: $sysdesc\n";
                print "DEBUG: Warranty Count: $warranty_count\n";
                print "\n";
        }

	#Place Warranty Info into Array
	if ($warranty_count != 0) {
		for $i (0 .. $#warranty_list) {
                        # Store Start Date (epoch time for easy sorting)
                        $sdate = $warranty_list[$i] =~ m/(<startDate>[TZ:\.[:digit:]\-]+<\/startDate>)/;
                        $sdate = $1;
                        $sdate = $sdate =~ m/(\d{4}\-(0[1-9]|1[0-2])\-\d{1,2})/;
                        $sdate = $1;
                        $warranties[$i][0] = Time::Piece->strptime($sdate, '%F')->strftime('%s');

                        # Store End Date (epoch time for easy sorting)
                        $edate = $warranty_list[$i] =~ m/(<endDate>[TZ:\.[:digit:]\-]+<\/endDate>)/;
                        $edate = $1;
                        $edate = $edate =~ m/(\d{4}\-(0[1-9]|1[0-2])\-\d{1,2})/;
                        $edate = $1;
                        $warranties[$i][1] = Time::Piece->strptime($edate, '%F')->strftime('%s');

                        # Store Entitlement
                        $entitle = $warranty_list[$i] =~ m/(<entitlementType>[[:alnum:][:space:]]+<\/entitlementType>)/;
                        $entitle = $1;
                        $entitle =~ s /<entitlementType>//;
                        $entitle =~ s /<\/entitlementType>//;
                        $warranties[$i][2] = $entitle;

                        # Store Level
                        $level = $warranty_list[$i] =~ m/(<serviceLevelDescription>[[:alnum:][:space:]\(\)\/]+<\/serviceLevelDescription>)/;
                        $level = $1;
                        $level =~ s /<serviceLevelDescription>//;
                        $level =~ s /<\/serviceLevelDescription>//;
                        $warranties[$i][3] = $level;

			if ($debug == 1) {		
				$k = $i + 1;
		                print "DEBUG: Warranty $k:  Start Date:  $warranties[$i][0]\n";
				print "DEBUG: Warranty $k:  End Date::  $warranties[$i][1]\n";
        	        	print "DEBUG: Warranty $k:  Entitlement:  $warranties[$i][2]\n";
				print "DEBUG: Warranty $k:  Level:  $warranties[$i][3]\n\n";
			}
		}
	}

	return;
}




#####
# SORT WARRANTY INFORMATION BY END DATE
#####
sub sub_sort () {
	my $i;

        #Debug
        if ($debug == 1) {
		print "DEBUG: SORT FUNCTION...\n";

	        for $i (0 .. $#warranties) {
        	        print "DEBUG: (Pre Sort) Index: $i  Start: $warranties[$i][0]  End: $warranties[$i][1]  Entitle: $warranties[$i][2]\n";
	        }
		print "\n";
	}

	@warranties = sort {$a->[1] <=> $b->[1]} @warranties;

        #Debug
        if ($debug == 1) {
        	for $i (0 .. $#warranties) {
                	print "DEBUG: (Aft Sort) Index: $i  Start: $warranties[$i][0]  End: $warranties[$i][1]  Entitle: $warranties[$i][2]\n";
	        }
	}

	return;
}



#####
# CALCULATIONS
#####
sub sub_calculations () {

        $current_epoch = time ();
        $crit_epoch = $CRIT_THRESHOLD * 24 * 60 * 60;
        $warn_epoch = $WARN_THRESHOLD * 24 * 60 * 60;

	$warranty_expiration = $warranties[$#warranties][1];	
	$warranty_daysleft = int(($warranty_expiration - $current_epoch) /24 /60 /60);

	return;
}



#####
# Threshold Checks
#####
sub sub_check_thresholds () {

	if ($warranty_count == 0) {
		$flag_crit = ++$flag_crit;
	}
	else {
	        #Critical Check (Days Remaining)
        	if ($warranty_expiration - $current_epoch <= $crit_epoch ) {
			$flag_crit = ++$flag_crit;
	        }

        	#Warning Check (Days Remaining)
	        if ($warranty_expiration - $current_epoch <= $warn_epoch ) {
			$flag_warn = ++$flag_warn;
	        }
	}

	return;
}



#####
# Check Icinga State to Exit with
#####
sub sub_check_state () {

        if ( $flag_crit > 0 ) {
		$EXIT_STATE = $STATE_CRITICAL;
	}
	elsif ( $flag_warn > 0 ) {
		$EXIT_STATE = $STATE_WARNING;
	}
	elsif ( $flag_crit == 0 && $flag_warn == 0 ) {
		$EXIT_STATE = $STATE_OK;
	}
	else {
		$EXIT_STATE = $STATE_UNKNOWN;
	}

	return;
}



#####
# Return Message
#####
sub sub_return_msg () {
	my ($i, $pad, $sdate, $edate, $dformat, $STATUS_MSG, $RETURN_MSG);

	#
	#Setup Return Message
	#

	#Check whether to print Icinga State in Output
	if ( $hide_exit_status != 1 ) {
		if    ($EXIT_STATE == 0) {$STATUS_MSG = "OK - ";}
		elsif ($EXIT_STATE == 1) {$STATUS_MSG = "WARNING - ";}
		elsif ($EXIT_STATE == 2) {$STATUS_MSG = "CRITICAL - ";}
		else                     {$STATUS_MSG = "UNKNOWN - ";}
	}

	#No information returned from Dell (null results)
	if ($sysdesc eq "null" && $shipdate eq "null") {
		$RETURN_MSG = sprintf ("NO SYSTEM FOUND, Check Command Arguments");
	}
	#No Active Warranties
	elsif ($warranty_count == 0) {
		$RETURN_MSG = sprintf ("No Warranties were Found!");
	}
	#Prepare Return Message
	else {
	        #Set Date Format and Padding
        	if ($date_format == 1) {
                	$dformat = "%F";
	                $pad = 11;
        	}
	        else {
        	        $dformat = "%D";
                	$pad = 9;
	        }

		#1st Line / Single line Output
		if ($line1_format == 2) {
                        $warranty_expiration = Time::Piece->strptime($warranty_expiration, '%s')->strftime($dformat);
			$RETURN_MSG = sprintf ("Tag: %s is under Warranty until: %${pad}s", $stag, $warranty_expiration);
		}
		elsif ($line1_format == 3) {
                        $warranty_expiration = Time::Piece->strptime($warranty_expiration, '%s')->strftime($dformat);
                        $RETURN_MSG = sprintf ("Tag: %s is under Warranty until: %${pad}s (%s days)", $stag, $warranty_expiration, $warranty_daysleft);
		}
		else {
			$RETURN_MSG = sprintf ("Tag: %s is under Warranty for: %4s days", $stag, $warranty_daysleft);
		}
	
		#Multiline Output
	        if ($custom_display eq "m" || $custom_display eq "v") {
			$RETURN_MSG = $RETURN_MSG . sprintf "\n";

                	for $i (0 .. $#warranties) {
                		$sdate = Time::Piece->strptime($warranties[$i][0], '%s')->strftime($dformat);
	                        $edate = Time::Piece->strptime($warranties[$i][1], '%s')->strftime($dformat);
        		
				#Print Only Valid Warranties if display option 'v' set, else print everything
				if ($custom_display eq "v" && $warranties[$i][1] < $current_epoch) {
					#Don't print this expired warranty
				}
				else {
					$RETURN_MSG = $RETURN_MSG . sprintf ("Start: %${pad}s   End: %${pad}s     %-10.10s  %-50.75s\n", $sdate, $edate, $warranties[$i][2], $warranties[$i][3]);		
				}
        	        }

		        if ($shipdate ne "null") {
                		$shipdate = Time::Piece->strptime($shipdate, '%s')->strftime($dformat);
		        }

		        $RETURN_MSG = $RETURN_MSG . sprintf "\n$sysdesc    Service Tag: $stag    Ship Date: $shipdate";
		}
	}
	
	#Print Return Message
	printf "$STATUS_MSG$RETURN_MSG";

	return;
}



#####
# Main
#####
sub_sanitize;

if (fc($type) ne "tag") {
	sub_get_snmp;
}

sub_get_token;
sub_get_warrantyinfo;
sub_parse_info;

if ($warranty_count != 0) {
	sub_sort;
	sub_calculations;
}

sub_check_thresholds;
sub_check_state;
sub_return_msg;

exit $EXIT_STATE;
