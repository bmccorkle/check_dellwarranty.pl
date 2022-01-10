# check_dellwarranty.pl
Monitoring Pluging to check warranties on Dell servers


This script checks the warranty status on a server (and potentially other Dell gear) using either a given service tag or attempted service tag retrieval over SNMP.  It will return a warning or critical if the warranty length (using the last expiring warranty of the returned collection) is below the warning or critical thresholds.  You must provide your Dell API Key Client ID and Secret into the 'USER CONFIGURABLE VARIABLES' section so it can communicate with Dell

OPTIONS:

        -h      Help
        -V      Version
        -H      Hostname or Address
        -C      SNMP: Community
        -p      SNMP: Port (Default: 161)
        -t      SNMP: Timeout (Default 5 sec)
        -v      SNMP: Version [1|2|3]  (Default: 3)
        -c      CRIT: Number of days remaining (Default: 10)
        -w      WARN: Number of days remaining (Default: 20)
        -T      Type: [chassis|idrac|server|switch|tag]
        -S      Service Tag (Type='tag')
        -d      Display Multiline Output [m|v]
                   m = Show All Warranties
                   v = Show Only Valid Warranties
        -x      Line 1 Display Format [1|2|3]
                   1 = Use Days Remaining (Default)
                   2 = Use Expiration Date
                   3 = Use Days Remaining & Expiration Date
        -y      Use %Y-%m-%d for dates (Default: %m/%d/%y)
        -z      DON'T Print exit status on Line 1 (Hate duplication)
        --un    SNMPv3: Username
        --sl    SNMPv3: Security Level [noauthnopriv|authnopriv|authpriv] (Default: authpriv)
        --ap    SNMPv3: Auth Protocol [md5|sha] (Default: sha)
        --ak    SNMPv3: Auth Password
        --pp    SNMPv3: Privacy Protocol [des|aes] (Default: aes)
        --pk    SNMPv3: Privacy Password

        Example 1: ./check_dellwarranty.pl -T tag -S SERVICETAG -w 20 -c 10
        Example 2: ./check_dellwarranty.pl -T server -H 10.0.0.1 -v 1 -C public -w 20 -c 10 -d m
        Example 3: ./check_dellwarranty.pl -T server -H 10.0.0.1 --un USERNAME --ak AUTHPASS --pk PRIVPASS -w 20 -c 10 -d m
