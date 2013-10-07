#!/bin/sh

mkdir -p logs

# wep
CLIENT_CONF_FILE="wpa_supplicant_wep.conf"

#STAUT
#AP="ath9k_htc"
AP="ath9k"
STA="ath10k"

#wep 64, one key, def key index 0
AP_CONF_FILE="hostapd_wep_tc1.conf"
./wep.py $AP $STA $AP_CONF_FILE $CLIENT_CONF_FILE 1

#wep 128, one key, def key index 0
AP_CONF_FILE="hostapd_wep_tc2.conf"
#./wep.py $AP $STA $AP_CONF_FILE $CLIENT_CONF_FILE 2

#wep 64, 4 keys, def key index AP-1, STA-2
AP_CONF_FILE="hostapd_wep_tc3.conf"
#./wep.py $AP $STA $AP_CONF_FILE $CLIENT_CONF_FILE 3 | tee logs/test_res.log | grep "TC RESULT"


#ATUT
AP="ath10k"
#STA="ath9k_htc"
STA="ath9k"

#wep 64, one key, def key index 0
AP_CONF_FILE="hostapd_wep_tc1.conf"
#./wep.py $AP $STA $AP_CONF_FILE $CLIENT_CONF_FILE 1

#wep 128, one key, def key index 0
AP_CONF_FILE="hostapd_wep_tc2.conf"
#./wep.py $AP $STA $AP_CONF_FILE $CLIENT_CONF_FILE 2

#wep 64, 4 keys, def key index AP-1, STA-2
AP_CONF_FILE="hostapd_wep_tc3.conf"
#./wep.py $AP $STA $AP_CONF_FILE $CLIENT_CONF_FILE 3







