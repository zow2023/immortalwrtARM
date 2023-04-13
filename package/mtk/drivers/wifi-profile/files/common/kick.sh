#!/bin/sh /etc/rc.common

start() {
    	kick=$(grep -e "KickStaRssiLow=" /etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat)
    	iwpriv ra0 set "$kick"
    	kick=$(grep -e "KickStaRssiLow=" /etc/wireless/mediatek/mt7986-ax6000.dbdc.b1.dat)
    	iwpriv rai0 set "$kick"
    	kick=$(grep -e "KickStaRssiHigh=" /etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat)
    	iwpriv ra1 set "$kick"    	
}



