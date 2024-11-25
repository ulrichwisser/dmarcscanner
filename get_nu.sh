#!/bin/sh
dig axfr +onesoa @zonedata.iis.se nu | awk '{ print $1 }' | grep .nu. | sort -u > nu-$(date '+%Y%m%d').txt
