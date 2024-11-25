#!/bin/sh
dig axfr +onesoa @zonedata.iis.se se | awk '{ print $1 }' | grep .se. | sort -u > se-$(date '+%Y%m%d').txt
