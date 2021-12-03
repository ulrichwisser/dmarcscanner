# dmarcscanner

This software expects aone argument, a filename.
The file should contain a list of domain names, one name per line.

The software will resolve for the DMARC record of the domain.
And keep statistics about the number of domains checked,
number of domains with DMarc records, v=DMARC1, p=none, p=quarantine and p=reject.

During the run it conveniently prints statistics and performance metrics.

# Performance
This is the run for .nu on the 3rd of December 2021:
- 246260 domains,
- 31804 (12.91%) DMarc,
- 29011 (11.78%) DMarc valid,
- 13605 (5.52%) p=none,
- 2078 (0.84%) p=quarantine,
- 13342 (5.42%) p=reject,
- 1m8.550682166s,
- 3592 domains/s
