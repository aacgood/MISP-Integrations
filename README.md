# MISP-Integrations


### misp2cs.py

This script queries MISP for events with a particular tag, extracts supported attribute types and uploads them as indicators via the CrowdStrike QueryAPI.

#### Supported MISP Attributes

 - ip-src
 - ip-dst
 - domain
 - md5
 - sha1
 - sha256

#### Sample usage

python3 -p tags -s "Upload to CrowdStrike" -q

Recommend adding this command to a cronjob to poll MISP at a set interval.

### TODO
- Add support to delete indicators
- Add command line paramater support to set expiry dates.
- PEP all the things
