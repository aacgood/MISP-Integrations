# MISP-Integrations

## CrowdStrike

### misp2cs.py

This script queries MISP for events with a particular tag, extracts supported attribute types and uploads them as indicators via the CrowdStrike QueryAPI. The script will tag the event and any supported attributes type in that event as "Uploaded to CrowdStrike". 

This script uses pymisp and will only upload attributes that are marked with an IDS flag. Ensure that MISP Warning lists and the IDS flag is used correctly to avoid false positives.

When CrowdStrike gets a hit on an indicator it will generate a threat_intel alert and provide the MISP event ID in the alert description.

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

#### Requirements
- Working knowledge of PyMISP
- Working knowledge of CrowdStirke QueryAPI
- QueryAPI Credentials
- MISP keys.py file. See https://github.com/MISP/PyMISP/blob/master/examples/keys.py.sample

#### TODO
- Add support to delete indicators.
- Add command line parameter support to set expiry dates.
- PEP all the things.
- Migrate to CrowdStrike Python API.
- Add command line parameter support for tags.
