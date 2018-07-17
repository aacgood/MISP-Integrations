#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
import json
import csv
import pprint
import requests

from collections import OrderedDict


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')


def cs_type(type):

    """
    Convert MISP attribute types to CS types
    :param type: MISP type
    :type type: string
    :return: cs type
    :rtype: str
    TODO: add support for ipv6
    """

    types = {
        'ip-dst': 'ipv4',
        'ip-src': 'ipv4'
    }

    if isinstance(type, dict):
        print(type.keys())
        return type

    if type in types:
        print('ipv4')
        return types[type]
    else:
        return type


def search(m, quiet, url, controller, out=None, **kwargs):

    event_list = []
    uuid_list = []
    result = m.search(controller, **kwargs)

    headers = {
        'Content-Type': 'application/json',
    }

    # Generate a list of MISP Event ID's and a list of UUID's
    for e in result['response']:
        event_list.append(e['Event']['id'])
        uuid_list.append(e['Event']['uuid'])

    # Iterate through the MISP Event UUID's and apply appropriate tags
    for uuid in uuid_list:
        misp.untag(uuid, "Upload to CrowdStrike")
        misp.tag(uuid, "Uploaded to CrowdStrike")

    # Iterate through event list and build a CSV table of events
    for event in event_list:
        x = misp.get_csv(eventid=event, context=['event_info','event_tag','event_threat_level_id'], misp_types=['ip-src', 'ip-dst', 'domain', 'md5', 'sha1', 'sha256'])
        reader = csv.DictReader(x.split('\n'))

        # Build CrowdStrike indicator
        for row in reader:
            data = {
                "type": cs_type(row.get('type')),
                "value": row.get('value'),
                "policy": "detect",
                "share_level": "red",
                "expiration_days": 60,
                "source": '{} {}'.format(
                    'MISP Event',
                    row.get('event_id')),
                "description": row.get('event_info')
            }

            indicator = '{}{}{}'.format(
                "[",
                json.dumps(data),
                "]"
            )

            # Post the indicator to the QueryAPI
            response = requests.post('https://falconapi.crowdstrike.com/indicators/entities/iocs/v1', headers=headers, data=indicator, auth=('', ''))

            # Apply tag to MISP attribute to indicate it has been uploaded as IOC
            misp.tag(row.get('uuid'), "Uploaded to CrowdStrike")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get all the events matching a value for a given param.')
    parser.add_argument("-p", "--param", required=True, help="Parameter to search (e.g. category, org, etc.)")
    parser.add_argument("-s", "--search", required=True, help="String to search.")
    parser.add_argument("-a", "--attributes", action='store_true', help="Search attributes instead of events")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if args.output is not None and os.path.exists(args.output):
        print('Output file already exists, abort.')
        exit(0)

    misp = init(misp_url, misp_key)
    kwargs = {args.param: args.search}

    if args.attributes:
        controller='attributes'
    else:
        controller='events'

    search(misp, misp_url, controller, args.output, **kwargs)
