#!/usr/bin/env python
# Copyright (c) 2017 @x0rz, @tehnlulz, @syncikin, iosiro
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
import certstream
from default_settings import bad_repuation_tlds
from utils import clean_domain, remove_tld, fuzzy_scorer
import logging_methods
from queue import Queue
import threading
import time
import Levenshtein
from fuzzywuzzy import fuzz
import sys
import json

google_sheets_queue = Queue()
log = logging_methods.logging_methods()

def score_domain(target_domain, watch_domain, keywords):
    '''
    Score the likelihood of the target domain being a phishing clone of the watch domain.

    :param target_domain: the domain of the newly registered certificate
    :param watch_domain: the domain being monitored
    :param watch_domain: whether the CA of the certificate is Let's Encrypt
    :return: the score of the domain in question.
    '''

    target_domain = clean_domain(target_domain)
    watch_domain = clean_domain(watch_domain)

    score = 0

    # If the target domain is the watch domain, don't score it
    if target_domain == watch_domain:
        return 0

    # If the parsed target domain is the watch domain, but with a different TLD, very suspicious 
    if remove_tld(watch_domain) == remove_tld(target_domain):
        return 100

    # If the parsed watch domain is in the target domain, but they aren't equal, suspicious 
    if remove_tld(watch_domain) in target_domain:
        score = 70

    # If they have a low levenshtein distance, suspicious
    l_distance = Levenshtein.distance(remove_tld(watch_domain),remove_tld(target_domain))
    fuzz_ratio = fuzz.token_sort_ratio(remove_tld(watch_domain),remove_tld(target_domain))

    if l_distance <= 3:
        score = 70 + 10 * (3-l_distance)
    elif fuzz_ratio > 80:
        score = fuzz_ratio - 20 

    # If the watch domain is in the target domain, but they aren't equal, suspicious
    if watch_domain in target_domain:
        return 100

    # TODO: add keyword functionality back in

    target_len = len(remove_tld(target_domain))
    watch_len = len(remove_tld(watch_domain))

    # If the target domain is much shorter than the watch domain, it's probably not much of a threat
    if target_len > watch_len / 2:
        # Detect the presence of the watch domain in the target domain 
        score = fuzzy_scorer({remove_tld(watch_domain): 100}, remove_tld(target_domain))
    
    # Detect suspicious domain structure
    # Remove initial '*.' for wildcard certificates
    if target_domain.startswith('*.'):
        target_domain = target_domain[2:]

        # Detect fake TLD (e.g. *.com-account-management.info)
        if any(fake_tld in remove_tld(target_domain) for fake_tld in ['com', 'net', 'org', 'io']):
            score += 20

    # Detect unreliable TLDs 
    if any(target_domain.endswith(bad_tld) for bad_tld in bad_repuation_tlds) :
        score += 20

    return score

def load_config_file(config_file):
    try:
        config_file = open(config_file, 'r')
        config = config_file.read()
        config_file.close()
        settings_dictionary = json.loads(config)
        globals().update(settings_dictionary)
        return True

    except Exception as e:
        print ("Error loading config file - {}\n{}".format(config_file,e))
        return False

def handle_score_and_log(domain, watchdomain, score):
    '''
    Pass the results logging methods and decide if we should log them.

    :param domain:
    :param watchdomain:
    :param score:
    :return:
    '''
    log.console_log(domain, watchdomain, score)
    if google_spreadsheet_url and len(google_spreadsheet_url) > 0:
        google_sheets_queue.put((domain, watchdomain, score, google_drive_email, google_spreadsheet_url, google_threshold ))
        #log.google_sheets_log(domain, watchdomain, score,google_drive_email, google_spreadsheet_url, google_threshold)

def callback(message, context):
    """Callback handler for certstream events."""

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        # Loop through all of the domains found in the cert
        for domain in all_domains:

            # Loop through each of the domains that we're watching for.
            for watch_domain in watchlist.keys():
                lets_encrypt = False
                keywords = watchlist[watch_domain]
                score = score_domain(domain.lower(), watch_domain, keywords)

                # More suspicious if it's issued by a free CA.
                if "Let's Encrypt" in message['data']['chain'][0]['subject']['aggregated']:
                    score += 20

                handle_score_and_log(clean_domain(domain), clean_domain(watch_domain), score)

def google_worker():
    '''
    This is the thread worker that will post data to sheets on our behalf.
    :return:
    '''
    while True:
        result = google_sheets_queue.get()
        if not result:
            time.sleep(1)
            continue
        domain, watchdomain, score, google_drive_email, google_spreadsheet_url, google_threshold = result
        log.google_sheets_log(domain, watchdomain, score, google_drive_email, google_spreadsheet_url, google_threshold)
        google_sheets_queue.task_done()
        time.sleep(1)

if len(sys.argv) != 2:
    print ("\nUsage: python3 blockphish.py monitoring_profiles/<profile>.json")
    sys.exit()

def main(config_file):
    load_config_file(config_file)
    # Spawn our google thread worker
    if google_spreadsheet_url and len(google_spreadsheet_url) > 0:
            print ("Spawning google sheets thread")
            t = threading.Thread(target=google_worker)
            t.start()

    # Start streaming certificates
    certstream.listen_for_events(callback)
    print()

if __name__ == "__main__":
    main(sys.argv[1])
