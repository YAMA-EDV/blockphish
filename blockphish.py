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
from utils import clean_domain, remove_tld, fuzzy_scorer_domain, fuzzy_scorer_keywords, is_whitelisted
import logging_methods
from queue import Queue
import threading
import time
import Levenshtein
from fuzzywuzzy import fuzz
import sys
from multiprocessing import Process
from unidecode import unidecode
import json

log = None

def score_domain(target_domain, watch_domain, keywords):
    '''
    Score the likelihood of the target domain being a phishing clone of the watch domain.

    :param target_domain: the domain of the newly registered certificate
    :param watch_domain: the domain being monitored
    :param watch_domain: whether the CA of the certificate is Let's Encrypt
    :return: the score of the domain in question.
    '''

    score = 0

    target_domain = clean_domain(target_domain)
    watch_domain = clean_domain(watch_domain)

    # If the target domain is the watch domain, don't score it
    if target_domain == watch_domain:
        return 0

    try:
        target_domain.encode('ascii')
    except UnicodeEncodeError:
        # Contains unicode, suspicious
        score+=20

    target_domain = unidecode(target_domain)

    # If the parsed target domain is the parsed watch domain, but with a different TLD, very suspicious
    if remove_tld(watch_domain) == remove_tld(target_domain):
        return 100

    # If the watch domain is in the target domain, but they aren't equal, suspicious
    if watch_domain in target_domain:
        return 100

    # If they have a low levenshtein distance, suspicious
    l_distance = Levenshtein.distance(remove_tld(watch_domain),remove_tld(target_domain))
    fuzz_ratio = fuzz.token_sort_ratio(remove_tld(watch_domain),remove_tld(target_domain))

    # Works for both short and long strings
    if l_distance <= 2:
        score = 50 + 25 * (2-l_distance)
    # Better with longer strings
    elif fuzz_ratio > 80:
        score = fuzz_ratio - 25
    
    # TODO: keyword functionality is temporarily disabled
    # score += fuzzy_scorer_keywords(keywords, remove_tld(target_domain))
    # print(fuzzy_scorer_keywords(keywords, remove_tld(target_domain)))

    target_len = len(remove_tld(target_domain))
    watch_len = len(remove_tld(watch_domain))

    # If the target domain is much shorter than the watch domain, it's probably not much of a threat
    if target_len > watch_len / 2 and target_len > 4:
        # Detect the presence of the watch domain in the target domain
        score += fuzzy_scorer_domain(remove_tld(watch_domain), remove_tld(target_domain))
        
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

    # If the target domain isn't split by .'s then check if it's too long to realistically look like the watch domain
    try:
        max_segment_target_domain = len(max(remove_tld(target_domain).replace("-", ".").split("."), key=len))
    except Exception as e:
        max_segment_target_domain = len(remove_tld(target_domain))

    if max_segment_target_domain > len(remove_tld(watch_domain)) * 1.5:
        score /= 2

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
    global log

    if not log and google_spreadsheet_key and len(google_spreadsheet_key):
        log = logging_methods.logging_methods(google_spreadsheet_key, config_name)
    elif not log:
        log = logging_methods.logging_methods(google_spreadsheet_key, config_name)

    log.console_log(domain, watchdomain, score)
    if google_spreadsheet_key and len(google_spreadsheet_key) > 0:
        log.google_sheets_log(domain, watchdomain, score, google_spreadsheet_key, google_threshold, config_name)


def callback(message, context):
    """Callback handler for certstream events."""

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        # Loop through all of the domains found in the cert
        for domain in all_domains:

            #Is the domain whitelisted
            if is_whitelisted(domain, whitelisted_domains):
                continue

            # Loop through each of the domains that we're watching
            for watch_domain in watchlist.keys():

                lets_encrypt = False
                keywords = watchlist[watch_domain]
                score = score_domain(domain.lower(), watch_domain, keywords)

                # More suspicious if it's issued by a free CA
                if "Let's Encrypt" in message['data']['chain'][0]['subject']['aggregated']:
                    score += 20

                handle_score_and_log(clean_domain(domain), clean_domain(watch_domain), score)


def main(config_file):
    load_config_file(config_file)
    # Start streaming certificates
    print ("Starting to stream certificates... this can take a few minutes...")
    certstream.listen_for_events(callback)
    print()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print ("\nUsage: python3 blockphish.py monitoring_profiles/<profile>.json")
        sys.exit()
    main(sys.argv[1])
