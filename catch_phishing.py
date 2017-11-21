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
from default_settings import watchlist, keywords, bad_repuation_tlds, google_spreadsheet_url, num_threads
from utils import clean_domain, split_domain_into_words, remove_tld
from matcher import fuzzy_scorer, watchdomain_in_domain
import logging_methods
from queue import Queue
import threading
import time

google_sheets_queue = Queue()
log = logging_methods.logging_methods()

def score_domain(target_domain, watch_domain, watch_keywords = []):
    '''
    Score the likelihood of the target domain being a phishing clone of the watch domain. 

    :param target_domain: the domain of the newly registered certificate
    :param watch_domain: the domain being monitored
    :param watch_domain: whether the CA of the certificate is Let's Encrypt
    :return: the score of the domain in question.
    '''

    keywords = watch_keywords

    target_domain = clean_domain(target_domain)
    watch_domain = clean_domain(watch_domain)

    score = 0

    # Step 0: If the target domain is the watch domain, don't score it
    if target_domain == watch_domain:
        return 0

    # Step 1: If the watch domain is in the target domain, but they aren't equal, very suspicious (0-100)
    if watch_domain in target_domain:
        score += 80

    # Step 2: Detect unreliable TLDs (0-20)
    for tld in bad_repuation_tlds:
        if target_domain.endswith(tld):
            score += 20

    # Step 3: Detect the presence of the keywords in the target domain (0-60)
    score += fuzzy_scorer(keywords, target_domain)*60

    # Step 4: Detect the presence of the watch domain in the target domain (0-80)
    domain_no_tld = remove_tld(watch_domain)
    score += fuzzy_scorer([domain_no_tld], target_domain)*100

    # Step 5: Detect suspicious domain structure (0-20)

    # Remove initial '*.' for wildcard certificates 
    if target_domain.startswith('*.'):
        target_domain = target_domain[2:]

        # Detect fake TLD (e.g. *.com-account-management.info)
        if target_domain[0] in ['com', 'net', 'org']:
            score += 20

    return score

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
        google_sheets_queue.put((domain, watchdomain, score))

def callback(message, context):
    """Callback handler for certstream events."""

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        # Loop through all of the domains found in the cert
        for domain in all_domains:

            # Loop through each of the domains that we're watching for.
            for watch_domain in watchlist:
                lets_encrypt = False

                score = score_domain(domain.lower(), watch_domain, keywords)

                # More suspicious if it's issued by a free CA.
                if "Let's Encrypt" in message['data']['chain'][0]['subject']['aggregated']:
                    score += 30
                
                handle_score_and_log(domain, watch_domain, score)

def google_worker():
    '''
    This is the thread worker that will post data to sheets on our behalf.
    :return:
    '''
    while True:
        domain, watchdomain, score = google_sheets_queue.get()
        log.google_sheets_log(domain, watchdomain, score)
        google_sheets_queue.task_done()
        time.sleep(1)

def main():
    # Spawn our google thread worker
    if google_spreadsheet_url and len(google_spreadsheet_url) > 0:
            print ("Spawning {} google sheets threads".format(num_threads))
            for i in range(num_threads):
                t = threading.Thread(target=google_worker)
                t.start()

    # Start streaming certificates
    certstream.listen_for_events(callback)

if __name__ == "__main__":
    main()
