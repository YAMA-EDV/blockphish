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
from utils import clean_domain, split_domain_into_words
from domain_matching import watchdomain_in_domain
from fuzzy_matching import fuzzy_matcher
import logging_methods
from queue import Queue
import threading
import time

google_sheets_queue = Queue()
log = logging_methods.logging_methods()

def score_domain(domain, watchdomain, watch_keywords):
    '''
    The domain to be analysed compared with the watchdomain that we are monitoring.

    :param domain: the domain of the newly registered cert.
    :param watchdomain: the domain that we are monitoring
    :return: the score of the domain in question.
    '''
    fuzzy = fuzzy_matcher()

    domain = clean_domain(domain)
    score = 0

    for t in bad_repuation_tlds:
        if domain.endswith(t):
            score += 20

    #Fuzzy matching
    score += fuzzy.score_keywords(keywords, domain)*100

    words_in_domain = split_domain_into_words(domain)
    for key in watch_keywords:
        if key in words_in_domain:
            score+= 50
        else:
            fuzzy_keyword_score = fuzzy.score_keywords(words_in_domain, key)
            score+=fuzzy_keyword_score

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]
        # ie. detect fake .com (ie. *.com-account-management.info)
        if words_in_domain[0] in ['com', 'net', 'org']:
            score += 10

    #is the watch domain embedded in the new domain.
        if watchdomain_in_domain(domain, watchdomain):
            score+=100

    return score

def handle_score_and_log(domain, watchdomain, score):
    '''
    Pass this to our various logging methods and decide if we should log them.
    :param domain:
    :param watchdomain:
    :param score:
    :return:
    '''
    #For now this is just logging to console, but google spreadsheets to come.
    log.console_log(domain, watchdomain, score)
    if google_spreadsheet_url and len(google_spreadsheet_url) > 0:
        google_sheets_queue.put((domain, watchdomain, score))
        #log.google_sheets_log(domain, watchdomain, score)

def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        #Cycle through all of our domains found in the cert
        for domain in all_domains:

            #Cycle through each of the domains that we're watching for.
            for watchdomain in watchlist:
                score = score_domain(domain.lower(), watchdomain, keywords)

                #If it's issued by free CA, more suspect.
                if "Let's Encrypt" in message['data']['chain'][0]['subject']['aggregated']:
                    score += 15
                handle_score_and_log(domain, watchdomain, score)

def google_worker():
    while True:
        domain, watchdomain, score = google_sheets_queue.get()
        log.google_sheets_log(domain, watchdomain, score)
        google_sheets_queue.task_done()
        time.sleep(1)

if google_spreadsheet_url and len(google_spreadsheet_url) > 0:
        print ("Spawning {} google sheets threads".format(num_threads))
        for i in range(num_threads):
            t = threading.Thread(target=google_worker)
            t.start()

certstream.listen_for_events(callback)
