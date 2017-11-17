#!/usr/bin/env python
# Copyright (c) 2017 @x0rz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
import re
import certstream
import tqdm
from tldextract import extract, TLDExtract
from termcolor import colored, cprint
from settings import watchlist, keywords, tlds
from fuzzy_matching import fuzzy_matcher


log_suspicious = 'suspicious_domains.log'

pbar = tqdm.tqdm(desc='certificate_update', unit='cert')

def clean_domain(domain):
    '''
    Tidy up the domain for processing.

    :param domain: domain to clean
    :return: cleaned up domain
    '''

    domain = domain.strip(".*").strip(".").strip().lower()
    return domain

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

    for t in tlds:
        if domain.endswith(t):
            score += 20

    #Fuzzy matching
    score += fuzzy.score_domains(domain, watchdomain)

    words_in_domain = split_domain_into_words(domain)
    for key in watch_keywords:
        if key in words_in_domain:
            score+= 50
        else:
            fuzzy_keyword_score = fuzzy.score_keywords(words_in_domain, key)
            if fuzzy_keyword_score > 50:
                score+=50

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

def split_domain_into_words(domain) :
    '''
    Split the domain into it words if possible, e.g. paypal-account.com -> ['paypal', 'account']
    :param domain:
    :return:
    '''
    #Remove the tld
    tld = extract(domain)
    domain = domain.replace(tld.suffix, "")


    #Get list of TLDs
    extract_object = TLDExtract()
    all_tlds = extract_object._get_tld_extractor()
    all_tlds = extract_object.tlds

    for tld in all_tlds:
        domain = domain.replace('.'+tld+'.', ".")

    words = set()
    current_word = ""
    for char in domain:
        if not char.isalnum():
            words.add(current_word)
            current_word = ""
            continue
        current_word += char
    return sorted(list(words))

def watchdomain_in_domain(new_domain, watchdomain):
    '''
    This function takes in the newly discovered domain and the domain that you are monitoring. It then determines whether
    or not the registered domain is imitating the watchdomain for e.g. is paypal.com in paypal.com.malicious.com

    :param new_domain: newly registered domain
    :param watchdomain: domain that we are monitoring
    :return: Boolean value reflecting whether the new_domain infringes on the watchdomain.
    '''
    is_subdomain_of_watchdomain = new_domain.endswith("."+watchdomain)
    is_watchdomain = new_domain == watchdomain
    if is_subdomain_of_watchdomain or is_watchdomain:
        #Okay, this is actually the watchdomain.
        return False

    #Okay, if it's not *the* domain, does if have the domain somewhere in it?
    if watchdomain in new_domain:
        return True

    #Nothing to see here.
    else:
        return False

def handle_score_and_log(domain, watchdomain, score):
    '''
    Pass this to our various logging methods and decide if we should log them.
    :param domain:
    :param watchdomain:
    :param score:
    :return:
    '''
    #For now this is just logging to console, but google spreadsheets to come.
    console_log(domain, watchdomain, score)


def console_log(domain, watchdomain, score):
    '''
    This will handle the writing of suspicious domains to the CLI.

    :param domain: The suspect domain
    :param watchdomain: The domain it appears to have impostered
    :param score: The score that our engine gave it.
    :return: None
    '''
    pbar.update(1)
    if score >= 100:
        tqdm.tqdm.write(
            "[!] Suspicious: "
            "{} (score={}) flagged for {}".format(colored(domain, 'red', attrs=['underline', 'bold']), score, watchdomain))
    elif score >= 90:
        tqdm.tqdm.write(
            "[!] Suspicious: "
            "{} (score={}) flagged for {}".format(colored(domain, 'red', attrs=['underline']), score, watchdomain))
    elif score >= 80:
        tqdm.tqdm.write(
            "[!] Likely    : "
            "{} (score={}) flagged for {}".format(colored(domain, 'yellow', attrs=['underline']), score, watchdomain))
    elif score >= 65:
        tqdm.tqdm.write(
            "[+] Potential : "
            "{} (score={}) flagged for {}".format(colored(domain, attrs=['underline']), score, watchdomain))

    if score >= 75:
        with open(log_suspicious, 'a') as f:
            f.write("{}\n".format(domain))

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

#certstream.listen_for_events(callback)
