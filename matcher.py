import Levenshtein
from fuzzywuzzy import fuzz
from math import log10

def fuzzy_scorer(keywords, target):
    '''
    This method uses a sliding window and the Levenshtein distance to determine if the keyword is found in any substrings of the target. e.g. it helps you recognize that 'paypol' is closely found in 'longpaypalstring'

    It will return a value between 0 and 1.

    :param keywords: List of keywords to monitor for a given domain.
    :param target: The potential phishing domain.
    :return: a float representing the score.
    '''
    
    score = 0.0

    for keyword in keywords:
        # Find the shorter string
        shorter,longer = (keyword,target) if len(keyword) < len(target) else (target,keyword)
        # Set the window length equal to the shorter string
        window_length = len(shorter)

        # Set the number of times to move the window
        num_iterations = len(longer)-len(shorter)+1

        # Find the Levenshtein distance with the highest ratio (lowest distance)
        for position in range(0, num_iterations):
            window = longer[position:position+window_length]
            result = Levenshtein.ratio(window, shorter)
            if(result > score):
                score = result

        simple = fuzz.ratio(keyword, target) / 100
        partial = fuzz.partial_ratio(keyword, target) / 100
        sort = fuzz.token_sort_ratio(keyword, target) / 100
        set_ratio = fuzz.token_set_ratio(keyword, target) / 100

        if simple > score:
            score = simple
        if partial > score:
            score = partial
        if sort > score:
            score = sort
        if set_ratio > score:
            score = set_ratio
    
    # Only looking for strings that are quite similar, anything less than that is noise
    if score < 0.7:
        score = 0

    return score

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
        # This is actually the watchdomain.
        return False

    # If it's not *the* domain, does it have the domain somewhere in it?
    if watchdomain in new_domain:
        return True

    # Nothing to see here.
    else:
        return False