from tldextract import extract, TLDExtract
import pythonwhois
import statistics
import Levenshtein
from fuzzywuzzy import fuzz


def clean_domain(domain):
    '''
    Tidy up the domain for processing.

    :param domain: domain to clean
    :return: cleaned up domain
    '''
    #Lets ensure that it's in an nice string format for idna

    try:
        domain = domain.encode("idna").decode("idna")
    except:
        pass
    domain = domain.strip("*.").strip(".").strip().lower()
    return domain

def is_whitelisted(domain, whitelist):
    '''
    Is the domain in our whitelist from the config file.
    '''
    cleaned_domain = clean_domain(domain)
    for white in whitelist:
        if domain.endswith(white):
            return True
    return False

def whois_lookup(domain):
    try:
        whois_data = pythonwhois.net.get_whois_raw(domain)
        if len(whois_data) > 0:
            return whois_data[0]
    except:
        return "Couldn't lookup WHOIS"

def split_domain_into_words(domain) :
    '''
    Split the domain into words if possible, e.g. paypal-account.com -> ['paypal', 'account']
    :param domain:
    :return:
    '''
    # Remove the tld
    tld = extract(domain)
    domain = domain.replace(tld.suffix, "")


    # Get list of TLDs
    extract_object = TLDExtract()
    all_tlds = extract_object.tlds

    for tld in all_tlds:
        domain = domain.replace('.'+tld+'.', ".")

    words = set()
    current_word = ""

    # Split the domain into words based on non-alphanumeric chars acting as splits.
    for char in domain:
        if not char.isalnum():
            if len(current_word) > 0:
                words.add(current_word)
            current_word = ""
            continue
        current_word += char
    return sorted(list(words))


def remove_tld(domain) :
    '''
    Split the domain into words if possible, e.g. paypal-account.com -> ['paypal', 'account']
    :param domain:
    :return:
    '''
    try:
    # Remove the tlds
        tld = extract(domain).suffix
        domain = ''.join(domain.rsplit(tld, 1)).strip('.')
    except Exception as e:
        #print ("Error Stripping TLD {}: domain is ".format(e, domain))
        pass
    return domain



def fuzzy_scorer_domain(domain, target):
    '''
    This method uses a sliding window and the Levenshtein distance to determine if the keyword is found in any substrings of the target. e.g. it helps you recognize that 'paypol' is closely found in 'longpaypalstring'

    It will return a value between 0 and 1.

    :param domain: Watch domain
    :param target: The potential phishing domain.
    :return: a float representing the score.
    '''

    score = 0

    # The watch domain is shorter than the target domain, so use a sliding window
    if len(domain) < len(target):
        shorter,longer = (domain,target) 
            # Set the window length equal to the shorter string
        window_length = len(shorter)

        # Set the number of times to move the window
        num_iterations = len(longer)-len(shorter)+1

        # Find the Levenshtein distance
        for position in range(0, num_iterations):
            window = longer[position:position+window_length]
            l_ratio = Levenshtein.ratio(window, shorter) * 100

            if l_ratio > 60:
                result = statistics.mean([100 - Levenshtein.distance(window, shorter) * 15, l_ratio, l_ratio])
            else:
                result = l_ratio
            if result > score:
                score = result
                
    # The target domain is shorter, so just use a single measurement
    else: 
        l_ratio = Levenshtein.ratio(domain, target) * 100
        score = statistics.mean([100 - Levenshtein.distance(domain, target) * 15, l_ratio, l_ratio])
    
    simple = fuzz.ratio(domain, target) 
    partial = fuzz.partial_ratio(domain, target)
    sort = fuzz.token_sort_ratio(domain, target)
    set_ratio = fuzz.token_set_ratio(domain, target)

    score = max([score, simple, partial, sort, set_ratio])

    # Only looking for strings that are quite similar, anything less than that is noise
    if score < 75:
        score = 0

    return score * 0.85

def fuzzy_scorer_keywords(keywords, target):
    '''
    This method uses a sliding window and the Levenshtein distance to determine if the keyword is found in any substrings of the target. e.g. it helps you recognize that 'paypol' is closely found in 'longpaypalstring'

    It will return a value between 0 and 1.

    :param keywords: List of keywords to monitor for a given domain.
    :param target: The potential phishing domain.
    :return: a float representing the score.
    '''

    score = 0
    value = 0

    for keyword, value in keywords.items():
        # Find the shorter string
        shorter,longer = (keyword,target) if len(keyword) < len(target) else (target,keyword)

        # Set the window length equal to the shorter string
        window_length = len(shorter)

        # Set the number of times to move the window
        num_iterations = len(longer)-len(shorter)+1

        # Find the Levenshtein distance
        for position in range(0, num_iterations):
            window = longer[position:position+window_length]
            l_ratio = Levenshtein.ratio(window, shorter) * 100

            if l_ratio > 60:
                result = statistics.mean([100 - Levenshtein.distance(window, shorter) * 10, l_ratio, l_ratio])
            else:
                result = l_ratio
            if result > score:
                score = result

        simple = fuzz.ratio(keyword, target)
        partial = fuzz.partial_ratio(keyword, target)
        sort = fuzz.token_sort_ratio(keyword, target)
        set_ratio = fuzz.token_set_ratio(keyword, target)

        old_score = score

        score = max([score, simple, partial, sort, set_ratio])

        if old_score != score:
            value = value

    score = (score - 15) * (value / 100) / 2

    if score < 60:
        score = 0

    return score * 0.90

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
