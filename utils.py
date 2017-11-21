from tldextract import extract, TLDExtract

def clean_domain(domain):
    '''
    Tidy up the domain for processing.

    :param domain: domain to clean
    :return: cleaned up domain
    '''
    domain = domain.strip("*.").strip(".").strip().lower()
    return domain


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
    # Remove the tlds
    tld = extract(domain).suffix
    domain = ''.join(domain.rsplit(tld, 1)).strip('.')

    return domain
