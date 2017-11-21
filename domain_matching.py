

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
