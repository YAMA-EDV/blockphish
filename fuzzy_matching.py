from fuzzywuzzy import fuzz, process, StringMatcher
import math
class fuzzy_matcher:
    def score_keywords(self, domain_words, keyword):
        '''

        :param domain:
        :param keywords:
        :return:
        '''
        keywords_matching_algs = [self._plain_levenshtein]
        score = 0.0
        for domain_word in domain_words:
            for m in keywords_matching_algs:
                score+=m(domain_word, keyword)
        return (score/len(keywords_matching_algs)) * 0.8

    def score_domains(self, domain, watchdomain):
        '''
        This method will take in the domain and watch domain and perform a series of fuzzy matches on it, returning an
        overall score indicating the likelihood that it is some kind of clone.

        :param domain: the domain to test
        :param watchdomain: the safedomain that we are monitoring.
        :return: score indicating likelihood of malicious
        '''
        domain_matching_algs = [self._plain_levenshtein]
        score = 0.0
        for m in domain_matching_algs:
            score+=m(domain, watchdomain)

        return (score/len(domain_matching_algs))*0.8



    def _plain_levenshtein(self, domain, watchdomain):
        '''
        This method takes in the two domains for comparison and returns the Levenshtein dist between them scored.
        :param domain:
        :param watchdomain:
        :return:
        '''
        exponent = 1.1
        dist = StringMatcher.distance(domain, watchdomain)
        adjusted_dist = math.pow(dist, exponent)
        max_len = math.pow(float(max(len(domain), len(watchdomain))), exponent)
        if adjusted_dist == 0:
            #Exact match, fwiw we return 0
            return 0
        else:
            score = (1.0 - (adjusted_dist/max_len))*100
            print ("Levenshtein is {} for {} {} ".format(score, domain, watchdomain))
            return score

    def _partial_ratio(self, domain, watchdomain):
        fuzz.partial_ratio()
