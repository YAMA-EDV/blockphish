import unittest
import sys
sys.path.append('../')
import catch_phishing

class test_main(unittest.TestCase):
    
    def test_domain_word_split(self):
        domain1 = "paypal-account.com"
        words = catch_phishing.split_domain_into_words(domain1)
        self.assertEqual(words, sorted(['paypal', 'account']))

        domain2 = "paypal.paypal.com.phishing.co.za"
        words = catch_phishing.split_domain_into_words(domain2)
        self.assertEqual(words, sorted(['paypal', 'phishing']))

    def test_domain_in_watchdomain(self):
        domain = "paypal.com.domain.com"
        watch_domain = "paypal.com"
        self.assertTrue(catch_phishing.watchdomain_in_domain(domain, watch_domain))

        domain = "otherdomain.com"
        watch_domain = "paypal.com"
        self.assertFalse(catch_phishing.watchdomain_in_domain(domain, watch_domain))


    def test_score_domain(self):
        
        domain = "paypal.com"
        watch_domain = "paypal.com"
        score = catch_phishing.score_domain(domain, watch_domain, [])
        print ("Domain: {} Watch Domain: {} Score: {}".format(domain, watch_domain, score))
        self.assertEqual(score, 0, "paypal.com is the watch domain and paypal.com is the suspect domain. Shouldn't flag")

        # Check for the domain in the watch_domain
        domain = "paypal.com.paypel.com"
        watch_domain = "paypal.com"
        score = catch_phishing.score_domain(domain, watch_domain, [])
        print ("Domain: {} Watch Domain: {} Score: {}".format(domain, watch_domain, score))
        self.assertGreater(score, 100, "domain in the watch_domain not flagging")

        # Check for simple typo
        domain = "paypel.com"
        watch_domain = "paypal.com"
        score = catch_phishing.score_domain(domain, watch_domain, [])
        print ("Domain: {} Watch Domain: {} Score: {}".format(domain, watch_domain, score))
        self.assertGreater(score, 80, "domain in the watch_domain not flagging")

        # Check for different TLD
        domain = "paypal.net"
        watch_domain = "paypal.com"
        score = catch_phishing.score_domain(domain, watch_domain, [])
        print ("Domain: {} Watch Domain: {} Score: {}".format(domain, watch_domain, score))
        self.assertGreater(score, 80, "domain in the watch_domain not flagging")
        
        # Check for keywords
        domain = "test.my.paypal.domain.com"
        watch_domain = "paypal.com"
        score = catch_phishing.score_domain(domain, watch_domain, ['paypal'])
        print ("Domain: {} Watch Domain: {} Score: {}".format(domain, watch_domain, score))
        self.assertGreater(score, 80, "domain in the watch_domain not flagging")
        
        # Check for keywords
        domain = "test.my.paypel.domain.com.co.za"
        watch_domain = "paypal.com"
        score = catch_phishing.score_domain(domain, watch_domain, ['paypal'])
        print ("Domain: {} Watch Domain: {} Score: {}".format(domain, watch_domain, score))
        self.assertGreater(score, 80, "domain in the watch_domain not flagging")

        # Check for keywords
        domain = "test.my.paypel-domain.com.co.za"
        watch_domain = "paypal.com"
        score = catch_phishing.score_domain(domain, watch_domain, ['paypal'])
        print ("Domain: {} Watch Domain: {} Score: {}".format(domain, watch_domain, score))
        self.assertGreater(score, 70, "domain in the watch_domain not flagging")

        # Check for similar but longer
        domain = "payinpal.com"
        watch_domain = "paypal.com"
        score = catch_phishing.score_domain(domain, watch_domain, ['paypel'])
        print ("Domain: {} Watch Domain: {} Score: {}".format(domain, watch_domain, score))
        self.assertGreater(score, 50, "domain in the watch_domain not flagging")
        
        # Check for no match
        domain = "johnsapples.com"
        watch_domain = "paypal.com"
        score = catch_phishing.score_domain(domain, watch_domain, ['salamander'])
        print ("Domain: {} Watch Domain: {} Score: {}".format(domain, watch_domain, score))
        self.assertLess(score, 10, "domain in the watch_domain not flagging")
        
def main():
    unittest.main()


if __name__ == '__main__':
    main()
