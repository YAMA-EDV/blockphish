'''
import unittest
import sys
sys.path.append('../')
from utils import fuzzy_scorer, watchdomain_in_domain

class test_fuzzy_matching(unittest.TestCase):
    def test_score_keywords(self):
        # Positive matches
        self.assertEqual((fuzzy_scorer({"paypal":100}, "paypal")), 100.0)
        self.assertEqual((fuzzy_scorer({"paypal":100}, "longpaypalstring")), 100.0)
        self.assertGreater((fuzzy_scorer({"paypol":100}, "paypal")), 80)
        self.assertEqual((fuzzy_scorer({"paypal1":100}, "paypal")), 100.0)

        # Negative matches
        self.assertLess((fuzzy_scorer({"z":100}, "longpaypalstring")), 30.0)
        self.assertLess((fuzzy_scorer({"zzzzz":100}, "longpaypalstring")), 30.0)

        # Fuzzy matches
        self.assertGreater((fuzzy_scorer({"paypol":100}, "longpaypalstring")), 80)
        self.assertLess((fuzzy_scorer({"poypol":100}, "longpaypalstring")), 75)
        self.assertLess((fuzzy_scorer({"poypoll":100}, "longpaypalstring")), 60)

        # Multiple keywords
        self.assertGreater((fuzzy_scorer({"zzzz":100, "qqq":100, "paypol":100, "ttt":100}, "longpaypalstring")), 80)

def main():
    unittest.main()


if __name__ == '__main__':
    main()
'''