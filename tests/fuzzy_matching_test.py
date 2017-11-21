import unittest
import sys
sys.path.append('../')
from matcher import fuzzy_scorer, watchdomain_in_domain

class test_fuzzy_matching(unittest.TestCase):
    def test_score_keywords(self):
        # Positive matches
        self.assertEqual((fuzzy_scorer({"paypal":100}, "paypal")), 1.0)
        self.assertEqual((fuzzy_scorer({"paypal":100}, "longpaypalstring")), 1.0)
        self.assertEqual((fuzzy_scorer({"paypol":100}, "paypal")), 0.83)
        self.assertEqual((fuzzy_scorer({"paypal1":100}, "paypal")), 1.0)

        # Negative matches
        self.assertEqual((fuzzy_scorer({"zzzzzz":100}, "longpaypalstring")), 0.0)

        # Fuzzy matches
        self.assertEqual((fuzzy_scorer({"paypol":100}, "longpaypalstring")), 0.83)
        self.assertEqual((fuzzy_scorer({"poypol":100}, "longpaypalstring")), 0)

        # Multiple keywords
        self.assertEqual((fuzzy_scorer({"zzzz":100, "qqq":100, "paypol":100, "ttt":100}, "longpaypalstring")), 0.83)

def main():
    unittest.main()


if __name__ == '__main__':
    main()
