import unittest
import sys
sys.path.append('../')
from matcher import fuzzy_scorer, watchdomain_in_domain

class test_fuzzy_matching(unittest.TestCase):
    def test_score_keywords(self):
        # Positive matches
        self.assertEqual((fuzzy_scorer(["paypal"], "paypal")), 1.0)
        self.assertEqual((fuzzy_scorer(["paypal"], "longpaypalstring")), 1.0)
        self.assertEqual((fuzzy_scorer(["paypol"], "paypal")), 0.8333333333333334)
        self.assertEqual((fuzzy_scorer(["paypal1"], "paypal")), 1.0)

        # Negative matches
        self.assertEqual((fuzzy_scorer(["zzzzzz"], "longpaypalstring")), 0.0)

        # Fuzzy matches
        self.assertEqual((fuzzy_scorer(["paypol"], "longpaypalstring")), 0.8333333333333334)
        self.assertEqual((fuzzy_scorer(["poypol"], "longpaypalstring")), 0.6666666666666666)

        # Multiple keywords
        self.assertEqual((fuzzy_scorer(["zzzz", "qqq", "poypol", "ttt"], "longpaypalstring")), 0.6666666666666666)

def main():
    unittest.main()


if __name__ == '__main__':
    main()
