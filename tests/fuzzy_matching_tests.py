import unittest
import sys
sys.path.append('../')
import fuzzy_matching

class test_fuzzy_matching(unittest.TestCase):
    def test_score_keywords(self):
        # Positive matches
        self.assertEqual((fuzzy_matching.fuzzy_matcher().score_keywords(["paypal"], "paypal")), 1.0)
        self.assertEqual((fuzzy_matching.fuzzy_matcher().score_keywords(["paypal"], "longpaypalstring")), 1.0)
        self.assertEqual((fuzzy_matching.fuzzy_matcher().score_keywords(["paypol"], "paypal")), 0.8333333333333334)
        self.assertEqual((fuzzy_matching.fuzzy_matcher().score_keywords(["paypal1"], "paypal")), 1.0)

        # Negative matches
        self.assertEqual((fuzzy_matching.fuzzy_matcher().score_keywords(["zzzzzz"], "longpaypalstring")), 0.0)

        # Fuzzy matches
        self.assertEqual((fuzzy_matching.fuzzy_matcher().score_keywords(["paypol"], "longpaypalstring")), 0.8333333333333334)
        self.assertEqual((fuzzy_matching.fuzzy_matcher().score_keywords(["poypol"], "longpaypalstring")), 0.6666666666666666)

        # Multiple keywords
        self.assertEqual((fuzzy_matching.fuzzy_matcher().score_keywords(["zzzz", "qqq", "poypol", "ttt"], "longpaypalstring")), 0.6666666666666666)

def main():
    unittest.main()


if __name__ == '__main__':
    main()
