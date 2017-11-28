from utils import *
import unittest
class test_main(unittest.TestCase):
    def test_split_domain(self):
        self.assertTrue(remove_tld("paypal.com") == "paypal")
        self.assertTrue(remove_tld("test"))

def main():
    unittest.main()


if __name__ == '__main__':
    main()
