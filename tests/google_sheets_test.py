import unittest
import sys
sys.path.append('../')
import sheets

class test_main(unittest.TestCase):
    def test_domain_word_split(self):
        goog = sheets.sheets_api("12Jnp_AR6DWAKFs6F6AR1IpX3TweGp9qNvfs7XEbBzqc", "test")
        goog.add_suspicious_phishing_entry([("test", "entry")])

def main():
    unittest.main()


if __name__ == '__main__':
    main()
