import unittest
import sys
sys.path.append('../')
import sheets

class test_main(unittest.TestCase):

    def test_domain_word_split(self):
        goog = sheets.sheets_api("17efqX2ubePcEghFbyOuFYIuHrPzQf2uxND1yKBgRKLc",
        "matt@zenoic.com")
        goog.add_suspicious_phishing_entry([("test", "entry")])

def main():
    unittest.main()


if __name__ == '__main__':
    main()
