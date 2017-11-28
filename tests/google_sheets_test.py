import unittest
import sys
sys.path.append('../')
import sheets

class test_main(unittest.TestCase):

    def test_domain_word_split(self):
        goog = sheets.sheets_api("1YzA4ybUqJdNAoeEq6L_US_zbF5SzT9_bWeXL2wyLizQ",
        "matt@zenoic.com")
        goog.add_suspicious_phishing_entry([("test", "entry")])

def main():
    unittest.main()


if __name__ == '__main__':
    main()
