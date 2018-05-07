import unittest
import logging_methods

class test_main(unittest.TestCase):
    def test_sheets_logging(self):
        log = logging_methods.logging_methods('17efqX2ubePcEghFbyOuFYIuHrPzQf2uxND1yKBgRKLc', 'monitoring_profiles/paypal.json')
        log.google_sheets_log("test.com", "test.com", 200, "17efqX2ubePcEghFbyOuFYIuHrPzQf2uxND1yKBgRKLc", 0, 'unittest')

def main():
    unittest.main()


if __name__ == '__main__':
    main()
