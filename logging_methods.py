from default_settings import google_spreadsheet_url, google_threshold
import sheets
import tqdm
from termcolor import colored
import datetime
from utils import whois_lookup
from tldextract import extract

log_suspicious = 'suspicious_domains.log'
pbar = tqdm.tqdm(desc='certificate_update', unit='cert')
goog_sheets = None

class logging_methods:
    def google_sheets_log(self, domain, watchdomain, score):
        '''
        This function is a wrapper for logging to google sheets.

        :param domain: Suspicious domain
        :param watchdomain: domain we flagged it impersonating
        :param score: score
        :return: Nothing.
        '''
        if score < google_threshold:
            return
        global goog_sheets
        if not goog_sheets:
            goog_sheets = sheets.sheets_api(google_spreadsheet_url)
        print ("logging....")
        if not(google_spreadsheet_url and len(google_spreadsheet_url) > 0):
            print ("Not sending to google spreadsheets. If you would like to send to a spreadsheet, configure it in the settings file.")
        top_level = extract(domain).registered_domain
        whois_data = whois_lookup(top_level)
        message = [('Date discovered', str(datetime.datetime.now())),('Suspicious Domain', domain), ('Watch domain', watchdomain), ('WHOIS', whois_data), ('Score', score)]
        goog_sheets.add_suspicious_phishing_entry(message)

    def console_log(self, domain, watchdomain, score):
        '''
        This will handle the writing of suspicious domains to the CLI.

        :param domain: The suspect domain
        :param watchdomain: The domain it appears to have impostered
        :param score: The score that our engine gave it.
        :return: None
        '''
        pbar.update(1)
        if score >= 120:
            tqdm.tqdm.write(
                "[!] Very Suspicious: "
                "{} (score={}) flagged for {}".format(colored(domain, 'red', attrs=['underline', 'bold']), score, watchdomain))
        elif score >= 100:
            tqdm.tqdm.write(
                "[!] Suspicious: "
                "{} (score={}) flagged for {}".format(colored(domain, 'red', attrs=['underline']), score, watchdomain))
        elif score >= 90:
            tqdm.tqdm.write(
                "[!] Likely    : "
                "{} (score={}) flagged for {}".format(colored(domain, 'yellow', attrs=['underline']), score, watchdomain))
        elif score >= 75:
            tqdm.tqdm.write(
                "[+] Potential : "
                "{} (score={}) flagged for {}".format(colored(domain, attrs=['underline']), score, watchdomain))
        '''
        else:
            tqdm.tqdm.write(
                "[+] Safe : "
                "{} (score={}) flagged for {}".format(colored(domain, attrs=['underline']), score, watchdomain))
        '''

        if score >= 75:
            with open(log_suspicious, 'a') as f:
                f.write("{}\n".format(domain))
