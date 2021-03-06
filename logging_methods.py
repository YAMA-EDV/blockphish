import sheets
import tqdm
from termcolor import colored
import datetime
from utils import whois_lookup
from tldextract import extract
from default_settings import auto_lookup_whois
from multiprocessing import Process
from image_utils import image_process
import requests

log_suspicious = 'suspicious_domains.log'
pbar = tqdm.tqdm(desc='certificate_update', unit='cert')

class logging_methods:
    def __init__(self,google_spreadsheet_key, log_to_cloud_functions, config_name):
        if google_spreadsheet_key:
            print (google_spreadsheet_key)
            self.goog_sheets = sheets.sheets_api(google_spreadsheet_key, config_name)
        self.reported_domains = set()
        self.im_util = image_process.image_utils()

    def report_cloud_function(self, cloudfunctions_url, domain, watchdomain, score, google_threshold):
        if domain in self.reported_domains or domain.strip("www.") in self.reported_domains:
            return
        else:
            self.reported_domains.add(domain)
        if score > google_threshold:
            r = requests.post(cloudfunctions_url, json = {"domain" : domain, "safeDomain" : watchdomain, "score" : score, "reasoning" : "Flagged as similar by SSL stream.", "source" : "blockphish"})

    def google_sheets_log(self, domain, watchdomain, score, google_sheets_url, google_threshold, config_name):
        '''
        This function is a wrapper for logging to google sheets.

        :param domain: Suspicious domain
        :param watchdomain: domain we flagged it impersonating
        :param score: score
        :return: Nothing.
        '''

        #If score below threshold.
        if score < google_threshold:
            return

        #Don't bother reporting both www.domain.com and domain.com
        if domain in self.reported_domains or domain.strip("www.") in self.reported_domains:
            return
        else:
            self.reported_domains.add(domain)

        #check if we need to initialise google_sheets.
        if not self.goog_sheets:
            self.goog_sheets = sheets.sheets_api(google_sheets_url, config_name)

        top_level = extract(domain).registered_domain
        if auto_lookup_whois:
            whois_data = whois_lookup(top_level)
        else:
            whois_data = "https://www.godaddy.com/whois/results.aspx?checkAvail=1&tmskey=&domain={}&prog_id=GoDaddy".format(domain)

        visual_similarity = self.im_util.compare_website_visually("http://" + domain, "http://" + watchdomain)
        print (visual_similarity)
        message = [('Date discovered', str(datetime.datetime.now())),('Suspicious Domain', domain), ('Watch domain', watchdomain), ('Score', score), ('Visual Similarity', visual_similarity), ('WHOIS', whois_data)]
        self.goog_sheets.add_suspicious_phishing_entry(message)

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
