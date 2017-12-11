import gspread
from oauth2client.service_account import ServiceAccountCredentials
from multiprocessing import Process
from threading import Thread
import logging
logger = logging.Logger("Sheets")
class sheets_api:
    def __init__(self, spreadsheet_url, config_name):
        self.config_name = config_name
        self.credentials = ServiceAccountCredentials.from_json_keyfile_name('credentials/creds.json',scopes=['https://spreadsheets.google.com/feeds','https://www.googleapis.com/auth/drive'])
        self.gc = gspread.authorize(self.credentials)
        self.spreadsheet_url = spreadsheet_url
        self.spreadsheet = self.gc.open_by_key(spreadsheet_url)
        self.first_run = True
        self.worksheet = None
        print ("Initialised sheets")

    def add_suspicious_phishing_entry(self, tuple_list):
        '''
        The tuple list should be a list of ("Attribute", "Value") tuples. e.g.

        [("IPAddress", "91.23.12.1", "User-Agent", "Mac OS Mozilla/1.1"),...]
        '''
        print("checking token")
        self.check_token_valid()
        print ("Getting the worksheet...")
        logger.info("Fetched worksheet..")
        if self.first_run:
            try:
                self.worksheet = self.spreadsheet.worksheet("SSL CERT Detect - {}".format(self.config_name))
            except gspread.exceptions.WorksheetNotFound:
                print("Error...")
                self.spreadsheet.add_worksheet(title="SSL CERT Detect - {}".format(self.config_name), rows="1", cols="10")
                self.worksheet = self.spreadsheet.worksheet("SSL CERT Detect - {}".format(self.config_name))

            values_list = self.worksheet.row_values(1)

            print ("Fetching current records")
            try:
                all_records = self.worksheet.get_all_values()
            except:
                all_records = []
            if len(all_records) == 0:
                #In otherwords, we need to format this worksheet appropriately
                header_list = [header[0] for header in tuple_list]
                self.worksheet.append_row(header_list)
            self.first_run = False


        #Now we need to add the values.
        value_list = [header[1] for header in tuple_list]

        #Send this to another proc - TODO handle this with a Queue.
        self.worksheet.append_row(value_list)
        print ("Row added...")

    def check_token_valid(self):
        try:
            #This is to intialise the spreadsheet if it's the first time running this code.
            if not self.spreadsheet:
                print("initiase sheets")
                self.spreadsheet = self.gc.open_by_key(self.spreadsheet_url)
                return True

            #This is to check whether we still have access to the spreadsheet.
            if self.credentials.access_token_expired:
                print("refresh token")
                self.gc.login()
                self.spreadsheet = self.gc.open_by_key(self.spreadsheet_url)
                return True

        except Exception as e:
            print (e)
            print ("ERROR")
            return False
