import gspread
from oauth2client.service_account import ServiceAccountCredentials
from default_settings import google_drive_email

class sheets_api:
    def __init__(self, spreadsheet_url):
        credentials = ServiceAccountCredentials.from_json_keyfile_name('credentials/creds.json',scopes=['https://spreadsheets.google.com/feeds','https://www.googleapis.com/auth/drive'])
        self.delegated_credentials = credentials.create_delegated(google_drive_email)
        self.gc = gspread.authorize(self.delegated_credentials)
        self.spreadsheet = None
        self.spreadsheet_url = spreadsheet_url
        self.first_run = True

    def add_suspicious_phishing_entry(self, tuple_list):
        '''
        The tuple list should be a list of ("Attribute", "Value") tuples. e.g.

        [("IPAddress", "91.23.12.1", "User-Agent", "Mac OS Mozilla/1.1"),...]
        '''

        self.check_token_valid()
        print ("Getting the worksheet...")
        worksheet = self.spreadsheet.get_worksheet(0)

        if self.first_run:
            print ("Fetching current records")
            all_records = worksheet.get_all_values()
            if len(all_records) == 0:
                #In otherwords, we need to format this worksheet appropriately
                header_list = [header[0] for header in tuple_list]
                print ("Adding row.... {}".format(header_list))
                worksheet.append_row(header_list)
            self.first_run = False

        #Now we need to add the values.
        print (tuple_list)
        value_list = [header[1] for header in tuple_list]
        print ("Adding row.... {}".format(value_list))
        worksheet.append_row(value_list)
        print ("row added...")

    def check_token_valid(self):
        try:
            #This is to check whether we still have access to the spreadsheet.
            if self.delegated_credentials.access_token_expired:
                self.gc.login()
                self.spreadsheet = self.gc.open_by_url(self.spreadsheet_url)
                return True

            #This is to intialise the spreadsheet if it's the first time running this code.
            if not self.spreadsheet:
                self.spreadsheet = self.gc.open_by_url(self.spreadsheet_url)
                return True

        except Exception as e:
            print (e)
            return False
