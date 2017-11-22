####################
#Google Spreadsheets SOC(Security Operations Centre)
####################

#Should be writable by the user specified credentials in
google_spreadsheet_url = ""
#The user to write changes to the spreadsheet under.
google_drive_email = ""
#If anything scores above this, we should send it to the google spreadsheet.
google_threshold = 90

####################
#Domains
####################

#Domains to monitor
watchlist = {
        "myetherwallet.com" :
            {"myetherwallet" : 100, "myether" : 50},
        "paypal.com" :
            {"paypal" : 90, "paypalcorp" : 50}
}


#Whitelist - do not create alerts for these domains.
whitelisted_domains = ["ethereum.org"]
