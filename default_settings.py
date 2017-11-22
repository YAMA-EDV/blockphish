####################
#Google Spreadsheets SOC(Security Operations Centre)
####################

#Should be writable by the user specified credentials in
google_spreadsheet_url = "https://docs.google.com/spreadsheets/d/1kLwTQBnhpcRKzYpFeHSh1zqOJMY8H5ESqEwKM0xhnJc/edit#gid=0"
#The user to write changes to the spreadsheet under.
google_drive_email = "matt@zenoic.com"
#If anything scores above this, we should send it to the google spreadsheet.
google_threshold = 75

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
bad_repuation_tlds = [
    '.ga',
    '.gq',
    '.ml',
    '.cf',
    '.tk',
    '.xyz',
    '.pw',
    '.cc',
    '.club',
    '.work',
    '.top',
    '.support',
    '.bank',
    '.info',
    '.study',
    '.party',
    '.click',
    '.country',
    '.stream',
    '.gdn',
    '.mom',
    '.xin',
    '.kim',
    '.men',
    '.loan',
    '.download',
    '.racing',
    '.online',
    '.center',
    '.ren',
    '.gb',
    '.win',
    '.review',
    '.vip',
    '.party',
    '.tech',
    '.science',
    '.business'
]
