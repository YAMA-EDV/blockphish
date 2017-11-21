####################
#Google Spreadsheets SOC(Security Operations Centre)
####################

#Should be writable by the user specified credentials in
google_spreadsheet_url = ""
#The user to write changes to the spreadsheet under.
google_drive_email = ""
#If anything scores above this, we should send it to the google spreadsheet.
google_threshold = 75

####################
#Domains
####################

#Domains to monitor
watchlist = ["myetherwallet.com", "paypal.com"]

#Whitelist - do not create alerts for these domains.
whitelisted_domains = ["google.com"]

keywords = {
    'myether' : 80,
    'localbitcoin': 70,
    'poloniex': 60,
    'coinhive': 70,
    'bithumb': 60,
    'kraken': 50, # some false positives
    'bitstamp': 60,
    'bittrex': 60,
    'blockchain': 70,
    'bitflyer': 60,
    'coinbase': 60,
    'hitbtc': 60,
    'lakebtc': 60,
    'bitfinex': 60,
    'bitconnect': 60,
    'coinsbank': 60
}

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
