#Rename this to settings.py


####################
#Google Spreadsheets SOC(Security Operations Centre)
####################

#Should be writable by the user specified credentials in
google_spreadsheet_url = ""
#The user to write changes to the spreadsheet under.
google_drive_email = ""
#Number of threads for google sheets worker (recommended is 1)
num_threads = 1

####################
#Domains
####################

#Domains to monitor
watchlist = ["myetherwallet.com", "paypal.com"]

#Whitelist - do not create alerts for these domains.
whitelisted_domains = ["google.com"]

keywords = {

# Cryptocurrency
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
    'coinsbank': 60,

# Miscellaneous & SE tricks
    'cgi-bin': 50,
    '.com-': 20,
    '-com.': 20,
    '.net-': 20,
    '.org-': 20,
    '.com-': 20,
    '.net.': 20,
    '.org.': 20,
    '.com.': 20,
    '.gov-': 30,
    '.gov.': 30,
    '.gouv-': 40,
    '-gouv-': 40,
    '.gouv.': 40,
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
