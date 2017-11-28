![BlockPhish](https://i.imgur.com/Y37F3Il.png)

# Phishing detection for cryptocurrency projects

Phishing remains one of the greatest off-chain security threats to the
cryptocurrency space, with increasingly sophisticated groups targeting
their victims across Slack, Telegram, forums, as well as email. This
project streams newly registered SSL certificates using
[certstream](https://certstream.calidog.io/) and attempts to identify
suspicious domains based on keywords set by the user in near real time.

![usage](https://i.imgur.com/4BGuXkR.gif)

### Installation

The program has not been tested with Python 2, we'd strongly
recommend using Python 3.

You will need the following python packages installed:

* termcolor
* certstream
* tqdm
* tld
* python_Levenshtein
* gspread
* fuzzywuzzy

To install the packages run:

```sh
pip3 install -r requirements.txt
```

### Setup

In order to service your own project, you will need to create a
monitoring profile. The simplest way to do this is copy one of the
existing profiles in the monitoring_profiles directory. After doing so,
adapt the configuration of the file as outlined below.

#### Domains

The watchlist variable in settings refers to specific domain(s) that you
intend to monitor. These will typically be the domain(s) associated with
your tokensale, project or company.
```
...
"watchlist" : {
    "myetherwallet.com": {
      "myetherwallet": 100, "myether": 50
    }
 }
...
```
In addition to the domains that you would like to monitor, you can
associate an arbitrary number of keywords with that domain. In the
example above, MyEtherWallet also wants to monitor the keywords
"myetherwallet" and "myether".

You can also whitelist domains that you do not want to monitor by adding them
to the whitelist variable in your monitoring profile:
```
...
"whitelisted_domains" : ["myetherwallet.com"]
...
```


#### Google SOC

A Security Operations Centre (SOC) is a unit dedicated to handling
security incidents in large organizations. Most teams working
out of the crypto/blockchain space will not have a SOC, and as a result
this project attempts to create a lean & reliable substitute by
bootstrapping off of Google Sheets. Doing so allows teams to handle and
attend to phishing incidents with relative ease, including setting email
alerts to notify of changes to the spreadsheet.

In order to configure this project to work with Google Sheets, you will
need to create signed credentials.

1. Create signed credentials for your google account. (Guide [here](https://gspread.readthedocs.io/en/latest/oauth2.html))
2. Save these credentials in a file called **creds.json** in the credentials
directory in this project.
3. Create a copy of the spreadsheet https://docs.google.com/spreadsheets/d/1kLwTQBnhpcRKzYpFeHSh1zqOJMY8H5ESqEwKM0xhnJc/,
or alternatively create a blank spreadsheet. Ensure that you grant *edit*
permission to the spreadsheet by the google account you set in the monitoring profile.
4. Update the following fields in your monitoring_profiles/monitoring_profile.json file:
```
...
  "google_spreadsheet_url" : "<your spreadsheet id>", #This is the value from the URL
                                                      #https://docs.google.com/spreadsheets/d/<KEY>/
  "google_drive_email" : "email@domain.com", #Account to access the spreadsheet as.
  "google_threshold" : 90, #Domains over this score will be written to the spreadsheet
...
```

You should now start seeing domains that score over the specified
threshold being written to your spreadsheet. [Setup email notifications](https://support.google.com/docs/answer/91588?co=GENIE.Platform%3DDesktop&hl=en)
on the spreadsheet to receive notifications any time the program writes
to the spreadsheet.

### Unit tests
You can ensure that everything is running as intended and setup correctly
by running:
```
python3 -m unittest discover -s tests/ -p '*_test.py'
```

### Usage

```
$ python3 blockphish.py monitoring_profile/profile.json
```

### Examples of suspicious domains

A clear clone of an existing well known brand with minor changes:

![Blockchain.info Clone](https://i.imgur.com/EBHn2VU.png)

A simple typo on MyEtherWallet:

![Myetherwallet](https://i.imgur.com/p0eXL68.png)

A [homograph](https://en.wikipedia.org/wiki/IDN_homograph_attack) attack
on MyEtherWallet (note the 'e's).

![Myetherwallet](https://i.imgur.com/YSTKcCC.png)

### Further assistance

If you would like [further assistance](https://www.iosiro.com/phishing-countermeasures/) with combatting phishing attacks we'd
love to [hear from you](https://www.iosiro.com/contact-us).

### Thanks

Thanks to @x0rz https://github.com/x0rz/phishing_catcher for the original inspiration.

License
-------
GNU GPLv3

Donations
---------

**ETH Donation Address:** 0x4fC60C34266af4106353c35d9600585e17F60512
