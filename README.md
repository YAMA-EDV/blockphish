![BlockPhish](https://i.imgur.com/Y37F3Il.png)

# Phishing detection for cryptocurrency projects

Phishing remains one of the greatest off chain security threats to the
cryptocurrency space with increasingly sophisitcated groups targeting
their victims across Slack, Telegram, forums as well as email. This
project streams newly registered SSL certificates using
[certstream](https://certstream.calidog.io/) and attempts to identify
suspicious domains based on keywords set by the user in near real time.

![usage](https://i.imgur.com/4BGuXkR.gif)

### Installation

The program has not been tested extensively with python 2, we'd strongly
recommend using python 3.

You will need the following python packages installed:

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
your tokensale and company. You can also whitelist domains that are
similarly named to your domain that you would not like to receive alerts
for.
```
...

...
```

#### Keywords

Select appropriate keywords for your project. For example, myetherwallet.com
might include:
```
...
keywords = {
    "myetherwallet" : 100,
    "etherwallet" : 80,
    "etherwal" : 60
    }
...
```

The integer associated with each keyword reflects the likelihood that a
domain containing the keyword is a malicious clone.

#### Google SOC

A Security Operations Centre (SOC) is a unit dedicated to handling
security incidents in large organisations. Most teams working
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
permission to the google account you set in the monitoring profile.
4. Update the following fields in your monitoring_profile.json file:
```
...
  "google_spreadsheet_url" : "https://docs.google.com/spreadsheets/d/<your spreadsheet>",
  "google_drive_email" : "email@domain.com", #Email to access the spreadsheet as.
  "google_threshold" : 90, #Domains over this score will be written to the spreadsheet
...
```
5. You should be good to

### Unit tests
You can ensure that everything is running as intended and setup correctly
by running:
```
python3 -m unittest discover -s tests/ -p '*_test.py'
```

### Usage

```
$ ./catch_phishing.py
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

If you would like further assistance with combatting phishing attacks we'd
be happy to [hear from you](https://www.iosiro.com/contact-us).

### Thanks
Thanks to @x0rz https://github.com/x0rz/phishing_catcher for the original inspiration.

License
----
GNU GPLv3
