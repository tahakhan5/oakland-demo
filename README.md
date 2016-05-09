# oakland-demo



## Requirements
(preferably in a virtualenv) run:
```
pip install -r requirements.txt
```

on OSX:
```
  brew install --with-python libdnet
```

## Initialization on WiFi Pineapple

1. Turn on the WiFi Pineapple and wait for the blue light to go stable.
1. Connect to the `Free_WiFi` access point.
1. In a browser go to `172.16.42.1:1471` and login.
1. Under the networking tab, enable `client AP` by scanning and connecting to a local WiFi for Internet access.
1. Under the configuration tab, enable the the landing page (disabled on default after device reboot.


## Usage
```
  python google_cookie.py [listening interface]
```
