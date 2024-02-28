# Recursive Resolver

## Prework

Before setting up the resolver, it would be useful to have the authoritative nameserver for the domain setup. To test this, you can use `nslookup attack.me <authoritative nameserver ip>`

## Update System

```
sudo apt update
sudo apt upgrade
```

## Install Bind

```
sudo apt install bind9 bind9utils
```

## Bind Configuration

### /etc/bind/named.conf.options

```
options {
	directory "/var/cache/bind";
	dnssec-validation no;
	listen-on { any; };
	use-v4-udp-ports { range 1337 1337; };
	forwarders { 10.13.37.5; };
        recursion yes;
};
```

- Make sure dnssec-validation is off. Older versions of bind will have a different setting for this, but turning off dns-sec is essential for the attack to work out properly.
- Note that we are setting a static source port here.
- The forwarder IP is the authoritative name server.
- The TTL for the record issued by the nameserver should be very low, to allow for debugging.

## Start/Enable Bind

### Check Configuration

- Check zone configuration with `sudo named-checkconf`.

### Start/Enable Service

- `sudo systemctl restart bind9`
- `sudo systemctl enable bind9`

## Test Nameserver

- Modify `/etc/resolv.conf` and add a new nameserver option. Ensure this new nameserver is the first nameserver in the file. Set this to the IP of the authoritative nameserver.
- `nslookup attack.me`. It should resolve and mention that a non-authoritative answer was given.
- 'nslookup attack.me {authoriative nameserver ip}`. This should return the record directly from the authoritative nameserver and not mention anything about the record not being authoritative.
- A sanity check can be done by doing `nslookup google.com`. nslookup should report back that the authoritative nameserver we set up failed to resolve, and it will query an additional dns server (the real server being used in whatever network setup). This lets us redirect traffic to the right place without cutting off normal internet/dns.
