# Authoritative Nameserver

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

### /etc/bind/named.config.options

```
options {
    directory "/var/cache/bind";
        listen-on { 10.13.37.5; }; # Only listen on internal network
        allow-transfer { none; };
        recursion no;
        querylog yes;
};
```

### /etc/bind/named.config.local

```
zone "attack.me" {
  type master;
  file "/var/lib/bind/db/attack.me";
  allow-query { any; };
  allow-transfer { 10.13.37.3; };
};
```

### /var/lib/bind/db/attack.me

- This file needs to be created. It is specified in the above zone configuration.

```
$ORIGIN attack.me.
$TTL	60;

@       IN      SOA     ns1.attack.me. root.attack.me. (
                            2024021101 ; serial
                            3600      ; refresh (1 hour)
                            600       ; retry (10 minutes)
                            86400     ; expire (1 day)
                            36000     ; minimum (10 hours)
                          )

@       IN      NS      ns1.attack.me.
ns1     IN      A       10.13.37.5
@       IN      A       10.13.37.5
```

Note that:
- The `ns1.attack.me` and `attack.me` records both point to the IP for this specific machine.
- The ns1 domain will be used in the configuration for the authoritative name server.

## Start/Enable Bind

### Check Configuration

- Check zone configuration with `sudo named-checkconf`.
- Check record syntax with `sudo named-checkzone attack.me /var/lib/bind/db/attack.me`.

### Start/Enable Service

- `sudo systemctl restart bind9`
- `sudo systemctl enable bind9`

## Test Nameserver

- `nslookup attack.me 10.13.37.5`

## Artifical Latency

```
sudo apt install iproute2
```

To add latency:

```
sudo tc qdisc add dev enp0s5 root netem delay 100ms
```

- Swap `enp0s5` with the interface pointing towards the resursive resolver.

To remove the latency:

```
sudo tc qdisc del dev enp0s5 root
```