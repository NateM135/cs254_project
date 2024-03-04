# Sad DNS Implementation


## Running Instructions

### Setup Nameserver

### Setup Recursive Resolver

### Setup Attacker

- Clone repository
- Initialize virtual environment with `python3 -m venv venv/`
- Activate virtual environment with `source ./venv/bin/activate` if on unix or `source ./venv/scripts/Activate.ps1` if on Windows
- Install dependencies with `pip3 install -r requirements.txt`
- Ensure the resolver's cache for the desired domain is not cached. This must be done on the resolver machine.
- Run attack **AS SUPERUSER** with `python3 attack.py`