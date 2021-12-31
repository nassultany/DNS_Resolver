# DNS Resolver

External libraries used:
    dnspython,cryptography

## How to run:
### Mydig
`python3 mydig.py <domain> <type>`

For example:

`python3 mydig.py www.apple.com A`

`python3 mydig.py yahoo.com NS`

`python3 mydig.py gmail.com MX`

### DNSSEC

`python3 mydnssec.py <domain>`

For example:

`python3 mydnssec.py internetsociety.org`

`python3 mydnssec.py dnssec-failed.org`
