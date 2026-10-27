d# Security Policy

## Responsible use

This tool performs offline static analysis of JSON Web Tokens and makes no
network requests. Use it only on tokens and systems you own or are explicitly
authorized to test.

The optional weak-secret check needs a wordlist you supply and the
`--i-own-this-token` flag. It runs entirely on your machine, never prints the
secret it finds, and never creates or forges tokens.

This project does not include, and will not accept, exploit-delivery tooling,
mass scanning, brute-forcing of live services, or token forging.

## Reporting a vulnerability in this tool

If you find a security problem in this project (for example a crash on crafted
input, a way to make it print a secret, or terminal-escape injection through
token contents), please report it privately using GitHub's "Report a
vulnerability" option under the repository's Security tab.

Include the version, steps to reproduce, and a sample token if relevant. Do not
include real secrets or tokens from systems you do not own.

## Support

This is a hobby and portfolio project provided as is, with no guaranteed
response time or maintenance schedule.