sslprobe
========

sslprobe is a tool that maps out a server's TLS configuration and identifies potential problems, such as supporting obsolete protocols or preferring weak cipher suites.
I like to play with Qualys' SSLLabs a lot, so I decided to make my own.

Usage
-----
From the command-line, type:
```
./sslprobe.php {HOST} [{PORT}]
```
e.g.
```
./sslprobe.php github.com
```
If you omit the port number, this script will default to 443 (HTTPS).

Example output:
![Example output](example-output.png)
