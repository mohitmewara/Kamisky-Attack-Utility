# Kamisky-Attack-Utility
The objective of this project is to mimic the Kamisky Attack in a closed environment.

Set-Up:
The details to set up the attacker and the client machine can be found in Report.pdf. The pdf also contains the findings and results.

Description:
Implemented the tool using C language in which the tool sends queries of none-existing domain names to DNS server and then do sequence number guessing attack by sending spoofed responses.

Cache Poisoning attack is made successful by designing the response payload in such a way that it makes a nameserver entry in DNS server's cache.

Special care has been taken to ensure that packets do not leak to the internet by implementing the Client and DNS servers in a closed environment.


