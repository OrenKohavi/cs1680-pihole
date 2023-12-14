# cs1680-pihole

## How to run the DNS server:
1. Ensure port 53 (or whichever port you choose to run the DNS server on) is not in use. (`sudo lsof -i :53` may be helpful)
2. run `make` to compile the DNS server
3. run `sudo ./main` to run the DNS server as root. This is required because the DNS server listens on port 53, which is a privileged port.
4. Enjoy!


## Introduction:
I set out to build a DNS server that functioned similarly to pihole. This means that it would forward legitimate DNS queries to a DNS server upstream (I used 8.8.8.8 for this project), but would block any DNS queries to domains that were on an advertising blacklist.
My goal was to make this DNS server robust and compatible enough that I could use it as my primary DNS server for real-world use. I planned to run this DNS server on an Azure VM, so that it would be assigned a static IP and would be accessible from anywhere.

I am happy to say that I've achieved everything I set out to do!

> **Try it out!** If you're looking at this soon after creation (i.e. 2023 or early 2024), it's highly likely that my DNS server is still up and publicly accessible. Try querying my DNS server at `20.109.124.88` (Port 53, of course), and give it a shot!

## Design/Implementation:
My DNS server is written entirely in C++, and I had an absolute blast learning about new and modern C++ features that I had never used before. It requires C++20 STL features to compile, and I learned a ton.

On startup, the script downloads a list of domains to block from an array of blocklist URLs, and then parses them into a trie. This trie is then used to check if a domain is on the blocklist. If it is, the DNS server responds with a fake IP address (0.0.0.0). If it is not, the DNS server forwards the query to the upstream DNS server, and simply acts as a proxy.

> Sidenote: I implemented the entire Trie class/structure in C++ from scratch for the blocklist, which was a wonderful learning experience.

The DNS server listens on both UDP and TCP to support modern DNS queries, and can be configured to listen on any port.

Once a request is received through either UDP or TCP, the DNS server parses the request and checks if the domain is on the blocklist. If it is, it responds with a fake IP address. If it is not, it forwards the request to the upstream DNS server and responds with the response from the upstream DNS server.

This is all demonstrated in my demo video, in the repository as `Demo_Video.mkv`

## Conclusions/Future work:

Working on this project was a blast, and was my first opportunity to experiment with new syscalls like `select`, and cool C++ features like references, classes, compiler hints, templates, etc. I learned a ton, and I'm very happy with the result.

Future work could include making the DNS server multithreaded, which would allow it to both handle simultaneous requests, and would also increase the robustness of the server, since a query that hangs or fails would not impact the DNS server as a whole.

Additional future work could include caching results from the upstream DNS server.