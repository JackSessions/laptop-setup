
## What has been tested
Verified by reproducing the behaviour on the lab laptop (alert raised in Kibana):
- **Creation Of An User Account**: `useradd` of a throwaway user
- **DNS Events Related To Mining Pools**: a DNS lookup of a listed pool domain

Converted and running without errors, but **not yet triggered**: Loading of Kernel Module via Insmod, NKN Detection,
DNS TOR Proxies, Executable from Webdav. My first Tor-proxy test used a made-up name that failed to resolve, so Zeek never
saw a reply; test with a name that actually resolves.
