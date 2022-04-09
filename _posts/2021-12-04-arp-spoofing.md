---
layout: single
title: ARP-SPOOFING
excerpt: "ARP spoofing is a Man in the Middle `(MitM)` attack that allows attackers to `intercept` communication between network devices."
date: 04-12-2021
classes: wide
header:
  teaser: "https://user-images.githubusercontent.com/84678370/124039879-b1ec3c80-d9fb-11eb-9dde-b5c5fd0209cc.jpg"
  teaser_home_page: true
  icon: "https://static.thenounproject.com/png/81023-200.png" 
categories:
  - MitM
tags:
  - Arp
  - Networking
  - Protocol
  - Credentials
  - Spoofing
---

<img src= "https://user-images.githubusercontent.com/84678370/124039879-b1ec3c80-d9fb-11eb-9dde-b5c5fd0209cc.jpg" width="300" height="200" />

> In this article we will see how to obtain `credentials` in `cleartext`, through an `arp spoofing` attack

<a href="https://my.ine.com/CyberSecurity/courses/6f986ca5/penetration-testing-basics" style="color:bluesky">__INE-LAB__</a>

> All tests in this article will be performed at the INE free lab.

### <span style="color:green"> ARP </span>

![E](https://marvel-b1-cdn.bc0a.com/f00000000216283/www.fortinet.com/content/fortinet-com/en_us/resources/cyberglossary/what-is-arp/_jcr_content/par/c05_container_copy_c/par/c28_image_copy_copy_.img.jpg/1625683953964.jpg)

> Image Src: <a href="https://marvel-b1-cdn.bc0a.com/f00000000216283/www.fortinet.com/content/fortinet-com/en_us/resources/cyberglossary/what-is-arp/_jcr_content/par/c05_container_copy_c/par/c28_image_cop" style="color:red">__Fortinet__</a> 

- - <a href="https://en.wikipedia.org/wiki/Address_Resolution_Protocol" style="color:bluesky">__Wikipedia__</a>
- - <a href="https://www.ionos.es/digitalguide/servidores/know-how/arp-resolucion-de-direcciones-en-la-red" style="color:bluesky">__Ionos__</a>
- - <a href="https://www.fortinet.com/resources/cyberglossary/what-is-arp" style="color:bluesky">__Fortinet__</a>

> The address resolution protocol `(ARP)` is a data link layer communications protocol responsible for finding the `(MAC)` hardware address that corresponds to a given `IP` address. This is done by sending an `(ARP request)` packet to the network broadcast address `(broadcast, MAC = FF FF FF FF FF FF FF FF FF FF FF FF FF)` containing the IP address being queried, and waiting for that `(or another)` machine to reply `(ARP reply)` with the Ethernet address that corresponds to it.


### <span style="color:green"> ARP-SPOOF </span>

- - <a href="https://github.com/HI0U/ArpSpoofing-Auto" style="color:bluesky">__Arp-Spoofing-Auto__</a>
- - <a href="https://www.veracode.com/security/arp-spoofing" style="color:bluesky">__Veracode__</a>
- - <a href="https://en.wikipedia.org/wiki/ARP_spoofing" style="color:bluesky">__Wikipedia__</a>
- - <a href="https://www.incibe-cert.es/blog/arp-spoofing" style="color:bluesky">__Incibe__</a>
- - <a href="https://www.imperva.com/learn/application-security/arp-spoofing/" style="color:bluesky">__Imperva__</a>

> `(MitM)` Usually the purpose is to `associate` the attacker's `MAC` address with the `IP` address of another node `(the attacked node)`, such as the default gateway. Any traffic directed to that node's IP address will be mistakenly `sent` to the attacker, rather than to its actual destination.


> To execute this attack i am going to use my `ArpSpoofing-Auto` tool writen in `bash`, which automates the `sniffing` process with the `ArpSpoof` and `tshark` tools, to give you a `.pcap` file to analyze with `wireshark`.


* Identify the telnet server and the client machine



* Intercept traffic between the two



* Analyze the traffic and steal valid credentials





![Telnet](https://user-images.githubusercontent.com/84678370/130321813-eb4b11b5-7ace-4a9f-ba15-e3e7319e4a91.png)



- __10.100.13.37 server, 10.100.13.36 client__





### <span style="color:green"> Arp-Spoofing Tool </span>

```

wget https://raw.githubusercontent.com/HI0U/ArpSpoofing-Auto/main/Auto-arp.sh

```

```

chmod +x Auto-arp.sh

```

```

./Auto-arp.sh

```

![Test](https://user-images.githubusercontent.com/84678370/130322952-681d33ce-8392-4dc5-96d5-daf177ad7226.png)


> Once we get that capture, you can analyze it in `wireshark` to get the `credentials` and connect to the server via `telnet`.

![ARP](https://user-images.githubusercontent.com/84678370/132102774-6af9dc44-8baa-40ac-9d65-845f5c241ef4.png)

---
