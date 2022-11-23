#HSRP-scapytest

##Overview
Utilising Scapy hsrp.py to atack. Building our own TLV for hsrpv2. Included additional tools like cdp and using kali's inbuilt arp scanner (more comprehensive than scapy)

###Usage
1. `pip3 install scapy`

2. Use wireshark or tool to identify active router and virtual IP address for the network. Also identify HSRP version

![image](https://user-images.githubusercontent.com/91510432/203464307-7d980250-61ad-424a-8a42-1209c3da0d66.png)

3. Launch attack using python script!

![image](https://user-images.githubusercontent.com/91510432/203464328-2535539d-5499-4b74-bf9a-843b3b12d313.png)


4. Script does routing automatically to route old packets to previous active router. Achieving MiTM. 

![image](https://user-images.githubusercontent.com/91510432/203464358-dae84a2e-4e98-4b2b-8190-b276d37933d9.png)

5. Use MiTM tools to sniff traffic. (Works best only for HTTP, not so effective anymore with HTTPS and hsts)

![image](https://user-images.githubusercontent.com/91510432/203464366-67f4e5e9-0902-4c7c-b244-0193ee97931e.png)

