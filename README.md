#HSRP-scapytest

##Overview
Utilising Scapy hsrp.py to atack. Building our own TLV for hsrpv2. Included additional tools like cdp and using kali's inbuilt arp scanner (more comprehensive than scapy)

###Usage
1. `pip3 install scapy`

2. Use wireshark or tool to identify active router and virtual IP address for the network.![image](https://user-images.githubusercontent.com/91510432/203463036-bc5124f6-49b0-4e3e-80fc-4ec89753b9bc.png)

3. Launch attack using python script![image](https://user-images.githubusercontent.com/91510432/203463143-d014b4da-252e-4708-bfad-138ee481566b.png)

4. Script does routing automatically to route old packets to previous active router. Achieving MiTM. 
![image](https://user-images.githubusercontent.com/91510432/203462936-b61ce08e-6430-48e0-afe9-b030d835999c.png)

5. Use MiTM tools to sniff traffic. (Works best only for HTTP, thought not so effective anymore with HTTPS and hsts)
![image](https://user-images.githubusercontent.com/91510432/203464038-2144cb7a-bb80-48ab-872c-1b4d88567eb6.png)
