# Simple OpenCanary HoneyPot 🍯

This is a writeup of a honeypot test and the steps i took and what i learned about the threat actors.

1. Prep & Setup

    I started off by creating a Linode nanode instance with no VPC and on the public facing internet running Ubuntu 22.04 LTS, i enabled the Linode internal firewall for the machine before even creating it to ensure secure setup. I updated and upgraded and made a non root user for admin work and changed the ssh port to a random port (as Open Canary will use 22 & 80). 

1. Choose ports & Log actions
    
    I chose ports 22 (fake ssh is common for brute force or password spraying) and 80 (fake Apache 2.4.41 server as web scanners are common attackers) for this example. I set both ports allowed via the Linode firewall and adjusted the Open Canary config file.
    
2. Startup Open Canary and watch logs
   
    I did not use any external logging such as Grafana or Zabbix for this, only on system logging with enhanced file access restrictions (this was chosen for simplicity and ease of setup). Although i did whip up a quick Python script with ritch to cleanly parse and show the data, this will be included in the full GitHub writeup repo and is shown in screen shots.
4. Wait
    
    I waited for around 48 hours before i fully looked at all the data and see what was attempted over the time it was open. I cant exactly get the full feel of a enterprise honeypot as that requires a honeynet or to work with a larger known enterprise network with attackers already snooping, although i do plan to later setup another honeypot related to the recent CVE-2025-55182 exploit and see if any threat actors are still attempting attacks on that and what kind.
    
5. Results
    
    This is a simpler approach to a honeypot as we aren't seeing any actual attempts at exploits (at least in this 48 hour instance) and you usually wont unless the system / service is very outdated and certain automated scanners start hitting that IP range within in the time its public facing. 
    
    I saw a few attempts to send POST requests to our fake http page, not resulting in much info about an attack or attempted vector(s). Main traffic came into the ssh port with random attempts with the most common pair being `root : 123456`. This is all expected and i would be lucky to have seen an actual attempt at manual exploitation of this server, but my point of this still stands true. SECURE YOUR CREDS, there are always and will always be bad actors and bots to find ways into your infrastructure.
    

## 🧪Core Info

- How long until first login attempt after going live?
    - 3 minutes and 21 seconds, this shows why basic network security is so important.
    - This IP `80.94.95.115` (based Romania) was linked to **16/94** security vendors marking it malicious, with itself having ports 22,53,111,3128, and 8006 open and responding on some.
    - Also this IP `193.32.162.151` which has clearly been known for this traffic as VirusTotal community notes have many auto honeypot reports about this brute force attempt, specifically how many connections it makes with just the first 45m counting 50+ separate attempts
    - And this IP `103.114.163.150` had sent over 2600+ ssh attempts over the 48 hours, being noted on virus total recently as a enum/port scanning IP but having only 2/94 security vendors marking it malicious.

<img width="1637" height="162" alt="image" src="https://github.com/user-attachments/assets/32bb7d02-57e9-4f0c-89ec-62294bfa28e2" />


- Top 5 usernames and passwords attempted
    - **Username**
    - root        
    - admin       
    - ubuntu      
    - user        
    - debian      
    
    - **Passwords**
    - 123456
    - 1234
    - 123
    - admin
    - ubuntu
    
- Geographic origin of attacks
    - Romania
    - Russia
    - Ukraine
    - United States
    - China
    - Mongolia


    <img width="1632" height="861" alt="image" src="https://github.com/user-attachments/assets/f575cf72-f0ae-4ecd-b5e7-b89f73d7dc54" />
