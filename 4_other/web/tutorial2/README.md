\newpage

## Appendix A1, Web: BadStore.net

This tutorial will walk through badstore web app hacking demo. The objective is to familiarize myself with web security assessment and to the best of my capabilities (both searching, reasoning and developing), try to come up with a) a common and strategic structure to follow when performing web assessments and b) a set of utilities to automate (as much as possible) the process.

**Expected outcomes**:
- structure to perform a web assessment
- tools to automate the assessment process

<!-- TOC depthFrom:1 depthTo:6 withLinks:1 updateOnSave:1 orderedList:0 -->

- [BadStore.net](#badstorenet)
	- [Getting the infrastructure](#getting-the-infrastructure)
	- [Introduction to the environment and background research on the structure (how to proceed)](#introduction-to-the-environment-and-background-research-on-the-structure-how-to-proceed)
	- [Diving into web hacking](#diving-into-web-hacking)
		- [Information gathering](#information-gathering)
			- [Fingerprinting](#fingerprinting)
			- [Finding out web tree through URL fuzzing](#finding-out-web-tree-through-url-fuzzing)
		- [Authentication](#authentication)
			- [Brute force](#brute-force)
	- [Review of the structure and classification of web vulns](#review-of-the-structure-and-classification-of-web-vulns)
	- [A few sites that provide help/advice](#a-few-sites-that-provide-helpadvice)

<!-- /TOC -->

### Getting the infrastructure
```bash
docker pull jvhoof/badstore-docker # v1.2.3
docker run -d -p 80:80 jvhoof/badstore-docker
```

### Introduction to the environment and background research on the structure (how to proceed)
I start review [@badstore.netv2.1.2006] which provides an intro to the environment. The document informs about a variety of different vulnerabilities and classifies them in different groups as follows:

- Authentication
  - Brute Force
  - Insufficient Authentication
  - Weak Password Recovery Validation
- Authorization
  - Credential/Session Prediction
  - Insufficient Authorization
  - Insufficient Session Expiration-
  - Session Fixation
- Client-side Attacks
  - Content Spoofing
  - Cross-site Scripting (XSS)
- Command Execution
  - Buffer Overflow
  - Format String Attack
  - LDAP Injection
  - OS Commanding
  - SQL Injection
  - SSI Injection-
  - XPath Injection
- Information Disclosure
  - Directory Indexing
  - Information Leakage
  - Path Traversal
  - Predictable Resource Location
- Logical Attacks
  - Abuse of Functionality
  - Denial of Service
  - Insufficient Anti-automation
  - Insufficient Process Validation

An alternative yet valid and good approach to web security is described by [@walden2008integrating] where he proposes the following structure:

- Web Application Input
  - HTTP Requests
  - URLs
  - Cookies
  - Form Parameterse. Encodings

- Client-side Technologies
  - Javascript Security
  - Java Security Model
  - ActiveX Trust Model
  - Bypassing Client Security

- Input-based Attacks
  - Path Traversal
  - Web Testing Proxies
  - Vulnerability Scanners
  - Input Validation
  - Blacklist Filters
  - Whitelist Filters

- Injection Attacks
  - Interpreters and Injection
  - SQL Injection
  - Shell Injection
  - File Inclusion
  - XML Injection
  - Separating Code and Data

- Cross-Site Attacks
  - Stored Cross-Site Scripting
  - Reflected Cross-Site Scripting
  - HTTP Header Injection
  - Cross-Site Request Forgery
  - Output Encoding

- Authentication
  - Basic, Digest, and Form Authentication
  - Passwords
  - SSL
  - Session Management

OWASP provides yet another methodology and structure at https://www.owasp.org/images/1/19/OTGv4.pdf which mainly defines the following sub-categories for active testing:

- Information Gathering
- Configuration and Deployment Management Testing
- Identity Management Testing
- Authentication Testing
- Authorization Testing
- Session Management Testing
- Input Validation Testing
- Error Handling
- Cryptography
- Business Logic Testing
- Client Side Testing

We'll be sticking with the first structure and complement it with a review at the very end that should provide a final (justified on experience) classification.

With regard the approach, [@meucci2014owasp] provides a comprehensive despcription of different ways to proceed:
- Manual inspection and reviews
- Threat modelling (led by NIST 800-30 [11], https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf)
- Source code review
- Penetration testing (cheap)

In the following sections we'd simply proceed with the last one which is the most common approch in most cases AFAIK

### Diving into web hacking
Let's dive into it. Fetched a few books for diving a bit deeper into this and went through them. Mostly:
- [ ] The Web Applications Hackers Handbook, second edition


#### Information gathering
Before diving into hacks, let's obtain some information about the website. This is somewhat nicely described at [@meucci2014owasp] and available online at https://www.owasp.org/index.php/Testing_Information_Gathering

##### Fingerprinting
When one fingerprints, usually, we'll aim to obtain the following:

- Whois is Details
- Software used and version
- OS Details
- Sub Domains
- File Name and File Path
- Scripting Platform & CMS Details
- Contact Details

We'll ommit the first one (since it's running in a docker container and it's a demo setup) but let's look into the others and see what we can fetch:

```bash
whatweb 192.168.1.0/24
http://192.168.1.0 ERROR: Network is unreachable - connect(2) for "192.168.1.0" port 80
http://192.168.1.0 [ Unassigned]
http://192.168.1.1 [200 OK] Cookies[SESSION], Country[RESERVED][ZZ], HTTPServer[micro_httpd], HttpOnly[SESSION], IP[192.168.1.1], JQuery[1.6.3], PasswordField[pass], Script[text/javascript], Title[movistar], X-Frame-Options[sameorigin], micro_httpd
http://192.168.1.8 ERROR: No route to host - connect(2) for "192.168.1.8" port 80
http://192.168.1.9 ERROR: No route to host - connect(2) for "192.168.1.9" port 80
http://192.168.1.5 ERROR: No route to host - connect(2) for "192.168.1.5" port 80
...
http://192.168.1.10 [ Unassigned]
http://192.168.1.24 [ Unassigned]
http://192.168.1.33 [200 OK] Apache[2.4.10], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.10 (Debian)], IP[192.168.1.33], Meta-Refresh-Redirect[/cgi-bin/badstore.cgi]
http://192.168.1.18 [ Unassigned]
http://192.168.1.12 ERROR: No route to host - connect(2) for "192.168.1.12" port 80
http://192.168.1.13 ERROR: No route to host - connect(2) for "192.168.1.13" port 80
http://192.168.1.6 ERROR: No route to host - connect(2) for "192.168.1.6" port 80
http://192.168.1.25 ERROR: No route to host - connect(2) for "192.168.1.25" port 80
http://192.168.1.16 ERROR: No route to host - connect(2) for "192.168.1.16" port 80
http://192.168.1.11 ERROR: No route to host - connect(2) for "192.168.1.11" port 80
```

That already tells us quite a bit!

Targetting the particular IP address:

```bash
whatweb 192.168.1.33
http://192.168.1.33 [200 OK] Apache[2.4.10], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.10 (Debian)], IP[192.168.1.33], Meta-Refresh-Redirect[/cgi-bin/badstore.cgi]
http://192.168.1.33/cgi-bin/badstore.cgi [200 OK] Apache[2.4.10], Country[RESERVED][ZZ], Frame, HTTPServer[Debian Linux][Apache/2.4.10 (Debian)], IP[192.168.1.33], Title[Welcome to BadStore.net v1.2.3s - The most insecure store on the 'Net!]
```

We now know we're dealing with an Apache that's installed into Debian. We also happen to know the version of Apache that's running.

Let's try some other tools:
```bash
./httprint -h 192.168.1.33 -s signatures.txt
httprint v0.301 (beta) - web server fingerprinting tool
(c) 2003-2005 net-square solutions pvt. ltd. - see readme.txt
http://net-square.com/httprint/
httprint@net-square.com

--------------------------------------------------
Host: 192.168.1.33
ICMP request time out on 192.168.1.33

--------------------------------------------------
```

Not very useful. Let's jump into the next topic

 ##### robots.txt

Searching on `http://192.168.1.33/robots.txt` one finds the following:

```bash
 # /robots.txt file for http://www.badstore.net/
 # mail webmaster@badstore.net for constructive criticism

User-agent: badstore_webcrawler
Disallow:

User-agent: googlebot
Disallow: /cgi-bin
Disallow: /scanbot # We like Google

User-agent: *
Disallow: /backup
Disallow: /cgi-bin
Disallow: /supplier
Disallow: /upload
```

##### Finding out web tree through URL fuzzing

A simple search follows below:

```bash
[+] [13:54:37] - [200] - [/backup/] -> http://192.168.1.33/backup/
[+] [13:54:37] - [200] - [/backup/] -> http://192.168.1.33/backup/
[+] -[200] -http://192.168.1.33/backup/
[+] -[200] -http://192.168.1.33/backup/
```

It's also possible to provide a list of keywords and expressions but we'll leave that aside for now.
Let's dive into pentesting.

#### Authentication

According to [@stuttard2011web], the phases of authentication web pentesting are:

![Testing the authentication mechanism, from @stuttard2011web](background/images/2019/09/bla.png)

Or in the second edition:

![Testing the authentication mechanism, from @stuttard2011web (second edition)](background/images/2019/09/second-edition.png)

Let's follow this methodology in the coming subsections:

##### Methodology

###### Test password quality

Attemped to register with weak password `1234`:

- username: test@gmail.com
- password: 1234

![Weak registration attempt](background/images/2019/09/weak-registration-attempt.png)

Seems it is valid because it allows me to log in successfully:

![Log in successful after registration with weak password](background/images/2019/09/log-in-successful-after-registration-with-weak-password.png)

Tested the registration format and it seems it only accepts 8 characters. Created another username:

- username: hola@gmail.com
- password: 12345678

It seems it tests the 8 characters. No limitation on the attempts to log in has been identified.

###### Test for username enumeration




###### Test for password guessing



###### Test account recovery
###### Test “remember me”
###### Test impersonation functions
###### Test username uniqueness
###### Test credential predictability
###### Check for unsafe transmission
###### Check for unsafe distribution
###### Test for fail-open logic
###### Testmultistageprocesses

##### Back to BadStore

For our case and according to [@badstore.netv2.1.2006], most of the areas that require authentication submit stuff in plain text and without encryption at all. Let's dive a bit into this.

![Indeed the parameters are sent in plain text](background/images/2019/08/indeed-the-parameters-are-sent-in-plan-text.png)

Something similar happens when logging in:

![Logging in isn't secured](background/images/2019/08/logging-in-isn-t-secured.png)

The implications of this I presume is that pretty much anyone listening in the network can literally obtain all the related information. Let's make a simple test using wireshark:

![Indeed that's the case, capture from wireshark while monitoring the network interface](background/images/2019/08/indeed-that-s-the-case-capture-from-wireshark-while-monitoring-the-network-interface.png)

##### Brute force
The objective of this section is to figure out the passwords of the different accounts in the system. For that, we first may need to figure out the accounts themselves. In this case it can easily be done (since they're directly printed) by navigating the website:

![User accounts leak](background/images/2019/08/user-accounts-leak.png)

From this point on, I guess one would go and try to figure out the admin account or other user's accounts.


##### Insufficient Authentication
TODO

##### Weak Password Recovery Validation
TODO

### Review of the structure and classification of web vulns
TODO (refer)

### A few sites that provide help/advice
- https://www.coursera.org/learn/software-security/supplement/H1cBJ/project-2
- https://d28rh4a8wq0iu5.cloudfront.net/softwaresec/virtual_machine/BadStore_net_v2_1_Manual.pdf
- https://www.cs.umd.edu/class/fall2012/cmsc498L/materials/BadStore_net_v1_2_Manual.pdf
- https://medium.com/syscall59/badstore-1-2-3-walkthrough-vulnhub-7816f3001333
- https://medium.com/yassergersy/badstore-assignment-d93422e56b31
