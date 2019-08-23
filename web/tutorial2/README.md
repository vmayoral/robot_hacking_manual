# BadStore.net

This tutorial will walk through badstore web app hacking demo. The objective is to familiarize myself with web security assessment and to the best of my capabilities (both searching, reasoning and developing), try to come up with a) a common and strategic structure to follow when performing web assessments and b) a set of utilities to automate (as much as possible) the process.

**Expected outcomes**:
- structure to perform a web assessment
- tools to automate the assessment process

## Getting the infrastructure
```bash
docker pull jvhoof/badstore-docker # v1.2.3
docker run -d -p 80:80 jvhoof/badstore-docker
```

## Introduction to the environment and background research on the structure (how to proceed)
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

We'll be sticking with the first structure and complement it with a review at the very end that should provide a final (justified on experience) classification.

## Diving into web hacking
Let's dive into it

### Authentication

#### Brute force
TODO

## Review of the structure and classification of web vulns
TODO (refer)

## A few sites that provide help/advice
- https://www.coursera.org/learn/software-security/supplement/H1cBJ/project-2
- https://d28rh4a8wq0iu5.cloudfront.net/softwaresec/virtual_machine/BadStore_net_v2_1_Manual.pdf
- https://www.cs.umd.edu/class/fall2012/cmsc498L/materials/BadStore_net_v1_2_Manual.pdf
- https://medium.com/syscall59/badstore-1-2-3-walkthrough-vulnhub-7816f3001333
- https://medium.com/@yassergersy/badstore-assignment-d93422e56b31