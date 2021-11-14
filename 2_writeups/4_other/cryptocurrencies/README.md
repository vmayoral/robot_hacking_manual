# Cryptocurrencies

This section will research the overall security landscape for cryptocurrencies and when applicable, its relationship to robotics.

<!-- TOC depthFrom:1 depthTo:6 withLinks:1 updateOnSave:1 orderedList:0 -->

- [Cryptocurrencies](#cryptocurrencies)
	- [General background](#general-background)
		- [Startups](#startups)
			- [Blockchain or cryptocurrency security startups](#blockchain-or-cryptocurrency-security-startups)
			- [Forensics](#forensics)
		- [Training and courses](#training-and-courses)
		- [Cryptos and other](#cryptos-and-other)
		- [Articles](#articles)
	- [Threat model](#threat-model)
	- [Weaknesses and vulnerabilities](#weaknesses-and-vulnerabilities)
	- [Cases of study](#cases-of-study)
	- [Other](#other)
		- [Anti-Money Laundering (AML)](#anti-money-laundering-aml)
		- [Academic articles](#academic-articles)
		- [Malware research](#malware-research)
		- [Standards](#standards)

<!-- /TOC -->

<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!--                          General background -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
## General background

- [x] https://www.lopp.net/bitcoin-information/security.html
  - [x] Jolly Roger's Security Guide for Beginners (online OPSEC) https://web.archive.org/web/20190331175207/https://www.deepdotweb.com/jolly-rogers-security-guide-for-beginners/  
  - [x] https://github.com/jlopp/physical-bitcoin-attacks/blob/master/README.md  
    - [ ] https://cointelegraph.com/news/two-masked-thieves-caught-on-tape-stealing-bitcoin-atm-in-the-us
  - [x] https://cryptosec.info/exchange-hacks/
    - [ ] https://discover.ledger.com/hackstimeline/
- [x] (VCs that might invest with cryptos) Biggest Crypto Hedge Funds and What They Tell About the Market https://cointelegraph.com/news/biggest-crypto-hedge-funds-and-what-they-tell-about-the-market

<details><summary><code>Blockchain or cryptocurrency security startups</code></summary>

### Startups
#### Blockchain or cryptocurrency security startups
- [Hosho](https://hosho.io/): They claim: *"The Global Leader in Blockchain Security"*. We provide industry leading technical audits of smart contracts for ICOs and token generation events.
- [Ledgerops](https://ledgerops.com/): LedgerOps is a leader in blockchain security. We provide offensive and defensive blockchain security services to keep you secure.
- [Certik](https://certik.org/): CertiK uses cutting-edge Formal Verification technology to prove hacker-resistance. Blockchain and smart contract auditing.
- [Bit-Sentinel](https://bit-sentinel.com): Reinforce your resilience to cyber attacks. Bit Sentinel performs professional independent penetration testing and provides certified cybersecurity services.

#### Forensics
- [Chainanalysis](https://www.chainalysis.com/): produces a wealth of interesting data on lost coins, hodling patterns and much more. Prevent, detect and investigate cryptocurrency money laundering, fraud and compliance violations.
- [Elliptic](https://www.elliptic.co/): The oldest forensics firm in the crypto world. Preventing and detecting criminal activity in cryptocurrencies.
- [Blockseer](https://www.blockseer.com/): Company that *"aims to reduce the level of disorder and chaos and increase the level of knowledge and analysis of the publicly accessible blockchain network"*.
- [Ciphertrace](https://ciphertrace.com/): Ciphertrace helps *“businesses and government make cryptocurrencies safe and trusted.”* 

</details>

<details><summary><code>Training and courses</code></summary>

### Training and courses
From where to potentially bring up a syllabus myself.

- [Cryptocurrency Investigator Certification Course](https://www.cryptoinvestigatortraining.com/)
- https://www.eventbrite.com/e/cryptocurrency-investigator-foundation-course-tickets-61950057289?aff=erelexpmlt
- https://www.eventbrite.com/e/cryptocurrency-forensic-investigator-advanced-course-tickets-61951483555?aff=erelexpmlt
- https://www.udemy.com/bitcoin-and-cryptocurrency-forensic-investigation-osint/

</details>

### Cryptos and other
- [ ]  Telegram Open Network (TON)
  - [ ] https://github.com/Kiku-Reise/TON
  - [ ] whitepaper https://test.ton.org/ton.pdf
  - [ ] https://test.ton.org/tvm.pdf
- [x] zcash http://zerocash-project.org/paper

### Articles
- [x] [Researchers Discover New Cryptocurrency-Focused Trojan](https://cointelegraph.com/news/researchers-discover-new-cryptocurrency-focused-trojan)  
- [ ] [Coinbase Says It Prevented a Crafty Phishing Attack to Exfiltrate Keys](https://cointelegraph.com/news/coinbase-says-it-prevented-a-crafty-phishing-attack-to-exfiltrate-keys)
- [ ] [PlusToken Suspected Ponzi Moves $240M in Four Bitcoin Transactions](https://cointelegraph.com/news/240m-in-suspected-scheme-assets-moves-in-four-bitcoin-transactions?utm_source=Telegram&utm_medium=social)
- [ ] Bitcoin History from bitcoin.com
  - [ ] Bitcoin History Part 1: In the Beginning  https://news.bitcoin.com/bitcoin-history-part-1-in-the-beginning/
  - [ ] Bitcoin History Part 2: The Bitcoin Symbol https://news.bitcoin.com/bitcoin-history-part-2-the-bitcoin-symbol/
  - [ ] ...
- [ ] 19-Year-Old Sentenced to 20 Months for Selling Stolen Data for BTC https://cointelegraph.com/news/19-year-old-sentenced-to-20-months-for-selling-stolen-data-for-btc
  - [ ] https://cointelegraph.com/news/hackers-steal-100-000-worth-of-btc-from-engineering-manager-at-crypto-custodian-bitgo
  - [ ] https://www.norfolk.police.uk/news/latest-news/16-08-2019/man-sentenced-hacking-offences#na
  - [ ] https://medium.com/coinmonks/the-most-expensive-lesson-of-my-life-details-of-sim-port-hack-35de11517124

<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!--                          Threat model                   -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
## Threat model
- [x] Bitcoin’s Security Model: A Deep Dive https://www.coindesk.com/bitcoins-security-model-deep-dive: 
  - *While each consensus model aims to prevent various theoretical attacks, it’s important to understand the goals for the model.*
  - Every security model has two main parts: `assumptions` and `guarantees`. If the assumptions used as inputs hold true, then so should the guarantees that are output by the model.
  - **In reality, the bitcoin protocol was and is being built without a formally defined specification or security model.**
- [ ] Understanding the bitcoinj security model https://bitcoinj.github.io/security-model



<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!--                          Weaknesses -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
## Weaknesses and vulnerabilities
- [ ] https://en.bitcoin.it/wiki/Weaknesses
- [ ] https://zhuzhuuu.com/vulnerablity/2018-09/tradingview-xss


<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!--                          Cases of study -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
## Cases of study

- [ ]  https://ledgerops.com/blog/2019/2/11/2018-blockchain-security-threat-report
- [ ] [WP2016_3-1_4_Blockchain_Security.pdf](/uploads/72f1996d30605fe97586ebb254b0d398/WP2016_3-1_4_Blockchain_Security.pdf)
- [ ] https://www.symantec.com/blogs/threat-intelligence/email-extortion-scams
- [ ] https://blog.cloudsploit.com/a-technical-analysis-of-the-capital-one-hack-a9b43d7c8aea
  - [ ] [thompson_complaint.pdf](/uploads/26c9cc3a7d39062cb4bb8b83d69b6b45/thompson_complaint.pdf)

<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!--                          Other -->
<!-- ///////////////////////////////////////////////////////////////// -->
<!-- ///////////////////////////////////////////////////////////////// -->
## Other
### Anti-Money Laundering (AML)
- Bitcoin Transaction Graph https://www.kaggle.com/ellipticco/elliptic-data-set

### Academic articles
- [x] Black Block Recorder: Immutable Black Box Logging for Robots via Blockchain https://ieeexplore.ieee.org/document/8764004/

### Malware research
- [x] Saefko: A new multi-layered RAT https://www.zscaler.com/blogs/research/saefko-new-multi-layered-rat: .NET based, Saefko RAT stays in the background and executes every time the user logs in. It fetches the chrome browser history looking for specific types of activities, such as those involving credit cards, business, social media, gaming, cryptocurrency, shopping, and more. It sends the data it has collected to its command-and-control (C&C) server and requests for further instructions. 

### Standards
- [ ] CryptoCurrency Security Standard (CCSS) https://cryptoconsortium.github.io/CCSS/: a set of requirements for all information systems that make use of cryptocurrencies, including exchanges, web applications, and cryptocurrency storage solutions.
  - They've got a somewhat interesting checklist https://cryptoconsortium.github.io/CCSS/Checklist/ and a reasonably verbose
  - Details section https://cryptoconsortium.github.io/CCSS/Details/