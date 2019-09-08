# Web
In this article I'll cover a variety of (like disorganized) topics that related to Web security. 

## Content

Yes, read **first tutorial 2**.

- [Tutorial 2: BadStore.net](tutorial2/) (**unfinished**)
- [Tutorial 1: Damn Vulnerable Web Application (DVWA)](tutorial1/) (**unfinished**)

## Notes 

<details><summary>Input from a professional pentester</summary>

From a web tester when performing an assessment:
- First two days, they typically research the infrastructure of the company
  - Dimension
  - Spread
  - Subdomains, etc.
- Reports
  - Often use https://www.giuspen.com/cherrytree/ to grasp information
  - Structure
    - Objective
    - Methodology (typically OWASP)
    - Executive summary
      - OK/KO
      - pie chart with vulns
      - Risks
    - Tech report, organized per vulns
      - CVSS as the general approach for quantifying the releance of the vuln
- OWASP Top 10
  - available from https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf
  - Analysis of the top 10
    - **Injection**: Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent
to an interpreter as part of a command or query. The attacker’s hostile data can trick the
interpreter into executing unintended commands or accessing data without proper authorization.
    - **Broken Authentication**: Application functions related to authentication and session management are often implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users’ identities temporarily or permanently.
    - **Sensitive Data Exposure**: Many web applications and APIs do not properly protect sensitive data, such as financial, healthcare, and PII. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes. Sensitive data may be compromised without extra protection, such as encryption at rest or in transit, and requires special precautions when exchanged with the browser.
    - **External Entities (XXE)**: Many older or poorly configured XML processors evaluate external entity references within XML documents. External entities can be used to disclose internal files using the file URI handler, internal file shares, internal port scanning, remote code execution, and denial of service attacks.
    - **Broken Access Control**: Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data, such as access other users' accounts, view sensitive files, modify other users’ data, change access rights, etc.
    - **Security Misconfiguration**: Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information. Not only must all operating systems, frameworks, libraries, and applications be securely configured, but they must be patched and upgraded in a timely fashion.
    - **Cross-Site Scripting (XSS)**: XSS flaws occur whenever an application includes untrusted data in a new web page without proper validation or escaping, or updates an existing web page with user-supplied data using a browser API that can create HTML or JavaScript. XSS allows attackers to execute scripts in the victim’s browser which can hijack user sessions, deface web sites, or redirect the user to malicious sites.
    - **Insecure Deserialization**: Insecure deserialization often leads to remote code execution. Even if deserialization flaws do not result in remote code execution, they can be used to perform attacks, including replay attacks, injection attacks, and privilege escalation attacks.
    - **Components with Known Vulnerabilities**: Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications and APIs using components with known vulnerabilities may undermine application defenses and enable various attacks and impacts.
    - **Insufficient Logging & Monitoring**: Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data. Most breach studies show time to detect a breach is over 200 days, typically detected by external parties rather than internal processes or monitoring.
- Footprinting
  - not ilegal
- Launch `nmap` over a servere that we don't control can potentially cause legal consequences.

</details>