# Damn Vulnerable Web Application (DVWA)
In this first article I touch into DVWA and provide a walkthough on how to explor different issues in this demo site.

## Setting up the infrastructure
First fetch the web application and launch it:

```bash
# Source 1, recommended, fetched from https://hub.docker.com/r/vulnerables/web-dvwa/
docker pull vulnerables/web-dvwa
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Source 2
# docker pull infoslack/dvwa
# docker run -d -p 80:80 infoslack/dvwa
```
Type `127.0.0.1/setup.php` in your browser. I had to create the database (there's a button at the end of the page) and then you should get something like:

![](frontpage.png)

Credentials are `admin:password`.

## Setting up a proxy
The proxy will allow to intercept all traffic and further investigate aspects of the web application.

Two main recommendations:
- ZAP https://es.wikipedia.org/wiki/OWASP_ZAP
- BURP available from https://portswigger.net/burp/communitydownload

BURP doesn't allow you to save stuff (*you need the proffesional one for this*). Configure it to redirect traffic to port `80`. This setup requires to navigate over the 8080 port (which will get redirected to port 80 by BURP).

--- 

Alternatively, we could redired all traffic to BURP configuring a proxy in the browser, e.g.: FoxyProxy for Chrome is available [here](https://chrome.google.com/webstore/detail/foxyproxy-standard/gcknhkkoolaabfmlnjonogaaifnjlfnp?hl=es-419).

----

## Footprinting and fingerprinting
There's a variety of tools that are helpful to analyze different things. Amongst them and for analyzing the SSL configuration of a server, the `sslyze` tool[1] is somewhat popular.

We'll use the `sslyze` command (`brew install sslyze` in OS X) and test it against some host (I'm using my own, http://acutronicrobotics.com but you may want to use yours):

<details><summary>Output of `sslyze --regular acutronicrobotics.com`</summary>

```bash
sslyze --regular acutronicrobotics.com


 AVAILABLE PLUGINS
 -----------------

  SessionRenegotiationPlugin
  RobotPlugin
  HttpHeadersPlugin
  FallbackScsvPlugin
  CertificateInfoPlugin
  SessionResumptionPlugin
  OpenSslCipherSuitesPlugin
  HeartbleedPlugin
  CompressionPlugin
  OpenSslCcsInjectionPlugin



 CHECKING HOST(S) AVAILABILITY
 -----------------------------

   acutronicrobotics.com:443                       => 34.246.183.163




 SCAN RESULTS FOR ACUTRONICROBOTICS.COM:443 - 34.246.183.163
 -----------------------------------------------------------

 * TLSV1_3 Cipher Suites:
      Server rejected all cipher suites.

 * Session Renegotiation:
       Client-initiated Renegotiation:    OK - Rejected
       Secure Renegotiation:              OK - Supported

 * Certificate Information:
     Content
       SHA1 Fingerprint:                  4057be81b1b0caf270c9ea9ef77de15dffa55d62
       Common Name:                       acutronicrobotics.com
       Issuer:                            Let's Encrypt Authority X3
       Serial Number:                     302738984565201563660219574384909004573021
       Not Before:                        2019-05-29 08:05:57
       Not After:                         2019-08-27 08:05:57
       Signature Algorithm:               sha256
       Public Key Algorithm:              RSA
       Key Size:                          2048
       Exponent:                          65537 (0x10001)
       DNS Subject Alternative Names:     [u'acutronicrobotics.com', u'www.acutronicrobotics.com']

     Trust
       Hostname Validation:               OK - Certificate matches acutronicrobotics.com
       Android CA Store (8.1.0_r9):       OK - Certificate is trusted
       iOS CA Store (11):                 OK - Certificate is trusted
       Java CA Store (jre-10.0.1):        OK - Certificate is trusted
       macOS CA Store (High Sierra):      OK - Certificate is trusted
       Mozilla CA Store (2018-04-12):     OK - Certificate is trusted
       Windows CA Store (2018-04-26):     OK - Certificate is trusted
       Symantec 2018 Deprecation:         OK - Not a Symantec-issued certificate
       Received Chain:                    acutronicrobotics.com --> Let's Encrypt Authority X3
       Verified Chain:                    acutronicrobotics.com --> Let's Encrypt Authority X3 --> DST Root CA X3
       Received Chain Contains Anchor:    OK - Anchor certificate not sent
       Received Chain Order:              OK - Order is valid
       Verified Chain contains SHA1:      OK - No SHA1-signed certificate in the verified certificate chain

     Extensions
       OCSP Must-Staple:                  NOT SUPPORTED - Extension not found
       Certificate Transparency:          WARNING - Only 2 SCTs included but Google recommends 3 or more

     OCSP Stapling
                                          NOT SUPPORTED - Server did not send back an OCSP response

 * Deflate Compression:
                                          OK - Compression disabled

 * SSLV2 Cipher Suites:
      Server rejected all cipher suites.

 * TLSV1 Cipher Suites:
       Forward Secrecy                    OK - Supported
       RC4                                OK - Not Supported

     Preferred:
        None - Server followed client cipher suite preference.
     Accepted:
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                ECDH-256 bits  256 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA                  DH-2048 bits   256 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA             DH-2048 bits   256 bits      HTTP 200 OK
        TLS_RSA_WITH_AES_256_CBC_SHA                      -              256 bits      HTTP 200 OK
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA                 -              256 bits      HTTP 200 OK
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                ECDH-256 bits  128 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA                  DH-2048 bits   128 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA             DH-2048 bits   128 bits      HTTP 200 OK
        TLS_RSA_WITH_AES_128_CBC_SHA                      -              128 bits      HTTP 200 OK
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA                 -              128 bits      HTTP 200 OK

 * Resumption Support:
      With Session IDs:                  OK - Supported (5 successful, 0 failed, 0 errors, 5 total attempts).
      With TLS Tickets:                  OK - Supported

 * TLSV1_1 Cipher Suites:
       Forward Secrecy                    OK - Supported
       RC4                                OK - Not Supported

     Preferred:
        None - Server followed client cipher suite preference.
     Accepted:
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                ECDH-256 bits  256 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA                  DH-2048 bits   256 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA             DH-2048 bits   256 bits      HTTP 200 OK
        TLS_RSA_WITH_AES_256_CBC_SHA                      -              256 bits      HTTP 200 OK
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA                 -              256 bits      HTTP 200 OK
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                ECDH-256 bits  128 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA                  DH-2048 bits   128 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA             DH-2048 bits   128 bits      HTTP 200 OK
        TLS_RSA_WITH_AES_128_CBC_SHA                      -              128 bits      HTTP 200 OK
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA                 -              128 bits      HTTP 200 OK

 * SSLV3 Cipher Suites:
      Server rejected all cipher suites.

 * OpenSSL CCS Injection:
                                          OK - Not vulnerable to OpenSSL CCS injection

 * Downgrade Attacks:
       TLS_FALLBACK_SCSV:                 OK - Supported

 * OpenSSL Heartbleed:
                                          OK - Not vulnerable to Heartbleed

 * TLSV1_2 Cipher Suites:
       Forward Secrecy                    OK - Supported
       RC4                                OK - Not Supported

     Preferred:
        None - Server followed client cipher suite preference.
     Accepted:
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256               DH-2048 bits   256 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA             DH-2048 bits   256 bits      HTTP 200 OK
        TLS_RSA_WITH_AES_256_CBC_SHA256                   -              256 bits      HTTP 200 OK
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                ECDH-256 bits  256 bits      HTTP 200 OK
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA                 -              256 bits      HTTP 200 OK
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384             ECDH-256 bits  256 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA                  DH-2048 bits   256 bits      HTTP 200 OK
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384             ECDH-256 bits  256 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384               DH-2048 bits   256 bits      HTTP 200 OK
        TLS_RSA_WITH_AES_256_CBC_SHA                      -              256 bits      HTTP 200 OK
        TLS_RSA_WITH_AES_256_GCM_SHA384                   -              256 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA             DH-2048 bits   128 bits      HTTP 200 OK
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                ECDH-256 bits  128 bits      HTTP 200 OK
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256             ECDH-256 bits  128 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256               DH-2048 bits   128 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA                  DH-2048 bits   128 bits      HTTP 200 OK
        TLS_RSA_WITH_AES_128_CBC_SHA                      -              128 bits      HTTP 200 OK
        TLS_RSA_WITH_AES_128_CBC_SHA256                   -              128 bits      HTTP 200 OK
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256               DH-2048 bits   128 bits      HTTP 200 OK
        TLS_RSA_WITH_AES_128_GCM_SHA256                   -              128 bits      HTTP 200 OK
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA                 -              128 bits      HTTP 200 OK
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256             ECDH-256 bits  128 bits      HTTP 200 OK

 * ROBOT Attack:
                                          OK - Not vulnerable


 SCAN COMPLETED IN 10.97 S
 -------------------------
 ```

### Analyzing a bit `acutronicrobotics.com`
- Look for `robot.txt` files: https://www.google.com/search?q=site%3Aacutronicrobotics.com+robot.txt&rlz=1C5CHFA_enES814ES814&oq=site%3Aacutronicrobotics.com+robot.txt&aqs=chrome..69i57j69i58.15214j0j7&sourceid=chrome&ie=UTF-8, from here we can get the sitemap: https://acutronicrobotics.com/sitemap.xml
- Sitemap can be further explored and visualized with https://codebeautify.org/xmlviewer
- Using `nmap` over the organization:
  - `brew install nmap` to install
  - `/usr/local/opt/nmap/bin/nmap` to launch

```bash
/usr/local/opt/nmap/bin/nmap acutronicrobotics.com
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-13 13:27 CEST
Nmap scan report for acutronicrobotics.com (34.246.183.163)
Host is up (0.082s latency).
rDNS record for 34.246.183.163: ec2-34-246-183-163.eu-west-1.compute.amazonaws.com
Not shown: 995 filtered ports
PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   open   ssh
80/tcp   open   http
443/tcp  open   https
3306/tcp closed mysql
```
</details>

 
 ## Resources
 - [1] https://github.com/nabla-c0d3/sslyze
