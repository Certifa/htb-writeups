## IMAGERY

![Logo Imagery](docs/logo%20imagery.png)

## Table of Contents

-
-
-
-

## Overview

Machine: Imagery
Difficulty: Medium
OS: Linux
Points: 30
Status: Active (write-up sanitized, no flags)

## About

Imagery is a chained attack box that demonstrates how small web-layer flaws and a misconfigured privileged utility can lead to full system takeover. The chain begins with an XSS to steal an administrator session, escalates to an admin-only LFI/backup download, then leverages locally decrypted artifacts and a sudo-enabled backup tool (Charcol) to create root cron jobs. Impact: full system compromise. Key mitigations: mark auth cookies HttpOnly/Secure, strictly validate file-read endpoints, remove NOPASSWD sudo rules from automation utilities, and enforce authenticated, auditable job scheduling.

## TL;DR

XSS → admin session theft → LFI/backup exfil → decrypt → sudo-enabled Charcol abused to add root cron → full root compromise.

## Setup / Notes

OS: Parrot
Tools: Burp Suite, wget, nc (netcat), python, openssl, base64, unzip/7z/tar, ssh/scp, john/hashcat/fcrackzip, grep/sed/awk.

## RECON

```
# Nmap 7.94SVN scan initiated Sat Sep 27 19:03:13 2025 as: nmap -sC -sV -p22,8000 -oN - -oX ./nmap-scans/nmap_10.129.253.147_d4dd715e_20250927_190200.xml 10.129.253.147
Nmap scan report for 10.129.253.147
Host is up (0.023s latency).

PORT     STATE SERVICE  VERSION
🟢 22/tcp   open  ssh      OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
|_  256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)
🟢 8000/tcp open  http-alt Werkzeug/3.1.3 Python/3.12.7
|_http-title: Image Gallery
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.1.3 Python/3.12.7
|     Date: Sat, 27 Sep 2025 19:03:27 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.1.3 Python/3.12.7
|     Date: Sat, 27 Sep 2025 19:03:22 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 146960
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Image Gallery</title>
|     <script src="static/tailwind.js"></script>
|     <link rel="stylesheet" href="static/fonts.css">
|     <script src="static/purify.min.js"></script>
|     <style>
|     body {
|     font-family: 'Inter', sans-serif;
|     margin: 0;
|     padding: 0;
|     box-sizing: border-box;
|     display: flex;
|     flex-direction: column;
|     min-height: 100vh;
|     position: fixed;
|     top: 0;
|     width: 100%;
|     z-index: 50;
|_    #app-con
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=9/27%Time=68D834F8%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,1B0F,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.1\.3
SF:\x20Python/3\.12\.7\r\nDate:\x20Sat,\x2027\x20Sep\x202025\x2019:03:22\x
SF:20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length
SF::\x20146960\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x2
SF:0lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x2
SF:0\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width
SF:,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Image\x20Gallery</ti
SF:tle>\n\x20\x20\x20\x20<script\x20src=\"static/tailwind\.js\"></script>\
SF:n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"static/fonts\.cs
SF:s\">\n\x20\x20\x20\x20<script\x20src=\"static/purify\.min\.js\"></scrip
SF:t>\n\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20body\x20
SF:{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x20'Int
SF:er',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ma
SF:rgin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20padding:\x
SF:200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20box-sizing:\x20bo
SF:rder-box;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20display:\x20
SF:flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20flex-direction:\
SF:x20column;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20min-height:
SF:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20nav\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20posit
SF:ion:\x20fixed;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20top:\x2
SF:00;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20width:\x20100%;\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20z-index:\x2050;\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20#app-con")%
SF:r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x2
SF:0Werkzeug/3\.1\.3\x20Python/3\.12\.7\r\nDate:\x20Sat,\x2027\x20Sep\x202
SF:025\x2019:03:27\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\
SF:r\nContent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!doctype\x20h
SF:tml>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x2
SF:0Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x2
SF:0the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20p
SF:lease\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Sep 27 19:04:55 2025 -- 1 IP address (1 host up) scanned in 102.12 seconds
# Nmap 7.94SVN scan initiated Sat Sep 27 19:04:55 2025 as: nmap -sU --top-ports 100 -oN - 10.129.253.147
```

That's alot of info, but we see 2 ports open. 22 and 8000.

Lets go to <'IP'>:8000

![Website Imagery](docs/website%20imagery.png)

Interesting, let's register first and see whats up.

![Register Imagery](docs/imagery%20register.png)

Nothing special, looks like a plain register. Let's make a account first.

![Dashboard Imagery](docs/image%20gallery.png)

So you can upload files, Good to know.

![Footer](docs/bottom%20footer.png)

Exploring the footer, one thing stands put. We can report a bug? hmm

![Bug Report](docs/report%20a%20bug.png)

Nice! This looks interesting. lets test if it even works

![Test Report](docs/bug%20report%20submit.png)

Submitted! Lets play around with it, lets see if we can get the cookies of the one recieving our bugs

![Bug XSS](docs/bug%20report%20xss.png)

Just done setting up my cookie stealer.

![Cookie](docs/cookie%20catch.png)

We got a session cookie!

## ENUMERATION
