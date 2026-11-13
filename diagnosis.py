
def _build(status, category, cause, summary, findings, recommendations):
    return {
        "status": status,          # healthy | warning | critical
        "category": category,      # DNS | Network | Web Server | TLS Certificate | Access | None
        "probable_cause": cause,
        "summary": summary,
        "findings": findings,
        "recommendations": recommendations,
    }


def diagnose(dns, ping, http, tls):
    findings, recs = [], []

    # ---- Step 1: DNS ----
    if not dns["success"]:
        findings.append(f"DNS: {dns['message']}")
        if dns["error_type"] in ("timeout", "dns_server_error"):
            recs += ["Check your internet connection.",
                     "Try another DNS server (for example 8.8.8.8 or 1.1.1.1).",
                     "Run 'ipconfig /flushdns' in PowerShell and test again."]
            return _build("critical", "DNS", "DNS server is not responding.",
                          "The domain could not be resolved because the DNS server did not answer.",
                          findings, recs)
        recs += ["Check the domain spelling for typos.",
                 "Verify the domain is registered and not expired.",
                 "Confirm the domain has an A/AAAA record at its DNS provider."]
        return _build("critical", "DNS", "Domain does not exist or has no DNS record.",
                      "The domain name could not be resolved to an IP address.", findings, recs)

    ip = dns["details"].get("primary_ip", "unknown")
    findings.append(f"DNS: resolved to {ip}.")

    ping_ok = ping["success"]
    findings.append(f"Ping: {ping['message']}")
    findings.append(f"HTTP/HTTPS: {http['message']}")
    findings.append(f"TLS: {tls['message']}")

    reached = http["details"].get("reachable", False)
    code = http["details"].get("status_code")
    tls_type = tls.get("error_type")

    # ---- Step 2: The web server answered ----
    if reached:
        if http["details"].get("https_failed"):
            if tls_type in ("certificate_error", "expired"):
                recs += ["Renew or reinstall the SSL certificate.",
                         "Make sure the certificate matches the domain name and includes the full chain."]
                return _build("critical", "TLS Certificate",
                              "HTTPS fails because of a certificate problem.",
                              "The site works over plain HTTP, but HTTPS is broken by an invalid certificate.",
                              findings, recs)
            recs += ["Confirm the server listens on port 443 with TLS enabled.",
                     "Check firewall rules and server TLS configuration."]
            return _build("critical", "TLS Certificate", "HTTPS is not working on the server.",
                          "The site responds over HTTP but HTTPS fails.", findings, recs)

        if code is not None and code >= 500:
            recs += ["The problem is on the server side; contact the site owner or check server logs.",
                     "Retry after a few minutes in case it is temporary."]
            return _build("critical", "Web Server", f"Server error (HTTP {code}).",
                          "The server is reachable but the web application is failing.", findings, recs)

        if code in (401, 403):
            recs += ["Check whether the site requires login or blocks automated clients.",
                     "Verify you are allowed to access this resource."]
            return _build("warning", "Access", f"Access restricted (HTTP {code}).",
                          "The server is reachable but refuses this request.", findings, recs)

        if code == 429:
            recs += ["Wait and retry later; the server is rate limiting requests."]
            return _build("warning", "Access", "Rate limited (HTTP 429).",
                          "The server is reachable but is limiting request frequency.", findings, recs)

        if code is not None and code >= 400:
            recs += ["Check the URL path.", "Verify the page or application exists on the server."]
            return _build("warning", "Web Server", f"Client error (HTTP {code}).",
                          "The server responded, but with an error status.", findings, recs)

        # HTTP is fine: check TLS and ping for secondary issues
        if not tls["success"]:
            recs += ["Fix the SSL certificate problem shown above."]
            return _build("warning", "TLS Certificate", "Certificate problem despite a working site.",
                          "The website loads, but the certificate check reported an issue.", findings, recs)

        if tls_type == "expiring_soon":
            recs += ["Renew the SSL certificate before it expires."]
            return _build("warning", "TLS Certificate", "Certificate is close to expiry.",
                          "Everything works, but the certificate expires soon.", findings, recs)

        if not ping_ok:
            recs += ["No action needed. Many servers and CDNs block ICMP ping by design."]
            findings.append("Note: ping failed, but the website works, so ICMP is most likely blocked.")

        return _build("healthy", "None", "No problem detected.",
                      "DNS, HTTP/HTTPS and the certificate are all working.", findings, recs)

    # ---- Step 3: The web server did NOT answer ----
    http_type = http.get("error_type")

    if http_type == "ssl_error" or tls_type in ("certificate_error", "expired"):
        recs += ["Renew or fix the SSL certificate (expired, wrong hostname or incomplete chain).",
                 "Check the certificate details in the TLS section above."]
        return _build("critical", "TLS Certificate", "TLS/certificate failure is blocking HTTPS.",
                      "The host is reachable but the secure connection cannot be established.",
                      findings, recs)

    if http_type == "connection_refused":
        recs += ["Check that the web server service is running.",
                 "Confirm it listens on ports 80/443 and the firewall allows them."]
        return _build("critical", "Web Server", "Web server is not listening on the expected port.",
                      "The host answered but actively refused the web connection.", findings, recs)

    if ping_ok:
        recs += ["The host is up, so the web service or port may be down or blocked.",
                 "Check the firewall, load balancer and web server status.",
                 "Try accessing the site from another network."]
        return _build("critical", "Web Server", "Host is reachable but the web service is not responding.",
                      "Ping works but HTTP/HTTPS fails (service down, filtered port or overloaded server).",
                      findings, recs)

    recs += ["Test from another network or device to rule out a local problem.",
             "Check your firewall, VPN or proxy settings.",
             "If you own the server, check that it is online and that routing/firewall rules allow traffic."]
    return _build("critical", "Network", "Host appears to be down or unreachable.",
                  "DNS works, but neither ping nor HTTP/HTTPS get a response (host down, routing issue or firewall).",
                  findings, recs)
