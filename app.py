
from flask import Flask, render_template, request, jsonify

from checks.common import clean_domain
from checks.dns_check import check_dns
from checks.ping_check import check_ping
from checks.http_check import check_http
from checks.ssl_check import check_ssl
from diagnosis import diagnose

app = Flask(__name__)


def run_diagnostics(domain):
    # Run the four individual network checks
    dns = check_dns(domain)

    # Use the resolved IP for ping when DNS succeeds
    target = dns["details"].get("primary_ip", domain) if dns["success"] else domain
    ping = check_ping(target)

    http = check_http(domain)
    tls = check_ssl(domain)

    # Combine all results using our existing diagnosis engine
    diagnosis_result = diagnose(dns, ping, http, tls)

    return {
        "domain": domain,
        "checks": [dns, ping, http, tls],
        "diagnosis": diagnosis_result
    }


@app.route("/", methods=["GET", "POST"])
def index():
    data = None
    error = None
    domain_value = ""

    if request.method == "POST":
        domain_value = request.form.get("domain", "")

        # Use the validation function we already tested
        domain, validation_error = clean_domain(domain_value)

        if validation_error:
            error = validation_error
        else:
            try:
                data = run_diagnostics(domain)
            except Exception as exc:
                app.logger.exception("Diagnostics failed")
                error = "Diagnostics could not be completed. Please check the server logs."

    return render_template(
        "index.html",
        data=data,
        error=error,
        domain_value=domain_value
    )


@app.route("/api/diagnose")
def api_diagnose():
    raw_domain = request.args.get("domain", "")
    domain, validation_error = clean_domain(raw_domain)

    if validation_error:
        return jsonify({"error": validation_error}), 400

    try:
        return jsonify(run_diagnostics(domain))
    except Exception:
        app.logger.exception("API diagnostics failed")
        return jsonify({"error": "Diagnostics could not be completed."}), 500


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "app": "ConnectCheck"
    })


if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
