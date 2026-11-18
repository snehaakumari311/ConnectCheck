
import os
import uuid

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

from checks.common import clean_domain
from checks.dns_check import check_dns
from checks.ping_check import check_ping
from checks.http_check import check_http
from checks.ssl_check import check_ssl

from diagnosis import diagnose
from analyzer.pcap_analyzer import analyze_pcap, ALLOWED_EXTENSIONS
from report import generate_pdf_report


app = Flask(__name__)

# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REPORT_FOLDER"] = REPORT_FOLDER
app.config["MAX_UPLOAD_MB"] = 10
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)


# --------------------------------------------------
# PHASE 1–4: NETWORK DIAGNOSTICS
# --------------------------------------------------

def run_diagnostics(domain):
    dns = check_dns(domain)

    target = (
        dns["details"].get("primary_ip", domain)
        if dns["success"]
        else domain
    )

    ping = check_ping(target)
    http = check_http(domain)
    tls = check_ssl(domain)

    diagnosis_result = diagnose(dns, ping, http, tls)

    return {
        "domain": domain,
        "checks": [dns, ping, http, tls],
        "diagnosis": diagnosis_result,
    }


@app.route("/", methods=["GET", "POST"])
def index():
    data = None
    error = None
    domain_value = ""

    if request.method == "POST":
        domain_value = request.form.get("domain", "")

        domain, validation_error = clean_domain(domain_value)

        if validation_error:
            error = validation_error
        else:
            try:
                data = run_diagnostics(domain)

            except Exception:
                app.logger.exception("Diagnostics failed")
                error = (
                    "Diagnostics could not be completed. "
                    "Please check the server logs."
                )

    return render_template(
        "index.html",
        data=data,
        error=error,
        domain_value=domain_value,
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
        return jsonify({
            "error": "Diagnostics could not be completed."
        }), 500


# --------------------------------------------------
# DOWNLOAD NETWORK DIAGNOSTIC PDF
# --------------------------------------------------

@app.route("/download-report", methods=["POST"])
def download_report():
    raw_domain = request.form.get("domain", "")
    domain, validation_error = clean_domain(raw_domain)

    if validation_error:
        return jsonify({"error": validation_error}), 400

    try:
        diagnostic_result = run_diagnostics(domain)

        pdf_buffer = generate_pdf_report(diagnostic_result)

        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"ConnectCheck_{domain}_Report.pdf",
        )

    except Exception:
        app.logger.exception("PDF report generation failed")
        return jsonify({
            "error": "Could not generate the PDF report."
        }), 500


# --------------------------------------------------
# PHASE 5: PCAP ANALYZER
# --------------------------------------------------

@app.route("/analyzer", methods=["GET", "POST"])
def analyzer():
    result = None
    error = None
    status = 200
    pcap_report_url = None

    if request.method == "POST":

        upload = request.files.get("pcap_file")

        if upload is None or not upload.filename:
            error = "Please choose a PCAP file."
            status = 400

        else:
            display_name = secure_filename(upload.filename) or "capture"
            extension = os.path.splitext(display_name)[1].lower()

            if extension not in ALLOWED_EXTENSIONS:
                error = "Only .pcap and .pcapng files are supported."
                status = 400

            else:
                saved_path = os.path.join(
                    UPLOAD_FOLDER,
                    uuid.uuid4().hex + extension,
                )

                try:
                    upload.save(saved_path)

                    analysis = analyze_pcap(
                        saved_path,
                        display_name,
                    )

                    if analysis["success"]:
                        result = analysis

                        # Prepare PCAP data for the existing PDF generator.
                        pcap_for_report = dict(analysis)

                        pcap_summary = dict(
                            analysis.get("summary", {})
                        )
                        pcap_summary.setdefault("filename", display_name)

                        pcap_for_report["summary"] = pcap_summary

                        # The report generator supports both diagnostic
                        # results and optional packet capture results.
                        report_data = {
                            "domain": f"PCAP file: {display_name}",
                            "checks": [],
                            "diagnosis": {
                                "status": "informational",
                                "category": "Packet Capture",
                                "probable_cause": (
                                    "Review the packet analysis findings."
                                ),
                                "summary": (
                                    "This report contains packet capture "
                                    "analysis results."
                                ),
                                "findings": [],
                                "recommendations": [],
                            },
                        }

                        pdf_buffer = generate_pdf_report(
                            report_data,
                            pcap_result=pcap_for_report,
                        )

                        # Save the generated PDF using a random identifier.
                        report_id = uuid.uuid4().hex

                        report_path = os.path.join(
                            REPORT_FOLDER,
                            report_id + ".pdf",
                        )

                        pdf_buffer.seek(0)

                        with open(report_path, "wb") as pdf_file:
                            pdf_file.write(pdf_buffer.getvalue())

                        # Provide the download link to analyzer.html.
                        pcap_report_url = url_for(
                            "download_pcap_report",
                            report_id=report_id,
                        )

                    else:
                        error = " ".join(analysis.get("errors", []))
                        status = 400

                except Exception:
                    app.logger.exception("PCAP analysis or report generation failed")
                    error = (
                        "The PCAP file could not be analysed "
                        "or its PDF report could not be generated."
                    )
                    status = 500

                finally:
                    if os.path.exists(saved_path):
                        try:
                            os.remove(saved_path)
                        except OSError:
                            app.logger.warning(
                                "Could not delete temporary PCAP upload."
                            )

    return render_template(
        "analyzer.html",
        result=result,
        error=error,
        max_mb=app.config["MAX_UPLOAD_MB"],
        pcap_report_url=pcap_report_url,
    ), status


# --------------------------------------------------
# DOWNLOAD PCAP ANALYSIS PDF
# --------------------------------------------------

@app.route("/download-pcap-report/<report_id>", methods=["GET"])
def download_pcap_report(report_id):

    # Accept only a 32-character hexadecimal UUID.
    if (
        len(report_id) != 32
        or any(char not in "0123456789abcdefABCDEF" for char in report_id)
    ):
        return jsonify({"error": "Invalid report ID."}), 400

    report_path = os.path.join(
        REPORT_FOLDER,
        report_id.lower() + ".pdf",
    )

    if not os.path.isfile(report_path):
        return jsonify({"error": "Report not found or already downloaded."}), 404

    try:
        response = send_file(
            report_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="ConnectCheck_PCAP_Analysis_Report.pdf",
        )

        # Delete the generated report after the response has been sent.
        def cleanup_report():
            try:
                if os.path.exists(report_path):
                    os.remove(report_path)
            except OSError:
                app.logger.warning(
                    "Could not delete downloaded PCAP report."
                )

        response.call_on_close(cleanup_report)

        return response

    except Exception:
        app.logger.exception("PCAP PDF download failed")
        return jsonify({
            "error": "Could not download the PCAP report."
        }), 500


# --------------------------------------------------
# FILE SIZE ERROR HANDLER
# --------------------------------------------------

@app.errorhandler(413)
def file_too_large(_err):
    message = (
        f"File too large. Maximum size is "
        f"{app.config['MAX_UPLOAD_MB']} MB."
    )

    if request.path.startswith("/analyzer"):
        return render_template(
            "analyzer.html",
            result=None,
            error=message,
            max_mb=app.config["MAX_UPLOAD_MB"],
            pcap_report_url=None,
        ), 413

    return jsonify({"error": message}), 413


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "app": "ConnectCheck",
    })


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000,
    )
