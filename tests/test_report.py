
from report import generate_pdf_report


def test_generate_diagnostic_pdf(tmp_path):
    diagnostic_result = {
        "domain": "example.com",
        "checks": [
            {
                "check": "DNS Resolution",
                "success": True,
                "message": "Domain resolved successfully."
            },
            {
                "check": "HTTP/HTTPS Check",
                "success": True,
                "message": "Website responded with 200 OK."
            }
        ],
        "diagnosis": {
            "status": "healthy",
            "category": "None",
            "probable_cause": "No problem detected.",
            "summary": "All network checks passed.",
            "findings": ["DNS resolution successful."],
            "recommendations": ["No action required."]
        }
    }

    pdf_buffer = generate_pdf_report(diagnostic_result)

    assert pdf_buffer is not None

    pdf_bytes = pdf_buffer.getvalue()
    assert pdf_bytes.startswith(b"%PDF")

    output_file = tmp_path / "test_report.pdf"
    output_file.write_bytes(pdf_bytes)

    assert output_file.exists()
    assert output_file.stat().st_size > 0


def test_generate_pdf_with_pcap():
    diagnostic_result = {
        "domain": "example.com",
        "checks": [],
        "diagnosis": {
            "status": "healthy",
            "category": "None",
            "probable_cause": "No problem detected.",
            "summary": "Network is healthy.",
            "findings": [],
            "recommendations": []
        }
    }

    pcap_result = {
        "summary": {
            "filename": "sample.pcap",
            "total_packets": 21,
            "total_bytes": 1502,
            "unique_source_ips": 3,
            "unique_destination_ips": 4,
            "duration_seconds": 10
        },
        "findings": [
            {"observation": "One unanswered DNS query."}
        ]
    }

    pdf_buffer = generate_pdf_report(diagnostic_result, pcap_result)

    assert pdf_buffer.getvalue().startswith(b"%PDF")


def test_invalid_diagnostic_input():
    import pytest

    with pytest.raises(ValueError):
        generate_pdf_report("invalid input")
