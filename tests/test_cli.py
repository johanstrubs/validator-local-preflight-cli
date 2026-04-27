from unittest.mock import AsyncMock, patch

from validator_preflight.checks import PASS, WARN, render_summary
from validator_preflight.cli import build_parser


def test_parser_upload_url_flag():
    parser = build_parser()
    args = parser.parse_args(["http://127.0.0.1:5005", "--upload-url", "https://example.com"])
    assert args.rpc_endpoint == "http://127.0.0.1:5005"
    assert args.upload_url == "https://example.com"


def test_render_summary_contains_statuses():
    text = render_summary(
        [
            {"name": "RPC reachability", "status": PASS, "detected_value": "ok", "expected_value": "ok", "remediation": ""},
            {"name": "Upload report", "status": WARN, "detected_value": "timeout", "expected_value": "200", "remediation": "retry"},
        ],
        color=False,
    )
    assert "RPC reachability" in text
    assert "UPLOAD REPORT" not in text
    assert "WARN" in text
