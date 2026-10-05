# File: test_app.py
#
# Copyright (c) 2016-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from pydantic import ValidationError
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionResult
from soar_sdk.cli.manifests.serializers import OutputsSerializer
from soar_sdk.exceptions import ActionFailure

from src.actions.get_screenshot import GetScreenshotParams, ScreenshotOutput, display_scrshot, get_screenshot
from src.app import Asset, app, test_connectivity as connectivity_action
from src.consts import (
    DEFAULT_REQUEST_TIMEOUT,
    SCREENSHOT_TOO_LARGE_MSG,
    SSMACHINE_JSON_DOMAIN,
    VALID_CACHE_LIMIT_MSG,
    VALID_MAX_SCREENSHOT_SIZE_MSG,
)
from src.helper import check_connectivity, download_screenshot, permalink, secret_hash, validate_configuration


@pytest.fixture
def asset():
    return Asset(ssmachine_key="unit-test-key", ssmachine_hash="unit-test-phrase")


@pytest.fixture
def response():
    result = Mock(status_code=200, headers={"Content-Type": "image/jpeg"}, content=b"image", text="")
    result.__enter__ = Mock(return_value=result)
    result.__exit__ = Mock(return_value=False)
    result.iter_content.return_value = [b"", b"abc", b"def"]
    return result


@pytest.fixture
def post(monkeypatch, response):
    mock = Mock(return_value=response)
    monkeypatch.setattr(requests, "post", mock)
    return mock


def test_defaults_and_required_fields():
    asset = Asset(ssmachine_key="unit-test-key")
    assert asset.ssmachine_hash is None
    assert validate_configuration(asset) == (0, 25 * 1024 * 1024)
    params = GetScreenshotParams(url="https://example.com")
    assert params.dimension == "120x90"
    assert params.delay == "200"
    assert params.filename is None
    with pytest.raises(ValidationError):
        Asset()
    with pytest.raises(ValidationError):
        GetScreenshotParams()


@pytest.mark.parametrize("cache_limit", [-1, 14.1, float("nan"), float("inf"), None, "invalid"])
def test_cache_validation(asset, cache_limit):
    asset.cache_limit = cache_limit
    with pytest.raises(ActionFailure, match="allowed range") as error:
        validate_configuration(asset)
    assert VALID_CACHE_LIMIT_MSG in str(error.value)


@pytest.mark.parametrize("cache_limit", [0, 0.041666, 14])
def test_cache_boundaries(asset, cache_limit):
    asset.cache_limit = cache_limit
    assert validate_configuration(asset)[0] == cache_limit


@pytest.mark.parametrize("size", [0, -1, float("nan"), float("inf"), None, "invalid"])
def test_download_size_validation(asset, size):
    asset.max_screenshot_size_mb = size
    with pytest.raises(ActionFailure, match="positive value") as error:
        validate_configuration(asset)
    assert VALID_MAX_SCREENSHOT_SIZE_MSG in str(error.value)


def test_secret_phrase_protocol():
    assert secret_hash("https://example.com", "phrase") == hashlib.md5(b"https://example.comphrase", usedforsecurity=False).hexdigest()
    assert secret_hash("https://example.com", None) == ""
    assert secret_hash("https://example.com", "") == ""


def test_stream_download_and_authentication(asset, post, response, tmp_path):
    params = {"url": "https://example.com", "hash": "digest"}
    file_path = Path(download_screenshot(asset, params, str(tmp_path)))
    assert file_path.read_bytes() == b"abcdef"
    assert params == {"url": "https://example.com", "hash": "digest"}
    post.assert_called_once_with(
        SSMACHINE_JSON_DOMAIN,
        params={**params, "key": asset.ssmachine_key, "cacheLimit": 0.0},
        stream=True,
        verify=True,
        timeout=DEFAULT_REQUEST_TIMEOUT,
    )
    response.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "headers,chunks",
    [
        ({"Content-Type": "image/jpeg", "Content-Length": "7"}, [b"abc"]),
        ({"Content-Type": "image/jpeg"}, [b"abc", b"defg"]),
        ({"Content-Type": "image/jpeg", "Content-Length": "3"}, [b"abc", b"defg"]),
    ],
)
def test_oversize_downloads_remove_partial_files(asset, post, response, tmp_path, headers, chunks):
    asset.max_screenshot_size_mb = 6 / (1024 * 1024)
    response.headers = headers
    response.iter_content.return_value = chunks
    with pytest.raises(ActionFailure, match=SCREENSHOT_TOO_LARGE_MSG):
        download_screenshot(asset, {}, str(tmp_path))
    assert not list(tmp_path.iterdir())


def test_invalid_content_length_and_exact_size(asset, post, response, tmp_path):
    asset.max_screenshot_size_mb = 6 / (1024 * 1024)
    response.headers = {"Content-Type": "IMAGE/JPEG", "Content-Length": "invalid"}
    file_path = Path(download_screenshot(asset, {}, str(tmp_path)))
    assert file_path.read_bytes() == b"abcdef"


@pytest.mark.parametrize(
    "status,content_type,message",
    [
        (401, "text/html", "HTTP status 401"),
        (500, "image/jpeg", "HTTP status 500"),
        (200, "application/json", "does not contain an image"),
    ],
)
def test_download_rejects_bad_responses(asset, post, response, tmp_path, status, content_type, message):
    response.status_code = status
    response.headers = {"Content-Type": content_type}
    with pytest.raises(ActionFailure, match=message):
        download_screenshot(asset, {}, str(tmp_path))
    assert not list(tmp_path.iterdir())


def test_stream_failure_cleans_file_and_redacts_secret(asset, post, response, tmp_path):
    def chunks():
        yield b"partial"
        raise requests.RequestException(f"request failed?key={asset.ssmachine_key}")

    response.iter_content.side_effect = chunks
    with pytest.raises(ActionFailure, match="REST API call") as error:
        download_screenshot(asset, {}, str(tmp_path))
    assert asset.ssmachine_key not in str(error.value)
    assert not list(tmp_path.iterdir())


def test_connection_failure_redacts_secret(asset, post, tmp_path):
    post.side_effect = requests.RequestException(f"url?key={asset.ssmachine_key}")
    with pytest.raises(ActionFailure) as error:
        download_screenshot(asset, {}, str(tmp_path))
    assert asset.ssmachine_key not in str(error.value)


def test_connectivity_preserves_query_auth(asset, post):
    check_connectivity(asset)
    kwargs = post.call_args.kwargs
    assert kwargs["params"]["url"] == "https://www.screenshotmachine.com"
    assert kwargs["params"]["key"] == asset.ssmachine_key
    assert kwargs["params"]["hash"] == secret_hash(kwargs["params"]["url"], asset.ssmachine_hash)
    soar = Mock()
    connectivity_action.__wrapped__(soar=soar, asset=asset)
    soar.set_message.assert_called_once_with("Test Connectivity Passed")


@pytest.mark.parametrize(
    "status,headers,text,message",
    [
        (200, {"Content-Type": "image/jpeg", "X-Screenshotmachine-Response": "invalid key"}, "", "invalid key"),
        (200, {"Content-Type": "text/html"}, "<script>hidden</script><p>API error</p>", "API error"),
        (503, {"Content-Type": "text/plain"}, "unavailable", "status_code: 503"),
        (200, {"Content-Type": "application/json"}, "{}", "does not contain an image"),
    ],
)
def test_connectivity_response_errors(asset, post, response, status, headers, text, message):
    response.status_code, response.headers, response.text = status, headers, text
    with pytest.raises(ActionFailure, match=message) as error:
        check_connectivity(asset)
    assert "Test connectivity failed" in str(error.value)
    assert "hidden" not in str(error.value)


def test_connectivity_redacts_vendor_error(asset, post, response):
    response.headers["X-Screenshotmachine-Response"] = f"rejected {asset.ssmachine_key} {asset.ssmachine_hash}"
    with pytest.raises(ActionFailure) as error:
        check_connectivity(asset)
    assert asset.ssmachine_key not in str(error.value)
    assert asset.ssmachine_hash not in str(error.value)


def test_permalink_excludes_credentials_and_cache():
    params = {"url": "https://example.com/a?b=1", "hash": "digest", "key": "unit-test-key", "cacheLimit": 3}
    result = permalink(params)
    query = parse_qs(urlparse(result).query)
    assert query["hash"] == ["digest"]
    assert "key" not in query
    assert "cacheLimit" not in query
    assert params["key"] == "unit-test-key"


@pytest.fixture
def soar(tmp_path):
    client = Mock(spec=SOARClient)
    client.get_executing_container_id.return_value = 42
    client.vault.get_vault_tmp_dir.return_value = str(tmp_path)
    client.vault.add_attachment.return_value = "unit-test-vault-id"
    client.vault.get_attachment.return_value = [SimpleNamespace(path="/vault/image.jpg", id=123, size=6)]
    return client


@pytest.mark.parametrize("filename,phrase", [(None, None), ("capture", "phrase")])
def test_get_screenshot_vault_summary_and_cleanup(asset, post, soar, tmp_path, filename, phrase):
    asset.ssmachine_hash = phrase
    output = get_screenshot.__wrapped__(GetScreenshotParams(url="https://example.com", filename=filename), soar=soar, asset=asset)
    expected_name = "capture.jpg" if filename else "https://example.com_screenshot.jpg"
    assert output.model_dump(by_alias=True, exclude_none=True)["name"] == expected_name
    assert output.vault_id == "unit-test-vault-id"
    assert output.vault_file_id == 123
    assert output.vault_file_path == "/vault/image.jpg"
    assert output.size == 6
    assert bool(output.permalink) == bool(phrase)
    soar.set_summary.assert_called_once_with(output)
    soar.set_message.assert_called_once_with("Screenshot downloaded successfully")
    assert soar.vault.add_attachment.call_args.kwargs["container_id"] == 42
    assert soar.vault.add_attachment.call_args.kwargs["file_name"] == expected_name
    assert not list(tmp_path.iterdir())


def test_vault_failure_cleans_temp_file(asset, post, soar, tmp_path):
    soar.vault.add_attachment.side_effect = RuntimeError("vault unavailable")
    with pytest.raises(ActionFailure, match="Error adding file to the vault"):
        get_screenshot.__wrapped__(GetScreenshotParams(url="https://example.com"), soar=soar, asset=asset)
    assert not list(tmp_path.iterdir())
    soar.set_summary.assert_not_called()


def test_missing_vault_metadata(asset, post, soar, tmp_path):
    soar.vault.get_attachment.return_value = []
    with pytest.raises(ActionFailure, match="Could not find meta information"):
        get_screenshot.__wrapped__(GetScreenshotParams(url="https://example.com"), soar=soar, asset=asset)
    assert not list(tmp_path.iterdir())


def test_invalid_config_prevents_download(asset, post, soar):
    asset.cache_limit = 15
    with pytest.raises(ActionFailure):
        get_screenshot.__wrapped__(GetScreenshotParams(url="https://example.com"), soar=soar, asset=asset)
    post.assert_not_called()
    soar.vault.add_attachment.assert_not_called()


def test_extra_api_fields_survive_serialization():
    raw = {
        "name": "capture.jpg",
        "size": 6,
        "vault_id": "unit-test-vault-id",
        "vault_file_id": 123,
        "vault_file_path": "/vault/image.jpg",
        "new_vendor_field": {"nested": [{"unknown": True}]},
        "unknown_values": [1, "two", None],
    }
    output = ScreenshotOutput(**raw)
    dumped = output.model_dump(by_alias=True, exclude_none=True)
    assert dumped == raw
    assert json.loads(output.model_dump_json(by_alias=True, exclude_none=True)) == raw
    assert ScreenshotOutput.model_validate(dumped).model_dump(by_alias=True, exclude_none=True) == raw


def test_widget_renders_vault_links_and_escapes_filename():
    output = ScreenshotOutput(
        name="<script>alert(1)</script>.jpg", size=6, vault_id="unit-test-vault-id", vault_file_id=123, vault_file_path="/vault/image.jpg"
    )
    result = ActionResult(True, "Screenshot downloaded successfully")
    result.add_data(output.model_dump(by_alias=True, exclude_none=True))
    rendered = display_scrshot(
        "get_screenshot",
        [({"total_objects": 1, "total_objects_successful": 1}, [result])],
        {"QS": {}, "container": 42, "app": 153, "no_connection": False, "google_maps_key": False},
    )
    assert "ssmachine_display" in rendered
    assert "&lt;script&gt;" in rendered
    assert "<script>alert(1)</script>" not in rendered
    assert "/download?document=/vault/image.jpg&id=123" in rendered
    assert ", 42, null, false)" in rendered
    assert rendered.index("File Name") < rendered.index("Vault ID")


def test_manifest_metadata_matches_legacy_contract():
    legacy = json.loads((Path(__file__).parent / "fixtures/legacy_manifest.json").read_text())
    actions = app.get_actions()
    assert set(actions) == {"test_connectivity", "get_screenshot"}
    meta = actions["get_screenshot"].meta
    original = legacy["actions"][1]
    assert (meta.action, meta.identifier, meta.type, meta.read_only, meta.versions, meta.verbose) == (
        original["action"],
        original["identifier"],
        original["type"],
        original["read_only"],
        original["versions"],
        original["verbose"],
    )
    config = Asset.to_json_schema()
    for name, field in legacy["configuration"].items():
        for key in ("data_type", "description", "order", "default"):
            if key in field:
                assert config[name][key] == field[key]
        assert config[name]["required"] == field.get("required", False)
    params = meta.parameters._to_json_schema()
    for name, field in original["parameters"].items():
        for key in ("data_type", "description", "order", "default", "contains"):
            if key in field:
                assert params[name][key] == field[key]
        assert params[name]["required"] == field.get("required", False)
        assert params[name]["primary"] == field.get("primary", False)
    outputs = {item["data_path"]: item for item in OutputsSerializer.serialize_datapaths(meta.parameters, meta.output, meta.summary_type)}
    for field in original["output"]:
        assert field["data_path"] in outputs
        assert outputs[field["data_path"]]["data_type"] == field["data_type"]
        assert outputs[field["data_path"]].get("contains") == field.get("contains")
    assert meta.render_as == "custom"
    assert app.app_meta_info["appid"] == legacy["appid"]
    assert app.app_meta_info["name"] == legacy["name"]


def test_sdk_serialization_keeps_aliases_and_extra_fields():
    output = ScreenshotOutput(
        name="capture.jpg",
        vault_id="unit-test-vault-id",
        size=6,
        vault_file_id=123,
        vault_file_path="/vault/image.jpg",
        unexpected_api_field={"nested": [1, {"more": "data"}]},
    )
    manager = Mock()
    assert app._adapt_action_result(
        output,
        manager,
        GetScreenshotParams(url="https://example.com"),
        message="Screenshot downloaded successfully",
        summary=output,
    )
    result = manager.add_result.call_args.args[0]
    assert result.get_data()[0]["name"] == "capture.jpg"
    assert "file_name" not in result.get_data()[0]
    assert result.get_data()[0]["unexpected_api_field"] == {"nested": [1, {"more": "data"}]}
    assert result.get_summary()["unexpected_api_field"] == {"nested": [1, {"more": "data"}]}
    assert result.get_summary()["name"] == "capture.jpg"


def test_registered_action_serializes_vault_output(asset, post, soar, monkeypatch):
    manager = Mock()
    monkeypatch.setattr(app, "actions_manager", manager)
    summary = {}
    soar.set_summary.side_effect = lambda value: summary.update(result=value)
    soar.get_summary.side_effect = lambda: summary["result"]
    soar.get_message.return_value = "Screenshot downloaded successfully"
    assert get_screenshot(GetScreenshotParams(url="https://example.com"), soar=soar, asset=asset)
    result = manager.add_result.call_args.args[0]
    assert result.get_data()[0]["vault_id"] == "unit-test-vault-id"
    assert result.get_summary()["vault_file_id"] == 123
    assert result.get_message() == "Screenshot downloaded successfully"


def test_registered_action_reports_download_failure(asset, post, response, soar, monkeypatch):
    manager = Mock()
    monkeypatch.setattr(app, "actions_manager", manager)
    response.status_code = 401
    assert not get_screenshot(GetScreenshotParams(url="https://example.com"), soar=soar, asset=asset)
    result = manager.add_result.call_args.args[0]
    assert "HTTP status 401" in result.get_message()
    soar.vault.add_attachment.assert_not_called()


def test_registered_connectivity_uses_asset_and_reports_success(asset, post, monkeypatch):
    manager = Mock()
    monkeypatch.setattr(app, "actions_manager", manager)
    monkeypatch.setattr(app, "_asset", asset, raising=False)
    assert connectivity_action(soar=Mock())
    assert manager.add_result.call_args.args[0].get_status()
