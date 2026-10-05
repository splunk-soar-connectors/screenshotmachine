# File: helper.py
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
import math
import tempfile
from pathlib import Path
from urllib.parse import unquote

from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .consts import (
    DEFAULT_REQUEST_TIMEOUT,
    DOWNLOAD_CHUNK_SIZE,
    MAX_CACHE_LIMIT,
    SCREENSHOT_TOO_LARGE_MSG,
    SSMACHINE_CUSTOM_HTTP_RESPONSE_HEADER,
    SSMACHINE_JSON_DOMAIN,
    SSMACHINE_UNAVAILABLE_MSG_ERROR,
    VALID_CACHE_LIMIT_MSG,
    VALID_MAX_SCREENSHOT_SIZE_MSG,
)


logger = getLogger()


def validate_configuration(asset):
    """Preserve the legacy numeric configuration limits before contacting the API."""
    try:
        cache_limit = float(asset.cache_limit)
        if not 0 <= cache_limit <= MAX_CACHE_LIMIT:
            raise ValueError
    except (TypeError, ValueError):
        raise ActionFailure(VALID_CACHE_LIMIT_MSG) from None
    try:
        size = float(asset.max_screenshot_size_mb)
        if not math.isfinite(size) or size <= 0:
            raise ValueError
        maximum_bytes = int(size * 1024 * 1024)
    except (TypeError, ValueError, OverflowError):
        raise ActionFailure(VALID_MAX_SCREENSHOT_SIZE_MSG) from None
    return cache_limit, maximum_bytes


def secret_hash(url, phrase):
    # The vendor's secret-phrase protocol requires MD5, rather than a security digest.
    return hashlib.md5(f"{url}{phrase}".encode(), usedforsecurity=False).hexdigest() if phrase else ""


def authenticated_params(asset, params):
    cache_limit, maximum_bytes = validate_configuration(asset)
    request_params = dict(params)
    # Screenshot Machine requires the key in the query string; header auth is unsupported.
    request_params["key"] = asset.ssmachine_key
    request_params["cacheLimit"] = cache_limit
    return request_params, maximum_bytes


def request_failure(error):
    # Request exceptions can contain the API key in the URL; never return their text.
    logger.debug("Screenshot Machine request failed: %s", type(error).__name__)
    return ActionFailure(f"REST API call to server failed. {SSMACHINE_UNAVAILABLE_MSG_ERROR}")


def remove_temporary_file(file_path):
    if file_path:
        try:
            Path(file_path).unlink(missing_ok=True)
        except OSError:
            pass


def download_screenshot(asset, params, temp_dir):
    # Manifest generation imports this module in the CLI environment without app dependencies.
    import requests

    request_params, maximum_bytes = authenticated_params(asset, params)
    file_path = None
    keep_file = False
    try:
        with requests.post(
            SSMACHINE_JSON_DOMAIN,
            params=request_params,
            stream=True,
            verify=True,
            timeout=DEFAULT_REQUEST_TIMEOUT,
        ) as response:
            if not 200 <= response.status_code < 300:
                raise ActionFailure(f"Screenshot Machine returned HTTP status {response.status_code}")
            if "image" not in response.headers.get("Content-Type", "").lower():
                raise ActionFailure("Screenshot Machine response does not contain an image")
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > maximum_bytes:
                        raise ActionFailure(SCREENSHOT_TOO_LARGE_MSG)
                except ValueError:
                    logger.debug("Screenshot Machine returned an invalid Content-Length header")
            with tempfile.NamedTemporaryFile(dir=temp_dir, suffix=".jpg", prefix="tmp_", delete=False) as screenshot_file:
                file_path = screenshot_file.name
                downloaded_bytes = 0
                for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
                    if not chunk:
                        continue
                    downloaded_bytes += len(chunk)
                    if downloaded_bytes > maximum_bytes:
                        raise ActionFailure(SCREENSHOT_TOO_LARGE_MSG)
                    screenshot_file.write(chunk)
        keep_file = True
        return file_path
    except ActionFailure:
        raise
    except Exception as error:
        raise request_failure(error) from None
    finally:
        if not keep_file:
            remove_temporary_file(file_path)


def permalink(params):
    # Keep requests runtime-only so manifest generation does not require app dependencies.
    import requests

    public_params = dict(params)
    public_params.pop("cacheLimit", None)
    public_params.pop("key", None)
    try:
        request = requests.Request(method="POST", url=SSMACHINE_JSON_DOMAIN, params=public_params).prepare()
        return unquote(request.url)
    except Exception as error:
        logger.debug("Screenshot Machine permalink failed: %s", type(error).__name__)
        return None


def check_connectivity(asset):
    # These libraries are needed only at runtime, not when the CLI imports app metadata.
    import requests
    from bs4 import BeautifulSoup

    url = "https://www.screenshotmachine.com"
    params, _ = authenticated_params(asset, {"url": url, "hash": secret_hash(url, asset.ssmachine_hash)})
    try:
        with requests.post(SSMACHINE_JSON_DOMAIN, params=params, stream=True, verify=True, timeout=DEFAULT_REQUEST_TIMEOUT) as response:
            custom_error = response.headers.get(SSMACHINE_CUSTOM_HTTP_RESPONSE_HEADER)
            if custom_error is not None:
                raise ActionFailure(f"Screenshot Machine Returned an error: {custom_error}")
            content_type = response.headers.get("Content-Type", "")
            if "html" in content_type:
                try:
                    soup = BeautifulSoup(response.text, "html.parser")
                    for element in soup(["script", "style", "footer", "nav"]):
                        element.extract()
                    details = "\n".join(line.strip() for line in soup.text.split("\n") if line.strip())
                except Exception:
                    details = "Cannot parse error details"
                raise ActionFailure(f"Status Code: {response.status_code}. Data from server:\n{details}\n")
            if not 200 <= response.status_code < 300:
                raise ActionFailure(f"Call returned error, status_code: {response.status_code}, data: {response.text}")
            if "image" not in content_type:
                raise ActionFailure(f"Response does not contain an image. status_code: {response.status_code}, data: {response.text}")
            # Consume the streamed response as the legacy connectivity check did.
            _ = response.content
    except ActionFailure as error:
        message = str(error)
        for secret in (asset.ssmachine_key, asset.ssmachine_hash):
            if secret:
                message = message.replace(secret, "[REDACTED]")
        message = message.replace("{", "{{").replace("}", "}}")
        raise ActionFailure(f"{message}. Test connectivity failed") from None
    except Exception as error:
        raise ActionFailure(f"{request_failure(error)}. Test connectivity failed") from None
