# File: app.py
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

from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.logging import getLogger

from .consts import DEFAULT_CACHE_LIMIT, DEFAULT_MAX_SCREENSHOT_SIZE_MB
from .helper import check_connectivity


logger = getLogger()


class Asset(BaseAsset):
    ssmachine_key: str = AssetField(description="API Key", sensitive=True, category=FieldCategory.CONNECTIVITY)
    ssmachine_hash: str | None = AssetField(description="API Secret Phrase", sensitive=True, required=False, category=FieldCategory.CONNECTIVITY)
    cache_limit: float = AssetField(
        description="Cache Limit (how old cached images are accepted (in days), Default: 0, Allowed range: 0 to 14)",
        default=DEFAULT_CACHE_LIMIT,
        required=False,
        category=FieldCategory.CONNECTIVITY,
    )
    max_screenshot_size_mb: float = AssetField(
        description="Maximum screenshot download size in MiB",
        default=DEFAULT_MAX_SCREENSHOT_SIZE_MB,
        required=False,
        category=FieldCategory.CONNECTIVITY,
    )


app = App(
    name="Screenshot Machine",
    app_type="information",
    logo="logo_screenshotmachine.svg",
    logo_dark="logo_screenshotmachine_dark.svg",
    product_vendor="Screenshot Machine",
    product_name="Screenshot Machine",
    publisher="Splunk",
    appid="776ab995-313e-48e7-bccd-e8c9650c239a",
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Validate the asset configuration for connectivity using supplied configuration."""
    logger.progress("Checking to see if Screenshotmachine.com is online...")
    check_connectivity(asset)
    soar.set_message("Test Connectivity Passed")
    logger.info("Test Connectivity Passed")


# Importing the module registers its action with the app.
from .actions import get_screenshot  # noqa: F401


if __name__ == "__main__":
    app.cli()
