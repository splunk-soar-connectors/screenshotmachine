# File: get_screenshot.py
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
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..consts import SSMACHINE_DEFAULT_DELAY, SSMACHINE_DEFAULT_DIMENSION
from ..helper import download_screenshot, permalink, remove_temporary_file, secret_hash, validate_configuration


class GetScreenshotParams(Params):
    url: str = Param(description="URL to screenshot", primary=True, cef_types=["url", "domain"])
    dimension: str = Param(
        description="Size of the web snapshot or webpage screenshot in format [width]x[height]. (Default: 120x90)",
        default=SSMACHINE_DEFAULT_DIMENSION,
        required=False,
    )
    filename: str | None = Param(description="The filename for storing the screenshot in the Vault", required=False)
    delay: str = Param(
        description="Based on delay value(in seconds) capturing engine should wait before the screenshot is created, (Default: 200)",
        default=SSMACHINE_DEFAULT_DELAY,
        required=False,
    )


class ScreenshotOutput(PermissiveActionOutput):
    # These fields mirror the summary so the SDK view can render vault metadata.
    # PermissiveActionOutput also retains undeclared response fields during serialization.
    file_name: str = OutputField(alias="name", cef_types=["url"], example_values=["https://www.testurl.com_screenshot.jpg"])
    permalink: str | None = OutputField(cef_types=["url"])
    size: int = OutputField(example_values=[48692])
    vault_file_id: int = OutputField(example_values=[123])
    vault_file_path: str = OutputField(example_values=["/opt/phantom/vault/02/5a/025a0aed68c79a9dc14fa11654ed9a21d521f79e"])
    vault_id: str = OutputField(cef_types=["vault id", "sha1"], example_values=["025a0aed68c79a9dc14fa11654ed9a21d521f79e"])


@app.view_handler(template="display_scrshot.html")
def render_screenshots(output: list[ScreenshotOutput]) -> dict:
    return {
        "results": [
            {
                "vault_id": item.vault_id,
                "vault_file_name": item.file_name,
                "vault_file_id": item.vault_file_id,
                "vault_file_path": item.vault_file_path,
            }
            for item in output
        ]
    }


@app.action(
    name="get screenshot",
    identifier="get_screenshot",
    description="Get a screenshot of a URL",
    action_type="investigate",
    read_only=True,
    versions="EQ(*)",
    summary_type=ScreenshotOutput,
    view_handler=render_screenshots,
    verbose="For the <b>dimensions</b> parameter, follow the instructions below<br> <ul> <li>value should be in format [width]x[height]. Default value is 120x90.</li><li>width can be any <b>natural number greater than or equals to 100 and smaller or equals to 1920.</b></li><li>height can be any <b>natural number greater than or equals to 100 and smaller or equals to 9999.</b> Also <b>full</b> value is accepted if you want to capture full length webpage screenshot.</li></ul>Examples:<br>320x240 - website thumbnail size 320x240 pixels<br>800x600 - website snapshot size 800x600 pixels<br>1024x768 - web screenshot size 1024x768 pixels<br>1920x1080 - webpage screenshot size 1920x1080 pixels<br>1024xfull - full page screenshot with width equals to 1024 pixels (can be pretty long).<br><br> For the <b>delay</b> parameter, Use higher values for websites which take more to time load before capturing the screenshot. <br> Allowed values are: (0, 200,400, 600, 800, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000).",
)
def get_screenshot(params: GetScreenshotParams, soar: SOARClient, asset: Asset) -> ScreenshotOutput:
    validate_configuration(asset)
    request_params = {
        "url": params.url,
        "filename": params.filename,
        "dimension": params.dimension,
        "format": "JPG",
        "delay": params.delay,
        "hash": secret_hash(params.url, asset.ssmachine_hash),
    }
    file_path = download_screenshot(asset, request_params, soar.vault.get_vault_tmp_dir())
    file_name = f"{params.filename}.jpg" if params.filename else f"{params.url}_screenshot.jpg"
    try:
        vault_id = soar.vault.add_attachment(
            container_id=soar.get_executing_container_id(),
            file_location=file_path,
            file_name=file_name,
        )
    except Exception as error:
        raise ActionFailure(f"Error adding file to the vault, Error: {error}") from None
    finally:
        remove_temporary_file(file_path)
    attachments = soar.vault.get_attachment(container_id=soar.get_executing_container_id(), vault_id=vault_id)
    if not attachments:
        raise ActionFailure("Could not find meta information of the downloaded screenshot's Vault")
    attachment = attachments[0]
    summary = ScreenshotOutput(
        name=file_name,
        vault_id=vault_id,
        vault_file_path=attachment.path,
        vault_file_id=attachment.id,
        size=attachment.size,
        **({"permalink": permalink(request_params)} if request_params["hash"] else {}),
    )
    soar.set_summary(summary)
    soar.set_message("Screenshot downloaded successfully")
    return summary
