# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pytest
from soar_sdk.action_results import ActionResult

from src.actions.get_screenshot import render_screenshots


@pytest.fixture
def view_context():
    return {"QS": {}, "container": 42, "app": 153, "no_connection": False, "google_maps_key": False}


def screenshot_metadata(name):
    return {
        "name": name,
        "size": 6,
        "vault_id": "unit-test-vault-id",
        "vault_file_id": 123,
        "vault_file_path": "/vault/image.jpg",
    }


def app_run(*results):
    return ({"total_objects": len(results), "total_objects_successful": len(results)}, list(results))


def test_sdk_output_renders_file_info_and_escapes_filename(view_context):
    result = ActionResult(True, "Screenshot downloaded successfully")
    result.add_data(screenshot_metadata("<script>alert(1)</script>.jpg"))

    rendered = render_screenshots("get_screenshot", [app_run(result)], view_context)

    assert "&lt;script&gt;" in rendered
    assert "<script>alert(1)</script>" not in rendered
    assert "unit-test-vault-id" in rendered
    assert "/download?document=/vault/image.jpg&id=123" in rendered
    assert ", 42, null, false)" in rendered
    assert rendered.index("File Name") < rendered.index("Vault ID")
    assert view_context["prerender"] is True


def test_multiple_sdk_outputs_render_in_original_order(view_context):
    first = ActionResult(True, "Screenshot downloaded successfully")
    first.add_data(screenshot_metadata("first.jpg"))
    second = ActionResult(True, "Screenshot downloaded successfully")
    second.add_data(screenshot_metadata("second.jpg"))

    rendered = render_screenshots("get_screenshot", [app_run(first), app_run(second)], view_context)

    assert rendered.count("first.jpg") == 1
    assert rendered.count("second.jpg") == 1
    assert rendered.index("first.jpg") < rendered.index("second.jpg")


def test_view_uses_output_data_and_ignores_summary(view_context):
    result = ActionResult(True, "Screenshot downloaded successfully")
    result.add_data(screenshot_metadata("sdk.jpg"))
    result.set_summary(screenshot_metadata("summary-only.jpg"))

    rendered = render_screenshots("get_screenshot", [app_run(result)], view_context)

    assert rendered.count("sdk.jpg") == 1
    assert "summary-only.jpg" not in rendered


def test_summary_only_result_is_not_adapted_to_sdk_output(view_context):
    result = ActionResult(True, "Screenshot downloaded successfully")
    result.set_summary(screenshot_metadata("legacy.jpg"))

    rendered = render_screenshots("get_screenshot", [app_run(result)], view_context)

    assert "ssmachine_display" in rendered
    assert "No screenshot data found" in rendered
    assert "legacy.jpg" not in rendered
    assert "/download?document=" not in rendered
    assert "Error in view function" not in rendered


def test_failed_result_does_not_create_screenshot_output(view_context):
    result = ActionResult(False, "Screenshot Machine returned an error: invalid_url")

    rendered = render_screenshots("get_screenshot", [app_run(result)], view_context)

    assert "No screenshot data found" in rendered
    assert "/download?document=" not in rendered
    assert "Error in view function" not in rendered
