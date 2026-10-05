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

from copy import deepcopy

import pytest
from soar_sdk.action_results import ActionResult

from src.actions.get_screenshot import display_scrshot


@pytest.fixture
def view_context():
    return {"QS": {}, "container": 42, "app": 153, "no_connection": False, "google_maps_key": False}


def screenshot_metadata(name):
    return {"name": name, "size": 6, "vault_id": "unit-test-vault-id", "vault_file_id": 123, "vault_file_path": "/vault/image.jpg"}


def app_run(*results):
    return ({"total_objects": len(results), "total_objects_successful": len(results)}, list(results))


@pytest.mark.parametrize("filename, escaped", [("legacy.jpg", "legacy.jpg"), ("<script>alert(1)</script>.jpg", "&lt;script&gt;")])
def test_legacy_summary_only_result_renders_without_mutation(view_context, filename, escaped):
    result = ActionResult(True, "Screenshot downloaded successfully")
    metadata = screenshot_metadata(filename)
    result.set_summary(metadata)
    original_summary = deepcopy(metadata)
    assert result.get_data() == []

    rendered = display_scrshot("get_screenshot", [app_run(result)], view_context)

    assert escaped in rendered
    assert "<script>alert(1)</script>" not in rendered
    assert "unit-test-vault-id" in rendered
    assert "/download?document=/vault/image.jpg&id=123" in rendered
    assert ", 42, null, false)" in rendered
    assert rendered.index("File Name") < rendered.index("Vault ID")
    assert view_context["prerender"] is True
    assert result.get_data() == []
    assert result.get_summary() == original_summary


@pytest.mark.parametrize("same_app_run", [False, True])
def test_mixed_legacy_and_sdk_app_runs_render_once_in_original_order(view_context, same_app_run):
    legacy = ActionResult(True, "Screenshot downloaded successfully")
    legacy.set_summary(screenshot_metadata("legacy.jpg"))
    sdk = ActionResult(True, "Screenshot downloaded successfully")
    metadata = screenshot_metadata("sdk.jpg")
    sdk.add_data(metadata)
    sdk.set_summary(metadata)

    runs = [app_run(legacy, sdk)] if same_app_run else [app_run(legacy), app_run(sdk)]
    rendered = display_scrshot("get_screenshot", runs, view_context)

    assert rendered.count("legacy.jpg") == 1
    assert rendered.count("sdk.jpg") == 1
    assert rendered.index("legacy.jpg") < rendered.index("sdk.jpg")
    assert rendered.count("/download?document=/vault/image.jpg&id=123") == 2
    assert legacy.get_data() == []
    assert sdk.get_data() == [metadata]


def test_existing_sdk_data_takes_precedence_over_summary(view_context):
    result = ActionResult(True, "Screenshot downloaded successfully")
    metadata = {**screenshot_metadata("sdk.jpg"), "extra_api_field": {"nested": [1, 2]}}
    result.add_data(metadata)
    result.set_summary(screenshot_metadata("summary-only.jpg"))
    original_data = deepcopy(result.get_data())
    original_summary = deepcopy(result.get_summary())

    rendered = display_scrshot("get_screenshot", [app_run(result)], view_context)

    assert rendered.count("sdk.jpg") == 1
    assert "summary-only.jpg" not in rendered
    assert result.get_data() == original_data
    assert result.get_summary() == original_summary


def test_empty_result_does_not_create_invalid_screenshot(view_context):
    result = ActionResult(True, "Screenshot downloaded successfully")

    rendered = display_scrshot("get_screenshot", [app_run(result)], view_context)

    assert "ssmachine_display" in rendered
    assert "File Info" not in rendered
    assert "/download?document=" not in rendered
    assert "Error in view function" not in rendered
    assert result.get_data() == []
