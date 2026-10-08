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

import subprocess
import sys
from pathlib import Path


def test_root_package_exposes_sdk_view_handler_in_fresh_interpreter():
    # A fresh interpreter reproduces SOAR's root-package view lookup; other tests
    # have already imported the action module and would hide missing imports.
    subprocess.run(
        [sys.executable, "-c", "import src; assert callable(src.actions.get_screenshot.render_screenshots)"],
        cwd=Path(__file__).resolve().parents[1],
        check=True,
        capture_output=True,
        text=True,
    )
