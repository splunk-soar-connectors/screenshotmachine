# File: ssmachine_consts.py
#
# Copyright (c) 2021-2023 Splunk Inc.
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

SSMACHINE_JSON_DOMAIN = 'https://api.screenshotmachine.com/'
SSMACHINE_DEFAULT_DIMENSION = '120x90'
SSMACHINE_DEFAULT_DELAY = '200'
MAX_CACHE_LIMIT = 14
DEFAULT_CACHE_LIMIT = 0
VALID_CACHE_LIMIT_MSG = "Please provide a valid value in the 'Cache Limit' configuration parameter, the allowed range is [0-14]"

# Constants relating to '_get_error_message_from_exception'
ERROR_CODE_MSG = 'Error code unavailable'
ERROR_MSG_UNAVAILABLE = 'Error message unavailable. Please check the asset configuration and|or action parameters'
PARSE_ERROR_MSG = 'Unable to parse the error message. Please check the asset configuration and|or action parameters'
SSMACHINE_UNAVAILABLE_MSG_ERROR = "Error message unavailable. Please check the asset configuration and|or action parameters"
SSMACHINE_CUSTOM_HTTP_RESPONSE_HEADER = 'X-Screenshotmachine-Response'
DEFAULT_REQUEST_TIMEOUT = 60  # in seconds
