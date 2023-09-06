# File: ssmachine_connector.py
#
# Copyright (c) 2016-2023 Splunk Inc.
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
#
#
# Phantom App imports
import hashlib
# Imports local to this App
import os
import urllib.parse
import uuid

import phantom.app as phantom
import phantom.rules as ph_rules
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault as Vault

from ssmachine_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class SsmachineConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SsmachineConnector, self).__init__()
        self._headers = None
        self._api_key = None
        self._api_phrase = None
        self._rest_url = None
        self.cache_limit = None

    def initialize(self):

        config = self.get_config()

        self._api_key = config.get('ssmachine_key')
        self._api_phrase = config.get('ssmachine_hash')
        self._rest_url = SSMACHINE_JSON_DOMAIN
        cache_limit = config.get('cache_limit', DEFAULT_CACHE_LIMIT)
        try:
            if DEFAULT_CACHE_LIMIT <= float(cache_limit) <= MAX_CACHE_LIMIT:
                self.cache_limit = float(cache_limit)
            else:
                return self.set_status(phantom.APP_ERROR, VALID_CACHE_LIMIT_MSG)
        except:
            return self.set_status(phantom.APP_ERROR, VALID_CACHE_LIMIT_MSG)

        return phantom.APP_SUCCESS

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error messages from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_msg = SSMACHINE_UNAVAILABLE_MSG_ERROR
        self.error_print("Exception Occurred.", dump_object=e)
        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = ERROR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ERROR_CODE_MSG
                error_msg = ERROR_MSG_UNAVAILABLE
        except:
            error_code = ERROR_CODE_MSG
            error_msg = ERROR_MSG_UNAVAILABLE

        try:
            if not error_code:
                error_text = 'Error Message: {0}'.format(error_msg)
            else:
                error_text = 'Error Code: {0}. Error Message: {1}'.format(error_code, error_msg)
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _process_html_response(self, response, action_result):

        # A html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(['script', 'style', 'footer', 'nav']):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = 'Cannot parse error details'

        message = 'Status Code: {0}. Data from server:\n{1}\n'.format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _parse_response(self, result, r):

        # It's ok if r.text is None, dump that, if the result object supports recording it
        if hasattr(result, 'add_debug_data'):
            result.add_debug_data({'r_status_code': r.status_code})
            result.add_debug_data({'r_text': r.text })
            result.add_debug_data({'r_headers': r.headers})

        if SSMACHINE_CUSTOM_HTTP_RESPONSE_HEADER in r.headers:
            return RetVal(result.set_status(
                phantom.APP_ERROR, 'Screenshot Machine Returned an error: {0}'.format(r.headers[SSMACHINE_CUSTOM_HTTP_RESPONSE_HEADER])), None)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, result)

        """
        if 'image' not in r.headers.get('content-type'):
            return (result.set_status(phantom.APP_ERROR,
                        "Unable to parse response as an image, status_code: {0}, data: {1}".format(r.status_code, r.content)),
                        r.status_code, r.headers.get('content-type'), r.content)
                        """

        if not (200 <= r.status_code < 300):
            message = r.text.replace('{', '{{').replace('}', '}}')
            return RetVal(result.set_status(
                phantom.APP_ERROR, 'Call returned error, status_code: {0}, data: {1}'.format(r.status_code, message)), None)

        if 'image' not in r.headers.get('Content-Type', ''):
            message = r.text.replace('{', '{{').replace('}', '}}')
            return RetVal(result.set_status(
                phantom.APP_ERROR, 'Response does not contain an image. status_code: {0}, data: {1}'.format(r.status_code, message)), None)

        # Things look fine
        return RetVal(phantom.APP_SUCCESS, r.content)

    def _make_rest_call(self, result, params=None, headers=None, json=None, method='get', stream=False):

        url = self._rest_url
        params['key'] = self._api_key
        params['cacheLimit'] = self.cache_limit

        if headers is None:
            headers = {}

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return result.set_status(phantom.APP_ERROR, 'Invalid method: {0}'.format(method)), None

        if not request_func:
            return result.set_status(phantom.APP_ERROR, 'Invalid method call: {0} for requests module'.format(method)), None

        try:
            r = request_func(url, headers=headers, params=params, json=json, stream=stream, verify=True)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            error_msg = 'REST API call to server failed. {}'.format(err)
            return result.set_status(phantom.APP_ERROR, error_msg), None

        return self._parse_response(result, r)

    def _test_connectivity(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        params = {'url': 'https://www.screenshotmachine.com'}
        # Check if we have a Secret Phrase
        params['hash'] = str(hashlib.md5(
            f"{params['url']}{self._api_phrase}".encode('utf-8')).hexdigest()) if self._api_phrase else ''
        self.save_progress('Checking to see if Screenshotmachine.com is online...')

        ret_val, resp_data = self._make_rest_call(action_result, params, method='post', stream=True)

        if phantom.is_fail(ret_val):
            action_result.append_to_message('Test connectivity failed')
            return action_result.get_status()

        self.save_progress('Test Connectivity Passed')
        return action_result.set_status(ret_val, 'Test Connectivity Passed')

    def _handle_get_screenshot(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        params = {
            'url': param['url'],
            'filename': param.get('filename'),
            'dimension': param.get('dimension', SSMACHINE_DEFAULT_DIMENSION),
            'format': 'JPG',
            'delay': '200',
            'hash': str(hashlib.md5(f"{param['url']}{self._api_phrase}".encode('utf-8')).hexdigest())
            if self._api_phrase else ''  # Check if we have a Secret Phrase
        }

        ret_val, image = self._make_rest_call(action_result, params, method='post', stream=True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        permalink = None
        # only create a permalink if the hash is used
        if params['hash']:
            permalink = self._get_sspermalink(params=params, method='post')

        file_name = '{}.jpg'.format(params['filename']) if params['filename'] else '{0}{1}'.format(
            param['url'], '_screenshot.gif')

        if hasattr(Vault, 'get_vault_tmp_dir'):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = '/opt/phantom/vault/tmp'

        temp_dir = '{0}{1}'.format(temp_dir, '/{}'.format(uuid.uuid4()))
        os.makedirs(temp_dir)
        file_path = os.path.join(temp_dir, 'tempimage.jpg')
        with open(file_path, 'wb') as f:
            f.write(image)

        success, msg, vault_id = ph_rules.vault_add(
            container=self.get_container_id(),
            file_location=file_path,
            file_name=file_name,
        )

        if not success:
            return action_result.set_status(phantom.APP_ERROR, "Error adding file to the vault, Error: {}".format(msg))

        _, _, vault_meta_info = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
        if not vault_meta_info:
            self.debug_print('Error while fetching meta information for vault ID: {}'.format(vault_id))
            return action_result.set_status(phantom.APP_ERROR, "Could not find meta information of "
                                                               "the downloaded screenshot's Vault")

        summary = {
            phantom.APP_JSON_VAULT_ID: vault_id,
            phantom.APP_JSON_NAME: file_name,
            'vault_file_path': vault_meta_info[0]['path'],
            phantom.APP_JSON_SIZE: vault_meta_info[0][phantom.APP_JSON_SIZE]
        }
        if permalink:
            summary['permalink'] = permalink
        action_result.update_summary(summary)
        self.debug_print("Successfully added file to the vault")

        return action_result.set_status(phantom.APP_SUCCESS, "Screenshot Downloaded successfully")

    def _get_sspermalink(self, params, method='get'):
        method = method.upper()
        url = self._rest_url
        # allow the permalink to retrieve from cache
        params.pop('cacheLimit', None)
        req = requests.Request(method=method, url=url, params=params)
        r = req.prepare()
        try:
            return urllib.parse.unquote(r.url)
        except:
            return r.url

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print('action_id', self.get_action_identifier())

        if action_id == 'get_screenshot':
            ret_val = self._handle_get_screenshot(param)
        elif action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)

        return ret_val


if __name__ == '__main__':

    import argparse
    import json
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass('Password: ')

    if username and password:
        try:
            print('Accessing the Login page')
            r = requests.get(BaseConnector._get_phantom_base_url() + 'login', verify=verify, timeout=DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print('Logging into Platform to get the session id')
            r2 = requests.post(BaseConnector._get_phantom_base_url() + 'login', verify=verify,
                               data=data, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print('Unable to get session id from the platfrom. Error: ' + str(e))
            sys.exit(1)

    if len(sys.argv) < 2:
        print('No test json specified as input')
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SsmachineConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
