[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2023 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""

## Backward Compatibility

In v3.0.0, For **get screenshot** action, 'size' parameter has been renamed with 'dimension' as per the screenshot [API documentation](https://www.screenshotmachine.com/website-screenshot-api.php). Hence, it is requested to the
end-user to please update their existing playbooks by re-inserting | modifying | deleting the
corresponding action blocks to ensure the correct functioning of the playbooks created on the
earlier versions of the app. 

## Asset Configuration

By using the **cache_limit** configuration parameter you can manage how old(in days) cached images
do you accept. **Allowed values are 0-14** . A zero value means always download fresh screenshots.
If you need a shorter interval than one day, you can use decimal numbers in the parameter, e.g.
cacheLimit=0.041666 means: use image from cache only if it is not older than one HOUR
(1/24=0.041666).

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Screenshot Machine server. Below are
the default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |
