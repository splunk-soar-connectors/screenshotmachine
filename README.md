[comment]: # "Auto-generated SOAR connector documentation"
# Screenshot Machine

Publisher: Splunk  
Connector Version: 3.0.0  
Product Vendor: Screenshot Machine  
Product Name: Screenshot Machine  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.1.0  

This app integrates with the Screenshot Machine service

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""

## Backward Compatibility

In v3.0.0, For **get screenshot** action, 'size' parameter has been renamed with 'dimension'. Hence, it is requested to the
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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Screenshot Machine asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**ssmachine_key** |  required  | password | API Key
**ssmachine_hash** |  optional  | password | API Secret Phrase
**cache_limit** |  optional  | numeric | Cache Limit (how old cached images are accepted (in days), Default: 0, Allowed range: 0 to 14)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get screenshot](#action-get-screenshot) - Get a screenshot of a URL  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get screenshot'
Get a screenshot of a URL

Type: **investigate**  
Read only: **True**

For the <b>dimensions</b> parameter, follow the instructions below<br> <ul> <li>value should be in format [width]x[height]. Default value is 120x90.</li><li>width can be any <b>natural number greater than or equals to 100 and smaller or equals to 1920.</b></li><li>height can be any <b>natural number greater than or equals to 100 and smaller or equals to 9999.</b> Also <b>full</b> value is accepted if you want to capture full length webpage screenshot.</li></ul>Examples:<br>320x240 - website thumbnail size 320x240 pixels<br>800x600 - website snapshot size 800x600 pixels<br>1024x768 - web screenshot size 1024x768 pixels<br>1920x1080 - webpage screenshot size 1920x1080 pixels<br>1024xfull - full page screenshot with width equals to 1024 pixels (can be pretty long).<br><br> For the <b>delay</b> parameter, Use higher values for websites which take more to time load before capturing the screenshot. <br> Allowed values are: (0, 200,400, 600, 800, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000).

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to screenshot | string |  `url`  `domain` 
**dimension** |  optional  | Size of the web snapshot or webpage screenshot in format [width]x[height]. (Default: 120x90) | string | 
**filename** |  optional  | The filename for storing the screenshot in the Vault | string | 
**delay** |  optional  | Based on delay value capturing engine should wait before the screenshot is created, (Default: 200) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.delay | string |  |   200  3000 
action_result.parameter.dimension | string |  |   122x123  123xfull 
action_result.parameter.filename | string |  |  
action_result.parameter.url | string |  `url`  `domain`  |   https://www.testurl.com 
action_result.data | string |  |  
action_result.summary.name | string |  `url`  |   https://www.testurl.com_screenshot.jpg 
action_result.summary.permalink | string |  `url`  |  
action_result.summary.size | numeric |  |   48692 
action_result.summary.vault_file_path | string |  |   /opt/phantom/vault/02/5a/025a0aed68c79a9dc14fa11654ed9a21d521f79e 
action_result.summary.vault_id | string |  `vault id`  `sha1`  |   025a0aed68c79a9dc14fa11654ed9a21d521f79e 
action_result.message | string |  |   Downloaded screenshot 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 