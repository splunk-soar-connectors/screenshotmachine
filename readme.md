[comment]: # "Auto-generated SOAR connector documentation"
# Screenshot Machine

Publisher: Splunk  
Connector Version: 2\.2\.3  
Product Vendor: Screenshot Machine  
Product Name: Screenshot Machine  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app integrates with the Screenshot Machine service

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
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
**ssmachine\_key** |  required  | password | API Key
**ssmachine\_hash** |  optional  | password | API Secret Phrase
**cache\_limit** |  optional  | numeric | Cache Limit \(how old cached images are accepted \(in days\), Default\: 0\)

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

The supported size types are\:<ul><li>Tiny\: \(120 x 90px\)</li><li>Small\: \(200 x 150px\)</li><li>Normal\: \(400 x 300px\)</li><li>Medium\: \(640 x 480px\)</li><li>Large\: \(800 x 600px\)</li><li>Full Page\: Complete page from the top to the bottom \(can be pretty long\)</li></ul><p>Sizes are passed with their full names \(e\.g\. <b>Tiny</b>, or <b>Full Page</b>\)\. The default size is <b>Full Page</b> if no size is defined\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to screenshot | string |  `url`  `domain` 
**size** |  optional  | Size of the screenshot | string | 
**filename** |  optional  | The filename for storing the screenshot in the Vault | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.size | string | 
action\_result\.parameter\.url | string |  `url`  `domain` 
action\_result\.parameter\.filename | string | 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.name | string |  `url` 
action\_result\.summary\.permalink | string |  `url` 
action\_result\.summary\.size | numeric | 
action\_result\.summary\.vault\_file\_path | string | 
action\_result\.summary\.vault\_id | string |  `vault id`  `sha1` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 