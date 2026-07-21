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

### API key transport

Screenshot Machine's documented API is an HTTP GET API and requires the customer `key` as a query
parameter. The vendor documentation does not describe a header- or request-body authentication
alternative, so this connector follows that vendor contract. Administrators should limit access to
API-service, proxy, and TLS-inspection logs that retain request targets, and rotate the API key if
those logs are exposed.

Configure a Screenshot Machine secret phrase whenever possible. The vendor requires the matching
`hash` when a secret phrase is enabled, which reduces the usefulness of a disclosed key; it does
not remove the key from the request URL. See the [Screenshot Machine API documentation](https://www.screenshotmachine.com/website-screenshot-api.php)
for the supported request format and secret-phrase behavior.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Screenshot Machine server. Below are
the default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http | tcp | 80 |
|         https | tcp | 443 |
