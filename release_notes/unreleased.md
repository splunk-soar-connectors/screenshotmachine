**Unreleased**

* Migrate the app to the Splunk SOAR SDK.
* Raise the minimum SOAR version from 6.3.0 to 7.0.0.
* Replace Python 3.9 support with Python 3.13 and 3.14 support.
* Change the test connectivity identifier from test_asset_connectivity to test_connectivity.
* Convert the screenshot widget to SDK Jinja2 rendering, using SDK default sizing and title.
* Add vault metadata to action_result.data for rendering while retaining the summary fields.
* Support rendering historical screenshots with summary-only results and mixed legacy/SDK results.
* Treat Screenshot Machine error images marked with the X-Screenshotmachine-Response header as failed requests instead of saving them as screenshots.
