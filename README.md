# PDLF --- Personal Dead Link Finder

**A lightweight, self-hosted PHP tool for finding broken links on your
own website.**

PDLF helps website owners scan their sites, identify links that may need
attention, review the results, and export them as CSV. It runs on your
own hosting account and stores scan data locally in SQLite.

> **Project status:** Early release / testing. PDLF 3.0 is being tested
> on a live, low-traffic website. It has not yet undergone an
> independent security audit or broad compatibility testing. Please test
> it in a suitable environment before relying on it for important sites.

## Screenshots

Add the supplied screenshots to a `screenshots/` folder in this
repository using these filenames:

  File                   Description
  ---------------------- ------------------------------------------
  `screenshots/p0.jpg`   Administrator login
  `screenshots/p1.jpg`   Dashboard after login
  `screenshots/p2.jpg`   Scan progress and completed scan
  `screenshots/p3.jpg`   Scan report, charts and broken-link list

![PDLF login screen](screenshots/p0.jpg)

![PDLF dashboard](screenshots/p1.jpg)

![PDLF scan progress](screenshots/p2.jpg)

![PDLF scan report](screenshots/p3.jpg)

## Features

-   **Self-hosted:** Runs on your own PHP-enabled web hosting.
-   **Single-file application:** The main application is `index.php`.
-   **SQLite storage:** Uses PDO SQLite; no MySQL server is required.
-   **Installation wizard:** Checks the PHP environment and guides the
    initial setup.
-   **Administrator login:** Creates one administrator account during
    installation.
-   **Configurable crawl scope:** Scan the starting host, selected
    subdomains, or all subdomains under the starting host.
-   **Optional resource checks:** Check images, CSS, scripts and
    embedded resources.
-   **File exclusions:** Configure extensions that should not be crawled
    for more links, or should be excluded from checking entirely.
-   **Live scan progress:** View discovered, pending, working, broken
    and unverified counts while a scan runs.
-   **Resumable scans:** Stop and resume scans; previous results are
    stored in SQLite.
-   **Scan history:** Revisit previous scans and their reports.
-   **Reports and charts:** Review HTTP response codes, link status,
    redirect information and the pages where links were found.
-   **CSV export:** Export scan results for further review in a
    spreadsheet.
-   **Request safeguards:** Uses request timeouts, response-size limits,
    redirect limits and URL/IP validation.
-   **No external service dependency:** The application does not require
    a hosted crawling service or external API.

## Requirements

The application source specifies these requirements:

-   PHP 8.0 or newer
-   PDO SQLite extension
-   SQLite 3.25 or newer
-   cURL extension with SSL support
-   DOM extension (`DOMDocument`)

Optional PHP extensions:

-   `mbstring` --- support for pages using legacy character encodings
-   `intl` --- internationalised domain-name handling

A web server configured to run PHP is also required. HTTPS is strongly
recommended, particularly because the administrator logs in through a
browser.

## Installation

1.  Check that your hosting environment meets the requirements above.
2.  Upload `index.php` to a directory on your website.
3.  Open that location in a browser over HTTPS.
4.  Follow the PDLF installation wizard.
5.  Create the administrator username and password.
6.  Sign in and configure your first scan.

The application creates its private data directory for configuration,
SQLite data, logs, backups and session files. The installer checks the
storage location and displays a warning when it is inside the public web
root.

**Important:** Do not ignore a warning that private application data is
publicly reachable. Prefer placing the data directory outside the web
root. If that is not possible, configure and verify the appropriate
access-denial rule for your web server. Apache `.htaccess` rules do not
protect an NGINX server.

The application supports the `PDLF_DATA_DIR` environment variable to
specify a custom data-directory path. Configure it to an appropriate
private directory if needed.

## Using PDLF

1.  Sign in to the administrator dashboard.
2.  Enter the starting URL of your website.
3.  Set the maximum number of links and request timeout.
4.  Choose the crawl scope:
    -   **This host only**
    -   **Selected subdomains**
    -   **All subdomains**
5.  Optionally enable resource checks and adjust file exclusions.
6.  Start the scan.
7.  Review the progress and open the report when the scan completes.
8.  Filter the report and export results to CSV if required.

The maximum-link setting limits how many links can be recorded for a
scan. If the limit is reached, the report indicates that discovery was
truncated; a scan at that limit should not be treated as complete
coverage of the entire site.

## Understanding link statuses

PDLF currently presents three main link classifications:

  -----------------------------------------------------------------------
  Status                              Meaning
  ----------------------------------- -----------------------------------
  **Working**                         A successful 2xx HTTP response.

  **Broken**                          A response or condition classified
                                      by the current code as a definite
                                      failure, including HTTP 404 and
                                      410.

  **Unverified**                      The application could not reliably
                                      determine whether the link works,
                                      for example because of access
                                      restrictions, rate limiting,
                                      timeouts or other inconclusive
                                      errors.
  -----------------------------------------------------------------------

Redirected links are also counted and their redirect information is
shown in the report.

**Classification caveat:** In the current source, most HTTP 5xx
responses are classified as Broken, while HTTP 503 is Unverified.
Server-side 5xx errors can be temporary, so review these results before
treating them as confirmed dead links. This behaviour should be
revisited before a stable release.

A 403 response, for example, does not necessarily mean a page is dead;
it may mean that the server is blocking the request.

## Crawl scope and external links

PDLF is intended to scan a website under the administrator's control.
The current dashboard offers host and subdomain scope choices. Links
outside the configured scope are not intended to be crawled.

The external-link checkbox has been removed from the current interface.
The uploaded source still contains legacy backend handling for the
`check_external` option, although the current form does not submit that
option. This is a known cleanup item; do not interpret the current
interface alone as an independent security audit of crawl-scope
enforcement.

Only scan websites you own or are authorised to test.

## Security notes

PDLF includes several protective measures in its current source,
including:

-   Password hashing for the administrator account
-   Session and CSRF-token handling
-   Security-related HTTP response headers
-   HTTPS certificate verification for cURL requests
-   Manual redirect handling rather than automatic redirect following
-   URL, DNS and IP-address checks intended to reduce server-side
    request forgery (SSRF) risk
-   Request timeouts, response-size limits and redirect limits
-   Private application storage for configuration, database, logs,
    backups and sessions

These measures reduce risk but do not guarantee that the application is
secure in every hosting environment. Server configuration matters,
especially for private data-directory protection. The project has not
been independently penetration-tested or security-audited.

Use a strong, unique administrator password, keep PHP and the web server
updated, use HTTPS, and keep backups of important data.

## Data and privacy

PDLF is designed to run on the website owner's hosting account. Scan
records are stored locally in an SQLite database in the application's
private data directory.

The application does not need a third-party crawling API or a cloud
account. Review the source code and your hosting environment to
understand exactly what requests your installation makes.

## Technology

-   PHP
-   SQLite
-   PDO
-   cURL
-   DOMDocument
-   HTML, CSS and JavaScript

## Known limitations

-   PDLF is currently a single-file PHP application.
-   Scanning is driven by browser/AJAX requests; a separate cron-based
    background worker is not part of this version.
-   Scan coverage is limited by the configured maximum-link setting and
    the pages the crawler can successfully retrieve.
-   Some websites restrict automated requests, require authentication,
    apply rate limits or behave differently for `HEAD` and `GET`
    requests. Results may therefore need manual review.
-   The current HTTP 5xx classification and legacy external-link backend
    handling are documented above and should be reviewed before a stable
    release.
-   Compatibility across different hosting providers, PHP configurations
    and web servers is still being tested.

## Contributing and bug reports

PDLF is an early-stage project. Bug reports, reproducible test cases,
code review and practical suggestions are welcome.

When reporting a problem, please include:

-   PHP version
-   Web server (Apache, NGINX, IIS, etc.)
-   Relevant PHP extensions
-   Steps to reproduce the issue
-   The exact error message, with passwords, session tokens, private
    URLs and other sensitive information removed

Please do not post your PDLF database, configuration file, session
files, credentials or private scan data in public issues.

## License

The source file declares the **MIT License**. Add a `LICENSE` file
containing the full MIT License text and the copyright holder/year
before publishing the repository.
