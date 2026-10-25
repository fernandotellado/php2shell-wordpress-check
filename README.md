# PHP2Shell Check

A read-only Site Health check that compares the PHP version your site is running with the releases that fix PHP2Shell (CVE-2026-109618 and CVE-2026-109619).

It adds one test to **Tools > Site Health** and one section to its **Info** tab. That is all it does. It sends nothing, scans nothing, stores nothing and has no settings page.

## What it checks

PHP published fixes for PHP2Shell in these releases:

| Branch | First fixed release |
|--------|---------------------|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

PHP 8.1 and older only got minimal source patches, not official releases. PHP 8.2 stops receiving security fixes on 31 December 2026.

The plugin reads `PHP_VERSION` from the process that is serving the request and compares it with that table. It also reports the PHP SAPI and the value of `session.upload_progress.enabled`, because PHP lists turning it off as the only mitigation for CVE-2026-115560, a third flaw with no fixed release yet.

## Results

| Your PHP | Site Health result |
|----------|--------------------|
| Equal to or newer than the fixed release of its branch | Good |
| A branch newer than 8.5 | Good |
| Lower than the fixed release of its branch | Recommended |
| 8.1 or older | Recommended |
| A pre-release build | Recommended |
| A version string the plugin cannot read | Recommended |

The test never returns "critical". A version number cannot prove a site is exposed or safe.

The "lower than the fixed release" result is deliberately not a verdict. Debian and Ubuntu ship security fixes without changing the version number PHP reports, so a patched server can still show 8.3.35. WordPress cannot tell the difference from the inside. In that case the test explains it and gives you a short message to send to your host, with your real version and SAPI already filled in.

## Extra notes the test can add

- The site runs PHP as an Apache module (`mod_php`), which PHP considers the most exposed setup.
- A `.user.ini` in the WordPress root or in `wp-admin` sets `session.upload_progress.enabled`. PHP warns that `.user.ini` does not take effect in time for this mitigation, even though `ini_get()` would report it as applied. Only those two locations are read.
- `session.upload_progress.enabled` is on (the PHP default).
- The branch is 8.2 and its end of support is close or past.

## What it does not do

- It does not detect an attack or a compromised site. Use a malware scanner for that.
- It does not look at the CLI or at other sites on the same server. Each WordPress install reports the PHP process serving its own requests.
- It cannot see an update that was never followed by a restart of the PHP processes: the old version is still the one running, and that is what you will see.
- It does not check the other mitigations PHP lists for the first CVE (`memory_limit`, `post_max_size`, web server or proxy limits). WordPress raises `memory_limit` at runtime, so the value PHP started with cannot be read from inside it.
- It cannot change PHP settings. `session.upload_progress.enabled` has to be set in `php.ini` or in the PHP-FPM pool, and on shared hosting that is your host's job.

## Tell the plugin your host confirmed the fix

If your host told you the fixes are applied through a backport, you can mark it so the test stops asking. Add this to `wp-config.php`:

```php
define( 'AYUDAWP_PHP2SHELL_CHECK_HOST_CONFIRMED', true );
```

Or use the filter:

```php
add_filter( 'ayudawp_php2shell_check_host_confirmed', '__return_true' );
```

This only turns the result green when the version number is inconclusive (lower than the fixed release, or 8.1 and older). It does not touch a pre-release or an unreadable version, and the plugin has no way to verify what your host told you.

## Requirements

- WordPress 5.2 or newer (the version that introduced Site Health)
- PHP 5.6 or newer

The code is written for PHP 5.6 on purpose. A check for old PHP versions has to load on old PHP versions.

## Installation

1. Download the ZIP from the releases page of this repository.
2. In WordPress, go to **Plugins > Add New Plugin > Upload Plugin** and upload it.
3. Activate it and open **Tools > Site Health**.

If you download the source ZIP from the green **Code** button instead, the folder will be called `php2shell-wordpress-check-main`. It works the same, because the plugin builds its paths from wherever it is installed.

## Updates

The plugin header has an `Update URI` that points to this repository, so WordPress will not offer you a different plugin with the same slug from WordPress.org. The flip side is that it does not update itself: to update, replace the plugin folder with the new version.

## Privacy

Nothing leaves your server. The plugin makes no HTTP requests, creates no options and no database tables, and stores no data. The only files it reads are `.user.ini` in the WordPress root and in `wp-admin`, capped at 64 KB each, to look for one setting.

## Translations

The plugin is in English and includes a Spanish (es_ES) translation. The `.pot` file is in `languages/` if you want to add another one.

## Changelog

### 1.0.0

- First release.

## Sources

- [PHP security advisory (php.net)](https://www.php.net/archive/2026.php)

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).

## Support

Need help or have suggestions?

- [Official website](https://servicios.ayudawp.com)
- [GitHub issues](https://github.com/fernandotellado/php2shell-wordpress-check/issues)
- [YouTube channel](https://www.youtube.com/AyudaWordPressES)
- [Documentation and tutorials](https://ayudawp.com)

Love the plugin? Please star the repository and help spread the word!

## About AyudaWP.com

We are specialists in WordPress security, SEO, AI and performance optimization plugins. We create tools that solve real problems for WordPress site owners while maintaining the highest coding standards and accessibility requirements.
