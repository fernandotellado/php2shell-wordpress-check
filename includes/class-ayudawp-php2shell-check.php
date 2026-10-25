<?php
/**
 * PHP2Shell check: logic and Site Health integration.
 *
 * Written for PHP 5.6+ on purpose: the plugin has to load on the same old PHP
 * versions it is meant to warn about. No scalar type hints, no return types,
 * no null coalescing operator, no trailing commas in calls.
 *
 * @package php2shell-wordpress-check
 */

// Prevent direct file access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only PHP2Shell check shown in Tools > Site Health.
 *
 * It only reads what the running PHP process reports about itself. It sends no
 * requests, scans nothing, stores nothing and creates no options.
 */
class Ayudawp_Php2shell_Check {

	/**
	 * First release of each PHP branch with the fixes for CVE-2026-109618 and
	 * CVE-2026-109619, from the PHP security advisory of 21 October 2026.
	 *
	 * @var array
	 */
	const FIXED_VERSIONS = array(
		'8.2' => '8.2.35',
		'8.3' => '8.3.36',
		'8.4' => '8.4.27',
		'8.5' => '8.5.12',
	);

	/**
	 * Unix time of 2027-01-01 00:00:00 UTC: PHP 8.2 stops receiving security
	 * support on 31 December 2026.
	 *
	 * @var int
	 */
	const PHP_82_SUPPORT_END = 1798761600;

	/**
	 * Register the hooks.
	 *
	 * Both filters only run when Site Health builds its tests or its Info tab,
	 * so nothing is added to a normal page load.
	 *
	 * @return void
	 */
	public static function init() {
		add_filter( 'site_status_tests', array( __CLASS__, 'register_test' ) );
		add_filter( 'debug_information', array( __CLASS__, 'add_debug_information' ) );
	}

	/**
	 * Load the bundled translations the first time they are needed.
	 *
	 * @return void
	 */
	private static function load_textdomain() {
		if ( is_textdomain_loaded( 'php2shell-wordpress-check' ) ) {
			return;
		}

		load_plugin_textdomain(
			'php2shell-wordpress-check',
			false,
			dirname( plugin_basename( AYUDAWP_PHP2SHELL_CHECK_FILE ) ) . '/languages'
		);
	}

	/**
	 * Add the direct test to Site Health.
	 *
	 * @param array $tests Site Health tests.
	 * @return array
	 */
	public static function register_test( $tests ) {
		self::load_textdomain();

		$tests['direct']['ayudawp_php2shell'] = array(
			'label' => __( 'PHP2Shell: PHP version', 'php2shell-wordpress-check' ),
			'test'  => array( __CLASS__, 'run_test' ),
		);

		return $tests;
	}

	/**
	 * Run the Site Health test.
	 *
	 * @return array Site Health result.
	 */
	public static function run_test() {
		self::load_textdomain();

		return self::build_result( self::get_facts() );
	}

	/**
	 * Add a section to the Info tab of Site Health.
	 *
	 * @param array $info Debug information sections.
	 * @return array
	 */
	public static function add_debug_information( $info ) {
		self::load_textdomain();

		$info['ayudawp_php2shell'] = array(
			'label'       => __( 'PHP2Shell check', 'php2shell-wordpress-check' ),
			'description' => __( 'Read from the PHP process that serves this site. Nothing is sent anywhere.', 'php2shell-wordpress-check' ),
			'fields'      => self::build_debug_fields( self::get_facts() ),
		);

		return $info;
	}

	/**
	 * Collect what the running PHP process reports about itself.
	 *
	 * PHP_VERSION and ini_get() describe the process serving this request, not
	 * the binary on disk, so an update that was never followed by a restart of
	 * the PHP processes still shows the old version here.
	 *
	 * @return array
	 */
	public static function get_facts() {
		$progress = ini_get( 'session.upload_progress.enabled' );

		return array(
			'version'         => PHP_VERSION,
			'sapi'            => PHP_SAPI,
			'evaluation'      => self::evaluate_version( PHP_VERSION ),
			// Null when the session extension is not loaded.
			'upload_progress' => ( false === $progress ) ? null : filter_var( $progress, FILTER_VALIDATE_BOOLEAN ),
			'user_ini'        => self::find_user_ini_overrides(),
			'host_confirmed'  => self::is_host_confirmed(),
		);
	}

	/**
	 * Compare a PHP version with the first fixed release of its branch.
	 *
	 * The version number alone is not proof of anything below the minimum:
	 * distributions such as Debian or Ubuntu backport the fix and keep the
	 * upstream number, so "below_minimum" is deliberately not "vulnerable".
	 *
	 * States: patched, newer_branch, below_minimum, no_official_fix,
	 * prerelease and unknown.
	 *
	 * @param string $version Value of PHP_VERSION.
	 * @return array With the keys state, branch and minimum.
	 */
	public static function evaluate_version( $version ) {
		$result = array(
			'state'   => 'unknown',
			'branch'  => '',
			'minimum' => '',
		);

		if ( ! preg_match( '/^(\d+)\.(\d+)\.(\d+)/', (string) $version, $matches ) ) {
			return $result;
		}

		$branch = $matches[1] . '.' . $matches[2];
		$core   = $branch . '.' . $matches[3];
		$suffix = substr( (string) $version, strlen( $core ) );
		$is_pre = (bool) preg_match( '/alpha|beta|rc|dev/i', $suffix );

		$result['branch'] = $branch;

		// 8.1 and older: the PHP project only published minimal source patches.
		if ( version_compare( $branch, '8.2', '<' ) ) {
			$result['state'] = 'no_official_fix';
			return $result;
		}

		$fixed = self::FIXED_VERSIONS;

		if ( isset( $fixed[ $branch ] ) ) {
			$result['minimum'] = $fixed[ $branch ];

			if ( version_compare( $core, $result['minimum'], '<' ) ) {
				$result['state'] = 'below_minimum';
			} elseif ( $is_pre && $core === $result['minimum'] ) {
				// A release candidate of the fixed release is not the fixed release.
				$result['state'] = 'prerelease';
			} else {
				$result['state'] = 'patched';
			}

			return $result;
		}

		// A branch newer than the ones in the advisory includes their fixes.
		$result['state'] = $is_pre ? 'prerelease' : 'newer_branch';

		return $result;
	}

	/**
	 * Look for a .user.ini that sets session.upload_progress.enabled.
	 *
	 * PHP says that .user.ini does not take effect in time for this mitigation,
	 * while ini_get() would still report the value as if it did. Only the WordPress
	 * root and wp-admin are read, so open_basedir cannot get in the way.
	 *
	 * @return array File names relative to the WordPress root.
	 */
	public static function find_user_ini_overrides() {
		$found = array();
		$files = array(
			'.user.ini'          => ABSPATH . '.user.ini',
			'wp-admin/.user.ini' => ABSPATH . 'wp-admin/.user.ini',
		);

		foreach ( $files as $name => $path ) {
			if ( ! is_file( $path ) || ! is_readable( $path ) ) {
				continue;
			}

			$contents = file_get_contents( $path, false, null, 0, 65536 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local read of a small ini file capped at 64 KB, no remote URL.

			if ( is_string( $contents ) && preg_match( '/^[ \t]*session\.upload_progress\.enabled[ \t]*=/mi', $contents ) ) {
				$found[] = $name;
			}
		}

		return $found;
	}

	/**
	 * Whether the site owner declared that the host confirmed the fixes.
	 *
	 * Set the constant AYUDAWP_PHP2SHELL_CHECK_HOST_CONFIRMED to true in
	 * wp-config.php, or return true from the ayudawp_php2shell_check_host_confirmed
	 * filter. It only turns the test green when the version number is inconclusive.
	 *
	 * @return bool
	 */
	private static function is_host_confirmed() {
		$default = defined( 'AYUDAWP_PHP2SHELL_CHECK_HOST_CONFIRMED' ) && AYUDAWP_PHP2SHELL_CHECK_HOST_CONFIRMED;

		return (bool) apply_filters( 'ayudawp_php2shell_check_host_confirmed', $default );
	}

	/**
	 * Build the Site Health result array.
	 *
	 * Never returns "critical": a version number cannot prove a site is
	 * exposed, so the worst outcome is "recommended".
	 *
	 * @param array $facts Result of get_facts().
	 * @return array
	 */
	public static function build_result( $facts ) {
		$state     = $facts['evaluation']['state'];
		$version   = $facts['version'];
		$minimum   = $facts['evaluation']['minimum'];
		$branch    = $facts['evaluation']['branch'];
		$confirmed = $facts['host_confirmed'] && in_array( $state, array( 'below_minimum', 'no_official_fix' ), true );
		$status    = 'recommended';
		$blocks    = array();
		$host_ask  = false;

		if ( $confirmed ) {
			$status   = 'good';
			$label    = __( 'You have marked the PHP2Shell fixes as confirmed by your host', 'php2shell-wordpress-check' );
			$blocks[] = self::p(
				sprintf(
					/* translators: %s: running PHP version */
					__( 'PHP reports version %s, which is lower than the first fixed releases, but you told this plugin that your host confirmed the fixes. This plugin cannot verify that.', 'php2shell-wordpress-check' ),
					self::code( $version )
				)
			);
		} elseif ( 'patched' === $state ) {
			$status   = 'good';
			$label    = __( 'Your PHP version includes the PHP2Shell fixes', 'php2shell-wordpress-check' );
			$blocks[] = self::p(
				sprintf(
					/* translators: 1: running PHP version, 2: first fixed release of the branch, 3: PHP branch */
					__( 'PHP reports version %1$s, which is equal to or newer than %2$s, the first release of the %3$s branch with the fixes for CVE-2026-109618 and CVE-2026-109619. This is the version of the process that is serving this page.', 'php2shell-wordpress-check' ),
					self::code( $version ),
					self::code( $minimum ),
					self::code( $branch )
				)
			);
			$blocks[] = self::support_note( $branch );
		} elseif ( 'newer_branch' === $state ) {
			$status   = 'good';
			$label    = __( 'Your PHP version includes the PHP2Shell fixes', 'php2shell-wordpress-check' );
			$blocks[] = self::p(
				sprintf(
					/* translators: 1: running PHP version, 2: PHP branch */
					__( 'PHP reports version %1$s. The %2$s branch is newer than the ones listed in the PHP advisory (8.2 to 8.5) and includes their fixes.', 'php2shell-wordpress-check' ),
					self::code( $version ),
					self::code( $branch )
				)
			);
		} elseif ( 'below_minimum' === $state ) {
			$label    = __( 'Your PHP version is lower than the one that fixes PHP2Shell', 'php2shell-wordpress-check' );
			$host_ask = true;
			$blocks[] = self::p(
				sprintf(
					/* translators: 1: running PHP version, 2: first fixed release of the branch, 3: PHP branch */
					__( 'PHP reports version %1$s, which is lower than %2$s, the first release of the %3$s branch with the fixes for CVE-2026-109618 and CVE-2026-109619.', 'php2shell-wordpress-check' ),
					self::code( $version ),
					self::code( $minimum ),
					self::code( $branch )
				)
			);
			$blocks[] = self::p(
				__( 'That does not prove your site is exposed. Distributions such as Debian or Ubuntu ship the fix without changing the version number PHP reports, and this plugin cannot tell the difference from inside WordPress. Ask your host.', 'php2shell-wordpress-check' )
			);
			$blocks[] = self::support_note( $branch );
		} elseif ( 'no_official_fix' === $state ) {
			$label    = __( 'Your PHP branch has no official PHP2Shell fix', 'php2shell-wordpress-check' );
			$host_ask = true;
			$blocks[] = self::p(
				sprintf(
					/* translators: %s: running PHP version */
					__( 'PHP reports version %s. The PHP project has not released official versions with the fixes for PHP 8.1 and older (it only published minimal source patches), so your protection depends on your host applying a backported fix.', 'php2shell-wordpress-check' ),
					self::code( $version )
				)
			);
			$blocks[] = self::p(
				__( 'Ask your host whether they have applied it, or move your site to a supported PHP version.', 'php2shell-wordpress-check' )
			);
		} elseif ( 'prerelease' === $state ) {
			$label    = __( 'You are running a pre-release PHP build', 'php2shell-wordpress-check' );
			$blocks[] = self::p(
				sprintf(
					/* translators: %s: running PHP version */
					__( 'PHP reports version %s, a pre-release build. Pre-release builds are not meant for production sites.', 'php2shell-wordpress-check' ),
					self::code( $version )
				)
			);
		} else {
			$label    = __( 'PHP2Shell: the PHP version could not be read', 'php2shell-wordpress-check' );
			$blocks[] = self::p(
				sprintf(
					/* translators: %s: version string reported by PHP */
					__( 'PHP reported the version %s, which this plugin cannot interpret.', 'php2shell-wordpress-check' ),
					self::code( $version )
				)
			);
		}

		foreach ( self::build_notes( $facts ) as $note ) {
			$blocks[] = $note;
		}

		if ( $host_ask ) {
			$blocks[] = self::host_message_block( $facts );
		}

		return array(
			'label'       => $label,
			'status'      => $status,
			'badge'       => array(
				'label' => __( 'Security', 'php2shell-wordpress-check' ),
				'color' => 'blue',
			),
			'description' => wp_kses_post( implode( '', $blocks ) ),
			'actions'     => wp_kses_post( self::advisory_link() ),
			'test'        => 'ayudawp_php2shell',
		);
	}

	/**
	 * Build the fields of the Info tab section.
	 *
	 * @param array $facts Result of get_facts().
	 * @return array
	 */
	public static function build_debug_fields( $facts ) {
		$evaluation = $facts['evaluation'];

		if ( null === $facts['upload_progress'] ) {
			$progress = __( 'Not available (session extension not loaded)', 'php2shell-wordpress-check' );
		} else {
			$progress = $facts['upload_progress'] ? __( 'On', 'php2shell-wordpress-check' ) : __( 'Off', 'php2shell-wordpress-check' );
		}

		return array(
			'php_version'     => array(
				'label' => __( 'PHP version (running)', 'php2shell-wordpress-check' ),
				'value' => $facts['version'],
			),
			'fixed_version'   => array(
				'label' => __( 'First fixed release of this branch', 'php2shell-wordpress-check' ),
				'value' => '' !== $evaluation['minimum'] ? $evaluation['minimum'] : __( 'None', 'php2shell-wordpress-check' ),
			),
			'result'          => array(
				'label' => __( 'Result', 'php2shell-wordpress-check' ),
				'value' => self::state_label( $evaluation['state'] ),
			),
			'sapi'            => array(
				'label' => __( 'PHP SAPI', 'php2shell-wordpress-check' ),
				'value' => $facts['sapi'],
			),
			'upload_progress' => array(
				'label' => 'session.upload_progress.enabled',
				'value' => $progress,
			),
			'user_ini'        => array(
				'label' => __( '.user.ini that sets it', 'php2shell-wordpress-check' ),
				'value' => empty( $facts['user_ini'] ) ? __( 'None found', 'php2shell-wordpress-check' ) : implode( ', ', $facts['user_ini'] ),
			),
			'host_confirmed'  => array(
				'label' => __( 'Marked as confirmed by your host', 'php2shell-wordpress-check' ),
				'value' => $facts['host_confirmed'] ? __( 'Yes', 'php2shell-wordpress-check' ) : __( 'No', 'php2shell-wordpress-check' ),
			),
		);
	}

	/**
	 * Short human label for a state.
	 *
	 * @param string $state State returned by evaluate_version().
	 * @return string
	 */
	private static function state_label( $state ) {
		switch ( $state ) {
			case 'patched':
				return __( 'Includes the fixes', 'php2shell-wordpress-check' );
			case 'newer_branch':
				return __( 'Newer branch than those in the advisory', 'php2shell-wordpress-check' );
			case 'below_minimum':
				return __( 'Lower than the fixed release (could be a backported fix)', 'php2shell-wordpress-check' );
			case 'no_official_fix':
				return __( 'No official fix for this branch', 'php2shell-wordpress-check' );
			case 'prerelease':
				return __( 'Pre-release build', 'php2shell-wordpress-check' );
			default:
				return __( 'Unknown', 'php2shell-wordpress-check' );
		}
	}

	/**
	 * Extra notes about the SAPI and about session.upload_progress.enabled.
	 *
	 * @param array $facts Result of get_facts().
	 * @return array HTML paragraphs.
	 */
	private static function build_notes( $facts ) {
		$notes = array();

		if ( in_array( $facts['sapi'], array( 'apache2handler', 'apache2filter', 'apache' ), true ) ) {
			$notes[] = self::p(
				__( 'This site runs PHP as an Apache module (mod_php). PHP considers it the most exposed setup, because the attack can succeed before any application code runs.', 'php2shell-wordpress-check' )
			);
		}

		if ( ! empty( $facts['user_ini'] ) ) {
			$names = array();
			foreach ( $facts['user_ini'] as $name ) {
				$names[] = self::code( $name );
			}

			$notes[] = self::p(
				sprintf(
					/* translators: %s: list of file names */
					__( 'The file %s sets session.upload_progress.enabled. PHP warns that .user.ini does not take effect in time for this mitigation, so do not count it as applied: set it in php.ini or in the PHP-FPM pool.', 'php2shell-wordpress-check' ),
					implode( ', ', $names )
				)
			);
		}

		if ( true === $facts['upload_progress'] ) {
			$notes[] = self::p(
				__( 'The setting session.upload_progress.enabled is on, which is the PHP default. Turning it off in php.ini or in the PHP-FPM pool is an extra mitigation recommended by PHP, and the only one it lists for CVE-2026-115560, a third flaw that has no fixed release yet. It does not replace updating PHP, and on shared hosting only your host can apply it.', 'php2shell-wordpress-check' )
			);
		}

		return $notes;
	}

	/**
	 * Note about the end of support of PHP 8.2.
	 *
	 * @param string $branch PHP branch.
	 * @return string HTML paragraph, empty for other branches.
	 */
	private static function support_note( $branch ) {
		if ( '8.2' !== $branch ) {
			return '';
		}

		if ( time() >= self::PHP_82_SUPPORT_END ) {
			return self::p( __( 'Branch 8.2 stopped receiving security fixes on 31 December 2026.', 'php2shell-wordpress-check' ) );
		}

		return self::p( __( 'Branch 8.2 stops receiving security fixes on 31 December 2026.', 'php2shell-wordpress-check' ) );
	}

	/**
	 * Message the site owner can send to the host, with the real version filled in.
	 *
	 * @param array $facts Result of get_facts().
	 * @return string HTML.
	 */
	private static function host_message_block( $facts ) {
		$message = sprintf(
			/* translators: 1: running PHP version, 2: PHP SAPI */
			__( 'Hello, have you applied the PHP patches for CVE-2026-109618 and CVE-2026-109619 (PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 or the equivalent backported fix) on the servers where my site runs? My site currently reports PHP %1$s running as %2$s. Can you confirm which package version is installed and that the PHP processes were restarted after the update?', 'php2shell-wordpress-check' ),
			$facts['version'],
			$facts['sapi']
		);

		return self::p( __( 'A message you can send to your host:', 'php2shell-wordpress-check' ) )
			. '<blockquote>' . self::p( esc_html( $message ) ) . '</blockquote>';
	}

	/**
	 * Link to the PHP security advisory, in the markup Site Health uses for actions.
	 *
	 * @return string HTML.
	 */
	private static function advisory_link() {
		return sprintf(
			'<p><a href="%1$s" target="_blank" rel="noopener noreferrer">%2$s<span class="screen-reader-text"> %3$s</span><span aria-hidden="true" class="dashicons dashicons-external"></span></a></p>',
			esc_url( 'https://www.php.net/archive/2026.php' ),
			esc_html__( 'Read the PHP security advisory', 'php2shell-wordpress-check' ),
			esc_html__( '(opens in a new tab)', 'php2shell-wordpress-check' )
		);
	}

	/**
	 * Wrap trusted, already escaped HTML in a paragraph.
	 *
	 * @param string $html Escaped HTML.
	 * @return string
	 */
	private static function p( $html ) {
		return '' === $html ? '' : '<p>' . $html . '</p>';
	}

	/**
	 * Escape a value and wrap it in <code>.
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	private static function code( $value ) {
		return '<code>' . esc_html( $value ) . '</code>';
	}
}
