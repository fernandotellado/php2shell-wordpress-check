<?php
/**
 * Plugin Name:       PHP2Shell Check
 * Plugin URI:        https://github.com/fernandotellado/php2shell-wordpress-check
 * Description:       Read-only Site Health check: compares your running PHP version with the releases that fix PHP2Shell (CVE-2026-109618 and CVE-2026-109619).
 * Version:           1.0.0
 * Requires at least: 5.2
 * Requires PHP:      5.6
 * Author:            Fernando Tellado
 * Author URI:        https://ayudawp.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       php2shell-wordpress-check
 * Domain Path:       /languages
 * Update URI:        https://github.com/fernandotellado/php2shell-wordpress-check
 *
 * @package php2shell-wordpress-check
 */

// Prevent direct file access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'AYUDAWP_PHP2SHELL_CHECK_VERSION', '1.0.0' );
define( 'AYUDAWP_PHP2SHELL_CHECK_FILE', __FILE__ );
define( 'AYUDAWP_PHP2SHELL_CHECK_DIR', plugin_dir_path( __FILE__ ) );

require_once AYUDAWP_PHP2SHELL_CHECK_DIR . 'includes/class-ayudawp-php2shell-check.php';

Ayudawp_Php2shell_Check::init();
