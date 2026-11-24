<?php
/**
 * Suspicious administrator account detection (pure logic + WordPress collectors).
 *
 * Detects:
 *   - New admins added since the previous scan baseline (high if unlogged /
 *     direct DB insert; info if recorded via wp-admin/CLI by an existing admin)
 *   - Users granted administrator / manage_options capability without a role
 *   - Known backdoor / malware admin usernames
 *   - Hidden administrators (present in DB but stripped from get_users() by a
 *     pre_user_query backdoor) and active pre_user_query hooks
 *
 * @package WordGate
 */

namespace WordGate\Scanner;

final class AdminAudit {

	const SNAPSHOT_OPTION = 'wordgate_admin_snapshot';

	/**
	 * Common backdoor usernames created by WordPress malware droppers.
	 */
	const SUSPICIOUS_USERNAMES = array(
		'wp_admin_support',
		'wordpress_support',
		'support_admin',
		'system_admin',
		'sysadmin_wp',
		'security_admin',
		'maintenance_admin',
		'plugin_update',
		'wpupdate',
		'wpcache',
		'wpadm',
		'adm1n',
		'admin_backup',
		'wp_backup',
		'superuser',
		'root',
		'wpengine_support_tmp',
	);

	/**
	 * Pure diff & audit of administrator snapshots. No WordPress dependency.
	 *
	 * @param array<int,array>|null $previous       Snapshot from prior scan, or null on first scan.
	 * @param array<int,array>      $current        Current admins from direct DB scan, keyed by user ID.
	 *                                              Each: id, login, email, registered, roles (string[]), caps (array<string,bool>).
	 * @param array<int,array>      $logged         Recent admin_created log records keyed by user_id: ['actor' => string, 'actor_id' => int].
	 * @param int[]|null            $visibleUserIds Admin IDs returned by get_users(), or null if not checked.
	 * @return array{baseline_created:bool,findings:array[]}
	 */
	public static function audit( $previous, array $current, array $logged = array(), $visibleUserIds = null ) {
		$findings         = array();
		$baseline_created = null === $previous;

		$visibleMap = null !== $visibleUserIds ? array_flip( array_map( 'intval', $visibleUserIds ) ) : null;

		foreach ( $current as $id => $admin ) {
			$id    = (int) $id;
			$login = (string) $admin['login'];
			$roles = isset( $admin['roles'] ) ? (array) $admin['roles'] : array();
			$caps  = isset( $admin['caps'] ) ? (array) $admin['caps'] : array();

			// 1. Admin exists in wp_users/wp_usermeta but is hidden from get_users().
			if ( null !== $visibleMap && ! isset( $visibleMap[ $id ] ) ) {
				$findings[] = array(
					'type'        => 'hidden_admin_user',
					'severity'    => 'critical',
					'title'       => sprintf( 'Hidden administrator account detected: %s', $login ),
					'description' => 'This administrator exists in the database but is hidden from the WordPress Users screen (a classic backdoor using pre_user_query). Inspect your theme, mu-plugins and plugins immediately, and delete this account.',
					'subject'     => 'hidden_admin:' . $id,
					'data'        => array(
						'user_id'    => $id,
						'user_login' => $login,
						'email'      => (string) $admin['email'],
						'registered' => (string) $admin['registered'],
					),
				);
			}

			// 2. Direct admin capability without a standard role (e.g. manage_options => true with no role).
			if ( empty( $roles ) && self::hasAdminCapability( $caps ) ) {
				$findings[] = array(
					'type'        => 'admin_no_role',
					'severity'    => 'high',
					'title'       => sprintf( 'User "%s" has administrator capability without a role', $login ),
					'description' => 'This user has raw administrator privileges in wp_usermeta without an assigned WordPress role, which can hide them from role-filtered admin lists. Verify this account or delete it.',
					'subject'     => 'admin_no_role:' . $id,
					'data'        => array(
						'user_id'    => $id,
						'user_login' => $login,
						'email'      => (string) $admin['email'],
						'caps'       => array_keys( array_filter( $caps ) ),
					),
				);
			}

			// 3. Known malware backdoor username.
			if ( in_array( strtolower( $login ), self::SUSPICIOUS_USERNAMES, true ) ) {
				$findings[] = array(
					'type'        => 'suspicious_admin_name',
					'severity'    => 'high',
					'title'       => sprintf( 'Administrator uses a known backdoor username: %s', $login ),
					'description' => 'This username matches a pattern frequently created by WordPress backdoors. If you did not create it, delete the account and rotate all passwords.',
					'subject'     => 'suspicious_admin_name:' . $id,
					'data'        => array(
						'user_id'    => $id,
						'user_login' => $login,
						'email'      => (string) $admin['email'],
					),
				);
			}

			// 4. Newly added admin since previous scan snapshot.
			if ( ! $baseline_created && ! isset( $previous[ $id ] ) ) {
				$logEntry = isset( $logged[ $id ] ) ? $logged[ $id ] : null;
				if ( $logEntry && ! empty( $logEntry['actor_id'] ) ) {
					$findings[] = array(
						'type'        => 'admin_added',
						'severity'    => 'info',
						'title'       => sprintf( 'New administrator account added: %s', $login ),
						'description' => sprintf( 'Created via WordPress by %s since the previous scan. Click "Trust this user" if expected.', $logEntry['actor'] ),
						'subject'     => 'admin_added:' . $id,
						'data'        => array(
							'user_id'    => $id,
							'user_login' => $login,
							'email'      => (string) $admin['email'],
							'actor'      => $logEntry['actor'],
						),
					);
				} else {
					$findings[] = array(
						'type'        => 'suspicious_admin',
						'severity'    => 'high',
						'title'       => sprintf( 'Unlogged administrator account appeared: %s', $login ),
						'description' => 'This administrator was added since the last scan without being recorded through WordPress (a common sign of direct database injection or a backdoor). Review the account immediately.',
						'subject'     => 'suspicious_admin:' . $id,
						'data'        => array(
							'user_id'    => $id,
							'user_login' => $login,
							'email'      => (string) $admin['email'],
							'registered' => (string) $admin['registered'],
						),
					);
				}
			}
		}

		return array(
			'baseline_created' => $baseline_created,
			'findings'         => $findings,
		);
	}

	/**
	 * Build the next persisted snapshot: on the first scan baseline every current
	 * admin; on later scans keep existing trusted admins that still exist plus any
	 * newly added admin the owner explicitly trusted (ignored).
	 *
	 * @param array<int,array>|null $previous
	 * @param array<int,array>      $current
	 * @param int[]                 $trustedIds User IDs whose new-admin issue was ignored ("Trust this user").
	 * @return array<int,array>
	 */
	public static function nextSnapshot( $previous, array $current, array $trustedIds = array() ) {
		if ( null === $previous ) {
			return $current;
		}
		$trusted = array_flip( array_map( 'intval', $trustedIds ) );
		$next    = array();
		foreach ( $current as $id => $admin ) {
			$id = (int) $id;
			if ( isset( $previous[ $id ] ) || isset( $trusted[ $id ] ) ) {
				$next[ $id ] = $admin;
			}
		}
		return $next;
	}

	/**
	 * Does a raw capabilities map grant administrator-level access?
	 *
	 * @param array<string,mixed> $caps
	 */
	public static function hasAdminCapability( array $caps ) {
		foreach ( array( 'administrator', 'manage_options', 'create_users', 'edit_plugins', 'activate_plugins' ) as $cap ) {
			if ( ! empty( $caps[ $cap ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Collect all administrator-capable users directly from the database (bypassing
	 * pre_user_query filters so hidden backdoor accounts cannot evade detection).
	 *
	 * @return array<int,array>
	 */
	public static function collectFromDatabase() {
		global $wpdb;
		$cap_key = $wpdb->get_blog_prefix() . 'capabilities';
		$roles   = wp_roles()->roles;
		$admin_roles = array( 'administrator' );
		foreach ( $roles as $role_slug => $role_data ) {
			if ( ! empty( $role_data['capabilities']['manage_options'] ) ) {
				$admin_roles[] = $role_slug;
			}
		}
		$admin_roles = array_values( array_unique( $admin_roles ) );
		$all_roles   = array_keys( $roles );

		// phpcs:disable WordPress.DB.PreparedSQL, WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT u.ID, u.user_login, u.user_email, u.user_registered, m.meta_value AS caps
				 FROM {$wpdb->users} u
				 INNER JOIN {$wpdb->usermeta} m ON m.user_id = u.ID AND m.meta_key = %s
				 WHERE m.meta_value LIKE %s OR m.meta_value LIKE %s OR m.meta_value LIKE %s",
				$cap_key,
				'%administrator%',
				'%manage_options%',
				'%activate_plugins%'
			),
			ARRAY_A
		);
		// phpcs:enable

		$admins = array();
		foreach ( (array) $rows as $row ) {
			$caps = maybe_unserialize( $row['caps'] );
			if ( ! is_array( $caps ) ) {
				continue;
			}
			$user_roles = array();
			foreach ( $caps as $k => $granted ) {
				if ( $granted && in_array( $k, $all_roles, true ) ) {
					$user_roles[] = $k;
				}
			}
			$is_admin = (bool) array_intersect( $user_roles, $admin_roles ) || self::hasAdminCapability( $caps );
			if ( ! $is_admin ) {
				continue;
			}
			$id            = (int) $row['ID'];
			$admins[ $id ] = array(
				'id'         => $id,
				'login'      => (string) $row['user_login'],
				'email'      => (string) $row['user_email'],
				'registered' => (string) $row['user_registered'],
				'roles'      => $user_roles,
				'caps'       => array_map( 'boolval', $caps ),
			);
		}
		return $admins;
	}

	/**
	 * Inspect active pre_user_query hooks that may be hiding users from wp-admin.
	 *
	 * @return array[] Each: name, file.
	 */
	public static function inspectPreUserQueryHooks() {
		global $wp_filter;
		if ( empty( $wp_filter['pre_user_query'] ) || empty( $wp_filter['pre_user_query']->callbacks ) ) {
			return array();
		}
		$hooks = array();
		foreach ( $wp_filter['pre_user_query']->callbacks as $priority => $callbacks ) {
			foreach ( $callbacks as $cb ) {
				$fn   = isset( $cb['function'] ) ? $cb['function'] : null;
				$name = 'unknown';
				$file = '';
				try {
					if ( is_string( $fn ) ) {
						$name = $fn;
						if ( function_exists( $fn ) ) {
							$ref  = new \ReflectionFunction( $fn );
							$file = (string) $ref->getFileName();
						}
					} elseif ( is_array( $fn ) && 2 === count( $fn ) ) {
						$cls  = is_object( $fn[0] ) ? get_class( $fn[0] ) : (string) $fn[0];
						$name = $cls . '::' . $fn[1];
						$ref  = new \ReflectionMethod( $fn[0], $fn[1] );
						$file = (string) $ref->getFileName();
					} elseif ( $fn instanceof \Closure ) {
						$name = 'Closure';
						$ref  = new \ReflectionFunction( $fn );
						$file = (string) $ref->getFileName() . ':' . $ref->getStartLine();
					}
				} catch ( \Throwable $e ) {
					// Keep best-effort label.
				}
				$hooks[] = array(
					'priority' => (int) $priority,
					'name'     => $name,
					'file'     => $file,
				);
			}
		}
		return $hooks;
	}

	/**
	 * Load admin_created event records from EventLog since the previous snapshot.
	 *
	 * @return array<int,array{actor:string,actor_id:int}>
	 */
	public static function recentLoggedCreations( $since = 0 ) {
		global $wpdb;
		$table = \WordGate\Log\EventLog::table();
		// phpcs:disable WordPress.DB.PreparedSQL, WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT user_login, details FROM {$table} WHERE type = 'admin_created' AND created >= %d ORDER BY id DESC LIMIT 200",
				max( 0, (int) $since )
			),
			ARRAY_A
		);
		// phpcs:enable
		$out = array();
		foreach ( (array) $rows as $r ) {
			$det = json_decode( (string) $r['details'], true );
			if ( is_array( $det ) && ! empty( $det['user_id'] ) ) {
				$out[ (int) $det['user_id'] ] = array(
					'actor'    => isset( $det['actor'] ) ? (string) $det['actor'] : '',
					'actor_id' => isset( $det['actor_id'] ) ? (int) $det['actor_id'] : 0,
				);
			}
		}
		return $out;
	}
}
