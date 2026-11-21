<?php
/**
 * Sends the block / throttle page and terminates the request.
 *
 * @package WordGate
 */

namespace WordGate\Waf;

final class Response {

	public static function send( array $decision, Request $request, array $config ) {
		$status = (int) $decision['status'];
		$ref    = substr( hash( 'sha256', $request->ip() . microtime( true ) ), 0, 12 );

		if ( ! headers_sent() ) {
			http_response_code( $status );
			header( 'Content-Type: text/html; charset=UTF-8' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
			header( 'X-Robots-Tag: noindex' );
			header( 'X-WordGate: ' . ( 429 === $status ? 'throttled' : 'blocked' ) );
			if ( 429 === $status ) {
				header( 'Retry-After: 60' );
			}
		}

		$title = 429 === $status ? 'Too many requests' : 'Access denied';
		$msg   = 429 === $status
			? 'You have made too many requests in a short period. Please wait a minute and try again.'
			: 'Your request was blocked by this site\'s firewall. If you believe this is a mistake, contact the site owner and include the reference below.';

		$reason = ! empty( $config['block_page']['show_reason'] ) && '' !== $decision['reason']
			? '<p><strong>Reason:</strong> ' . htmlspecialchars( $decision['reason'], ENT_QUOTES, 'UTF-8' ) . '</p>'
			: '';

		$ip = htmlspecialchars( $request->ip(), ENT_QUOTES, 'UTF-8' );

		echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">'
			. '<title>' . $title . '</title><style>body{font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f6f7f9;color:#1d2327;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}'
			. 'main{background:#fff;max-width:520px;margin:16px;padding:32px;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.1)}h1{margin-top:0;font-size:1.4em}code{background:#f0f0f1;padding:2px 6px;border-radius:4px}small{color:#646970}</style></head>'
			. '<body><main><h1>' . $title . '</h1><p>' . $msg . '</p>' . $reason
			. '<p><small>Reference: <code>' . $ref . '</code> &middot; Your IP: <code>' . $ip . '</code> &middot; Protected by WordGate</small></p></main></body></html>';
		exit;
	}
}
