<?php

namespace OpenIDConnectServer\Encryption;

use OAuth2\Encryption\Jwt;

/**
 * Reject algorithm values that the upstream JWT decoder compares loosely.
 */
class StrictJwt extends Jwt {
	public function decode( $jwt, $key = null, $allowed_algorithms = true ) {
		if ( $allowed_algorithms ) {
			$parts = explode( '.', $jwt );
			if ( 3 !== count( $parts ) ) {
				return false;
			}

			$header = json_decode( $this->urlSafeB64Decode( $parts[0] ), true );
			if ( ! is_array( $header ) || ! isset( $header['alg'] ) || ! is_string( $header['alg'] ) ) {
				return false;
			}

			if ( is_array( $allowed_algorithms ) && ! in_array( $header['alg'], $allowed_algorithms, true ) ) {
				return false;
			}
		}

		return parent::decode( $jwt, $key, $allowed_algorithms );
	}
}
