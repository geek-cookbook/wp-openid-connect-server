<?php

use OAuth2\Encryption\Jwt;
use OAuth2\Storage\JwtAccessToken;
use OpenIDConnectServer\Encryption\StrictJwt;
use OpenIDConnectServer\Storage\PublicKeyStorage;
use PHPUnit\Framework\TestCase;

class StrictJwtTest extends TestCase {
	private static string $public_key;
	private static string $private_key;
	private JwtAccessToken $storage;

	public static function setUpBeforeClass(): void {
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A sandbox can lack a writable OpenSSL random-state file.
		$key = @openssl_pkey_new( array( 'private_key_bits' => 2048 ) );
		if ( false === $key ) {
			throw new RuntimeException( 'Could not generate an RSA test key.' );
		}

		openssl_pkey_export( $key, $private_key );
		self::$private_key = $private_key;
		self::$public_key  = openssl_pkey_get_details( $key )['key'];
	}

	protected function setUp(): void {
		$this->storage = new JwtAccessToken(
			new PublicKeyStorage( self::$public_key, self::$private_key ),
			null,
			new StrictJwt()
		);
	}

	public function test_valid_rs256_token_is_accepted(): void {
		$token = ( new Jwt() )->encode( $this->payload(), self::$private_key, 'RS256' );
		$this->assertNotFalse( $this->storage->getAccessToken( $token ) );
	}

	/**
	 * @dataProvider invalid_algorithms
	 */
	public function test_public_key_hmac_forgery_is_rejected( $algorithm ): void {
		$jwt    = new Jwt();
		$header = array(
			'typ' => 'JWT',
			'alg' => $algorithm,
		);
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- This test runs without WordPress.
		$input = $jwt->urlSafeB64Encode( json_encode( $header ) ) . '.' . $jwt->urlSafeB64Encode( json_encode( $this->payload() ) );
		$token = $input . '.' . $jwt->urlSafeB64Encode( hash_hmac( 'sha256', $input, self::$public_key, true ) );

		$this->assertFalse( $this->storage->getAccessToken( $token ) );
	}

	public function invalid_algorithms(): array {
		return array(
			'boolean true' => array( true ),
			'HS256 string' => array( 'HS256' ),
		);
	}

	private function payload(): array {
		return array(
			'aud'   => 'test-client',
			'sub'   => 'test-user',
			'exp'   => time() + 3600,
			'scope' => 'openid profile',
		);
	}
}
