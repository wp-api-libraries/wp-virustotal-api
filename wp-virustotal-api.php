<?php
/**
 * WP VirusTotal API (https://virustotal.com/en/documentation/public-api/)
 *
 * @package WP-VirusTotal-API
 */

/* Exit if accessed directly. */
if ( ! defined( 'ABSPATH' ) ) { exit; }

/* Check if class exists. */
if ( ! class_exists( 'KrakenAPI' ) ) {

	/**
	 * VirusTotalAPI class.
	 */
	class VirusTotalAPI {

		/**
		 * API Key.
		 *
		 * @var string
		 */
		static private $api_key;

		/**
		 * URL to the API.
		 *
		 * @var string
		 */
		private $base_uri = 'https://www.virustotal.com/vtapi/v2/';


		 /**
		 * __construct function.
		 *
		 * @access public
		 * @param mixed $api_key API Key.
		 * @param mixed $api_secret API Secret.
		 * @return void
		 */
		public function __construct( $api_key ) {

			static::$api_key = $api_key;

		}

		/**
		 * Fetch the request from the API.
		 *
		 * @access private
		 * @param mixed $request Request URL.
		 * @return $body Body.
		 */
		private function fetch( $request ) {

			$response = wp_remote_get( $request );
			$code = wp_remote_retrieve_response_code( $response );

			if ( 200 !== $code ) {
				return new WP_Error( 'response-error', sprintf( __( 'Server response code: %d', 'text-domain' ), $code ) );
			}

			$body = wp_remote_retrieve_body( $response );

			return json_decode( $body );

		}

		/**
		 * Scan a File.
		 *
		 * @access public
		 * @param mixed $file File.
		 * @return void
		 */
		public function scan_file( $file ) {

			$request = $this->base_uri . 'file/scan';

			return $this->fetch( $request );

		}

		/**
		 * Rescan a File.
		 *
		 * @access public
		 * @param mixed $resource Resource is a md5/sha1/sha256 hash of file or url.
		 * @return void
		 */
		public function rescan_file( $resource ) {

			$request = $this->base_uri . 'file/rescan';

			return $this->fetch( $request );

		}

		/**
		 * Get File Report.
		 *
		 * @access public
		 * @param mixed $resource Resource is a md5/sha1/sha256 hash of file or url.
		 * @return void
		 */
		public function get_file_report( $resource ) {

			$request = $this->base_uri . 'file/report';

			return $this->fetch( $request );

		}

		/**
		 * Scan a Url.
		 *
		 * @access public
		 * @param mixed $url Url.
		 * @return void
		 */
		public function scan_url( $url ) {

			$request = $this->base_uri . 'url/scan';

			return $this->fetch( $request );
		}

		/**
		 * Get URL Report.
		 *
		 * @access public
		 * @param mixed $resource Resource is a md5/sha1/sha256 hash of file or url.
		 * @param string $scan (default: '') Optional parameter that when set to "1" will automatically submit the URL for analysis.
		 * @return void
		 */
		public function get_url_report( $resource, $scan = '' ) {

			$request = $this->base_uri . 'url/report';

			return $this->fetch( $request );
		}

		/**
		 * Get IP Address Report.
		 *
		 * @access public
		 * @param mixed $ip IP Address.
		 * @return void
		 */
		public function get_ipaddress_report( $ip ) {

			$request = $this->base_uri . 'ip-address/report';

			return $this->fetch( $request );
		}

		/**
		 * Get Domain Report.
		 *
		 * @access public
		 * @param mixed $domain Domain.
		 * @return void
		 */
		public function get_domain_report( $domain ) {

			$request = $this->base_uri . 'domain/report';

			return $this->fetch( $request );
		}

		/**
		 * Add Comment to Resource.
		 *
		 * @access public
		 * @param mixed $resource Resource is a md5/sha1/sha256 hash of file or url.
		 * @param mixed $comment
		 * @return void
		 */
		public function add_comment( $resource, $comment ) {

			$request = $this->base_uri . 'comments/put';

			return $this->fetch( $request );
		}


	}
}
