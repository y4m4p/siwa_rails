module Apple
  class SignInWithAppleService
    APPLE_TOKEN_URI = "https://appleid.apple.com/auth/token".freeze
    APPLE_PUBLIC_KEY_URI = "https://appleid.apple.com/auth/keys".freeze
    APPLE_AUDIENCE_URI = "https://appleid.apple.com".freeze

    TOKEN_REQUEST_GRANT_TYPE = "authorization_code".freeze

    CLIENT_SECRET_ENCRYPTION_ALGORITHM = "ES256".freeze
    ID_TOKEN_DECRYPTION_ALGORITHM = "RS256".freeze

    STANDARD_JWT_KEYS = %w(iss aud exp iat sub nonce c_hash at_hash auth_time).freeze

    MAX_ATTEMPT_COUNTS = 3

    def initialize(authorization_code, id_token, client_id)
      if authorization_code.blank? || id_token.blank?
        raise ArgumentError, "Authorization code and id token must be present."
      end

      if client_id.blank?
        raise ArgumentError, "client_id must be specified."
      end

      @authorization_code = authorization_code
      @claimed_id_token = id_token
      @client_id = client_id
      @legitimate_id_token = ""
    end

    def verify_credentials!
      verify_authorization_code_hash!

      tokens = request_tokens!(@authorization_code)
      @legitimate_id_token = tokens[:id_token]

      jwks = request_apple_public_keys!

      verify_claim!(jwks)
    end

    private
      def decode_without_verification(id_token)
        JWT.decode(id_token, nil, nil).first.with_indifferent_access
      rescue JWT::DecodeError => e
        raise SignInWithAppleErrors::ValidationError, "Could not decode id_token. #{e.full_message}"
      end

      # Validates the authorization_code values regarding to the OpenID Connect Core documents
      # Ref: https://openid.net/specs/openid-connect-core-1_0.html#CodeValidation
      def verify_authorization_code_hash!
        sha_256 = OpenSSL::Digest::SHA256.new
        digest = sha_256.digest(@authorization_code)
        left_half_digest = digest[0...(digest.size / 2)]
        encoded_digest = Base64.urlsafe_encode64(left_half_digest, padding: false)

        code_hash = decode_without_verification(@claimed_id_token)[:c_hash]

        unless code_hash == encoded_digest
          raise SignInWithAppleErrors::AuthorizationCodeMismatch, "Authorization Code is invalid. Authorization_code value: #{@authorization_code}, c_hash value: #{code_hash}"
        end
      end

      # Validates the ID Token Claim values regarding to the OpenID Connect Core documents.
      # Ref: https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2
      def verify_claim!(jwks)
        legitimate_payload, _legitimate_header = decode_without_verification(@legitimate_id_token)

        options = {
          algorithm: ID_TOKEN_DECRYPTION_ALGORITHM,
          jwks: jwks,
          iss: legitimate_payload[:iss],
          verify_iss: true,
          aud: legitimate_payload[:aud],
          verify_aud: true,
          sub: legitimate_payload[:sub],
          verify_sub: true,
        }

        # The next method provides validation for *iss*, *aud*, *exp*, *sub* and *jwt_signature*.
        claimed_payload, _claimed_header = JWT.decode(@claimed_id_token, nil, true, options).first.with_indifferent_access

        # We assume that non standard jwt keys would be an End-User specific key.
        # Ref: https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2
        # > If either ID Token contains Claims about the End-User,
        # > any that are present in both SHOULD have the same values in both.
        claimed_payload.each do |k, v|
          if STANDARD_JWT_KEYS.exclude?(k) && legitimate_payload.key?(k)
            unless v == legitimate_payload[k]
              raise SignInWithAppleErrors::EndUserClaimMismatch, "End-User claim mismatch detected. Mismatched key: #{k}, Claimed value: #{v}, Apple's value: #{legitimate_payload[k]}."
            end
          end
        end

        # Check for replay attacks
        unless claimed_payload[:nonce] == legitimate_payload[:nonce]
          raise SignInWithAppleErrors::NonceMismatch, "Nonce mismatch detected. Claimed nonce: #{claimed_payload[:nonce]}, Apple's nonce: #{legitimate_payload[:nonce]}."
        end

        claimed_payload
      rescue JWT::InvalidIssuerError
        raise SignInWithAppleErrors::InvalidIssuer, "Issuer mismatch detected. Claimed iss: #{decode_without_verification(@claimed_id_token)[:iss]}, Apple's iss: #{decode_without_verification(@legitimate_id_token)[:iss]}."
      rescue JWT::InvalidAudError
        raise SignInWithAppleErrors::AudienceMismatch, "Audience mismatch detected. Claimed aud: #{decode_without_verification(@claimed_id_token)[:aud]}, Apple's aud: #{decode_without_verification(@legitimate_id_token)[:aud]}."
      rescue JWT::InvalidSubError
        raise SignInWithAppleErrors::SubjectMismatch, "Subject mismatch detected. Claimed sub: #{decode_without_verification(@claimed_id_token)[:sub]}, Apple's sub: #{decode_without_verification(@legitimate_id_token)[:sub]}."
      rescue JWT::ExpiredSignature
        raise SignInWithAppleErrors::ExpiredToken, "The claimed id token has been expired."
      rescue JWT::VerificationError
        raise SignInWithAppleErrors::InvalidSignature, "JWT Signature is incorrect."
      end

      def request_apple_public_keys!
        attempt = 0

        get_params = {
          client_id: ENV["APPLE_SERVICE_ID"],
        }

        uri = URI(APPLE_PUBLIC_KEY_URI)
        uri.query = URI.encode_www_form(get_params)
        req = Net::HTTP::Get.new(uri.request_uri)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true

        begin
          res = http.request(req)

          if res.is_a?(Net::HTTPSuccess)
            apple_public_key = JSON.parse(res.body)
            apple_public_key.with_indifferent_access
          else
            raise "There was an error when connecting with the Public Key Endpoint #{APPLE_PUBLIC_KEY_URI}"
          end
        rescue StandardError => e
          attempt += 1

          if attempt < MAX_ATTEMPT_COUNTS
            retry
          end

          raise ::SignInWithAppleErrors::ConnectionFailed, e.message
        end
      end

      def request_tokens!(authorization_code)
        post_params = {
          grant_type: TOKEN_REQUEST_GRANT_TYPE,
          client_id: @client_id,
          client_secret: client_secret,
          code: authorization_code,
        }

        uri = URI(APPLE_TOKEN_URI)
        req = Net::HTTP::Post.new(uri.request_uri)
        req.set_form_data(post_params)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true

        begin
          res = http.request(req)

          # We will not retry a token request twice, because authorization code might already be expired.
          if res.is_a?(Net::HTTPSuccess)
            token_response = JSON.parse(res.body)
            token_response.with_indifferent_access
          else
            raise "There was an error when connecting with the Token Endpoint (#{APPLE_TOKEN_URI})"
          end
        rescue StandardError => e
          raise ::SignInWithAppleErrors::ConnectionFailed, e.message
        end
      end

      def client_secret
        payload = {
          iss: ENV["APPLE_TEAM_ID"],
          aud: APPLE_AUDIENCE_URI,
          sub: @client_id,
          iat: Time.now.to_i,
          exp: Time.now.to_i + 300,
        }

        private_key = SignInWithAppleConst::PRIVATE_KEY
        headers = { kid: ENV["APPLE_KEY_ID"] }

        JWT.encode(payload, private_key, CLIENT_SECRET_ENCRYPTION_ALGORITHM, headers)
      end

  end
end
