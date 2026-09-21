module Oidc
  # The RSA key pair that signs access tokens, plus its public JWK representation.
  #
  # Production must supply the private key as a PEM in OIDC_PRIVATE_KEY. In
  # development and test a key is generated on first use and kept in tmp/ so
  # tokens survive a server restart.
  module SigningKey
    ALGORITHM = "RS256"
    KEY_SIZE = 2048

    class << self
      def private_key
        @private_key ||= load_private_key
      end

      def public_key
        private_key.public_key
      end

      # Key ID (RFC 7638 JWK thumbprint). It goes in each token's header so a
      # verifier can pick the matching key out of the JWKS, which is what will
      # make key rotation possible later.
      def kid
        @kid ||= begin
          canonical = JSON.generate({ e: encode(public_key.e), kty: "RSA", n: encode(public_key.n) })
          JWT::Base64.url_encode(Digest::SHA256.digest(canonical))
        end
      end

      # The public half as a JWK (RFC 7517), ready to serve from the JWKS endpoint.
      def jwk
        { kty: "RSA", use: "sig", alg: ALGORITHM, kid: kid, n: encode(public_key.n), e: encode(public_key.e) }
      end

      private
        # RSA modulus/exponent are big-endian unsigned integers, base64url-encoded without padding.
        def encode(bignum)
          JWT::Base64.url_encode(bignum.to_s(2))
        end

        def load_private_key
          if (pem = ENV["OIDC_PRIVATE_KEY"].presence)
            OpenSSL::PKey::RSA.new(pem.gsub("\\n", "\n"))
          elsif Rails.env.production?
            raise "OIDC_PRIVATE_KEY must be set in production"
          else
            load_or_generate_development_key
          end
        end

        def load_or_generate_development_key
          path = Rails.root.join("tmp/oidc_signing_key.pem")
          return OpenSSL::PKey::RSA.new(path.read) if path.exist?

          OpenSSL::PKey::RSA.generate(KEY_SIZE).tap { |key| path.write(key.to_pem) }
        end
    end
  end
end
