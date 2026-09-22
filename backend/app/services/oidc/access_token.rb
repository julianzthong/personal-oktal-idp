module Oidc
  # Issues and verifies signed JWT access tokens following the RFC 9068 profile:
  # https://www.rfc-editor.org/rfc/rfc9068
  #
  # The audience is this server (the issuer), because the only API these tokens
  # unlock so far is our own /userinfo. The client that obtained the token is
  # recorded separately in the `client_id` claim. The ID token, by contrast, is
  # addressed to the client.
  module AccessToken
    TYPE = "at+jwt".freeze

    module_function

    def issue(user:, client:, scopes:, now: Time.current)
      config = Rails.configuration.x.oidc

      payload = {
        iss: config.issuer,
        sub: user.id,
        aud: config.issuer,
        client_id: client.client_id,
        scope: scopes.join(" "),
        iat: now.to_i,
        exp: (now + config.access_token_ttl).to_i,
        jti: SecureRandom.uuid
      }

      JWT.encode(payload, SigningKey.private_key, SigningKey::ALGORITHM, { kid: SigningKey.kid, typ: TYPE })
    end

    # Returns the token's claims if it is a valid, unexpired access token that
    # we issued, and nil otherwise.
    #
    # The algorithm is fixed by us and never taken from the token's header, which
    # is what stops the "alg: none" and "sign with the public key as an HMAC
    # secret" forgeries. The typ check keeps other JWTs we sign, like ID tokens,
    # from being accepted here.
    def verify(token)
      config = Rails.configuration.x.oidc

      payload, header = JWT.decode(
        token, SigningKey.public_key, true,
        algorithms: [ SigningKey::ALGORITHM ],
        iss: config.issuer, verify_iss: true,
        aud: config.issuer, verify_aud: true,
        required_claims: %w[ exp iss aud sub ]
      )
      payload if header["typ"] == TYPE
    rescue JWT::DecodeError
      nil
    end
  end
end
