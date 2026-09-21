module Oidc
  # Issues signed JWT access tokens following the RFC 9068 profile:
  # https://www.rfc-editor.org/rfc/rfc9068
  module AccessToken
    module_function

    def issue(user:, client:, scopes:, now: Time.current)
      config = Rails.configuration.x.oidc

      payload = {
        iss: config.issuer,
        sub: user.id,
        aud: client.client_id,
        client_id: client.client_id,
        scope: scopes.join(" "),
        iat: now.to_i,
        exp: (now + config.access_token_ttl).to_i,
        jti: SecureRandom.uuid
      }

      JWT.encode(payload, SigningKey.private_key, SigningKey::ALGORITHM, { kid: SigningKey.kid, typ: "at+jwt" })
    end
  end
end
