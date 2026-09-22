module Oidc
  # Issues the OpenID Connect ID token (OIDC Core §2, §3.1.3.6): a signed JWT
  # that tells the relying party who authenticated and when. Unlike the access
  # token it is addressed to the client (aud = client_id) and is meant to be
  # read by it. Claims for the profile/email scopes are deliberately absent:
  # in the code flow those are served from /userinfo (Core §5.4).
  module IdToken
    module_function

    def issue(user:, client:, access_token:, nonce: nil, auth_time: nil, now: Time.current)
      config = Rails.configuration.x.oidc

      payload = {
        iss: config.issuer,
        sub: user.id,
        aud: client.client_id,
        iat: now.to_i,
        exp: (now + config.id_token_ttl).to_i,
        auth_time: auth_time&.to_i,
        nonce: nonce,
        at_hash: at_hash(access_token)
      }.compact

      JWT.encode(payload, SigningKey.private_key, SigningKey::ALGORITHM, { kid: SigningKey.kid })
    end

    # Binds the ID token to the access token issued with it: the base64url of
    # the left half of the access token's hash. The hash function is the one
    # named by the token's alg, so SHA-256 for RS256 (Core §3.1.3.6).
    def at_hash(access_token)
      JWT::Base64.url_encode(Digest::SHA256.digest(access_token)[0, 16])
    end
  end
end
