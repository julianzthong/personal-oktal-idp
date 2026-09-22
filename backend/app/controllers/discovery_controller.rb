# OpenID Provider metadata (OIDC Discovery 1.0 §3). A relying party given only
# the issuer URL can fetch this and configure itself.
class DiscoveryController < ApplicationController
  def show
    config = Rails.configuration.x.oidc
    issuer = config.issuer.chomp("/")

    expires_in 1.hour, public: true
    render json: {
      issuer: config.issuer,
      authorization_endpoint: "#{issuer}/authorize",
      token_endpoint: "#{issuer}/token",
      userinfo_endpoint: "#{issuer}/userinfo",
      jwks_uri: "#{issuer}/.well-known/jwks.json",
      response_types_supported: [ "code" ],
      grant_types_supported: [ "authorization_code" ],
      subject_types_supported: [ "public" ],
      code_challenge_methods_supported: [ Oidc::Pkce::METHOD ],
      id_token_signing_alg_values_supported: [ Oidc::SigningKey::ALGORITHM ],
      token_endpoint_auth_methods_supported: [ "client_secret_basic", "client_secret_post" ],
      scopes_supported: config.supported_scopes,
      claims_supported: %w[ iss sub aud exp iat auth_time nonce at_hash name email email_verified ]
    }
  end
end
