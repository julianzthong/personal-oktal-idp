# Settings for the hand-rolled OIDC provider. See app/services/oidc/.
Rails.application.config.x.oidc.tap do |oidc|
  # Value of the `iss` claim. Must match the URL relying parties use to reach this server.
  oidc.issuer = ENV.fetch("OIDC_ISSUER", "http://localhost:3000")

  oidc.access_token_ttl = 1.hour

  # Authorization codes are single-use and meant to be redeemed immediately
  # (RFC 6749 recommends a maximum of 10 minutes).
  oidc.authorization_code_ttl = 60.seconds

  oidc.supported_scopes = %w[ openid profile email ].freeze
end
