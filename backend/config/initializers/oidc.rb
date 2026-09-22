# Settings for the hand-rolled OIDC provider. See app/services/oidc/.
Rails.application.config.x.oidc.tap do |oidc|
  # Value of the `iss` claim. Must match the URL relying parties use to reach this server.
  oidc.issuer = ENV.fetch("OIDC_ISSUER", "http://localhost:3000")

  # The React app. It hosts the login page and is the only origin allowed to call
  # /login and /logout from a browser (see cors.rb).
  oidc.frontend_origin = ENV.fetch("FRONTEND_ORIGIN", "http://localhost:5173")

  # Where /authorize sends users who aren't logged in yet.
  oidc.login_url = ENV.fetch("OIDC_LOGIN_URL", "#{oidc.frontend_origin}/login")

  oidc.access_token_ttl = 1.hour
  oidc.id_token_ttl = 10.minutes

  # Authorization codes are single-use and meant to be redeemed immediately
  # (RFC 6749 recommends a maximum of 10 minutes).
  oidc.authorization_code_ttl = 60.seconds

  oidc.supported_scopes = %w[ openid profile email ].freeze
end
