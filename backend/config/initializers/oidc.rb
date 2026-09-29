# Settings for the hand-rolled OIDC provider. See app/services/oidc/.
Rails.application.config.x.oidc.tap do |oidc|
  # Value of the `iss` claim. Must match the URL relying parties use to reach this server.
  oidc.issuer = ENV.fetch("OIDC_ISSUER", "http://localhost:3000")

  # The React app. It hosts the login page and is the only origin allowed to call
  # /login and /logout from a browser (see cors.rb).
  oidc.frontend_origin = ENV.fetch("FRONTEND_ORIGIN", "http://localhost:5173")

  # Where /authorize sends users who aren't logged in yet.
  oidc.login_url = ENV.fetch("OIDC_LOGIN_URL", "#{oidc.frontend_origin}/login")

  # Where /authorize sends a logged-in user who hasn't yet approved these scopes for this client.
  oidc.consent_url = ENV.fetch("OIDC_CONSENT_URL", "#{oidc.frontend_origin}/consent")

  oidc.access_token_ttl = 1.hour
  oidc.id_token_ttl = 10.minutes

  # Refresh tokens are only issued when offline_access is requested, and they
  # rotate on every use (see RefreshToken and TokensController).
  oidc.refresh_token_ttl = 30.days

  # Authorization codes are single-use and meant to be redeemed immediately
  # (RFC 6749 recommends a maximum of 10 minutes).
  oidc.authorization_code_ttl = 60.seconds

  oidc.supported_scopes = %w[ openid profile email offline_access ].freeze
end
