# Be sure to restart your server when you modify this file.

# Cross-Origin Resource Sharing. The browser only lets a page read a response
# from another origin if that origin says so. The block below runs when the
# middleware stack is built, which is after all initializers, so it can read
# Rails.configuration.x.oidc (set in oidc.rb).
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  # The login and signup pages run on the frontend origin and call these with the session
  # cookie. Credentialed CORS requires one exact origin; "*" is not allowed.
  allow do
    origins Rails.configuration.x.oidc.frontend_origin

    # Retry-After is exposed so the UI can say how long a throttled user must wait.
    resource "/signup", headers: :any, methods: [ :post, :options ], credentials: true, expose: [ "Retry-After" ]
    resource "/login", headers: :any, methods: [ :post, :options ], credentials: true, expose: [ "Retry-After" ]
    resource "/logout", headers: :any, methods: [ :delete, :options ], credentials: true
  end

  # Public metadata that browser-based relying parties need to read. No
  # credentials are involved, so any origin is fine.
  allow do
    origins "*"

    resource "/.well-known/*", headers: :any, methods: [ :get, :options ], credentials: false
  end
end
