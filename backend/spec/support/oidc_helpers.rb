module OidcHelpers
  PASSWORD = "correct horse battery".freeze

  # Test vector from RFC 7636 Appendix B.
  PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".freeze
  PKCE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".freeze

  def create_user(email: "ada@example.com", password: PASSWORD)
    User.create!(email: email, password: password)
  end

  def create_client(name: "Example App", redirect_uri: "https://app.example.com/callback")
    OauthClient.create!(name: name, redirect_uri: redirect_uri)
  end

  def log_in(user, password: PASSWORD)
    post "/login", params: { email: user.email, password: password }
    expect(response).to have_http_status(:ok)
  end

  # A valid /authorize request for the client. Handy for checking whether a session exists:
  # logged in redirects to the client's callback, logged out redirects to the login page.
  def authorize_params(client)
    { response_type: "code", client_id: client.client_id, redirect_uri: client.redirect_uri,
      code_challenge: PKCE_CHALLENGE, code_challenge_method: "S256" }
  end

  def redirect_params
    Rack::Utils.parse_query(URI.parse(response.location).query)
  end

  def basic_auth_header(client_id, client_secret)
    { "Authorization" => ActionController::HttpAuthentication::Basic.encode_credentials(client_id, client_secret) }
  end
end

RSpec.configure do |config|
  config.include OidcHelpers, type: :request
  config.include ActiveSupport::Testing::TimeHelpers
end
