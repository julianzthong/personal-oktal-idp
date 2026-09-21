module OidcHelpers
  PASSWORD = "correct horse battery".freeze

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
