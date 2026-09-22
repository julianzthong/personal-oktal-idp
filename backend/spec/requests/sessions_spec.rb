require "rails_helper"

RSpec.describe "DELETE /logout", type: :request do
  it "ends the session, so /authorize asks for a login again" do
    user = create_user
    client = create_client
    authorize_params = {
      response_type: "code", client_id: client.client_id, redirect_uri: client.redirect_uri,
      code_challenge: OidcHelpers::PKCE_CHALLENGE, code_challenge_method: "S256"
    }
    log_in(user)
    get "/authorize", params: authorize_params
    expect(response.location).to start_with(client.redirect_uri)

    delete "/logout"
    expect(response).to have_http_status(:no_content)

    get "/authorize", params: authorize_params
    expect(response.location).to start_with(Rails.configuration.x.oidc.login_url)
  end
end

RSpec.describe "POST /login", type: :request do
  let!(:user) { create_user }

  it "authenticates the user and starts a session" do
    post "/login", params: { email: "ada@example.com", password: OidcHelpers::PASSWORD }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to eq("id" => user.id, "email" => "ada@example.com")
    expect(response.headers["Set-Cookie"]).to include("_oktal_idp_session=")
  end

  it "accepts a JSON request body" do
    post "/login", params: { email: "ada@example.com", password: OidcHelpers::PASSWORD }.to_json,
      headers: { "Content-Type" => "application/json" }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to include("email" => "ada@example.com")
  end

  it "ignores email case and surrounding whitespace" do
    post "/login", params: { email: "  ADA@example.com ", password: OidcHelpers::PASSWORD }

    expect(response).to have_http_status(:ok)
  end

  it "rejects a wrong password" do
    post "/login", params: { email: "ada@example.com", password: "wrong" }

    expect(response).to have_http_status(:unauthorized)
    expect(response.parsed_body).to eq("error" => "invalid_credentials")
  end

  it "rejects an unknown email" do
    post "/login", params: { email: "nobody@example.com", password: OidcHelpers::PASSWORD }

    expect(response).to have_http_status(:unauthorized)
  end
end
