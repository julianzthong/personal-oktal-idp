require "rails_helper"

RSpec.describe "POST /token", type: :request do
  let(:user) { create_user }
  let(:client) { create_client }
  let!(:authorization_code) do
    AuthorizationCode.issue!(user: user, client: client, scopes: %w[openid email], redirect_uri: client.redirect_uri)
  end
  let(:params) do
    { grant_type: "authorization_code", code: authorization_code.code, redirect_uri: client.redirect_uri,
      client_id: client.client_id, client_secret: client.client_secret }
  end

  def decode(token)
    JWT.decode(token, Oidc::SigningKey.public_key, true, algorithms: [ "RS256" ])
  end

  it "exchanges the code for an RS256-signed JWT access token" do
    post "/token", params: params

    expect(response).to have_http_status(:ok)
    expect(response.headers["Cache-Control"]).to include("no-store")
    expect(response.parsed_body).to include("token_type" => "Bearer", "expires_in" => 3600, "scope" => "openid email")

    payload, header = decode(response.parsed_body["access_token"])
    expect(header).to include("alg" => "RS256", "typ" => "at+jwt", "kid" => Oidc::SigningKey.kid)
    expect(payload).to include(
      "iss" => Rails.configuration.x.oidc.issuer,
      "sub" => user.id,
      "aud" => client.client_id,
      "client_id" => client.client_id,
      "scope" => "openid email"
    )
    expect(payload["exp"] - payload["iat"]).to eq(1.hour.to_i)
  end

  it "accepts client credentials via HTTP Basic auth" do
    post "/token",
      params: params.except(:client_id, :client_secret),
      headers: basic_auth_header(client.client_id, client.client_secret)

    expect(response).to have_http_status(:ok)
  end

  it "marks the code as consumed" do
    post "/token", params: params

    expect(authorization_code.reload).to be_consumed
  end

  it "rejects a wrong client secret" do
    post "/token", params: params.merge(client_secret: "wrong")

    expect(response).to have_http_status(:unauthorized)
    expect(response.parsed_body).to include("error" => "invalid_client")
  end

  it "rejects a code that has already been used" do
    post "/token", params: params
    post "/token", params: params

    expect(response).to have_http_status(:bad_request)
    expect(response.parsed_body).to include("error" => "invalid_grant")
  end

  it "rejects an expired code" do
    travel_to(2.minutes.from_now) { post "/token", params: params }

    expect(response.parsed_body).to include("error" => "invalid_grant")
  end

  it "rejects a redirect_uri that differs from the authorization request" do
    post "/token", params: params.merge(redirect_uri: "https://app.example.com/other")

    expect(response.parsed_body).to include("error" => "invalid_grant")
    expect(authorization_code.reload).not_to be_consumed
  end

  it "rejects a code that was issued to a different client" do
    other_client = create_client(name: "Other App")

    post "/token", params: params.merge(client_id: other_client.client_id, client_secret: other_client.client_secret)

    expect(response.parsed_body).to include("error" => "invalid_grant")
  end

  it "rejects unsupported grant types" do
    post "/token", params: params.merge(grant_type: "password")

    expect(response.parsed_body).to include("error" => "unsupported_grant_type")
  end
end
