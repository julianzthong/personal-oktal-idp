require "rails_helper"

RSpec.describe "POST /token", type: :request do
  let(:user) { create_user }
  let(:client) { create_client }
  let!(:authorization_code) do
    AuthorizationCode.issue!(
      user: user, client: client, scopes: %w[openid email], redirect_uri: client.redirect_uri,
      code_challenge: OidcHelpers::PKCE_CHALLENGE, nonce: "n-0S6_WzA2Mj", auth_time: 5.minutes.ago.change(usec: 0)
    )
  end
  let(:params) do
    { grant_type: "authorization_code", code: authorization_code.code, redirect_uri: client.redirect_uri,
      client_id: client.client_id, client_secret: client.client_secret,
      code_verifier: OidcHelpers::PKCE_VERIFIER }
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
      "aud" => Rails.configuration.x.oidc.issuer,
      "client_id" => client.client_id,
      "scope" => "openid email"
    )
    expect(payload["exp"] - payload["iat"]).to eq(1.hour.to_i)
  end

  it "also issues an ID token for the openid scope, bound to the nonce and access token" do
    post "/token", params: params

    body = response.parsed_body
    id_token, header = JWT.decode(
      body["id_token"], Oidc::SigningKey.public_key, true,
      algorithms: [ "RS256" ],
      iss: Rails.configuration.x.oidc.issuer, verify_iss: true,
      aud: client.client_id, verify_aud: true
    )

    expect(header).to include("alg" => "RS256", "kid" => Oidc::SigningKey.kid)
    expect(id_token).to include(
      "sub" => user.id, "aud" => client.client_id, "nonce" => "n-0S6_WzA2Mj",
      "auth_time" => authorization_code.auth_time.to_i
    )
    expect(id_token["exp"] - id_token["iat"]).to eq(10.minutes.to_i)

    # at_hash = base64url(left half of SHA-256(access_token)), computed independently here
    expected_at_hash = Base64.urlsafe_encode64(Digest::SHA256.digest(body["access_token"])[0, 16], padding: false)
    expect(id_token["at_hash"]).to eq(expected_at_hash)
  end

  it "omits the ID token when the openid scope was not granted" do
    code = AuthorizationCode.issue!(user: user, client: client, scopes: %w[email], redirect_uri: client.redirect_uri,
      code_challenge: OidcHelpers::PKCE_CHALLENGE)

    post "/token", params: params.merge(code: code.code)

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to include("access_token" => be_present)
    expect(response.parsed_body).not_to have_key("id_token")
  end

  it "leaves the nonce claim out when the authorization request had none" do
    code = AuthorizationCode.issue!(user: user, client: client, scopes: %w[openid], redirect_uri: client.redirect_uri,
      code_challenge: OidcHelpers::PKCE_CHALLENGE)

    post "/token", params: params.merge(code: code.code)

    id_token, = JWT.decode(response.parsed_body["id_token"], nil, false)
    expect(id_token).not_to have_key("nonce")
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

  it "rejects a wrong code_verifier without consuming the code" do
    post "/token", params: params.merge(code_verifier: "x" * 43)

    expect(response).to have_http_status(:bad_request)
    expect(response.parsed_body).to include("error" => "invalid_grant")
    expect(authorization_code.reload).not_to be_consumed
  end

  it "rejects a malformed code_verifier" do
    post "/token", params: params.merge(code_verifier: "short")

    expect(response.parsed_body).to include("error" => "invalid_grant")
  end

  it "requires a code_verifier, even with valid client credentials" do
    post "/token", params: params.except(:code_verifier)

    expect(response).to have_http_status(:bad_request)
    expect(response.parsed_body).to include("error" => "invalid_request")
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
