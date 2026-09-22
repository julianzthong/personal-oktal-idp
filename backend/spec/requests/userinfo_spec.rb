require "rails_helper"

RSpec.describe "GET /userinfo", type: :request do
  let(:user) { create_user.tap { |u| u.update!(name: "Ada Lovelace") } }
  let(:client) { create_client }
  let(:issuer) { Rails.configuration.x.oidc.issuer }
  let(:scopes) { %w[openid profile email] }
  let(:access_token) { Oidc::AccessToken.issue(user: user, client: client, scopes: scopes) }

  def bearer(token)
    { "Authorization" => "Bearer #{token}" }
  end

  # A token shaped exactly like ours, but signed by a different key.
  def forged_token(key: OpenSSL::PKey::RSA.new(2048), **overrides)
    payload = {
      iss: issuer, sub: user.id, aud: issuer, client_id: client.client_id, scope: "openid profile email",
      iat: Time.current.to_i, exp: 1.hour.from_now.to_i, jti: SecureRandom.uuid
    }.merge(overrides).compact
    JWT.encode(payload, key, "RS256", { typ: "at+jwt" })
  end

  it "returns the claims allowed by the token's scopes" do
    get "/userinfo", headers: bearer(access_token)

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to eq(
      "sub" => user.id, "name" => "Ada Lovelace", "email" => "ada@example.com", "email_verified" => false
    )
    expect(response.headers["Cache-Control"]).to include("no-store")
  end

  it "also answers POST (OIDC Core §5.3.1)" do
    post "/userinfo", headers: bearer(access_token)

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to include("sub" => user.id)
  end

  describe "scope filtering" do
    it "returns only sub for the openid scope alone" do
      get "/userinfo", headers: bearer(Oidc::AccessToken.issue(user: user, client: client, scopes: %w[openid]))

      expect(response.parsed_body).to eq("sub" => user.id)
    end

    it "returns email claims but no name for openid email" do
      get "/userinfo", headers: bearer(Oidc::AccessToken.issue(user: user, client: client, scopes: %w[openid email]))

      expect(response.parsed_body).to eq("sub" => user.id, "email" => "ada@example.com", "email_verified" => false)
    end

    it "returns the name for openid profile" do
      get "/userinfo", headers: bearer(Oidc::AccessToken.issue(user: user, client: client, scopes: %w[openid profile]))

      expect(response.parsed_body).to eq("sub" => user.id, "name" => "Ada Lovelace")
    end

    it "leaves out claims the user has no value for, instead of sending null" do
      user.update!(name: nil)

      get "/userinfo", headers: bearer(access_token)

      expect(response.parsed_body).not_to have_key("name")
      expect(response.parsed_body).to include("email" => "ada@example.com")
    end

    it "reports email_verified: false rather than dropping it" do
      get "/userinfo", headers: bearer(access_token)

      expect(response.parsed_body).to include("email_verified" => false)
    end

    it "refuses a token without the openid scope" do
      get "/userinfo", headers: bearer(Oidc::AccessToken.issue(user: user, client: client, scopes: %w[email]))

      expect(response).to have_http_status(:forbidden)
      expect(response.headers["WWW-Authenticate"]).to eq('Bearer error="insufficient_scope", error_description="The access token needs the openid scope", scope="openid"')
      expect(response.parsed_body).to include("error" => "insufficient_scope")
    end
  end

  describe "rejecting bad credentials" do
    def expect_invalid_token
      expect(response).to have_http_status(:unauthorized)
      expect(response.headers["WWW-Authenticate"]).to start_with('Bearer error="invalid_token"')
      expect(response.parsed_body).to include("error" => "invalid_token")
      expect(response.body).not_to include(user.email)
    end

    it "challenges a request with no credentials, without an error code" do
      get "/userinfo"

      expect(response).to have_http_status(:unauthorized)
      expect(response.headers["WWW-Authenticate"]).to eq("Bearer")
    end

    it "does not accept other authorization schemes" do
      get "/userinfo", headers: { "Authorization" => "Basic #{Base64.strict_encode64('a:b')}" }

      expect(response).to have_http_status(:unauthorized)
      expect(response.headers["WWW-Authenticate"]).to eq("Bearer")
    end

    it "does not accept the token as a query parameter" do
      get "/userinfo", params: { access_token: access_token }

      expect(response).to have_http_status(:unauthorized)
    end

    it "rejects garbage" do
      get "/userinfo", headers: bearer("not.a.jwt")

      expect_invalid_token
    end

    it "rejects an expired token" do
      token = access_token
      travel_to(2.hours.from_now) { get "/userinfo", headers: bearer(token) }

      expect_invalid_token
    end

    it "rejects a token signed by some other key" do
      get "/userinfo", headers: bearer(forged_token)

      expect_invalid_token
    end

    it "rejects a token whose payload was edited after signing" do
      header, _payload, signature = access_token.split(".")
      edited = Base64.urlsafe_encode64({ iss: issuer, sub: create_user(email: "victim@example.com").id, aud: issuer,
        scope: "openid email", exp: 1.hour.from_now.to_i }.to_json, padding: false)

      get "/userinfo", headers: bearer([ header, edited, signature ].join("."))

      expect_invalid_token
    end

    it "rejects an unsigned token (alg: none)" do
      payload = { iss: issuer, sub: user.id, aud: issuer, scope: "openid", exp: 1.hour.from_now.to_i }
      get "/userinfo", headers: bearer(JWT.encode(payload, nil, "none", { typ: "at+jwt" }))

      expect_invalid_token
    end

    it "rejects a token HMAC-signed with our public key as the secret (algorithm confusion)" do
      payload = { iss: issuer, sub: user.id, aud: issuer, scope: "openid", exp: 1.hour.from_now.to_i }
      get "/userinfo", headers: bearer(JWT.encode(payload, Oidc::SigningKey.public_key.to_pem, "HS256", { typ: "at+jwt" }))

      expect_invalid_token
    end

    it "rejects an ID token used as an access token" do
      id_token = Oidc::IdToken.issue(user: user, client: client, access_token: access_token)

      get "/userinfo", headers: bearer(id_token)

      expect_invalid_token
    end

    it "rejects a token addressed to someone else" do
      get "/userinfo", headers: bearer(forged_token(key: Oidc::SigningKey.private_key, aud: "https://other.example.com"))

      expect_invalid_token
    end

    it "rejects a token from a different issuer" do
      get "/userinfo", headers: bearer(forged_token(key: Oidc::SigningKey.private_key, iss: "https://evil.example.com"))

      expect_invalid_token
    end

    it "rejects a correctly signed token that has no expiry" do
      get "/userinfo", headers: bearer(forged_token(key: Oidc::SigningKey.private_key, exp: nil))

      expect_invalid_token
    end

    it "rejects a correctly signed token that lacks the at+jwt type" do
      payload = { iss: issuer, sub: user.id, aud: issuer, scope: "openid", exp: 1.hour.from_now.to_i }
      get "/userinfo", headers: bearer(JWT.encode(payload, Oidc::SigningKey.private_key, "RS256"))

      expect_invalid_token
    end

    it "rejects a valid token whose user no longer exists" do
      token = access_token
      user.destroy!

      get "/userinfo", headers: bearer(token)

      expect_invalid_token
    end
  end

  describe "CORS" do
    it "lets a browser app on any origin call it with a bearer token, without credentials" do
      options "/userinfo", headers: {
        "Origin" => "https://rp.example.com", "Access-Control-Request-Method" => "GET",
        "Access-Control-Request-Headers" => "authorization"
      }
      expect(response.headers["Access-Control-Allow-Origin"]).to eq("*")
      expect(response.headers["Access-Control-Allow-Headers"]).to include("authorization")

      get "/userinfo", headers: bearer(access_token).merge("Origin" => "https://rp.example.com")
      expect(response.headers["Access-Control-Allow-Origin"]).to eq("*")
      expect(response.headers).not_to have_key("Access-Control-Allow-Credentials")
    end

    it "lets the browser read why a token was rejected" do
      get "/userinfo", headers: { "Origin" => "https://rp.example.com" }

      expect(response.headers["Access-Control-Expose-Headers"]).to include("WWW-Authenticate")
    end
  end
end
