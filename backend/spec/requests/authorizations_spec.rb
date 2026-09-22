require "rails_helper"

RSpec.describe "GET /authorize", type: :request do
  let(:user) { create_user }
  let(:client) { create_client }
  let(:params) do
    { response_type: "code", client_id: client.client_id, redirect_uri: client.redirect_uri,
      scope: "openid email", state: "xyz", nonce: "abc123",
      code_challenge: OidcHelpers::PKCE_CHALLENGE, code_challenge_method: "S256" }
  end

  context "when the user is logged in" do
    before { log_in(user) }

    it "redirects to the client's redirect_uri with a code and the original state" do
      get "/authorize", params: params

      expect(response).to have_http_status(:found)
      expect(response.location).to start_with("https://app.example.com/callback?")
      expect(redirect_params).to include("state" => "xyz", "code" => be_present)
    end

    it "stores a short-lived code for the user and client with the requested scopes" do
      get "/authorize", params: params

      authorization_code = AuthorizationCode.lookup(redirect_params["code"])
      expect(authorization_code).to have_attributes(
        user: user, oauth_client: client, scopes: %w[openid email], redirect_uri: client.redirect_uri,
        nonce: "abc123", code_challenge: OidcHelpers::PKCE_CHALLENGE
      )
      expect(authorization_code.expires_at).to be_within(5.seconds).of(60.seconds.from_now)
      expect(authorization_code.auth_time).to be_within(5.seconds).of(Time.current)
    end

    it "does not store the code in plaintext" do
      get "/authorize", params: params

      expect(AuthorizationCode.pluck(:code_digest)).not_to include(redirect_params["code"])
    end

    it "redirects with an error, not a code, for an unsupported response_type" do
      get "/authorize", params: params.merge(response_type: "token")

      expect(response).to have_http_status(:found)
      expect(redirect_params).to eq("error" => "unsupported_response_type", "state" => "xyz")
      expect(AuthorizationCode.count).to eq(0)
    end

    it "redirects with an error for an unknown scope" do
      get "/authorize", params: params.merge(scope: "openid admin")

      expect(redirect_params).to eq("error" => "invalid_scope", "state" => "xyz")
    end

    # PKCE is mandatory, and only S256 is accepted.
    it "requires a code_challenge" do
      get "/authorize", params: params.except(:code_challenge)

      expect(response).to have_http_status(:found)
      expect(redirect_params).to include(
        "error" => "invalid_request", "state" => "xyz", "error_description" => /code_challenge is required/
      )
      expect(AuthorizationCode.count).to eq(0)
    end

    it "rejects the plain challenge method" do
      get "/authorize", params: params.merge(code_challenge_method: "plain")

      expect(redirect_params).to include("error" => "invalid_request", "error_description" => /must be S256/)
      expect(AuthorizationCode.count).to eq(0)
    end

    it "rejects a missing challenge method rather than defaulting to plain" do
      get "/authorize", params: params.except(:code_challenge_method)

      expect(redirect_params).to include("error" => "invalid_request", "error_description" => /must be S256/)
    end

    it "rejects a malformed code_challenge" do
      get "/authorize", params: params.merge(code_challenge: "too-short")

      expect(redirect_params).to include("error" => "invalid_request", "error_description" => /base64url SHA-256/)
    end
  end

  context "when the user is not logged in" do
    it "redirects to the login page, carrying the original request, and issues no code" do
      get "/authorize", params: params

      expect(response).to have_http_status(:found)
      expect(response.location).to start_with("#{Rails.configuration.x.oidc.login_url}?")
      return_to = redirect_params.fetch("return_to")
      expect(return_to).to start_with("#{Rails.configuration.x.oidc.issuer}/authorize?")
      expect(Rack::Utils.parse_query(URI.parse(return_to).query)).to include(
        "client_id" => client.client_id, "state" => "xyz", "code_challenge" => OidcHelpers::PKCE_CHALLENGE
      )
      expect(AuthorizationCode.count).to eq(0)
    end

    it "issues a code when the returned request is resumed after logging in" do
      get "/authorize", params: params
      resume_path = URI.parse(redirect_params.fetch("return_to")).request_uri

      log_in(user)
      get resume_path

      expect(response.location).to start_with("https://app.example.com/callback?")
      expect(redirect_params).to include("code" => be_present, "state" => "xyz")
    end

    it "does not send an unregistered redirect_uri on to the login page" do
      get "/authorize", params: params.merge(redirect_uri: "https://evil.example.com/callback")

      expect(response).to have_http_status(:bad_request)
      expect(response.location).to be_nil
    end
  end

  # These must render an error instead of redirecting, otherwise /authorize
  # would redirect the browser to an attacker-chosen URL.
  context "when client_id or redirect_uri can't be trusted" do
    before { log_in(user) }

    it "does not redirect to an unregistered redirect_uri" do
      get "/authorize", params: params.merge(redirect_uri: "https://evil.example.com/callback")

      expect(response).to have_http_status(:bad_request)
      expect(response.location).to be_nil
      expect(AuthorizationCode.count).to eq(0)
    end

    it "does not redirect for an unknown client_id" do
      get "/authorize", params: params.merge(client_id: "nope")

      expect(response).to have_http_status(:bad_request)
      expect(response.location).to be_nil
    end
  end
end
