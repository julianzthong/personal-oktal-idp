require "rails_helper"

RSpec.describe "GET /authorize", type: :request do
  let(:user) { create_user }
  let(:client) { create_client }
  let(:params) do
    { response_type: "code", client_id: client.client_id, redirect_uri: client.redirect_uri,
      scope: "openid email", state: "xyz" }
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
        user: user, oauth_client: client, scopes: %w[openid email], redirect_uri: client.redirect_uri
      )
      expect(authorization_code.expires_at).to be_within(5.seconds).of(60.seconds.from_now)
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
  end

  context "when the user is not logged in" do
    it "returns 401 login_required and issues no code" do
      get "/authorize", params: params

      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body).to include("error" => "login_required")
      expect(AuthorizationCode.count).to eq(0)
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
