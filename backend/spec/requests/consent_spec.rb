require "rails_helper"

RSpec.describe "GET /consent", type: :request do
  let(:user) { create_user }
  let(:client) { create_client }
  let(:params) do
    { response_type: "code", client_id: client.client_id, redirect_uri: client.redirect_uri,
      scope: "openid email", state: "xyz", code_challenge: OidcHelpers::PKCE_CHALLENGE, code_challenge_method: "S256" }
  end

  context "when the user is logged in" do
    before { log_in(user) }

    it "approving creates a grant and redirects to the client with a code" do
      expect { get "/consent", params: params.merge(allow: "true") }.to change(Grant, :count).by(1)

      expect(response.location).to start_with("https://app.example.com/callback?")
      expect(redirect_params).to include("code" => be_present, "state" => "xyz")
      expect(Grant.find_by(user: user, oauth_client: client).scopes).to contain_exactly("openid", "email")
    end

    it "denying redirects to the client with access_denied and issues no code" do
      expect { get "/consent", params: params.merge(allow: "false") }.not_to change(AuthorizationCode, :count)

      expect(response.location).to start_with("https://app.example.com/callback?")
      expect(redirect_params).to eq(
        "error" => "access_denied", "error_description" => "The user denied the request", "state" => "xyz"
      )
      expect(Grant.count).to eq(0)
    end

    it "treats a missing allow param as a denial" do
      get "/consent", params: params

      expect(redirect_params).to include("error" => "access_denied")
    end

    it "merges newly approved scopes into an existing grant rather than replacing it" do
      grant_consent(user, client, %w[profile])

      get "/consent", params: params.merge(allow: "true")

      expect(Grant.find_by(user: user, oauth_client: client).scopes).to contain_exactly("profile", "openid", "email")
    end

    it "approving again when everything was already granted is a harmless no-op" do
      grant_consent(user, client, %w[openid email])

      expect { get "/consent", params: params.merge(allow: "true") }.not_to change(Grant, :count)

      expect(response.location).to start_with("https://app.example.com/callback?")
    end

    it "validates the request the same way /authorize does, independent of how it's reached" do
      get "/consent", params: params.merge(allow: "true", response_type: "token")

      expect(redirect_params).to eq("error" => "unsupported_response_type", "state" => "xyz")
      expect(Grant.count).to eq(0)
    end

    it "does not redirect to an unregistered redirect_uri" do
      get "/consent", params: params.merge(allow: "true", redirect_uri: "https://evil.example.com/callback")

      expect(response).to have_http_status(:bad_request)
      expect(response.location).to be_nil
    end
  end

  context "when the user is not logged in" do
    it "redirects to the login page with a return_to that resumes the decision" do
      get "/consent", params: params.merge(allow: "true")

      expect(response.location).to start_with("#{Rails.configuration.x.oidc.login_url}?")
      return_to = redirect_params.fetch("return_to")
      expect(return_to).to start_with("#{Rails.configuration.x.oidc.issuer}/consent?")
      expect(Rack::Utils.parse_query(URI.parse(return_to).query)).to include("allow" => "true", "state" => "xyz")
      expect(Grant.count).to eq(0)
    end

    it "completes the decision once that return_to is resumed after logging in" do
      get "/consent", params: params.merge(allow: "true")
      resume_path = URI.parse(redirect_params.fetch("return_to")).request_uri

      log_in(user)
      get resume_path

      expect(response.location).to start_with("https://app.example.com/callback?")
      expect(Grant.find_by(user: user, oauth_client: client)).to be_present
    end
  end
end
