require "rails_helper"

RSpec.describe "CORS", type: :request do
  let(:frontend_origin) { Rails.configuration.x.oidc.frontend_origin }
  let(:preflight_headers) do
    { "Origin" => frontend_origin, "Access-Control-Request-Method" => "POST", "Access-Control-Request-Headers" => "content-type" }
  end

  it "answers the frontend's preflight for /login, allowing credentials" do
    options "/login", headers: preflight_headers

    expect(response).to have_http_status(:ok)
    expect(response.headers["Access-Control-Allow-Origin"]).to eq(frontend_origin)
    expect(response.headers["Access-Control-Allow-Credentials"]).to eq("true")
  end

  it "answers the frontend's preflight for /signup too" do
    options "/signup", headers: preflight_headers

    expect(response.headers["Access-Control-Allow-Origin"]).to eq(frontend_origin)
    expect(response.headers["Access-Control-Allow-Credentials"]).to eq("true")
  end

  it "adds the CORS headers to the real /login response" do
    user = create_user

    post "/login", params: { email: user.email, password: OidcHelpers::PASSWORD }, headers: { "Origin" => frontend_origin }

    expect(response).to have_http_status(:ok)
    expect(response.headers["Access-Control-Allow-Origin"]).to eq(frontend_origin)
    expect(response.headers["Access-Control-Allow-Credentials"]).to eq("true")
  end

  it "does not let any other origin make credentialed calls" do
    options "/login", headers: preflight_headers.merge("Origin" => "https://evil.example.com")

    expect(response.headers["Access-Control-Allow-Origin"]).to be_nil
  end

  it "keeps /token off-limits to browsers on other origins" do
    options "/token", headers: preflight_headers.merge("Origin" => "https://rp.example.com")

    expect(response.headers["Access-Control-Allow-Origin"]).to be_nil
  end

  it "lets any origin read the JWKS and discovery document, without credentials" do
    %w[/.well-known/jwks.json /.well-known/openid-configuration].each do |path|
      get path, headers: { "Origin" => "https://rp.example.com" }

      expect(response.headers["Access-Control-Allow-Origin"]).to eq("*")
      expect(response.headers).not_to have_key("Access-Control-Allow-Credentials")
    end
  end
end
