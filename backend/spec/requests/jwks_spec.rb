require "rails_helper"

RSpec.describe "GET /.well-known/jwks.json", type: :request do
  it "publishes the public signing key as a JWK set" do
    get "/.well-known/jwks.json"

    expect(response).to have_http_status(:ok)
    expect(response.headers["Cache-Control"]).to include("public")

    keys = response.parsed_body["keys"]
    expect(keys.size).to eq(1)
    expect(keys.first).to include(
      "kty" => "RSA", "use" => "sig", "alg" => "RS256", "kid" => Oidc::SigningKey.kid,
      "n" => be_present, "e" => "AQAB"
    )
  end

  it "never exposes private key material" do
    get "/.well-known/jwks.json"

    expect(response.parsed_body["keys"].first.keys).not_to include("d", "p", "q", "dp", "dq", "qi")
  end
end
