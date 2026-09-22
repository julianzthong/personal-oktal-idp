require "rails_helper"

RSpec.describe "GET /.well-known/openid-configuration", type: :request do
  let(:issuer) { Rails.configuration.x.oidc.issuer }

  it "publishes the provider metadata" do
    get "/.well-known/openid-configuration"

    expect(response).to have_http_status(:ok)
    expect(response.headers["Cache-Control"]).to include("public")
    expect(response.parsed_body).to include(
      "issuer" => issuer,
      "authorization_endpoint" => "#{issuer}/authorize",
      "token_endpoint" => "#{issuer}/token",
      "jwks_uri" => "#{issuer}/.well-known/jwks.json",
      "response_types_supported" => [ "code" ],
      "subject_types_supported" => [ "public" ],
      "code_challenge_methods_supported" => [ "S256" ],
      "id_token_signing_alg_values_supported" => [ "RS256" ],
      "scopes_supported" => include("openid")
    )
  end

  it "only advertises endpoints that exist" do
    get "/.well-known/openid-configuration"
    metadata = response.parsed_body

    expect(metadata).not_to have_key("userinfo_endpoint")

    # The advertised paths are real routes, not just plausible-looking strings.
    %w[authorization_endpoint token_endpoint jwks_uri].each do |name|
      path = URI.parse(metadata.fetch(name)).path
      expect { Rails.application.routes.recognize_path(path, method: name == "token_endpoint" ? "POST" : "GET") }
        .not_to raise_error
    end
  end
end
