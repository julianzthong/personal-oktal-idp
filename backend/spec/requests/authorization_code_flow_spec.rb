require "rails_helper"

# The whole loop as a relying party sees it: log in, get a code from /authorize,
# redeem it at /token, then verify the token using only the public JWKS.
RSpec.describe "Authorization code flow", type: :request do
  it "issues an access token that verifies against the published JWKS" do
    user = create_user
    client = create_client
    log_in(user)

    get "/authorize", params: {
      response_type: "code", client_id: client.client_id, redirect_uri: client.redirect_uri, scope: "openid profile"
    }
    code = redirect_params.fetch("code")

    post "/token", params: {
      grant_type: "authorization_code", code: code, redirect_uri: client.redirect_uri,
      client_id: client.client_id, client_secret: client.client_secret
    }
    access_token = response.parsed_body.fetch("access_token")

    get "/.well-known/jwks.json"
    jwk = JWT::JWK.import(response.parsed_body["keys"].first)

    payload, = JWT.decode(
      access_token, jwk.public_key, true,
      algorithms: [ "RS256" ],
      iss: Rails.configuration.x.oidc.issuer, verify_iss: true,
      aud: client.client_id, verify_aud: true
    )
    expect(payload).to include("sub" => user.id, "scope" => "openid profile")
  end
end
