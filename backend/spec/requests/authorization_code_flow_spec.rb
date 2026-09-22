require "rails_helper"

# The whole loop as a relying party sees it: discover the provider, log in, get
# a code from /authorize, redeem it at /token, then verify both tokens using
# only the public JWKS.
RSpec.describe "Authorization code flow", type: :request do
  it "issues an access token and ID token that verify against the published JWKS" do
    user = create_user
    client = create_client
    issuer = Rails.configuration.x.oidc.issuer

    get "/.well-known/openid-configuration"
    metadata = response.parsed_body
    expect(metadata["issuer"]).to eq(issuer)
    expect(metadata["code_challenge_methods_supported"]).to eq([ "S256" ])

    # What a relying party does: keep a random verifier, send only its hash.
    verifier = SecureRandom.urlsafe_base64(32)
    challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)

    log_in(user)

    get "/authorize", params: {
      response_type: "code", client_id: client.client_id, redirect_uri: client.redirect_uri,
      scope: "openid profile", nonce: "n-0S6_WzA2Mj",
      code_challenge: challenge, code_challenge_method: "S256"
    }
    code = redirect_params.fetch("code")

    post "/token", params: {
      grant_type: "authorization_code", code: code, redirect_uri: client.redirect_uri,
      client_id: client.client_id, client_secret: client.client_secret, code_verifier: verifier
    }
    tokens = response.parsed_body

    get URI.parse(metadata["jwks_uri"]).path
    jwk = JWT::JWK.import(response.parsed_body["keys"].first)

    access_token, = JWT.decode(
      tokens.fetch("access_token"), jwk.public_key, true,
      algorithms: [ "RS256" ], iss: issuer, verify_iss: true, aud: client.client_id, verify_aud: true
    )
    expect(access_token).to include("sub" => user.id, "scope" => "openid profile")

    id_token, = JWT.decode(
      tokens.fetch("id_token"), jwk.public_key, true,
      algorithms: [ "RS256" ], iss: issuer, verify_iss: true, aud: client.client_id, verify_aud: true
    )
    expect(id_token).to include("sub" => user.id, "nonce" => "n-0S6_WzA2Mj", "auth_time" => be_a(Integer))
  end
end
