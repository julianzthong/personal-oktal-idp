require "rails_helper"

RSpec.describe "POST /token (refresh_token grant)", type: :request do
  let(:user) { create_user }
  let(:client) { create_client }
  let(:refresh_token) { RefreshToken.issue!(user: user, client: client, scopes: %w[openid email offline_access], auth_time: 5.minutes.ago.change(usec: 0)) }
  let(:params) do
    { grant_type: "refresh_token", refresh_token: refresh_token.token,
      client_id: client.client_id, client_secret: client.client_secret }
  end

  it "exchanges it for a new access token with the original scope and auth_time" do
    post "/token", params: params

    expect(response).to have_http_status(:ok)
    expect(response.headers["Cache-Control"]).to include("no-store")
    body = response.parsed_body
    expect(body).to include("token_type" => "Bearer", "scope" => "openid email offline_access")

    payload, = JWT.decode(body["access_token"], Oidc::SigningKey.public_key, true, algorithms: [ "RS256" ])
    expect(payload).to include("sub" => user.id, "scope" => "openid email offline_access")

    id_token, = JWT.decode(body["id_token"], Oidc::SigningKey.public_key, true, algorithms: [ "RS256" ], aud: client.client_id, verify_aud: true)
    expect(id_token).to include("sub" => user.id, "auth_time" => refresh_token.auth_time.to_i)
  end

  it "does not carry a nonce into the new ID token (refreshing isn't a fresh authentication)" do
    post "/token", params: params

    id_token, = JWT.decode(response.parsed_body["id_token"], nil, false)
    expect(id_token).not_to have_key("nonce")
  end

  describe "rotation" do
    it "returns a new refresh token, different from the one presented" do
      post "/token", params: params

      new_token = response.parsed_body.fetch("refresh_token")
      expect(new_token).to be_present
      expect(new_token).not_to eq(refresh_token.token)
    end

    it "consumes the presented token so it cannot be used again" do
      post "/token", params: params

      expect(refresh_token.reload.consumed_at).to be_present
    end

    it "keeps the new token in the same family and carrying the same auth_time" do
      post "/token", params: params

      rotated = RefreshToken.lookup(response.parsed_body["refresh_token"])
      expect(rotated.family_id).to eq(refresh_token.family_id)
      expect(rotated.auth_time).to eq(refresh_token.auth_time)
    end

    it "lets the new token be used for a further refresh (the chain keeps going)" do
      post "/token", params: params
      second_token = response.parsed_body.fetch("refresh_token")

      post "/token", params: params.merge(refresh_token: second_token)

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body["refresh_token"]).not_to eq(second_token)
    end
  end

  describe "reuse detection" do
    it "rejects a refresh token that has already been used" do
      post "/token", params: params

      post "/token", params: params

      expect(response).to have_http_status(:bad_request)
      expect(response.parsed_body).to include("error" => "invalid_grant", "error_description" => "The refresh token has already been used")
    end

    it "revokes every token in the family, including the one legitimately issued by the first refresh" do
      post "/token", params: params
      current_token = response.parsed_body.fetch("refresh_token")

      # The already-used token gets presented again (e.g. it was stolen, or a
      # client double-submitted an old copy of it).
      post "/token", params: params

      # Now even the token that was legitimately handed back is dead too.
      post "/token", params: params.merge(refresh_token: current_token)
      expect(response.parsed_body).to include("error" => "invalid_grant")
    end

    it "does not re-issue a refresh token to a token that was killed by reuse detection" do
      post "/token", params: params
      post "/token", params: params # reuse: kills the family

      expect(RefreshToken.where(family_id: refresh_token.family_id).pluck(:revoked_at)).to all(be_present)
    end
  end

  describe "scope narrowing (RFC 6749 §6)" do
    it "requesting no scope keeps the original scope" do
      post "/token", params: params

      expect(response.parsed_body["scope"]).to eq("openid email offline_access")
    end

    it "accepts a narrower scope than what was originally granted" do
      post "/token", params: params.merge(scope: "openid email")

      expect(response.parsed_body).to include("scope" => "openid email")
      rotated = RefreshToken.lookup(response.parsed_body["refresh_token"])
      expect(rotated.scopes).to eq(%w[openid email])
    end

    it "rejects a scope broader than what the refresh token covers" do
      post "/token", params: params.merge(scope: "openid email offline_access admin")

      expect(response).to have_http_status(:bad_request)
      expect(response.parsed_body).to include("error" => "invalid_scope")
      expect(refresh_token.reload).not_to be_consumed
    end
  end

  it "rejects an unknown refresh token" do
    post "/token", params: params.merge(refresh_token: "not-a-real-token")

    expect(response.parsed_body).to include("error" => "invalid_grant")
  end

  it "requires a refresh_token param" do
    post "/token", params: params.except(:refresh_token)

    expect(response).to have_http_status(:bad_request)
    expect(response.parsed_body).to include("error" => "invalid_request")
  end

  it "rejects an expired refresh token, without treating it as reuse" do
    token = refresh_token
    travel_to(31.days.from_now) { post "/token", params: params }

    expect(response.parsed_body).to include("error" => "invalid_grant")
    expect(token.reload.revoked_at).to be_nil
  end

  it "rejects a token presented to a different client than it was issued to" do
    other_client = create_client(name: "Other App")

    post "/token", params: params.merge(client_id: other_client.client_id, client_secret: other_client.client_secret)

    expect(response.parsed_body).to include("error" => "invalid_grant")
  end

  it "rejects a wrong client secret" do
    post "/token", params: params.merge(client_secret: "wrong")

    expect(response).to have_http_status(:unauthorized)
    expect(response.parsed_body).to include("error" => "invalid_client")
  end
end
