# The OIDC token endpoint (authorization code grant, RFC 6749 §4.1.3).
class TokensController < ApplicationController
  before_action :prevent_caching

  def create
    client = authenticate_client
    return render_invalid_client unless client

    unless params[:grant_type] == "authorization_code"
      return render_oauth_error("unsupported_grant_type")
    end
    if params[:code].blank? || params[:redirect_uri].blank? || params[:code_verifier].blank?
      return render_oauth_error("invalid_request", "code, redirect_uri and code_verifier are required")
    end

    authorization_code = client.authorization_codes.lookup(params[:code])
    unless redeemable?(authorization_code) && authorization_code.consume!
      return render_oauth_error("invalid_grant", "The authorization code is invalid, expired or already used, or the redirect_uri or code_verifier does not match")
    end

    render json: token_response(authorization_code)
  end

  private
    def token_response(authorization_code)
      user, client, scopes = authorization_code.user, authorization_code.oauth_client, authorization_code.scopes
      access_token = Oidc::AccessToken.issue(user: user, client: client, scopes: scopes)

      response = {
        access_token: access_token,
        token_type: "Bearer",
        expires_in: Rails.configuration.x.oidc.access_token_ttl.to_i,
        scope: scopes.join(" ")
      }
      # The ID token is what makes this OpenID Connect rather than plain OAuth 2.0.
      if scopes.include?("openid")
        response[:id_token] = Oidc::IdToken.issue(
          user: user, client: client, access_token: access_token,
          nonce: authorization_code.nonce, auth_time: authorization_code.auth_time
        )
      end
      response
    end

    # The redirect_uri must be identical to the one used at /authorize (RFC 6749 §4.1.3),
    # and the code_verifier must hash to the challenge stored with the code (RFC 7636 §4.6).
    # Both are checked before the code is consumed, so a wrong guess doesn't burn it.
    def redeemable?(authorization_code)
      authorization_code.present? &&
        !authorization_code.expired? &&
        !authorization_code.consumed? &&
        authorization_code.redirect_uri == params[:redirect_uri] &&
        Oidc::Pkce.verified?(verifier: params[:code_verifier], challenge: authorization_code.code_challenge)
    end

    # Supports client_secret_basic (Authorization header) and client_secret_post (body).
    def authenticate_client
      client_id, client_secret =
        if basic_auth?
          ActionController::HttpAuthentication::Basic.user_name_and_password(request)
        else
          [ params[:client_id], params[:client_secret] ]
        end

      client = OauthClient.find_by(client_id: client_id.to_s)
      client if client&.authenticate_client_secret(client_secret.to_s)
    end

    def basic_auth?
      ActionController::HttpAuthentication::Basic.has_basic_credentials?(request)
    end

    def render_invalid_client
      response.headers["WWW-Authenticate"] = 'Basic realm="token"' if basic_auth?
      render_oauth_error("invalid_client", status: :unauthorized)
    end
end
