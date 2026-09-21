# The OIDC token endpoint (authorization code grant, RFC 6749 §4.1.3).
class TokensController < ApplicationController
  before_action :prevent_caching

  def create
    client = authenticate_client
    return render_invalid_client unless client

    unless params[:grant_type] == "authorization_code"
      return render_oauth_error("unsupported_grant_type")
    end
    return render_oauth_error("invalid_request", "code and redirect_uri are required") if params[:code].blank? || params[:redirect_uri].blank?

    authorization_code = client.authorization_codes.lookup(params[:code])
    unless redeemable?(authorization_code) && authorization_code.consume!
      return render_oauth_error("invalid_grant", "Authorization code is invalid, expired or already used")
    end

    render json: {
      access_token: Oidc::AccessToken.issue(user: authorization_code.user, client: client, scopes: authorization_code.scopes),
      token_type: "Bearer",
      expires_in: Rails.configuration.x.oidc.access_token_ttl.to_i,
      scope: authorization_code.scopes.join(" ")
    }
  end

  private
    # The redirect_uri must be identical to the one used at /authorize (RFC 6749 §4.1.3).
    def redeemable?(authorization_code)
      authorization_code.present? &&
        !authorization_code.expired? &&
        !authorization_code.consumed? &&
        authorization_code.redirect_uri == params[:redirect_uri]
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

    # Token responses must not be cached (RFC 6749 §5.1).
    def prevent_caching
      response.headers["Cache-Control"] = "no-store"
      response.headers["Pragma"] = "no-cache"
    end
end
