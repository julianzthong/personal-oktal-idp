# The OIDC token endpoint: the authorization code grant (RFC 6749 §4.1.3) and
# the refresh token grant (RFC 6749 §6).
class TokensController < ApplicationController
  before_action :prevent_caching

  def create
    client = authenticate_client
    return render_invalid_client unless client

    case params[:grant_type]
    when "authorization_code"
      handle_authorization_code_grant(client)
    when "refresh_token"
      handle_refresh_token_grant(client)
    else
      render_oauth_error("unsupported_grant_type")
    end
  end

  private
    def handle_authorization_code_grant(client)
      if params[:code].blank? || params[:redirect_uri].blank? || params[:code_verifier].blank?
        return render_oauth_error("invalid_request", "code, redirect_uri and code_verifier are required")
      end

      authorization_code = client.authorization_codes.lookup(params[:code])
      unless redeemable?(authorization_code) && authorization_code.consume!
        return render_oauth_error("invalid_grant", "The authorization code is invalid, expired or already used, or the redirect_uri or code_verifier does not match")
      end

      scopes = authorization_code.scopes
      refresh_token =
        if scopes.include?("offline_access")
          RefreshToken.issue!(user: authorization_code.user, client: client, scopes: scopes, auth_time: authorization_code.auth_time)
        end

      render json: token_response(
        user: authorization_code.user, client: client, scopes: scopes, auth_time: authorization_code.auth_time,
        nonce: authorization_code.nonce, refresh_token: refresh_token
      )
    end

    # Rotation: every refresh consumes the presented token and issues a new one
    # in its place, sharing the same family. A token that fails to consume —
    # because it was already used, or the family was already shut down — is
    # normally treated as reuse and shuts the whole family off. The one
    # exception is a same-token retry that arrives soon enough, and whose
    # child was never touched: that looks like a lost response rather than
    # theft, so it's forgiven once, by advancing past the untouched child
    # instead of the (dead) token that was actually presented.
    def handle_refresh_token_grant(client)
      return render_oauth_error("invalid_request", "refresh_token is required") if params[:refresh_token].blank?

      refresh_token = client.refresh_tokens.lookup(params[:refresh_token])
      return render_oauth_error("invalid_grant", "The refresh token is invalid or has expired") unless refresh_token && !refresh_token.expired?

      scopes = narrowed_scopes(refresh_token)
      return render_oauth_error("invalid_scope", "Cannot request a scope beyond what was originally granted") unless scopes

      if refresh_token.consume!
        return render json: rotate_and_respond(refresh_token, client: client, scopes: scopes)
      end

      if refresh_token.grace_eligible? && refresh_token.replaced_by.consume!
        return render json: rotate_and_respond(refresh_token.replaced_by, client: client, scopes: scopes)
      end

      refresh_token.revoke_family!
      render_oauth_error("invalid_grant", "The refresh token has already been used")
    end

    # auth_time is invariant across a family (rotate! always carries it
    # forward), so it's always read off whichever token is being rotated here.
    def rotate_and_respond(consumed_token, client:, scopes:)
      rotated = RefreshToken.rotate!(consumed_token, scopes: scopes)
      token_response(user: consumed_token.user, client: client, scopes: scopes, auth_time: consumed_token.auth_time, refresh_token: rotated)
    end

    # RFC 6749 §6: an omitted scope means "the same as before"; an explicit one
    # may narrow it but never request more than the refresh token itself covers.
    def narrowed_scopes(refresh_token)
      return refresh_token.scopes if params[:scope].blank?

      requested = params[:scope].to_s.split
      requested if (requested - refresh_token.scopes).empty?
    end

    def token_response(user:, client:, scopes:, auth_time:, nonce: nil, refresh_token: nil)
      access_token = Oidc::AccessToken.issue(user: user, client: client, scopes: scopes)

      response = {
        access_token: access_token,
        token_type: "Bearer",
        expires_in: Rails.configuration.x.oidc.access_token_ttl.to_i,
        scope: scopes.join(" ")
      }
      response[:refresh_token] = refresh_token.token if refresh_token
      # The ID token is what makes this OpenID Connect rather than plain OAuth 2.0.
      if scopes.include?("openid")
        response[:id_token] = Oidc::IdToken.issue(user: user, client: client, access_token: access_token, nonce: nonce, auth_time: auth_time)
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
