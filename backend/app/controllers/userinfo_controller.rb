# The OIDC UserInfo endpoint (OIDC Core §5.3): given an access token, returns
# claims about its user, limited to what the token's scopes allow. Accepts GET
# and POST. The token is read from the Authorization header only (RFC 6750 §2.1).
class UserinfoController < ApplicationController
  before_action :prevent_caching

  def show
    token = bearer_token
    return render_bearer_error(:unauthorized) unless token

    claims = Oidc::AccessToken.verify(token)
    user = User.find_by(id: claims["sub"]) if claims
    return render_bearer_error(:unauthorized, "invalid_token", "The access token is invalid or has expired") unless user

    scopes = claims["scope"].to_s.split
    return render_bearer_error(:forbidden, "insufficient_scope", "The access token needs the openid scope", scope: "openid") unless scopes.include?("openid")

    render json: Oidc::UserClaims.for(user, scopes)
  end

  private
    def bearer_token
      request.authorization.to_s[/\ABearer +(\S+)\z/i, 1]
    end

    # RFC 6750 §3: the failure is described in a WWW-Authenticate challenge. With
    # no credentials at all the challenge carries no error code.
    def render_bearer_error(status, error = nil, description = nil, **attributes)
      challenge = { error: error, error_description: description, **attributes }.compact
      response.headers["WWW-Authenticate"] = [ "Bearer", challenge.map { |name, value| %(#{name}="#{value}") }.join(", ") ].join(" ").strip

      if error
        render json: { error: error, error_description: description }.compact, status: status
      else
        head status
      end
    end
end
