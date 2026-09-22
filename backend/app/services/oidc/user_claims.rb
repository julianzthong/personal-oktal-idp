module Oidc
  # The user claims /userinfo returns for a set of granted scopes (OIDC Core §5.4).
  # `sub` is always present; the rest depend on scope. Claims the user has no
  # value for are left out rather than sent as null (§5.3.2).
  module UserClaims
    module_function

    def for(user, scopes)
      claims = { sub: user.id }
      claims[:name] = user.name if scopes.include?("profile")
      if scopes.include?("email")
        claims[:email] = user.email
        claims[:email_verified] = user.email_verified
      end
      claims.compact
    end
  end
end
