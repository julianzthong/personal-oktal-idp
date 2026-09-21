# Publishes the public key(s) relying parties use to verify access token signatures.
class JwksController < ApplicationController
  def show
    expires_in 1.hour, public: true
    render json: { keys: [ Oidc::SigningKey.jwk ] }
  end
end
