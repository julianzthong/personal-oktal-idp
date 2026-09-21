# The OIDC authorization endpoint (authorization code flow, RFC 6749 §4.1.1).
class AuthorizationsController < ApplicationController
  # client_id and redirect_uri are checked before anything else, and a failure
  # here is rendered directly rather than redirected. Redirecting to an
  # unvalidated redirect_uri would turn this endpoint into an open redirector.
  before_action :load_client_and_redirect_uri

  def show
    return redirect_with_error("unsupported_response_type") unless params[:response_type] == "code"

    scopes = params[:scope].to_s.split
    return redirect_with_error("invalid_scope") unless (scopes - Rails.configuration.x.oidc.supported_scopes).empty?

    # There is no login or consent UI yet, so an anonymous request just gets a 401.
    return render_oauth_error("login_required", status: :unauthorized) unless current_user

    authorization_code = AuthorizationCode.issue!(
      user: current_user, client: @client, scopes: scopes, redirect_uri: @client.redirect_uri
    )
    redirect_to redirect_url_with(code: authorization_code.code), allow_other_host: true
  end

  private
    def load_client_and_redirect_uri
      @client = OauthClient.find_by(client_id: params[:client_id].to_s)
      return render_oauth_error("invalid_request", "Unknown client_id") unless @client
      render_oauth_error("invalid_request", "redirect_uri does not match a registered URI") unless @client.redirect_uri_registered?(params[:redirect_uri])
    end

    def redirect_with_error(error)
      redirect_to redirect_url_with(error: error), allow_other_host: true
    end

    # `state` is opaque to us; the client uses it to tie the response to its own request.
    def redirect_url_with(response_params)
      uri = URI.parse(@client.redirect_uri)
      query = URI.decode_www_form(uri.query.to_s) + response_params.merge(state: params[:state].presence).compact.to_a
      uri.query = URI.encode_www_form(query)
      uri.to_s
    end
end
