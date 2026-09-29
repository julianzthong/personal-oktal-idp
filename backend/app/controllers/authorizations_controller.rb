# The OIDC authorization endpoint (authorization code flow, RFC 6749 §4.1.1),
# plus the consent decision that /authorize sends the user off to make.
class AuthorizationsController < ApplicationController
  # client_id and redirect_uri are checked before anything else, and a failure
  # here is rendered directly rather than redirected. Redirecting to an
  # unvalidated redirect_uri would turn this endpoint into an open redirector.
  before_action :load_client_and_redirect_uri
  before_action :validate_authorization_request, only: %i[ show consent ]

  def show
    return redirect_to_login unless current_user

    if Grant.covers?(user: current_user, client: @client, scopes: scopes)
      issue_code_and_redirect
    else
      redirect_to_consent
    end
  end

  # Where the consent page sends the user's decision (GET, not a fetch: this
  # has to end in a real top-level navigation to the client's redirect_uri, and
  # it carries the session cookie cross-site the same way /authorize itself
  # does, which needs a top-level GET under SameSite=Lax).
  def consent
    return redirect_to_login unless current_user

    if params[:allow] == "true"
      Grant.grant!(user: current_user, client: @client, scopes: scopes)
      issue_code_and_redirect
    else
      redirect_with_error("access_denied", "The user denied the request")
    end
  end

  private
    def scopes
      @scopes ||= params[:scope].to_s.split
    end

    def load_client_and_redirect_uri
      @client = OauthClient.find_by(client_id: params[:client_id].to_s)
      return render_oauth_error("invalid_request", "Unknown client_id") unless @client
      render_oauth_error("invalid_request", "redirect_uri does not match a registered URI") unless @client.redirect_uri_registered?(params[:redirect_uri])
    end

    def validate_authorization_request
      return redirect_with_error("unsupported_response_type") unless params[:response_type] == "code"
      return redirect_with_error("invalid_scope") unless (scopes - Rails.configuration.x.oidc.supported_scopes).empty?

      if (description = pkce_error)
        redirect_with_error("invalid_request", description)
      end
    end

    def issue_code_and_redirect
      authorization_code = AuthorizationCode.issue!(
        user: current_user, client: @client, scopes: scopes, redirect_uri: @client.redirect_uri,
        code_challenge: params[:code_challenge], nonce: params[:nonce].presence,
        auth_time: Time.zone.at(session[:auth_time])
      )
      redirect_to redirect_url_with(code: authorization_code.code), allow_other_host: true
    end

    def redirect_with_error(error, description = nil)
      redirect_to redirect_url_with(error: error, error_description: description), allow_other_host: true
    end

    # Send the browser to the login page, telling it where to come back to. The
    # return URL is always this endpoint (whichever action called this) on our
    # own issuer, rebuilt from the configured issuer rather than the Host
    # header, and the resumed request is validated from scratch when it
    # arrives, so it can't be used as an open redirect.
    def redirect_to_login
      config = Rails.configuration.x.oidc
      return_to = "#{config.issuer.chomp('/')}#{request.path}?#{request.query_string}"
      redirect_to "#{config.login_url}?#{{ return_to: return_to }.to_query}", allow_other_host: true
    end

    # Send the browser to the consent page, with enough to show what's being
    # asked for and a return_to that resumes the flow at #consent with the
    # user's decision appended.
    def redirect_to_consent
      config = Rails.configuration.x.oidc
      return_to = "#{config.issuer.chomp('/')}/consent?#{request.query_string}"
      redirect_to "#{config.consent_url}?#{{ return_to: return_to, client_name: @client.name, scope: scopes.join(' ') }.to_query}",
        allow_other_host: true
    end

    # PKCE is mandatory for every client, and only the S256 method is supported.
    # Returns a description of what's wrong with the request, or nil if it's fine.
    def pkce_error
      if params[:code_challenge].blank?
        "code_challenge is required (PKCE)"
      elsif params[:code_challenge_method] != Oidc::Pkce::METHOD
        "code_challenge_method must be #{Oidc::Pkce::METHOD}"
      elsif !Oidc::Pkce.valid_challenge?(params[:code_challenge])
        "code_challenge must be the unpadded base64url SHA-256 hash of the code_verifier"
      end
    end

    # `state` is opaque to us; the client uses it to tie the response to its own request.
    def redirect_url_with(response_params)
      uri = URI.parse(@client.redirect_uri)
      query = URI.decode_www_form(uri.query.to_s) + response_params.merge(state: params[:state].presence).compact.to_a
      uri.query = URI.encode_www_form(query)
      uri.to_s
    end
end
