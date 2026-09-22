class ApplicationController < ActionController::API
  private
    def current_user
      return @current_user if defined?(@current_user)
      @current_user = User.find_by(id: session[:user_id]) if session[:user_id] && session[:auth_time]
    end

    # Starts a fresh session for the user; resetting first avoids session fixation.
    def start_session_for(user)
      reset_session
      session[:user_id] = user.id
      session[:auth_time] = Time.current.to_i
    end

    # Error body shape from RFC 6749 §5.2, also used for /authorize errors that
    # can't be safely redirected to the client.
    def render_oauth_error(error, description = nil, status: :bad_request)
      render json: { error: error, error_description: description }.compact, status: status
    end
end
