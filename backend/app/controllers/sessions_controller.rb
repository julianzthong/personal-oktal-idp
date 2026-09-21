class SessionsController < ApplicationController
  def create
    user = User.authenticate_by(email: params[:email].to_s, password: params[:password].to_s)

    if user
      reset_session # avoid session fixation
      session[:user_id] = user.id
      render json: { id: user.id, email: user.email }
    else
      render json: { error: "invalid_credentials" }, status: :unauthorized
    end
  end
end
