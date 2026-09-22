class SessionsController < ApplicationController
  def create
    user = User.authenticate_by(email: params[:email].to_s, password: params[:password].to_s)

    if user
      start_session_for(user)
      render json: { id: user.id, email: user.email }
    else
      render json: { error: "invalid_credentials" }, status: :unauthorized
    end
  end

  def destroy
    reset_session
    head :no_content
  end
end
