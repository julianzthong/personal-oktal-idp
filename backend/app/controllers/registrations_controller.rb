# Open self-service signup. A new account is logged in straight away, so the
# user lands back in whatever /authorize request sent them here.
class RegistrationsController < ApplicationController
  def create
    user = User.new(signup_params)

    if user.save
      start_session_for(user)
      render json: { id: user.id, email: user.email }, status: :created
    else
      render_signup_errors(user.errors.full_messages)
    end
  rescue ActiveRecord::RecordNotUnique
    # Two signups for the same email racing past the uniqueness validation.
    render_signup_errors([ "Email has already been taken" ])
  end

  private
    def signup_params
      params.permit(:email, :password, :password_confirmation)
    end

    def render_signup_errors(messages)
      render json: { error: "invalid_signup", errors: messages }, status: :unprocessable_content
    end
end
