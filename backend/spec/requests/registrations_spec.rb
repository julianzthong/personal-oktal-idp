require "rails_helper"

RSpec.describe "POST /signup", type: :request do
  let(:password) { OidcHelpers::PASSWORD }
  let(:params) { { email: "New.User@Example.com", password: password, password_confirmation: password } }
  let(:client) { create_client }

  def logged_in?
    get "/authorize", params: authorize_params(client)
    response.location.start_with?(client.redirect_uri)
  end

  it "creates the account" do
    expect { post "/signup", params: params }.to change(User, :count).by(1)

    user = User.find_by!(email: "new.user@example.com")
    expect(response).to have_http_status(:created)
    expect(response.parsed_body).to eq("id" => user.id, "email" => "new.user@example.com")
    expect(user.authenticate(password)).to eq(user)
    expect(user.password_digest).not_to include(password)
  end

  it "stores an optional name, trimmed" do
    post "/signup", params: params.merge(name: "  Grace Hopper ")

    expect(User.find_by!(email: "new.user@example.com").name).to eq("Grace Hopper")
  end

  it "treats a blank name as no name" do
    post "/signup", params: params.merge(name: "   ")

    expect(response).to have_http_status(:created)
    expect(User.find_by!(email: "new.user@example.com").name).to be_nil
  end

  it "logs the new user in, so /authorize continues instead of asking for a login" do
    post "/signup", params: params

    expect(logged_in?).to be(true)
  end

  it "accepts a JSON body" do
    post "/signup", params: params.to_json, headers: { "Content-Type" => "application/json" }

    expect(response).to have_http_status(:created)
  end

  context "when the email is already registered" do
    before { create_user(email: "new.user@example.com") }

    it "rejects it regardless of case, and does not log anyone in" do
      expect { post "/signup", params: params }.not_to change(User, :count)

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body).to include("error" => "invalid_signup", "errors" => [ "Email has already been taken" ])
      expect(logged_in?).to be(false)
    end
  end

  it "reports a duplicate that slips past validation (a concurrent signup) the same way" do
    allow_any_instance_of(User).to receive(:save).and_raise(ActiveRecord::RecordNotUnique)

    post "/signup", params: params

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body["errors"]).to eq([ "Email has already been taken" ])
  end

  {
    "a password that is too short" => [ { password: "short", password_confirmation: "short" }, /Password is too short/ ],
    "a confirmation that doesn't match" => [ { password_confirmation: "something else entirely" }, /Password confirmation doesn't match/ ],
    "a malformed email" => [ { email: "not-an-email" }, /Email is invalid/ ],
    "a missing email" => [ { email: "" }, /Email can't be blank/ ],
    "a name that is too long" => [ { name: "x" * 101 }, /Name is too long/ ],
    "a missing password" => [ { password: "", password_confirmation: "" }, /Password can't be blank/ ]
  }.each do |description, (overrides, message)|
    it "rejects #{description}, creating nothing and logging nobody in" do
      expect { post "/signup", params: params.merge(overrides) }.not_to change(User, :count)

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body["errors"]).to include(message)
      expect(logged_in?).to be(false)
    end
  end

  it "ignores attributes it wasn't meant to accept" do
    post "/signup", params: params.merge(id: SecureRandom.uuid, password_digest: "x", admin: true)

    expect(response).to have_http_status(:created)
    expect(User.find_by!(email: "new.user@example.com").password_digest).not_to eq("x")
  end
end
