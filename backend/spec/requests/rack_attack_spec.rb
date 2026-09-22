require "rails_helper"

RSpec.describe "Rate limiting", type: :request do
  # The test environment uses a null cache, which counts nothing. Give
  # Rack::Attack a real one just for these examples.
  around do |example|
    original = Rack::Attack.cache.store
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
    example.run
    Rack::Attack.cache.store = original
  end

  def from(ip)
    { env: { "REMOTE_ADDR" => ip } }
  end

  def signup(ip:, n: SecureRandom.hex(4))
    post "/signup", params: { email: "user-#{n}@example.com", password: OidcHelpers::PASSWORD }, **from(ip)
  end

  def login(ip:, email: "nobody@example.com", **options)
    post "/login", params: { email: email, password: "wrong" }, **from(ip), **options
  end

  describe "POST /signup" do
    it "allows 5 signups an hour from one address, then answers 429 with Retry-After" do
      5.times do
        signup(ip: "203.0.113.10")
        expect(response).to have_http_status(:created)
      end

      signup(ip: "203.0.113.10")

      expect(response).to have_http_status(:too_many_requests)
      expect(response.parsed_body).to eq("error" => "rate_limited")
      expect(response.headers["Retry-After"].to_i).to be_between(1, 1.hour.to_i)
      expect(User.count).to eq(5)
    end

    it "counts each address separately" do
      5.times { signup(ip: "203.0.113.10") }

      signup(ip: "203.0.113.11")

      expect(response).to have_http_status(:created)
    end
  end

  describe "POST /login" do
    it "allows 10 attempts a minute from one address, however many accounts it tries" do
      10.times do |i|
        login(ip: "203.0.113.20", email: "victim-#{i}@example.com")
        expect(response).to have_http_status(:unauthorized)
      end

      login(ip: "203.0.113.20", email: "victim-11@example.com")

      expect(response).to have_http_status(:too_many_requests)
      expect(response.headers["Retry-After"].to_i).to be_between(1, 1.minute.to_i)
    end

    it "allows 5 attempts a minute against one account, even from different addresses" do
      5.times do |i|
        login(ip: "198.51.100.#{i + 1}", email: "victim@example.com")
        expect(response).to have_http_status(:unauthorized)
      end

      login(ip: "198.51.100.99", email: "victim@example.com")

      expect(response).to have_http_status(:too_many_requests)
    end

    it "treats the same email in a different case, or in a JSON body, as the same account" do
      3.times { |i| login(ip: "198.51.100.#{i + 1}", email: "Victim@Example.com") }
      2.times do |i|
        post "/login", params: { email: " victim@example.com ", password: "wrong" }.to_json,
          headers: { "Content-Type" => "application/json" }, **from("198.51.100.#{i + 50}")
      end

      login(ip: "198.51.100.99", email: "VICTIM@example.com")

      expect(response).to have_http_status(:too_many_requests)
    end

    it "still lets other accounts log in while one is throttled" do
      other = create_user(email: "other@example.com")
      6.times { |i| login(ip: "198.51.100.#{i + 1}", email: "victim@example.com") }

      post "/login", params: { email: other.email, password: OidcHelpers::PASSWORD }, **from("198.51.100.200")

      expect(response).to have_http_status(:ok)
    end

    it "does not break the login body for the app after the throttle reads it" do
      user = create_user

      post "/login", params: { email: user.email, password: OidcHelpers::PASSWORD }.to_json,
        headers: { "Content-Type" => "application/json" }, **from("203.0.113.30")

      expect(response).to have_http_status(:ok)
    end
  end

  it "lets the browser read Retry-After on a throttled response (CORS)" do
    origin = Rails.configuration.x.oidc.frontend_origin
    10.times { login(ip: "203.0.113.40") }

    login(ip: "203.0.113.40", headers: { "Origin" => origin })

    expect(response).to have_http_status(:too_many_requests)
    expect(response.headers["Access-Control-Allow-Origin"]).to eq(origin)
    expect(response.headers["Access-Control-Expose-Headers"]).to include("Retry-After")
  end
end
