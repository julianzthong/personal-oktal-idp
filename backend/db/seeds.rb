# Sample data for trying the OIDC flow by hand in development. Idempotent, and
# deliberately never run outside development: these credentials are public.
#
#   bin/rails db:seed
#
# Log in at the frontend with dev@example.com / password123. The client matches
# the sample relying party (sample-rp/), which listens on localhost:4000.
if Rails.env.development?
  User.find_or_create_by!(email: "dev@example.com") do |user|
    user.password = "password123"
  end

  OauthClient.find_or_create_by!(client_id: "sample-rp") do |client|
    client.name = "Sample Relying Party"
    client.redirect_uri = "http://localhost:4000/callback"
    client.client_secret = "sample-rp-secret"
  end
end
