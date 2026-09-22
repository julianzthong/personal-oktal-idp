Rails.application.routes.draw do
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  post "signup", to: "registrations#create"
  post "login", to: "sessions#create"
  delete "logout", to: "sessions#destroy"
  get "authorize", to: "authorizations#show"
  post "token", to: "tokens#create"
  match "userinfo", to: "userinfo#show", via: [ :get, :post ]
  get "/.well-known/jwks.json", to: "jwks#show", format: false
  get "/.well-known/openid-configuration", to: "discovery#show", format: false
end
