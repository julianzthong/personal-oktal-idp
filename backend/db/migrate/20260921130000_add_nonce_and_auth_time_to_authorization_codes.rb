class AddNonceAndAuthTimeToAuthorizationCodes < ActiveRecord::Migration[8.1]
  def change
    # nonce: opaque value from the /authorize request, echoed into the ID token.
    # auth_time: when the user actually authenticated, which is not when the code was issued.
    add_column :authorization_codes, :nonce, :string
    add_column :authorization_codes, :auth_time, :datetime
  end
end
