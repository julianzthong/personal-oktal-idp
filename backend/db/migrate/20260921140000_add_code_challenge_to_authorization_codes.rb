class AddCodeChallengeToAuthorizationCodes < ActiveRecord::Migration[8.1]
  def change
    # PKCE S256 challenge (RFC 7636). Nullable only so the migration is safe on
    # existing rows; the model requires it on every new code.
    add_column :authorization_codes, :code_challenge, :string
  end
end
