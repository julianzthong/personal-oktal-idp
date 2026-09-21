class CreateAuthorizationCodes < ActiveRecord::Migration[8.1]
  def change
    create_table :authorization_codes, id: :uuid do |t|
      t.references :user, null: false, foreign_key: true, type: :uuid
      t.references :oauth_client, null: false, foreign_key: true, type: :uuid
      # SHA-256 of the code handed to the client; the plaintext is never stored.
      t.string :code_digest, null: false
      t.string :scopes, array: true, null: false, default: []
      # The redirect_uri from the authorization request, which /token must match.
      t.string :redirect_uri, null: false
      t.datetime :expires_at, null: false
      t.datetime :consumed_at

      t.timestamps
    end
    add_index :authorization_codes, :code_digest, unique: true
  end
end
