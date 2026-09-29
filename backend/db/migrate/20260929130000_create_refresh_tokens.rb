class CreateRefreshTokens < ActiveRecord::Migration[8.1]
  def change
    create_table :refresh_tokens, id: :uuid do |t|
      t.references :user, null: false, foreign_key: true, type: :uuid
      t.references :oauth_client, null: false, foreign_key: true, type: :uuid
      # Groups every token descended from one original issuance, so reuse
      # detection can revoke the whole rotation chain at once.
      t.uuid :family_id, null: false
      t.string :token_digest, null: false
      t.string :scopes, array: true, null: false, default: []
      # When the user actually authenticated — carried forward from the
      # authorization code, since refreshing doesn't re-authenticate them.
      t.datetime :auth_time, null: false
      t.datetime :expires_at, null: false
      t.datetime :consumed_at
      t.datetime :revoked_at

      t.timestamps
    end
    add_index :refresh_tokens, :token_digest, unique: true
    add_index :refresh_tokens, :family_id
  end
end
