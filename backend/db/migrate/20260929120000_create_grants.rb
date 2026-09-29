class CreateGrants < ActiveRecord::Migration[8.1]
  def change
    # Records that a user has already consented to a client seeing a set of
    # scopes, so /authorize can skip the consent screen on a later visit.
    create_table :grants, id: :uuid do |t|
      t.references :user, null: false, foreign_key: true, type: :uuid
      t.references :oauth_client, null: false, foreign_key: true, type: :uuid
      t.string :scopes, array: true, null: false, default: []

      t.timestamps
    end
    add_index :grants, [ :user_id, :oauth_client_id ], unique: true
  end
end
