class CreateOauthClients < ActiveRecord::Migration[8.1]
  def change
    create_table :oauth_clients, id: :uuid do |t|
      t.string :name, null: false
      t.string :client_id, null: false
      t.string :client_secret_digest, null: false
      t.string :redirect_uri, null: false

      t.timestamps
    end
    add_index :oauth_clients, :client_id, unique: true
  end
end
