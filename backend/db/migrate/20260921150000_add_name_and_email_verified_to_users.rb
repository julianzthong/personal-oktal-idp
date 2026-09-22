class AddNameAndEmailVerifiedToUsers < ActiveRecord::Migration[8.1]
  def change
    # Both are served from /userinfo: `name` for the profile scope, and
    # `email_verified` alongside `email`. Nothing verifies emails yet, so the
    # latter is false for everyone.
    add_column :users, :name, :string
    add_column :users, :email_verified, :boolean, null: false, default: false
  end
end
