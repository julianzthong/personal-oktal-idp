# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_09_21_140000) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"

  create_table "authorization_codes", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "auth_time"
    t.string "code_challenge"
    t.string "code_digest", null: false
    t.datetime "consumed_at"
    t.datetime "created_at", null: false
    t.datetime "expires_at", null: false
    t.string "nonce"
    t.uuid "oauth_client_id", null: false
    t.string "redirect_uri", null: false
    t.string "scopes", default: [], null: false, array: true
    t.datetime "updated_at", null: false
    t.uuid "user_id", null: false
    t.index ["code_digest"], name: "index_authorization_codes_on_code_digest", unique: true
    t.index ["oauth_client_id"], name: "index_authorization_codes_on_oauth_client_id"
    t.index ["user_id"], name: "index_authorization_codes_on_user_id"
  end

  create_table "oauth_clients", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "client_id", null: false
    t.string "client_secret_digest", null: false
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.string "redirect_uri", null: false
    t.datetime "updated_at", null: false
    t.index ["client_id"], name: "index_oauth_clients_on_client_id", unique: true
  end

  create_table "properties", force: :cascade do |t|
    t.string "address", null: false
    t.boolean "available", default: true, null: false
    t.decimal "bathrooms", precision: 3, scale: 1, null: false
    t.integer "bedrooms", null: false
    t.string "city", null: false
    t.datetime "created_at", null: false
    t.string "external_id"
    t.datetime "listed_at"
    t.jsonb "raw_data", default: {}, null: false
    t.decimal "rent", precision: 10, scale: 2, null: false
    t.string "source"
    t.integer "square_feet"
    t.string "state", null: false
    t.string "unit"
    t.datetime "updated_at", null: false
    t.string "zip_code", null: false
    t.index ["available"], name: "index_properties_on_available"
    t.index ["city"], name: "index_properties_on_city"
    t.index ["source", "external_id"], name: "index_properties_on_source_and_external_id", unique: true
    t.index ["zip_code"], name: "index_properties_on_zip_code"
  end

  create_table "users", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "email", null: false
    t.string "password_digest", null: false
    t.datetime "updated_at", null: false
    t.index ["email"], name: "index_users_on_email", unique: true
  end

  add_foreign_key "authorization_codes", "oauth_clients"
  add_foreign_key "authorization_codes", "users"
end
