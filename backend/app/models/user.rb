class User < ApplicationRecord
  has_secure_password

  has_many :authorization_codes, dependent: :destroy

  normalizes :email, with: ->(email) { email.strip.downcase }

  validates :email, presence: true, uniqueness: true, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :password, length: { minimum: 8 }, allow_nil: true
end
