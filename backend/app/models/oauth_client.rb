# A registered relying party. The secret is stored bcrypt-hashed; the plaintext
# is only available on the instance that generated it, right after creation:
#
#   client = OauthClient.create!(name: "My App", redirect_uri: "https://app.example/callback")
#   client.client_secret # => plaintext, shown once; gone after a reload
class OauthClient < ApplicationRecord
  # Adds #client_secret=, #authenticate_client_secret and the client_secret_digest column.
  has_secure_password :client_secret, validations: false

  has_many :authorization_codes, dependent: :destroy

  before_validation :generate_credentials, on: :create

  validates :name, presence: true
  validates :client_id, presence: true, uniqueness: true
  validates :client_secret_digest, presence: true
  validate :redirect_uri_is_absolute_http_uri

  # Redirect URIs are compared by exact string match (RFC 6749 §3.1.2.3).
  def redirect_uri_registered?(uri)
    uri.present? && ActiveSupport::SecurityUtils.secure_compare(uri, redirect_uri)
  end

  private
    def generate_credentials
      self.client_id ||= SecureRandom.urlsafe_base64(16)
      self.client_secret = SecureRandom.urlsafe_base64(32) if client_secret_digest.blank?
    end

    def redirect_uri_is_absolute_http_uri
      uri = URI.parse(redirect_uri.to_s)
      unless uri.is_a?(URI::HTTP) && uri.host.present? && uri.fragment.nil?
        errors.add(:redirect_uri, "must be an absolute http(s) URI without a fragment")
      end
    rescue URI::InvalidURIError
      errors.add(:redirect_uri, "is not a valid URI")
    end
end
