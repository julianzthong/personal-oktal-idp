# A short-lived, single-use credential a relying party exchanges at /token for
# an access token. Only a SHA-256 digest is stored; the plaintext exists on the
# instance returned by .issue! and nowhere else.
class AuthorizationCode < ApplicationRecord
  belongs_to :user
  belongs_to :oauth_client

  attr_reader :code

  validates :code_digest, :redirect_uri, :expires_at, presence: true

  scope :unexpired, -> { where("expires_at > ?", Time.current) }

  class << self
    def issue!(user:, client:, scopes:, redirect_uri:)
      code = SecureRandom.urlsafe_base64(32)
      record = create!(
        user: user,
        oauth_client: client,
        scopes: scopes,
        redirect_uri: redirect_uri,
        code_digest: digest(code),
        expires_at: Rails.configuration.x.oidc.authorization_code_ttl.from_now
      )
      record.instance_variable_set(:@code, code)
      record
    end

    # The code is 256 bits of randomness, so an unsalted digest is sufficient.
    def digest(code)
      Digest::SHA256.hexdigest(code.to_s)
    end

    def lookup(code)
      find_by(code_digest: digest(code)) if code.present?
    end
  end

  def expired?
    expires_at <= Time.current
  end

  def consumed?
    consumed_at.present?
  end

  # Atomically marks the code as used. Returns false if it was already consumed
  # (e.g. two concurrent /token requests racing with the same code).
  def consume!
    self.class.where(id: id, consumed_at: nil).update_all(consumed_at: Time.current) == 1
  end
end
