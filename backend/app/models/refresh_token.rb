# A long-lived, rotating credential a relying party exchanges at /token for a
# fresh access token, without the user authenticating again. Only a SHA-256
# digest is stored; the plaintext exists on the instance returned by .issue!
# or .rotate! and nowhere else.
#
# Each use consumes the token and issues a new one in its place (rotation),
# all sharing a family_id. Presenting a token that has already been consumed —
# evidence it may have been copied by someone else — revokes every token in
# that family, cutting off both a thief and whichever party still holds a now-
# stale copy of it.
class RefreshToken < ApplicationRecord
  belongs_to :user
  belongs_to :oauth_client

  attr_reader :token

  validates :token_digest, :scopes, :expires_at, :family_id, :auth_time, presence: true

  class << self
    # Starts a new rotation family, from an authorization_code grant.
    def issue!(user:, client:, scopes:, auth_time:)
      create_in_family!(user: user, client: client, scopes: scopes, auth_time: auth_time, family_id: SecureRandom.uuid)
    end

    # Issues the next token in `previous`'s family, as part of rotating it away.
    def rotate!(previous, scopes: previous.scopes)
      create_in_family!(
        user: previous.user, client: previous.oauth_client, scopes: scopes,
        auth_time: previous.auth_time, family_id: previous.family_id
      )
    end

    # The token is 256 bits of randomness, so an unsalted digest is sufficient.
    def digest(token)
      Digest::SHA256.hexdigest(token.to_s)
    end

    def lookup(token)
      find_by(token_digest: digest(token)) if token.present?
    end

    private
      def create_in_family!(user:, client:, scopes:, auth_time:, family_id:)
        token = SecureRandom.urlsafe_base64(32)
        record = create!(
          user: user,
          oauth_client: client,
          scopes: scopes,
          auth_time: auth_time,
          family_id: family_id,
          token_digest: digest(token),
          expires_at: Rails.configuration.x.oidc.refresh_token_ttl.from_now
        )
        record.instance_variable_set(:@token, token)
        record
      end
  end

  def expired?
    expires_at <= Time.current
  end

  def consumed?
    consumed_at.present?
  end

  # Atomically marks the token used. False if it was already consumed, or the
  # family was already revoked — either way, a sign this token shouldn't be
  # honored, and the caller should treat it as reuse.
  def consume!
    self.class.where(id: id, consumed_at: nil, revoked_at: nil).update_all(consumed_at: Time.current) == 1
  end

  # Shuts down every token descended from the same original issuance.
  def revoke_family!
    self.class.where(family_id: family_id, revoked_at: nil).update_all(revoked_at: Time.current)
  end
end
