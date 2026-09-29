# A user's standing consent for a client to be issued tokens with a given set
# of scopes. One row per (user, client): approving a new scope later merges
# into it rather than creating a second grant.
class Grant < ApplicationRecord
  belongs_to :user
  belongs_to :oauth_client

  validates :scopes, presence: true

  class << self
    # Whether the user has already approved every one of `scopes` for `client`.
    def covers?(user:, client:, scopes:)
      granted = find_by(user: user, oauth_client: client)&.scopes || []
      (scopes - granted).empty?
    end

    def grant!(user:, client:, scopes:)
      grant = find_or_initialize_by(user: user, oauth_client: client)
      grant.scopes = (grant.scopes + scopes).uniq
      grant.save!
      grant
    end
  end
end
