class AddReplacedByToRefreshTokens < ActiveRecord::Migration[8.1]
  def change
    # Points a rotated-away token at the token that replaced it. Lets a lost-
    # response retry be told apart from real reuse: if the child here has never
    # itself been touched, the parent being presented again looks like a
    # network retry, not theft (see RefreshToken#grace_eligible?). A child can
    # only ever replace one parent, hence the unique index.
    add_reference :refresh_tokens, :replaced_by, type: :uuid, foreign_key: { to_table: :refresh_tokens }, index: { unique: true }
  end
end
