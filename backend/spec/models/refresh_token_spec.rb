require "rails_helper"

RSpec.describe RefreshToken, type: :model do
  let(:user) { create_user }
  let(:client) { create_client }
  let(:auth_time) { 5.minutes.ago.change(usec: 0) }

  describe ".issue!" do
    it "returns a record whose plaintext token hashes to the stored digest" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)

      expect(refresh_token.token).to be_present
      expect(refresh_token.token_digest).to eq(described_class.digest(refresh_token.token))
    end

    it "starts a fresh family each time" do
      first = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)
      second = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)

      expect(first.family_id).not_to eq(second.family_id)
    end

    it "sets an expiry from the configured TTL" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)

      expect(refresh_token.expires_at).to be_within(5.seconds).of(30.days.from_now)
    end
  end

  describe ".lookup" do
    it "finds the record by the plaintext token" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)

      expect(described_class.lookup(refresh_token.token)).to eq(refresh_token)
    end

    it "does not store the token in plaintext" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)

      expect(described_class.pluck(:token_digest)).not_to include(refresh_token.token)
    end

    it "returns nil for a token that doesn't exist" do
      expect(described_class.lookup("nonexistent")).to be_nil
    end
  end

  describe ".rotate!" do
    it "carries the family, user, client and auth_time forward" do
      original = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)

      rotated = described_class.rotate!(original)

      expect(rotated.family_id).to eq(original.family_id)
      expect(rotated.user).to eq(user)
      expect(rotated.oauth_client).to eq(client)
      expect(rotated.auth_time).to eq(auth_time)
      expect(rotated.token).not_to eq(original.token)
    end

    it "keeps the original scopes by default, or takes a narrower set" do
      original = described_class.issue!(user: user, client: client, scopes: %w[openid email], auth_time: auth_time)

      expect(described_class.rotate!(original).scopes).to eq(%w[openid email])
      expect(described_class.rotate!(original, scopes: %w[openid]).scopes).to eq(%w[openid])
    end

    it "links the previous token to its replacement" do
      original = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)

      rotated = described_class.rotate!(original)

      expect(original.reload.replaced_by).to eq(rotated)
    end
  end

  describe "#consume!" do
    it "marks the token consumed and returns true the first time" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)

      expect(refresh_token.consume!).to be(true)
      expect(refresh_token.reload.consumed_at).to be_present
    end

    it "returns false on a second attempt, without changing the original consumed_at" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)
      refresh_token.consume!
      first_consumed_at = refresh_token.reload.consumed_at

      expect(refresh_token.consume!).to be(false)
      expect(refresh_token.reload.consumed_at).to eq(first_consumed_at)
    end

    it "returns false for a token whose family was already revoked" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)
      refresh_token.revoke_family!

      expect(refresh_token.consume!).to be(false)
    end
  end

  describe "#revoke_family!" do
    it "revokes every token sharing the family, whatever their own state" do
      original = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)
      rotated = described_class.rotate!(original)
      original.consume!

      rotated.revoke_family!

      expect(original.reload.revoked_at).to be_present
      expect(rotated.reload.revoked_at).to be_present
    end

    it "does not touch a different family" do
      family_a = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)
      family_b = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)

      family_a.revoke_family!

      expect(family_b.reload.revoked_at).to be_nil
    end
  end

  describe "#grace_eligible?" do
    let(:grace_period) { Rails.configuration.x.oidc.refresh_token_grace_period }

    it "is false for a token that was never consumed" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)

      expect(refresh_token.grace_eligible?).to be(false)
    end

    it "is true once consumed, within the window, with an untouched replacement" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)
      refresh_token.consume!
      described_class.rotate!(refresh_token)

      expect(refresh_token.reload.grace_eligible?).to be(true)
    end

    it "is false once the window has passed" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)
      refresh_token.consume!
      described_class.rotate!(refresh_token)

      travel_to((grace_period + 1.second).from_now) { expect(refresh_token.reload.grace_eligible?).to be(false) }
    end

    it "is false once the replacement has itself been consumed" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)
      refresh_token.consume!
      child = described_class.rotate!(refresh_token)
      child.consume!

      expect(refresh_token.reload.grace_eligible?).to be(false)
    end

    it "is false once the replacement has been revoked" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)
      refresh_token.consume!
      child = described_class.rotate!(refresh_token)
      child.revoke_family!

      expect(refresh_token.reload.grace_eligible?).to be(false)
    end

    it "is false for a token with no replacement at all" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)
      refresh_token.consume!

      expect(refresh_token.grace_eligible?).to be(false)
    end

    it "is false once the family has been revoked" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)
      refresh_token.consume!
      described_class.rotate!(refresh_token)
      refresh_token.revoke_family!

      expect(refresh_token.reload.grace_eligible?).to be(false)
    end
  end

  describe "#expired?" do
    it "is false before expiry and true after" do
      refresh_token = described_class.issue!(user: user, client: client, scopes: %w[openid], auth_time: auth_time)

      expect(refresh_token.expired?).to be(false)
      travel_to(31.days.from_now) { expect(refresh_token.expired?).to be(true) }
    end
  end
end
