require "rails_helper"

RSpec.describe Grant, type: :model do
  let(:user) { create_user }
  let(:client) { create_client }

  describe ".covers?" do
    it "is false when there is no grant at all" do
      expect(described_class.covers?(user: user, client: client, scopes: %w[openid])).to be(false)
    end

    it "is true once every requested scope has been granted" do
      described_class.grant!(user: user, client: client, scopes: %w[openid email])

      expect(described_class.covers?(user: user, client: client, scopes: %w[openid email])).to be(true)
      expect(described_class.covers?(user: user, client: client, scopes: %w[openid])).to be(true)
    end

    it "is false if even one requested scope is missing" do
      described_class.grant!(user: user, client: client, scopes: %w[openid])

      expect(described_class.covers?(user: user, client: client, scopes: %w[openid email])).to be(false)
    end

    it "is true trivially when nothing is being requested" do
      expect(described_class.covers?(user: user, client: client, scopes: [])).to be(true)
    end

    it "does not let one client's grant cover another client's request" do
      other_client = create_client(name: "Other App")
      described_class.grant!(user: user, client: client, scopes: %w[openid])

      expect(described_class.covers?(user: user, client: other_client, scopes: %w[openid])).to be(false)
    end
  end

  describe ".grant!" do
    it "creates a grant on first use" do
      expect { described_class.grant!(user: user, client: client, scopes: %w[openid]) }.to change(described_class, :count).by(1)
    end

    it "merges new scopes into the existing row instead of creating a second one" do
      described_class.grant!(user: user, client: client, scopes: %w[openid])

      expect { described_class.grant!(user: user, client: client, scopes: %w[email]) }.not_to change(described_class, :count)
      expect(described_class.find_by(user: user, oauth_client: client).scopes).to contain_exactly("openid", "email")
    end

    it "does not duplicate a scope that was already granted" do
      described_class.grant!(user: user, client: client, scopes: %w[openid])

      described_class.grant!(user: user, client: client, scopes: %w[openid])

      expect(described_class.find_by(user: user, oauth_client: client).scopes).to eq(%w[openid])
    end
  end
end
