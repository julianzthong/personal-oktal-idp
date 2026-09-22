require "rails_helper"

RSpec.describe Oidc::Pkce do
  let(:verifier) { OidcHelpers::PKCE_VERIFIER }
  let(:challenge) { OidcHelpers::PKCE_CHALLENGE }

  it "computes the S256 challenge from the RFC 7636 Appendix B test vector" do
    expect(described_class.challenge_for(verifier)).to eq(challenge)
  end

  describe ".verified?" do
    it "accepts the verifier that produced the challenge" do
      expect(described_class.verified?(verifier: verifier, challenge: challenge)).to be(true)
    end

    it "rejects a different verifier" do
      expect(described_class.verified?(verifier: "x" * 43, challenge: challenge)).to be(false)
    end

    it "fails closed when there is no stored challenge" do
      expect(described_class.verified?(verifier: verifier, challenge: nil)).to be(false)
    end

    it "rejects a missing verifier" do
      expect(described_class.verified?(verifier: nil, challenge: challenge)).to be(false)
    end
  end

  describe ".valid_verifier?" do
    it "allows 43 to 128 unreserved characters" do
      expect(described_class.valid_verifier?("a" * 43)).to be(true)
      expect(described_class.valid_verifier?("a" * 128)).to be(true)
      expect(described_class.valid_verifier?("Az09-._~" * 6)).to be(true)
    end

    it "rejects out-of-range lengths and characters outside the unreserved set" do
      expect(described_class.valid_verifier?("a" * 42)).to be(false)
      expect(described_class.valid_verifier?("a" * 129)).to be(false)
      expect(described_class.valid_verifier?("#{'a' * 42}+")).to be(false)
      expect(described_class.valid_verifier?("#{'a' * 42}\n")).to be(false)
    end
  end

  describe ".valid_challenge?" do
    it "accepts exactly 43 base64url characters" do
      expect(described_class.valid_challenge?(challenge)).to be(true)
    end

    it "rejects padded, short or non-base64url values" do
      expect(described_class.valid_challenge?("#{challenge}=")).to be(false)
      expect(described_class.valid_challenge?(challenge[0, 42])).to be(false)
      expect(described_class.valid_challenge?("#{challenge[0, 42]}+")).to be(false)
      expect(described_class.valid_challenge?(nil)).to be(false)
    end
  end
end
