module Oidc
  # Proof Key for Code Exchange (RFC 7636). The client invents a random
  # code_verifier, sends only its SHA-256 hash (the code_challenge) to
  # /authorize, and reveals the verifier at /token. Whoever redeems the code
  # must therefore be the party that started the flow, even if the code itself
  # leaked through the browser redirect.
  #
  # Only S256 is supported. The `plain` method sends the verifier itself as the
  # challenge, which protects nothing against anyone who can see the request.
  module Pkce
    METHOD = "S256".freeze

    # A SHA-256 digest is 32 bytes, which is always 43 characters of unpadded base64url.
    CHALLENGE_FORMAT = /\A[A-Za-z0-9_-]{43}\z/
    # RFC 7636 §4.1: 43 to 128 characters from the "unreserved" URI set.
    VERIFIER_FORMAT = /\A[A-Za-z0-9\-._~]{43,128}\z/

    module_function

    def challenge_for(verifier)
      Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
    end

    def valid_challenge?(challenge)
      CHALLENGE_FORMAT.match?(challenge.to_s)
    end

    def valid_verifier?(verifier)
      VERIFIER_FORMAT.match?(verifier.to_s)
    end

    # Fails closed: a code with no stored challenge can never be redeemed.
    def verified?(verifier:, challenge:)
      challenge.present? &&
        valid_verifier?(verifier) &&
        ActiveSupport::SecurityUtils.secure_compare(challenge_for(verifier), challenge)
    end
  end
end
