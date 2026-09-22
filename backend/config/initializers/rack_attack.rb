# Rate limiting for the endpoints where someone can guess passwords or spam
# accounts. Counters live in Rails.cache, which is an in-process memory store
# unless configured otherwise: limits apply per server process and reset when it
# restarts. Point the cache at a shared store (Redis, memcached) before running
# more than one process. The specs use a null cache, so only the throttle specs
# swap in a real one.
class Rack::Attack
  SIGNUP_PATH = "/signup".freeze
  LOGIN_PATH = "/login".freeze
  MAX_BODY_BYTES = 4096

  # A person makes a handful of accounts; a script makes thousands.
  throttle("signups/ip", limit: 5, period: 1.hour) do |req|
    req.ip if req.post? && req.path == SIGNUP_PATH
  end

  # Guessing passwords for many accounts from one address...
  throttle("logins/ip", limit: 10, period: 1.minute) do |req|
    req.ip if req.post? && req.path == LOGIN_PATH
  end

  # ...and guessing passwords for one account from many addresses. The trade-off
  # is that someone can also burn a victim's attempts; the short period keeps
  # that lockout brief.
  throttle("logins/email", limit: 5, period: 1.minute) do |req|
    email = posted_email(req) if req.post? && req.path == LOGIN_PATH
    Digest::SHA256.hexdigest(email) if email
  end

  # The email from a form or JSON login body, normalized like User#email.
  def self.posted_email(req)
    email = req.params["email"]
    if email.nil? && (raw = req.body.read(MAX_BODY_BYTES)).present?
      body = JSON.parse(raw)
      email = body["email"] if body.is_a?(Hash)
    end
    email.to_s.strip.downcase.presence
  rescue JSON::ParserError, TypeError, Rack::QueryParser::ParamsTooDeepError, Rack::QueryParser::InvalidParameterError
    nil
  ensure
    req.body.rewind if req.body.respond_to?(:rewind)
  end

  self.throttled_responder = lambda do |request|
    match = request.env["rack.attack.match_data"]
    retry_after = match[:period] - (match[:epoch_time] % match[:period])
    [ 429, { "Content-Type" => "application/json", "Retry-After" => retry_after.to_s }, [ { error: "rate_limited" }.to_json ] ]
  end
end

ActiveSupport::Notifications.subscribe("throttle.rack_attack") do |*, payload|
  request = payload[:request]
  Rails.logger.warn("[rack-attack] throttled #{request.env['rack.attack.matched']} ip=#{request.ip} path=#{request.path}")
end
