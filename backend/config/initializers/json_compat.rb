# TODO: Remove this file once a released Rails includes the json 3 fix (merged to
# 8-1-stable in rails/rails#58601 but not in 8.1.3.1; expected in 8.1.4). After
# upgrading, delete it and confirm the specs still pass, in particular the
# JSON-body login in spec/requests/sessions_spec.rb.
#
# json 3.0 made JSON.parse options keyword-only, but ActiveSupport::JSON.decode
# in activesupport 8.1.3.1 still passes them as a positional hash. That raises
# "wrong number of arguments (given 2, expected 1)" whenever Rails decrypts a
# cookie (the login session) or parses a JSON request body. This restores the
# json 2.x calling convention so we don't have to pin json below 3.
module JsonPositionalOptionsCompat
  def parse(source, opts = nil, **options)
    super(source, **(opts || {}), **options)
  end
end

JSON.singleton_class.prepend(JsonPositionalOptionsCompat)
