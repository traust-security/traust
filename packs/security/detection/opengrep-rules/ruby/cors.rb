Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    # ruleid: traust-ruby-cors-any-origin-with-credentials
    origins(/.*/)
    resource "/api/*", headers: :any, methods: %i[get post], credentials: true
  end

  allow do
    # ruleid: traust-ruby-cors-any-origin-with-credentials
    origins { |_source, _env| true }
    resource "*", headers: :any, credentials: true
  end

  allow do
    # ok: traust-ruby-cors-any-origin-with-credentials
    origins "https://app.example.org"
    resource "*", headers: :any, credentials: true
  end

  allow do
    # ok: traust-ruby-cors-any-origin-with-credentials
    origins(/.*/)
    resource "/public/*", headers: :any, methods: [:get]
  end

  allow do
    # Exact origin comparison, not a substring or suffix match.
    # ok: traust-ruby-cors-any-origin-with-credentials
    origins { |source, _env| source == "https://app.example.org" }
    resource "/api/*", headers: :any, methods: %i[get post], credentials: true
  end

  allow do
    # Only public, non-sensitive responses belong on this resource.
    # ok: traust-ruby-cors-any-origin-with-credentials
    origins { |_source, _env| true }
    resource "/public/*", headers: :any, methods: [:get], credentials: false
  end
end
