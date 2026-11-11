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
end
