class Client
  def connect(host)
    http = Net::HTTP.new(host, 443)
    http.use_ssl = true
    # ruleid: traust-ruby-cryptography-tls-verify-none
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    # ruleid: traust-ruby-cryptography-tls-verify-none
    conn = Faraday.new(url: host, ssl: { verify: false })
    # ok: traust-ruby-cryptography-tls-verify-none
    safe = Faraday.new(url: host, ssl: { verify: true })
  end

  def codes(password, blob)
    # ruleid: traust-ruby-cryptography-weak-random-secret
    reset_code = rand(100_000..999_999)
    # ok: traust-ruby-cryptography-weak-random-secret
    reset_code = SecureRandom.random_number(1_000_000)
    # ok: traust-ruby-cryptography-weak-random-secret
    delay = rand(5)
    # ruleid: traust-ruby-cryptography-weak-hash
    digest = Digest::MD5.hexdigest(password)
    # ok: traust-ruby-cryptography-weak-hash
    strong = Digest::SHA256.hexdigest(blob)
  end
end
