class Importer
  def restore_job(payload)
    # ruleid: traust-ruby-deserialization-yaml-unsafe-load
    job = YAML.unsafe_load(payload[:job])
  end

  def remote_settings(url)
    # ruleid: traust-ruby-deserialization-yaml-unsafe-load
    YAML.load(Net::HTTP.get(URI(url)))
  end

  def uploaded(io)
    # ruleid: traust-ruby-deserialization-yaml-unsafe-load
    YAML.load(io.read)
  end

  def restore(blob)
    # ruleid: traust-ruby-deserialization-marshal-load
    Marshal.load(blob)
  end

  def safe(body)
    # ok: traust-ruby-deserialization-yaml-unsafe-load
    YAML.safe_load(body, permitted_classes: [Date])
    # ok: traust-ruby-deserialization-yaml-unsafe-load
    YAML.load(body, permitted_classes: [Symbol])
    # ok: traust-ruby-deserialization-yaml-unsafe-load
    YAML.load("a: 1")
    # ok: traust-ruby-deserialization-marshal-load
    JSON.parse(body)
  end
end
