class Importer
  def restore_job(payload)
    # ruleid: traust-ruby-deserialization-yaml-unsafe-load
    job = YAML.unsafe_load(payload[:job])
  end

  def restore_psych_job(payload)
    # ruleid: traust-ruby-deserialization-yaml-unsafe-load
    Psych.unsafe_load(payload[:job])
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
    # Psych and YAML expose the same safe load API on Psych 4+.
    # Permit no Ruby object classes for settings received across a trust boundary.
    # ok: traust-ruby-deserialization-yaml-unsafe-load
    Psych.load(body, permitted_classes: [])
    # ok: traust-ruby-deserialization-yaml-unsafe-load
    Psych.safe_load(body, permitted_classes: [])
    # ok: traust-ruby-deserialization-yaml-unsafe-load
    YAML.safe_load(body, permitted_classes: [])
    # ok: traust-ruby-deserialization-marshal-load
    JSON.parse(body)
  end

  def restore_fixed(body)
    # Replace object deserialization with data-only parsing, then validate its schema.
    # ok: traust-ruby-deserialization-marshal-load
    JSON.parse(body, create_additions: false)
  end
end
