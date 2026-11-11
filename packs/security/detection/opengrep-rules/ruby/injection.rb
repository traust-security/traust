require 'open-uri'

class Preview
  def fetch
    # ruleid: traust-ruby-injection-kernel-open
    body = open(link.target).read
    # ruleid: traust-ruby-injection-kernel-open
    data = URI.open(params[:source]).read
    # ruleid: traust-ruby-injection-kernel-open
    URI.parse(target_url).open
  end

  def render_banner(theme)
    template = theme.fetch('banner')
    # ruleid: traust-ruby-injection-erb-template
    ERB.new(template).result(binding)
  end

  def fine(path)
    # ok: traust-ruby-injection-kernel-open
    File.open(path).read
    # ok: traust-ruby-injection-kernel-open
    open("/etc/app/defaults.yml").read
    # ok: traust-ruby-injection-erb-template
    ERB.new("Hello <%= name %>").result(binding)
    # ok: traust-ruby-injection-erb-template
    ERB.new(File.read(TEMPLATE)).result(binding)
  end
end

class OrdersController < ApplicationController
  def index
    # ruleid: traust-ruby-injection-sql-interpolation
    @orders = Order.where("region = '#{params[:region]}'")
    # ruleid: traust-ruby-injection-sql-interpolation
    @recent = Order.order(params[:sort])
    # ruleid: traust-ruby-injection-sql-interpolation
    Order.find_by_sql("SELECT * FROM orders WHERE label LIKE '%#{q}%'")
    # ruleid: traust-ruby-injection-sql-interpolation
    ActiveRecord::Base.connection.execute("DELETE FROM carts WHERE owner = '#{owner}'")
    # ok: traust-ruby-injection-sql-interpolation
    @safe = Order.where("region = ?", params[:region])
    # ok: traust-ruby-injection-sql-interpolation
    @hash = Order.where(region: params[:region]).order(:created_at)
  end

  def thumbnail
    # ruleid: traust-ruby-injection-shell-interpolation
    system("convert #{params[:file]} -resize 64x64 thumb.png")
    # ruleid: traust-ruby-injection-shell-interpolation
    listing = `ls -la #{params[:dir]}`
    # ruleid: traust-ruby-injection-shell-interpolation
    out, _ = Open3.capture2("git log #{branch}")
    # ruleid: traust-ruby-injection-shell-interpolation
    archive = %x(tar -czf out.tgz #{folder})
    # ok: traust-ruby-injection-shell-interpolation
    system("convert", params[:file], "-resize", "64x64", "thumb.png")
    # ok: traust-ruby-injection-shell-interpolation
    system("make clean")
  end
end
