class PreviewsController < ApplicationController
  def show
    # ruleid: traust-ruby-xss-html-safe
    @snippet = params[:snippet].html_safe
    # ruleid: traust-ruby-xss-html-safe
    @banner = raw("<b>#{params[:title]}</b>")
    # ok: traust-ruby-xss-html-safe
    @clean = sanitize(params[:snippet]).html_safe
    # ok: traust-ruby-xss-html-safe
    @label = t(".welcome_html").html_safe
  end

  def preview
    # ruleid: traust-ruby-xss-html-safe
    render html: params[:fragment]
  end

  def template
    # ruleid: traust-ruby-injection-render-inline
    render inline: params[:template]
    # ok: traust-ruby-injection-render-inline
    render inline: "<p><%= @name %></p>"
  end
end
