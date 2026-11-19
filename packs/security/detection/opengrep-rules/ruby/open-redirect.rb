class SessionsController < ApplicationController
  def done
    # ruleid: traust-ruby-open-redirect-params
    redirect_to params[:return_to]
  end

  def bounce
    # ruleid: traust-ruby-open-redirect-params
    redirect_to(next_url, allow_other_host: true)
  end

  def home
    # ok: traust-ruby-open-redirect-params
    redirect_to root_path
  end

  def fixed_done
    # Rails 7 url_from rejects external hosts and falls back to a local route.
    # ok: traust-ruby-open-redirect-params
    redirect_to(url_from(params[:return_to]) || root_path)
  end
end
