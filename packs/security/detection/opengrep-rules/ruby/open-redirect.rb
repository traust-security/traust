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
end
