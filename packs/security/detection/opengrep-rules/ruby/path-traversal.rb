class DownloadsController < ApplicationController
  def show
    # ruleid: traust-ruby-path-traversal-params-taint
    send_file File.join(Rails.root, "reports", params[:name])
  end

  def raw
    # ruleid: traust-ruby-path-traversal-params-taint
    render plain: File.read("/srv/docs/#{params[:page]}")
  end

  def safe
    # ok: traust-ruby-path-traversal-params-taint
    send_file File.join(Rails.root, "reports", File.basename(params[:name]))
  end

  def fixed
    # ok: traust-ruby-path-traversal-params-taint
    send_file Rails.root.join("reports", "summary.pdf")
  end
end
