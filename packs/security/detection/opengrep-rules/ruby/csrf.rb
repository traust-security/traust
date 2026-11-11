class PaymentsController < ApplicationController
  # ruleid: traust-ruby-csrf-protection-skipped
  skip_before_action :verify_authenticity_token, only: [:refund]

  def refund; end
end

class ProfilesController < ApplicationController
  # ruleid: traust-ruby-csrf-protection-skipped
  skip_forgery_protection
end

class ArchiveController < ActionController::Base
  # ruleid: traust-ruby-csrf-protection-skipped
  protect_from_forgery with: :exception, except: :purge
end

class SignedController < ApplicationController
  # ok: traust-ruby-csrf-protection-skipped
  protect_from_forgery with: :exception
end

class Api::RecordsController < ActionController::API
  # ok: traust-ruby-csrf-protection-skipped
  skip_before_action :verify_authenticity_token, raise: false
end
