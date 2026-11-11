class AccountsController < ApplicationController
  def create
    # ruleid: traust-ruby-mass-assignment-permit-all
    Account.create!(params.require(:account).permit!)
  end

  def merge
    # ruleid: traust-ruby-mass-assignment-permit-all
    current_user.accounts.find(params[:id]).update(params[:account].permit!)
  end

  def import
    # ruleid: traust-ruby-mass-assignment-permit-all
    Account.new(params.to_unsafe_h)
  end

  def rename
    # ok: traust-ruby-mass-assignment-permit-all
    current_user.accounts.find(params[:id]).update(params.require(:account).permit(:label))
  end

  def widen
    # ok: traust-ruby-mass-assignment-permit-all
    filters = params.slice(:period, :order).permit!
    Account.where(filters.to_h)
  end

  def sizes
    # ok: traust-ruby-mass-assignment-permit-all
    @dimensions = params[:sizes].permit!.to_h
  end

  def audit
    # ok: traust-ruby-mass-assignment-permit-all
    Rails.logger.info(params.to_unsafe_h.except(:password))
  end

  private

  def listing_params
    # ok: traust-ruby-mass-assignment-permit-all
    params.permit!
    { label: params[:label] }
  end

  def search_params
    # ok: traust-ruby-mass-assignment-permit-all
    params.permit(:q, :page).to_unsafe_h
  end

  def service_params
    # ok: traust-ruby-mass-assignment-permit-all
    { params: params.to_unsafe_h, actor: current_user }
  end

  def account_params
    # ruleid: traust-ruby-mass-assignment-permit-all
    params.require(:account).permit!
  end
end
