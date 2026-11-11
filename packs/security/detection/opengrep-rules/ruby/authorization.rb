class NotebooksController < ApplicationController
  def index
    @notebooks = current_user.notebooks.where(archived: false)
  end

  def show
    # ruleid: traust-ruby-authorization-unscoped-find-beside-scoped
    @notebook = Notebook.find(params[:id])
  end

  def edit
    @notebook = current_user.notebooks.find(params[:id])
  end

  def publish
    # ok: traust-ruby-authorization-unscoped-find-beside-scoped
    @notebook = Notebook.find(params[:id])
    authorize @notebook
  end
end

class BadgesController < ApplicationController
  def index
    @badges = current_user.badges.where(active: true)
  end

  def revoke
    # ok: traust-ruby-authorization-unscoped-find-beside-scoped
    badge = Badge.find(params[:id])
    guardian.ensure_can_revoke!(badge)
    badge.destroy!
  end
end

class MembersController < ApplicationController
  def index
    @members = current_user.members.all
  end

  def impersonate
    if current_user.staff?
      # ok: traust-ruby-authorization-unscoped-find-beside-scoped
      @member = Member.find(params[:id])
    end
  end
end

class TagsController < ApplicationController
  def show
    # ok: traust-ruby-authorization-unscoped-find-beside-scoped
    @tag = Tag.find(params[:id])
  end
end
