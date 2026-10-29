# frozen_string_literal: true

# Draws POST /api/templates/pdf -> Api::TemplatesPdfController#create.
#
# `config/routes.rb` declares `resources :templates, only: %i[update show index
# destroy]` inside `namespace :api` — no `create` — and carries no catch-all or
# glob route, so appending here cannot shadow or be shadowed by anything.
#
# Appending from an initializer (rather than editing config/routes.rb) keeps the
# upstream image byte-identical apart from two bind mounts. `routes.append`
# registers a block that Rails evaluates at the END of the route set every time
# routes are drawn, including on reload. The `zz_` prefix only makes the load
# order obvious to a human; correctness does not depend on it.
#
# Without this route ErrorsController rewrites the 404 for `/api/templates/pdf`
# into "This feature is available in Pro Edition" — that message is a 404
# handler, not a licence check.
Rails.application.routes.append do
  namespace :api, defaults: { format: :json } do
    post 'templates/pdf', to: 'templates_pdf#create', as: :templates_pdf
  end
end
