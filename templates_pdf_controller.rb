# frozen_string_literal: true

# POST /api/templates/pdf for open-source DocuSeal.
#
# The open-source distribution ships every library this endpoint needs — PDF
# decryption, AcroForm extraction, pdfium rendering, page previews, SHA-256 and
# blob upload all live in Templates::CreateAttachments — and lib/ability.rb
# grants `create` on Template with no licence check. The Pro edition withholds
# the feature purely by not shipping a controller and not drawing the route, so
# adding both back is enough to make it work.
#
# This is a port of app/controllers/templates_uploads_controller.rb (the web-UI
# "upload a PDF" flow) onto Api::ApiBaseController, so X-Auth-Token auth,
# current_account and CanCan authorisation behave exactly as they do for every
# other /api endpoint.
#
# Deliberately NOT supported (see docuseal-ext/README.md): `file` as a
# downloadable URL, `external_id` upsert, `shared_link`, `flatten`,
# `remove_tags`. 9D sends none of them, and the URL form in particular is an
# outbound fetch driven by request input.
module Api
  class TemplatesPdfController < ApiBaseController
    # NOTE: none of the private methods below may be named `create_params`,
    # `template_params` or `resource_params` — CanCanCan treats those as the
    # strong-parameters source for `Template.new` and would try to assign
    # `documents`/`folder_name` as columns.
    load_and_authorize_resource :template, parent: false

    InvalidRequest = Class.new(StandardError)

    rescue_from InvalidRequest,
                ActiveRecord::RecordInvalid,
                Templates::CreateAttachments::InvalidFileType do |e|
      render json: { error: e.message }, status: :unprocessable_content
    end

    rescue_from Templates::CreateAttachments::PdfEncrypted do
      render json: { error: 'PDF is password-protected; supply `password`.' }, status: :unprocessable_content
    end

    def create
      @default_submitter_claimed = false

      documents_params = permitted_params[:documents].to_a

      raise InvalidRequest, '`documents` must be a non-empty array.' if documents_params.blank?

      files = documents_params.map { |document| build_uploaded_file(document) }

      save_template!(files)

      attachments, = Templates::CreateAttachments.call(
        @template, { files:, password: permitted_params[:password] }, extract_fields: true
      )

      schema = attachments.map { |a| { 'attachment_uuid' => a.uuid, 'name' => a.filename.base } }

      # Explicit `fields` win. With none, fall back to whatever the PDF itself
      # declared (AcroForm widgets / {{...}} text tags) — what the web flow does.
      fields = build_fields(documents_params, attachments)
      fields = Templates::ProcessDocument.normalize_attachment_fields(@template, attachments) if fields.blank?

      @template.update!(schema:, fields:)

      WebhookUrls.enqueue_events(@template, 'template.created')

      SearchEntries.enqueue_reindex(@template)

      render json: Templates::SerializeForApi.call(@template)
    end

    private

    def permitted_params
      @permitted_params ||= params.permit(
        :name,
        :folder_name,
        :password,
        documents: [
          :name,
          :file,
          { fields: [
            :name, :type, :role, :required, :title, :description,
            { areas: %i[x y w h page option] }
          ] }
        ]
      )
    end

    def save_template!(files)
      @template.account = current_account
      @template.author = current_user
      @template.folder = TemplateFolders.find_or_create_by_name(current_user, permitted_params[:folder_name])
      @template.name = permitted_params[:name].presence || File.basename(files.first.original_filename, '.*')

      # A Template built in memory carries its default submitter exactly as the
      # model's `attribute :submitters` default declares it. Round-tripping
      # through as_json guarantees string keys, which is what every reader
      # downstream (including normalize_attachment_fields) indexes by.
      @template.submitters = @template.submitters.as_json

      Templates.maybe_assign_access(@template)

      @template.save!
    end

    # Base64 -> ActionDispatch::Http::UploadedFile via a Tempfile, following
    # TemplatesUploadsController#create_file_params_from_url. Content type is
    # sniffed from the bytes, never trusted from the supplied name.
    def build_uploaded_file(document)
      filename = document[:name].to_s.strip

      raise InvalidRequest, 'Each document requires a `name`.' if filename.blank?

      tempfile = Tempfile.new
      tempfile.binmode
      tempfile.write(decode_file(document[:file]))
      tempfile.rewind

      type = Marcel::MimeType.for(tempfile)

      # Rejecting archives up front keeps documents[i] aligned with the
      # attachment CreateAttachments returns at index i, which is how fields are
      # bound to their document. extract_zip_files would fan one entry out into
      # several and break that mapping.
      unless type == Templates::CreateAttachments::PDF_CONTENT_TYPE || type.include?('image')
        raise InvalidRequest, "Unsupported document content type `#{type}`; expected a PDF."
      end

      ActionDispatch::Http::UploadedFile.new(tempfile:, filename:, type:)
    end

    def decode_file(value)
      value = value.to_s

      raise InvalidRequest, 'Each document requires a base64-encoded `file`.' if value.blank?

      if value.start_with?('http://', 'https://')
        raise InvalidRequest, '`file` must be base64-encoded content; downloadable URLs are not supported.'
      end

      begin
        Base64.strict_decode64(value)
      rescue ArgumentError
        # Some clients wrap base64 at 76 columns (MIME); strict_decode64 rejects
        # the newlines, decode64 does not.
        Base64.decode64(value)
      end
    end

    # @return [Array<Hash>] template `fields`, one flat list across all documents.
    def build_fields(documents_params, attachments)
      documents_params.each_with_index.flat_map do |document, index|
        attachment = attachments[index]

        next [] if attachment.nil?

        document[:fields].to_a.map { |field| build_field(field, attachment) }
      end
    end

    def build_field(field, attachment)
      {
        'uuid' => SecureRandom.uuid,
        'submitter_uuid' => submitter_uuid_for(field[:role]),
        'name' => field[:name].presence,
        'type' => field[:type].presence || 'text',
        'required' => field.key?(:required) ? ActiveModel::Type::Boolean.new.cast(field[:required]) : true,
        'title' => field[:title].presence,
        'description' => field[:description].presence,
        'preferences' => {},
        'areas' => field[:areas].to_a.map { |area| build_area(area, attachment) }
      }.compact
    end

    # PAGE INDEXING — the one thing here worth reading twice.
    #
    # The Pro API documents `page` as 1-based ("Page number of the field area.
    # Starts from 1.", docs/openapi.json), while DocuSeal *stores* it 0-based:
    # the signing form resolves the DOM id `page-{attachment_uuid}-{page}` and
    # Submissions::GenerateResultAttachments does `pdf.pages[area['page']]`.
    #
    # An EXPLICIT `page` is accepted 1-based and decremented, so this patch
    # stays drop-in if upstream ever ships the endpoint. Anything below 1 is
    # clamped to page 1 rather than silently becoming -1 — which in Ruby indexes
    # the LAST page when stamping, while rendering nowhere at all in the signing
    # form.
    #
    # DIVERGENCE FROM PRO — an ABSENT `page` means the LAST page.
    # Pro documents no default, and there is no shipped endpoint to compare
    # against, so it presumably falls back to the first page. 9D needs the last
    # one: the integration puts its "sign here"
    # field there, which is also the only reading under which the y: 0.85 the
    # client sends makes sense — the bottom of page 1 is the middle of a
    # waiver's opening paragraph. A caller that wants the first page sends
    # `page: 1`, so no Pro-compatible behaviour is lost, only a default added
    # where Pro has none observable.
    def build_area(area, attachment)
      {
        'x' => area[:x].to_f,
        'y' => area[:y].to_f,
        'w' => area[:w].to_f,
        'h' => area[:h].to_f,
        'attachment_uuid' => attachment.uuid,
        'page' => area[:page].present? ? zero_based_page(area[:page]) : last_page_index(attachment)
      }.tap { |built| built['option'] = area[:option] if area[:option].present? }
    end

    def zero_based_page(value)
      [value.to_i, 1].max - 1
    end

    def last_page_index(attachment)
      [page_count(attachment), 1].max - 1
    end

    # Page count of an attachment CreateAttachments has already processed.
    #
    # Deliberately NOT a re-parse of the PDF. Templates::ProcessDocument has
    # already written the real pdfium page count onto the attachment —
    # `generate_pdf_preview_images` sets metadata['pdf']['number_of_pages'] from
    # `doc.page_count` and saves it, before CreateAttachments returns.
    #
    # This is the SAME expression app/views/submit_form/show.html.erb uses to
    # decide how many `page-{uuid}-{n}` containers to draw, so a last page
    # derived from it is guaranteed to match a container that exists.
    #
    # `preview_images.size` is only the fallback the view also carries: it is
    # right for an image attachment (one page, no 'pdf' metadata) and would be
    # WRONG for a long PDF, where previews stop at
    # ProcessDocument::MAX_NUMBER_OF_PAGES_PROCESSED and the rest are rendered
    # on demand — a 20-page PDF has 16 of them.
    def page_count(attachment)
      (attachment.metadata.dig('pdf', 'number_of_pages') || attachment.preview_images.size).to_i
    end

    # SUBMITTER ROLES.
    #
    # A fresh Template is created with exactly ONE default submitter. If the
    # first incoming role does not match it we RENAME that submitter instead of
    # appending, so the template never carries a submitter that owns no fields —
    # such a template produces a submission that cannot be completed. Further
    # distinct roles are appended as normal.
    def submitter_uuid_for(role)
      name = role.presence || Template::DEFAULT_SUBMITTER_NAME
      submitters = @template.submitters

      submitter =
        if (existing = submitters.find { |s| s['name'] == name })
          existing
        elsif submitters.one? && !@default_submitter_claimed
          submitters.first.tap { |s| s['name'] = name }
        else
          submitters.push({ 'name' => name, 'uuid' => SecureRandom.uuid }).last
        end

      # Once the first role is resolved the default submitter is either matched
      # or renamed; either way it must never be renamed a second time.
      @default_submitter_claimed = true

      submitter['uuid']
    end
  end
end
