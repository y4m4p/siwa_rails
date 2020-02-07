module Auth
  class AppleController < ActionController::API
    def auth
      # name will only be present for the initial request.
      param! :name, String, blank: true, required: false
      param! :authorization_code, String, min_length: 5, blank: true, required: true
      param! :id_token, String, min_length: 5, blank: true, required: true

      @payload = Apple::SignInWithAppleService.new(authorization_code, id_token, client_id).verify_credentials!

      render json: @payload
    end

    private

      def id_token
        params[:id_token]
      end

      def authorization_code
        params[:authorization_code]
      end

      def name
        params[:name]
      end

      def client_id
        # The application identifier for your app.
        ENV.fetch("APPLE_APP_ID", nil)
      end

  end
end