module Grip
  module Exceptions
    class NotFound < Base
      def initialize
        @status = HTTP::Status::NOT_FOUND
        super "The endpoint you have requested was not found on the server."
      end

      def status_code : Int32
        @status.not_nil!.value
      end
    end
  end
end
