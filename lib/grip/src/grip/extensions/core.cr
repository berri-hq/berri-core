require "./*"

class HTTP::Server::Context
  include Grip::Extensions::Context
end

class HTTP::Server::Response
  include Grip::Extensions::Response
end

class String
  include Grip::Extensions::String
end

abstract struct Number
  include Grip::Extensions::Number
end
