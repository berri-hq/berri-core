module Swagger
  struct Request
    # Returns request with scheme reference
    #
    # ```
    # Swagger::Request.new("User", "User struct", "application/x-www-form-urlencoded")
    # ```
    def self.new(ref name : String, description : String? = nil, content_type : String? = nil)
      schema = Schema.use_reference(name)
      new(schema, description, content_type)
    end

    # Returns request with properties
    #
    # ```
    # Swagger::Request.new([
    #   Swagger::Property.new("username", "string", "User name"),
    #   Swagger::Property.new("email", "string", ""),
    #   Swagger::Property.new("password"),
    #   Swagger::Property.new("confirm_password"),
    # ], "User form data", "application/x-www-form-urlencoded")
    # ```
    def self.new(properties request_properties : Array(Property), description : String? = nil, content_type : String? = nil)
      required = [] of String
      properties = request_properties.each_with_object(Hash(String, Objects::Property).new) do |property, obj|
        obj[property.name] = Objects::Property.new(type: property.type, description: property.description, default: property.default_value)
        required << property.name if property.required
      end

      schema = Schema.new(type: "object", properties: properties, required: required)
      new(schema, description, content_type)
    end

    def self.new(schema : Schema, description : String? = nil, content_type : String? = nil)
      new(MediaType.new(schema), description, content_type)
    end

    property media_type
    property description
    property content_type

    def initialize(@media_type : MediaType, @description : String? = nil, @content_type : String? = nil)
    end
  end
end
