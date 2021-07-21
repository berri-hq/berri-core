require "../../spec_helper"

describe Swagger::Objects::Server do
  describe "#new" do
    it "should works" do
      raw = Swagger::Objects::Server.new("http://example.com", "Production")
      raw.url.should eq "http://example.com"
      raw.description.should eq "Production"
      raw.variables.should be_nil
    end

    it "should accept url only" do
      raw = Swagger::Objects::Server.new("http://example.com")
      raw.url.should eq "http://example.com"
      raw.description.should be_nil
      raw.variables.should be_nil
    end
  end

  describe "#to_json" do
    it "should works" do
      raw = Swagger::Objects::Server.new("http://example.com", "Production")
      raw.to_json.should eq %Q{{"url":"http://example.com","description":"Production"}}

      raw = Swagger::Objects::Server.new("http://example.com")
      raw.to_json.should eq %Q{{"url":"http://example.com"}}
    end
  end
end
