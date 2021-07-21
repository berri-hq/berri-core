require "./spec_helper"

describe "Grip::Dsl::Macros" do
  it "Tests the HTTP verb macro" do
    app = HttpApplication.new
    app.run
  end

  it "Tests the WebSocket verb macro" do
    app = WebSocketApplication.new
    app.run
  end

  it "Tests the error macro" do
    app = ErrorApplication.new
    app.run
  end
end
