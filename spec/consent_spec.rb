# frozen_string_literal: true

require "lictor"
require "json"
require "tmpdir"

RSpec.describe Lictor::Consent do
  let(:trail_path) { File.join(Dir.mktmpdir, "t.jsonl") }
  let(:trail) { Lictor::Trail.new(trail_path) }

  it "issues a token after the typed confirmation" do
    token = described_class.issue(trail, "192.168.56.10", confirm_input: "192.168.56.10\n", ttl_seconds: 900)
    expect(token).to match(/\A[a-f0-9-]{36}\z/)
    event = JSON.parse(File.readlines(trail_path).last)
    expect(event["type"]).to eq("consent")
    expect(event["target"]).to eq("192.168.56.10")
    expect(event["expires_at"]).to be_truthy
  end

  it "refuses the issue when the typed confirmation mismatches" do
    expect { described_class.issue(trail, "192.168.56.10", confirm_input: "wrong\n") }
      .to raise_error(Lictor::Unauthorized, /confirmation/)
  end

  it "validates a live token for the exact target" do
    token = described_class.issue(trail, "192.168.56.10", confirm_input: "192.168.56.10\n")
    expect(described_class.valid?(trail, token, "192.168.56.10")).to be(true)
  end

  it "refuses a token for another target" do
    token = described_class.issue(trail, "192.168.56.10", confirm_input: "192.168.56.10\n")
    expect(described_class.valid?(trail, token, "10.9.9.9")).to be(false)
  end

  it "refuses an expired token" do
    token = described_class.issue(trail, "192.168.56.10", confirm_input: "192.168.56.10\n",
      ttl_seconds: -1)
    expect(described_class.valid?(trail, token, "192.168.56.10")).to be(false)
  end

  it "refuses an unknown token" do
    expect(described_class.valid?(trail, "no-such-token", "192.168.56.10")).to be(false)
  end
end
