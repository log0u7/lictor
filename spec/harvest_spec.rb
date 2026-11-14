# frozen_string_literal: true

require "lictor/harvest"

RSpec.describe Lictor::Harvest do
  # The real lab banners: one line, several names, each with its address.
  # The callme-eval banner is the regression case that caught the greedy
  # tail: every address collapsed onto the first label.
  describe "parse_banner" do
    it "pairs each address with its own label on one line" do
      banner = "callme-eval: arm() at 0x4011e6 fire() at 0x40122e open() at 0x401282 pop3() at 0x4011b6 probe() at 0x4011ba\nsequence? "
      got = Lictor::Harvest.parse_banner(banner)
      expect(got).to eq("arm" => 0x4011e6, "fire" => 0x40122e, "open" => 0x401282,
        "pop3" => 0x4011b6, "probe" => 0x4011ba)
    end

    it "pairs the eval twins' two leaks" do
      expect(Lictor::Harvest.parse_banner("srop-eval: gadget() at 0x401186 sh_cmd() at 0x401200\nname? "))
        .to eq("gadget" => 0x401186, "sh_cmd" => 0x401200)
      expect(Lictor::Harvest.parse_banner("ret2libc-eval: main() at 0x401200 vuln() at 0x401280 rdi() at 0x401300\nname? "))
        .to eq("main" => 0x401200, "vuln" => 0x401280, "rdi" => 0x401300)
    end

    it "names the single leak (orw-eval)" do
      expect(Lictor::Harvest.parse_banner("orw-eval: buf() at 0x7ffd1234\nname? "))
        .to eq("buf" => 0x7ffd1234)
    end

    it "falls back to the plain word before the address" do
      expect(Lictor::Harvest.parse_banner("ret2func: win at 0x4011d6\n"))
        .to eq("win" => 0x4011d6)
    end

    it "collapses nothing: the first label never owns the second address" do
      expect(Lictor::Harvest.parse_banner("callme-eval: arm() at 0x4011e6 fire() at 0x40122e"))
        .to have_key("fire")
    end
  end
end
