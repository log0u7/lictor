# frozen_string_literal: true

require 'lictor'
require 'augure'
require 'tmpdir'

RSpec.describe Lictor::Recon do
  let(:fixture) { File.expand_path('fixtures/nmap_scan.xml', __dir__) }

  describe '.from_nmap_xml' do
    it 'inventories open services of live hosts only' do
      targets = described_class.from_nmap_xml(fixture)
      expect(targets).to eq([
                              { host: '192.168.56.10', port: 22, service: 'ssh', product: 'OpenSSH', version: '8.9p1' },
                              { host: '192.168.56.10', port: 80, service: 'http', product: 'nginx', version: '1.18.0' },
                              { host: '192.168.56.11', port: 21, service: 'ftp', product: 'vsftpd', version: '2.3.4' }
                            ])
    end
  end

  describe '.service_candidates' do
    it 'emits host:port entries matching the allowlist format' do
      expect(described_class.service_candidates(fixture))
        .to contain_exactly('192.168.56.10:22', '192.168.56.10:80', '192.168.56.11:21')
    end

    it 'never contains wildcards (the gate contract)' do
      described_class.service_candidates(fixture).each do |entry|
        expect(entry).not_to include('*')
      end
    end
  end

  describe '.facts' do
    it 'emits network facts the augure engine parses' do
      facts_text = described_class.facts(fixture)
      facts = Augure::Facts.parse(facts_text)
      expect(facts.rel('remote')).to eq([['true']])
      expect(facts.rel('service')).to include(['ssh'], ['http'], ['ftp'])
      expect(facts.rel('software_version')).to include(['OpenSSH 8.9p1'])
    end

    it 'sanitizes the banner data - a hostile target cannot forge facts' do
      dir = Dir.mktmpdir
      # an XML whose version carries a quote: the sanitized fact stays parseable
      xml = File.join(dir, 'scan.xml')
      File.write(xml, <<~X)
        <nmaprun>
          <host><status state="up"/><address addr="10.9.9.9" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="80"><state state="open"/>
          <service name="http" product="nginx" version="1.0") .
          nx("false"/></service>
          </ports></host></nmaprun>
      X
      facts = described_class.facts(xml)
      expect { Augure::Facts.parse(facts) }.not_to raise_error
      expect(facts).not_to include('nx("false")')
    end
  end
end
