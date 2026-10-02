# frozen_string_literal: true

require "nmap/xml"

module Lictor
  # Recon bridge: nmap XML in, target inventory out. ruby-nmap (1.0.3,
  # postmodern) parses the XML; Lictor emits allowlist candidates in the
  # exact format the Gates accept - explicit host:port entries, wildcards
  # structurally impossible. Recon never runs nmap itself: the operator
  # scans, Lictor reads.
  module Recon
    Target = Struct.new(:host, :port, :service, :product, :version, keyword_init: false)

    module_function

    def from_nmap_xml(path)
      Nmap::XML.open(path).hosts.flat_map do |host|
        next [] unless host.status.state == :up

        host.ports.select { |port| port.state == :open }.map do |port|
          svc = port.service
          {
            host: host.address,
            port: port.number,
            service: svc&.name,
            product: svc&.product,
            version: svc&.version
          }
        end
      end
    end

    def allowlist_candidates(path)
      from_nmap_xml(path).map { |t| "#{t[:host]}:#{t[:port]}" }
    end
  end
end
