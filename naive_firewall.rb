# Implements a naive firewall which stores firewall rules in a list.
#
# This program can be run in the terminal using this command:
#   ruby naive_firewall.rb

require_relative "firewall_rule"
require "csv"
require "set"

class Firewall

  attr_reader :fw_rules

  def initialize(csv_file_path = nil)
    # Initialize the firewall by reading and storing the firewall rules of the
    # CSV file.
    @fw_rules = Set.new
    if csv_file_path
      CSV.foreach(csv_file_path) do |csv_fw_rule|
        direction, protocol, port, ip_address = csv_fw_rule
        add_fw_rule(
          FirewallRule.new(
            direction: direction, protocol: protocol, port: port,
            ip_address: ip_address
          )
        )
      end
    end
  end

  def add_fw_rule(fw_rule)
    # Add the provided firewall rule to the data structure.
    @fw_rules.add(fw_rule)
  end

  def accept_packet(direction:, protocol:, port:, ip_address:)
    # Determine whether the firewall can accept the packet with its rules.
    @fw_rules.each do |fw_rule|
      if fw_rule.is_match(direction, protocol, port, ip_address)
        return true
      end
    end
    false
  end

end

if __FILE__ == $0
  start_time = Time.now.to_f
  fw = Firewall.new("500k_rules.csv")
  end_time = Time.now.to_f
  duration = end_time - start_time
  puts "Naive firewall time duration to add rules: #{duration}"

  start_time = Time.now.to_f
  res = fw.accept_packet(
    direction: "inbound", protocol: "tcp", port: 80, ip_address: "192.168.1.2"
  )
  puts "#{res}"
  res = fw.accept_packet(
    direction: "inbound", protocol: "udp", port: 53, ip_address: "192.168.2.1"
  )
  puts "#{res}"
  res = fw.accept_packet(
    direction: "outbound", protocol: "tcp", port: 10234,
    ip_address: "192.168.10.11"
  )
  puts "#{res}"
  res = fw.accept_packet(
    direction: "inbound", protocol: "tcp", port: 81, ip_address: "192.168.1.2"
  )
  puts "#{res}"
  res = fw.accept_packet(
    direction: "inbound", protocol: "udp", port: 24, ip_address: "52.12.48.92"
  )
  puts "#{res}"
  end_time = Time.now.to_f
  duration = end_time - start_time
  puts "Naive firewall time duration to accept packets: #{duration}"
end
