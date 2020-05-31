# Implements a firewall which stores firewall rules to account for
# space and time complexity.
#
# This program can be run in the terminal using this command:
#   ruby firewall.rb

require_relative "firewall_rule"
require "csv"
require "set"

class Firewall

  attr_reader :fw_rules, :num_ports_bucket

  def initialize(csv_file_path = nil)
    # Initialize the firewall by reading and storing the firewall rules of the
    # CSV file.

    # initialize the data structure to store firewall rules
    num_buckets = 64
    @num_ports_bucket = 65536 / num_buckets
    @fw_rules = {
      "inbound" => {
        "tcp" => Array.new(num_buckets),
        "udp" => Array.new(num_buckets),
      },
      "outbound" => {
        "tcp" => Array.new(num_buckets),
        "udp" => Array.new(num_buckets),
      },
    }
    for i in 0...num_buckets
      @fw_rules["inbound"]["tcp"][i] = Set.new
      @fw_rules["inbound"]["udp"][i] = Set.new
      @fw_rules["outbound"]["tcp"][i] = Set.new
      @fw_rules["outbound"]["udp"][i] = Set.new
    end

    # read firewall rules from CSV file and add them to the data structure
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
    start_bucket = fw_rule.min_port / @num_ports_bucket
    end_bucket = fw_rule.max_port / @num_ports_bucket
    curr_fw_rules = @fw_rules[fw_rule.direction][fw_rule.protocol]
    for bucket_num in start_bucket..end_bucket
      curr_fw_rules[bucket_num].add(fw_rule)
    end
  end

  def accept_packet(direction:, protocol:, port:, ip_address:)
    # Determine whether the firewall can accept the packet with its rules.
    bucket_num = port / @num_ports_bucket
    @fw_rules[direction][protocol][bucket_num].each do |fw_rule|
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
  puts "Firewall time duration to add rules: #{duration}"

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
  puts "Firewall time duration to accept packets: #{duration}"
end
