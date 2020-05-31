# This file defines the data structure to represent a firewall rule.

require_relative "ip_address"

class FirewallRule

  attr_reader :direction, :protocol, :min_port, :max_port, :min_ip, :max_ip

  def initialize(direction:, protocol:, port:, ip_address:)
    # Constructs a firewall rule given the provided four fields.
    @direction = direction
    @protocol = protocol
    ports = port.split("-")
    if ports.length == 1
      @min_port = ports[0].to_i
      @max_port = ports[0].to_i
    else
      @min_port = ports[0].to_i
      @max_port = ports[1].to_i
    end
    ip_addresses = ip_address.split("-")
    if ip_addresses.length == 1
      @min_ip = IPAddress.new(ip_addresses[0])
      @max_ip = IPAddress.new(ip_addresses[0])
    else
      @min_ip = IPAddress.new(ip_addresses[0])
      @max_ip = IPAddress.new(ip_addresses[1])
    end
  end

  def is_match(direction, protocol, port, ip_address)
    # Determines whether the provided four fields match the current
    # `FirewallRule` object's four fields.
    if @direction != direction
      return false
    elsif @protocol != protocol
      return false
    elsif port < @min_port or port > @max_port
      return false
    else
      ip = IPAddress.new(ip_address)
      if ip < @min_ip or ip > @max_ip
        return false
      end
      true
    end
  end

  def ==(other)
    # Implements the "==" operator to compare `FirewallRule` objects.
    @direction == other.direction and @protocol == other.protocol and
    @min_port == other.min_port and @max_port == other.max_port and
    @min_ip == other.min_ip and @max_ip == other.max_ip
  end

  def hash
    # Implements the hash function for `FirewallRule` objects.
    [@direction, @protocol, @min_port, @max_port, @min_ip, @max_ip].hash
  end

  def eql?(other)
    # Implements the hash equality opertator to compare `FirewallRule` objects.
    hash == other.hash
  end

end
