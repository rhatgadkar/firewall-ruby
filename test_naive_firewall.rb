# Unit tests to check functionality of naive_firewall.py.
#
# These unit tests can be run in the terminal using this command:
#   ruby test_naive_firewall.rb

require_relative "firewall_rule"
require_relative "naive_firewall"
require "test/unit"

class TestNaiveFirewall < Test::Unit::TestCase

	def test_no_add_duplicate_rules
		# Verify that duplicate rules cannot be added.
		fw = Firewall.new
		fw.add_fw_rule(
			FirewallRule.new(
				direction: "inbound", protocol: "tcp", port: "80",
				ip_address: "192.168.1.2"
			)
		)
		assert_equal(fw.fw_rules.length, 1)
		fw.add_fw_rule(
			FirewallRule.new(
				direction: "inbound", protocol: "tcp", port: "80",
				ip_address: "192.168.1.2"
			)
		)
		assert_equal(fw.fw_rules.length, 1)
	end

	def test_no_add_duplicate_range_port_rules
		# Verify that duplicate range port rules cannot be added.
		fw = Firewall.new
		fw.add_fw_rule(
			FirewallRule.new(
				direction: "inbound", protocol: "tcp", port: "50-100",
				ip_address: "192.168.1.2"
			)
		)
		assert_equal(fw.fw_rules.length, 1)
		fw.add_fw_rule(
			FirewallRule.new(
				direction: "inbound", protocol: "tcp", port: "50-100",
				ip_address: "192.168.1.2"
			)
		)
		assert_equal(fw.fw_rules.length, 1)
	end

	def test_no_add_duplicate_ipaddr_rules
		# Verify that duplicate range IP address rules cannot be added.
		fw = Firewall.new
		fw.add_fw_rule(
			FirewallRule.new(
				direction: "inbound", protocol: "tcp", port: "80",
				ip_address: "192.168.1.2-192.168.2.2"
			)
		)
		assert_equal(fw.fw_rules.length, 1)
		fw.add_fw_rule(
			FirewallRule.new(
				direction: "inbound", protocol: "tcp", port: "80",
				ip_address: "192.168.1.2-192.168.2.2"
			)
		)
		assert_equal(fw.fw_rules.length, 1)
	end

	def test_firewall_allow_packet
		# Verify firewall allows a packet that matches a rule.
		fw = Firewall.new
		fw.add_fw_rule(
			FirewallRule.new(
				direction: "inbound", protocol: "tcp", port: "80",
				ip_address: "192.168.1.2"
			)
		)
		assert(
			fw.accept_packet(
				direction: "inbound", protocol: "tcp", port: 80,
				ip_address: "192.168.1.2"
			)
		)
	end

	def test_firewall_block_packet
		# Verify firewall blocks a packet that doesn't match a rule
		fw = Firewall.new
		fw.add_fw_rule(
			FirewallRule.new(
				direction: "inbound", protocol: "tcp", port: "80",
				ip_address: "192.168.1.2"
			)
		)
		assert(
			!fw.accept_packet(
				direction: "outbound", protocol: "tcp", port: 80,
				ip_address: "192.168.1.2"
			)
		)
		assert(
			!fw.accept_packet(
				direction: "inbound", protocol: "udp", port: 80,
				ip_address: "192.168.1.2"
			)
		)
		assert(
			!fw.accept_packet(
				direction: "inbound", protocol: "udp", port: 81,
				ip_address: "192.168.1.2"
			)
		)
		assert(
			!fw.accept_packet(
				direction: "outbound", protocol: "tcp", port: 80,
				ip_address: "192.168.1.3"
			)
		)
	end

  def test_firewall_allow_range_port_packet
    # Verify firewall allows a packet that matches a rule with ranged port
    # numbers.
    fw = Firewall.new
    fw.add_fw_rule(
      FirewallRule.new(
        direction: "inbound", protocol: "tcp", port: "1-65535",
        ip_address: "192.168.1.2"
      )
    )
    assert(
      fw.accept_packet(
        direction: "inbound", protocol: "tcp", port: 1,
        ip_address: "192.168.1.2"
      )
    )
    assert(
      fw.accept_packet(
        direction: "inbound", protocol: "tcp", port: 65535,
        ip_address: "192.168.1.2"
      )
    )
    assert(
      fw.accept_packet(
        direction: "inbound", protocol: "tcp", port: 30000,
        ip_address: "192.168.1.2"
      )
    )
  end

  def test_firewall_block_range_port_packet
    # Verify firewall blocks a packet that doesn't match a rule with ranged
    # port numbers.
    fw = Firewall.new
    fw.add_fw_rule(
      FirewallRule.new(
        direction: "inbound", protocol: "tcp", port: "80-90",
        ip_address: "192.168.1.2"
      )
    )
    assert(
      !fw.accept_packet(
        direction: "inbound", protocol: "tcp", port: 79,
        ip_address: "192.168.1.2"
      )
    )
    assert(
      !fw.accept_packet(
        direction: "inbound", protocol: "tcp", port: 91,
        ip_address: "192.168.1.2"
      )
    )
  end

  def test_firewall_allow_range_ipaddr_packet
    # Verify firewall allows a packet that matches a rule with ranged IP
    # addresses.
    fw = Firewall.new
    fw.add_fw_rule(
      FirewallRule.new(
        direction: "inbound", protocol: "tcp", port: "80",
        ip_address: "0.0.0.0-255.255.255.255"
      )
    )
    assert(
      fw.accept_packet(
        direction: "inbound", protocol: "tcp", port: 80,
        ip_address: "0.0.0.0"
      )
    )
    assert(
      fw.accept_packet(
        direction: "inbound", protocol: "tcp", port: 80,
        ip_address: "255.255.255.255"
      )
    )
    assert(
      fw.accept_packet(
        direction: "inbound", protocol: "tcp", port: 80,
        ip_address: "192.168.1.2"
      )
    )
  end

  def test_firewall_block_range_ipaddr_packet
    # Verify firewall blocks a packet that doesn't match a rule with ranged IP
    # addresses.
    fw = Firewall.new
    fw.add_fw_rule(
      FirewallRule.new(
        direction: "inbound", protocol: "tcp", port: "80",
        ip_address: "192.168.1.2-192.168.2.1"
      )
    )
    assert(
      !fw.accept_packet(
        direction: "inbound", protocol: "tcp", port: 80,
        ip_address: "192.168.1.1"
      )
    )
    assert(
      !fw.accept_packet(
        direction: "inbound", protocol: "tcp", port: 91,
        ip_address: "192.168.2.2"
      )
    )
  end

end
