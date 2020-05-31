# This file defines the data structure to represent an IP address.

class IPAddress

  attr_reader :octets

  def initialize(ip_address)
    # Constructs the tuple to represent the provided IP address.
    @octets = ip_address.split(".")
  end

  def <(other)
    # Implements the "<" operator to compare `IPAddress` objects.
    for i in 1...4
      if @octets[i] < other.octets[i]
        return true
      elsif @octets[i] > other.octets[i]
        return false
      end
    end
    false
  end

  def >(other)
    # Implements the ">" operator to compare `IPAddress` objects.
    for i in 1...4
      if @octets[i] > other.octets[i]
        return true
      elsif @octets[i] < other.octets[i]
        return false
      end
    end
    false
  end

  def ==(other)
    # Implements the "==" operator to compare `IPAddress` objects.
    for i in 1...4
      if @octets[i] != other.octets[i]
        return false
      end
    end
    true
  end

  def hash
    # Implements the hash function for `IPAddress` objects.
    @octets.hash
  end

  def eql?(other)
    # Implements the hash equality operator to compare `IPAddress` objects.
    hash == other.hash
  end

end
