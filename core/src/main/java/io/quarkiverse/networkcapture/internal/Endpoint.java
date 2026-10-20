package io.quarkiverse.networkcapture.internal;

import java.net.InetAddress;

/**
 * The local address and port of a process's socket. A null {@link #address()} is a wildcard bind, such as
 * {@code 0.0.0.0} or {@code ::}, which matches a packet on any address of this machine.
 * <p>
 * The address is held in the same textual form that a packet's is decoded into, so that the two compare as
 * strings: an IPv4 address as a dotted quad, an IPv6 address as {@link InetAddress#getHostAddress()} renders it,
 * and an IPv4-mapped IPv6 address as the IPv4 address it maps to.
 */
public record Endpoint(String address, int port) {

    /**
     * The endpoint of a socket bound to a wildcard address, which matches a packet on any address of this machine.
     */
    public Endpoint(int port) {
        this(null, port);
    }

    /**
     * The endpoint of a socket bound to an address literal, which may be bracketed or carry a zone, as lsof writes
     * it. The address is a wildcard when the literal is {@code *}, is unspecified, or is not an address.
     */
    public static Endpoint of(String literal, int port) {
        return new Endpoint(normalize(literal), port);
    }

    /**
     * The canonical form of an address literal, or null when it is a wildcard or is not an address.
     */
    public static String normalize(String literal) {
        if (literal == null || literal.isEmpty() || literal.equals("*")) {
            return null;
        }
        String bare = literal.startsWith("[") && literal.endsWith("]")
                ? literal.substring(1, literal.length() - 1)
                : literal;
        int zone = bare.indexOf('%');
        if (zone >= 0) {
            bare = bare.substring(0, zone);
        }
        try {
            return canonical(InetAddress.ofLiteral(bare));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * The canonical form of an address, or null when it is a wildcard.
     */
    public static String canonical(InetAddress address) {
        return address.isAnyLocalAddress() ? null : address.getHostAddress();
    }

    /**
     * Whether a packet carrying this address and port is this socket's traffic.
     */
    public boolean matches(String packetAddress, int packetPort) {
        return port == packetPort && (address == null || address.equals(packetAddress));
    }
}
