# zuring-tls

minimalish use of tls with io_uring in Zig

## Purpose

The stdlib finally has TLS support, but the abstraction it presents has a few challenges when interfacing with io_uring without async support in the compiler. This is a minimal worked example highlighting strategies for marrying the two together.

## Examples

See [main.zig](https://github.com/hmusgrave/zuring-tls/blob/master/src/main.zig).
