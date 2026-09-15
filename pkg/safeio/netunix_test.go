package safeio

import "net"

// netListenUnix creates a unix socket at path and returns a closer. Kept in its
// own file so the walk test does not import net directly.
func netListenUnix(path string) (func(), error) {
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return func() { _ = l.Close() }, nil
}
