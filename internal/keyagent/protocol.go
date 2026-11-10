package keyagent

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/api-go/safe"
)

const maxFrame = 64 * 1024
const (
	opPing byte = iota
	opKeep
	opExport
	opForget
	opForgetAll
)

var errNotRunning = errors.New("key agent is not running")
var ErrUnavailable = errors.New("key agent unavailable")
var ErrNotKept = errors.New("key is not kept or has expired")

// One bounded binary message per connection. Secret material never enters JSON,
// command-line arguments, environment variables, or a persistent file.
func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > maxFrame {
		return nil, errors.New("invalid agent frame length")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		safe.ZeroMemory(data)
		return nil, err
	}
	return data, nil
}
func writeFrame(w io.Writer, data []byte) error {
	if len(data) == 0 || len(data) > maxFrame {
		return errors.New("invalid agent frame length")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, data)
}
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

type request struct {
	Op             byte
	Name, Language string
	TTL            int64
	Fingerprint    [32]byte
	Secret         []byte
}

func encodeRequest(r request) ([]byte, error) {
	if len(r.Name) > 255 || len(r.Language) > 32 || len(r.Secret) > 128 {
		return nil, errors.New("invalid agent request")
	}
	data := make([]byte, 43+len(r.Name)+len(r.Language)+len(r.Secret))
	data[0] = r.Op
	binary.BigEndian.PutUint64(data[1:9], uint64(r.TTL))
	copy(data[9:41], r.Fingerprint[:])
	data[41], data[42] = byte(len(r.Name)), byte(len(r.Language))
	n := 43
	n += copy(data[n:], r.Name)
	n += copy(data[n:], r.Language)
	copy(data[n:], r.Secret)
	return data, nil
}
func decodeRequest(data []byte) (request, error) {
	if len(data) < 43 {
		return request{}, errors.New("invalid agent request")
	}
	a, b := int(data[41]), int(data[42])
	if a > 255 || b > 32 || 43+a+b > len(data) {
		return request{}, errors.New("invalid agent request")
	}
	r := request{Op: data[0], TTL: int64(binary.BigEndian.Uint64(data[1:9])), Name: string(data[43 : 43+a]), Language: string(data[43+a : 43+a+b]), Secret: data[43+a+b:]}
	copy(r.Fingerprint[:], data[9:41])
	return r, nil
}
