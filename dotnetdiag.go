package dotnetdiag

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"

	"golang.org/x/text/encoding/unicode"
)

var (
	ErrSessionIDMismatch = fmt.Errorf("session ID missmatch")
	ErrHeaderMalformed   = fmt.Errorf("malformed header")
	ErrDiagnosticServer  = fmt.Errorf("diagnostic server")
)

// DOTNET_IPC_V1 magic header.
var magic = [...]byte{0x44, 0x4F, 0x54, 0x4E, 0x45, 0x54, 0x5f, 0x49, 0x50, 0x43, 0x5F, 0x56, 0x31, 0x00}

type Header struct {
	Magic      [14]uint8
	Size       uint16
	CommandSet uint8
	CommandID  uint8
	Reserved   uint16
}

const headerSize = 20

const (
	_ = iota
	CommandSetDump
	CommandSetEventPipe
	CommandSetProfiler
	CommandSetProcess

	CommandSetServer = 0xFF
)

const (
	_ = iota
	EventPipeStopTracing
	EventPipeCollectTracing
	EventPipeCollectTracing2

	ProcessInfo2 = 4
)

type CollectTracingPayload struct {
	CircularBufferSizeMB uint32
	Format               Format
	Providers            []ProviderConfig
}

type Format uint32

const (
	FormatNetPerf Format = iota
	FormatNetTrace
)

type ProviderConfig struct {
	Keywords     uint64
	LogLevel     uint32
	ProviderName string
	FilterData   string
}

type ErrorResponse struct {
	Code uint32
}

type CollectTracingResponse struct {
	SessionID uint64
}

type StopTracingPayload struct {
	SessionID uint64
}

type StopTracingResponse struct {
	SessionID uint64
}

type ProcessInfo2Response struct {
	ProcessId                     uint64
	CommandLine                   string
	OS                            string
	Arch                          string
	RuntimeCookie                 [16]byte
	ManagedEntrypointAssemblyName string
	ClrProductVersion             string
}

func writeMessage(w io.Writer, commandSet, commandID uint8, payload []byte) error {
	bw := bufio.NewWriter(w)
	err := binary.Write(bw, binary.LittleEndian, Header{
		Magic:      magic,
		Size:       uint16(headerSize + len(payload)),
		CommandSet: commandSet,
		CommandID:  commandID,
		Reserved:   0,
	})
	if err != nil {
		return err
	}
	if _, err = bw.Write(payload); err != nil {
		return err
	}
	return bw.Flush()
}

func readResponseHeader(r io.Reader) error {
	var h Header
	if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
		return err
	}
	if h.Magic != magic {
		return ErrHeaderMalformed
	}
	if !(h.CommandSet == CommandSetServer && h.CommandID == 0xFF) {
		return nil
	}
	// TODO: improve error handling.
	var er ErrorResponse
	if err := binary.Read(r, binary.LittleEndian, &er); err != nil {
		return err
	}
	return fmt.Errorf("%w: error code %#x", ErrDiagnosticServer, er.Code)
}

func (p CollectTracingPayload) Bytes() []byte {
	b := new(bytes.Buffer)
	_ = binary.Write(b, binary.LittleEndian, p.CircularBufferSizeMB)
	_ = binary.Write(b, binary.LittleEndian, p.Format)
	_ = binary.Write(b, binary.LittleEndian, uint32(len(p.Providers)))
	for _, x := range p.Providers {
		_ = binary.Write(b, binary.LittleEndian, x.Keywords)
		_ = binary.Write(b, binary.LittleEndian, x.LogLevel)
		b.Write(mustStringBytes(x.ProviderName))
		b.Write(mustStringBytes(x.FilterData))
	}
	return b.Bytes()
}

func (p StopTracingPayload) Bytes() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, p.SessionID)
	return b
}

var enc = unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()

func mustStringBytes(s string) []byte {
	b := new(bytes.Buffer) // TODO pre-allocate
	if len(s) > 0 {
		_ = binary.Write(b, binary.LittleEndian, uint32(len(s)+1))
		x, err := enc.Bytes([]byte(s))
		if err != nil {
			panic(err)
		}
		b.Write(x)
	}
	_ = binary.Write(b, binary.LittleEndian, uint16(0))
	return b.Bytes()
}

func readUtf16String(r io.Reader) (string, error) {
	var l uint32
	if err := binary.Read(r, binary.LittleEndian, &l); err != nil {
		return "", err
	}
	if l == 0 {
		return "", errors.New("invalid string length")
	}
	data := make([]uint16, l)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return "", err
	}
	return string(utf16.Decode(data[:len(data)-1])), nil
}
