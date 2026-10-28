package quic

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// This exercises the same packet-local append used for a 1-RTT packet after
// long-header packets have already been written into a coalesced datagram.
func TestPacketPaddingRespectsCoalescedDatagramBudget(t *testing.T) {
	const (
		maxDatagramSize = 1200
		prefixSize      = 1000
		aeadOverhead    = 16
	)
	version := protocol.Version1
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	sealer := reviewShortHeaderSealer{}
	prefix := reviewInitialPacket(t, prefixSize, connID, sealer, version)
	buffer := &packetBuffer{Data: make([]byte, prefixSize, maxDatagramSize)}
	copy(buffer.Data, prefix)
	pnManager := &reviewPacketNumberManager{pn: 7}

	datagram := &wire.DatagramFrame{DataLenPresent: true, Data: []byte("datagram-data")}
	stream := &wire.StreamFrame{StreamID: 0, DataLenPresent: true, Data: []byte("stream-data")}
	pl := payload{
		frames:       []ackhandler.Frame{{Frame: datagram}},
		streamFrames: []ackhandler.StreamFrame{{Frame: stream}},
		length:       datagram.Length(version) + stream.Length(version),
	}
	packer := &packetPacker{
		packetPadding: &packetPaddingState{
			cfg:          PacketPaddingConfig{MaxPadding: 256, BurstBytes: 512, BytesPerSecond: 64},
			tokens:       512,
			adaptiveBias: 1000, // makes the selected target equal the supplied maximum.
		},
		pnManager: pnManager,
		rand:      *rand.New(rand.NewPCG(1, 2)),
	}

	shortPacket, err := packer.appendShortHeaderPacket(
		buffer,
		connID,
		pnManager.pn,
		protocol.PacketNumberLen2,
		protocol.KeyPhaseBit(0),
		pl,
		0,
		maxDatagramSize-prefixSize,
		sealer,
		false,
		version,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := buffer.Len(); got > maxDatagramSize {
		t.Fatalf("coalesced datagram length = %d, want <= %d", got, maxDatagramSize)
	}
	if got := shortPacket.Length; got != maxDatagramSize-prefixSize {
		t.Fatalf("short-header packet length = %d, want %d (padding should use the available budget)", got, maxDatagramSize-prefixSize)
	}
	if !bytes.Equal(buffer.Data[:prefixSize], prefix) {
		t.Fatal("appending the 1-RTT packet changed the existing long-header prefix")
	}

	// The test sealer leaves the packet plaintext intact, allowing us to parse
	// the padded payload and verify both non-padding frames survived unchanged.
	shortHeaderLen := int(wire.ShortHeaderLen(connID, protocol.PacketNumberLen2))
	payloadStart := prefixSize + shortHeaderLen
	payloadEnd := buffer.Len() - aeadOverhead
	frames := buffer.Data[payloadStart:payloadEnd]
	parser := wire.NewFrameParser(true, false, false)
	var gotDatagram, gotStream bool
	for len(frames) > 0 {
		frameType, typeLen, err := parser.ParseType(frames, protocol.Encryption1RTT)
		if err != nil {
			t.Fatal(err)
		}
		frames = frames[typeLen:]
		switch frameType {
		case wire.FrameTypeDatagramWithLength:
			parsed, n, err := parser.ParseDatagramFrame(frameType, frames, version)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(parsed.Data, datagram.Data) {
				t.Fatalf("DATAGRAM data = %q, want %q", parsed.Data, datagram.Data)
			}
			gotDatagram = true
			frames = frames[n:]
		default:
			if !frameType.IsStreamFrameType() {
				t.Fatalf("unexpected frame type %v", frameType)
			}
			parsed, n, err := parser.ParseStreamFrame(frameType, frames, version)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.StreamID != stream.StreamID || !bytes.Equal(parsed.Data, stream.Data) {
				t.Fatalf("STREAM frame = (id %d, data %q), want (id %d, data %q)", parsed.StreamID, parsed.Data, stream.StreamID, stream.Data)
			}
			gotStream = true
			frames = frames[n:]
		}
	}
	if !gotDatagram || !gotStream {
		t.Fatalf("decoded frames: DATAGRAM=%t STREAM=%t", gotDatagram, gotStream)
	}
}

func reviewInitialPacket(t *testing.T, size int, connID protocol.ConnectionID, sealer reviewShortHeaderSealer, version protocol.Version) []byte {
	t.Helper()
	crypto := &wire.CryptoFrame{Data: bytes.Repeat([]byte{0x5a}, 900)}
	pl := payload{frames: []ackhandler.Frame{{Frame: crypto}}, length: crypto.Length(version)}
	p := &packetPacker{rand: *rand.New(rand.NewPCG(3, 4))}
	for padding := protocol.ByteCount(0); padding < protocol.ByteCount(size); padding++ {
		buffer := &packetBuffer{Data: make([]byte, 0, size)}
		header := &wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeInitial,
				Version:          version,
				DestConnectionID: connID,
				SrcConnectionID:  connID,
			},
			PacketNumber:    1,
			PacketNumberLen: protocol.PacketNumberLen2,
		}
		if _, err := p.appendLongHeaderPacket(buffer, header, pl, padding, sealer, version); err != nil {
			t.Fatal(err)
		}
		if buffer.Len() == protocol.ByteCount(size) {
			_, initialPacket, rest, err := wire.ParsePacket(buffer.Data)
			if err != nil {
				t.Fatalf("generated Initial prefix is invalid: %v", err)
			}
			if len(initialPacket) != size || len(rest) != 0 {
				t.Fatalf("generated Initial prefix parsed as packet=%d rest=%d, want packet=%d rest=0", len(initialPacket), len(rest), size)
			}
			return buffer.Data
		}
	}
	t.Fatalf("couldn't construct a %d-byte Initial packet prefix", size)
	return nil
}

type reviewPacketNumberManager struct{ pn protocol.PacketNumber }

func (m *reviewPacketNumberManager) PeekPacketNumber(protocol.PacketNumberSpace) (protocol.PacketNumber, protocol.PacketNumberLen) {
	return m.pn, protocol.PacketNumberLen2
}
func (m *reviewPacketNumberManager) PopPacketNumber(protocol.PacketNumberSpace) protocol.PacketNumber {
	return m.pn
}

type reviewShortHeaderSealer struct{}

var _ handshake.ShortHeaderSealer = reviewShortHeaderSealer{}

func (reviewShortHeaderSealer) Seal(dst, src []byte, _ protocol.PacketNumber, _ []byte) []byte {
	dst = append(dst, src...)
	return append(dst, make([]byte, 16)...)
}
func (reviewShortHeaderSealer) EncryptHeader([]byte, *byte, []byte) {}
func (reviewShortHeaderSealer) Overhead() int                       { return 16 }
func (reviewShortHeaderSealer) KeyPhase() protocol.KeyPhaseBit      { return protocol.KeyPhaseBit(0) }
