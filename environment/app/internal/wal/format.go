package wal

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"example.com/durable-relay/internal/model"
)

const (
	HeaderSize     = 24
	FormatVersion  = uint16(1)
	MaximumPayload = 4 << 20
)

var frameMagic = [4]byte{'D', 'R', 'W', '1'}

type Header struct {
	Magic    [4]byte
	Version  uint16
	Flags    uint16
	Length   uint32
	Checksum uint32
	Sequence uint64
}

func Encode(event model.Event) ([]byte, []byte, error) {
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal event: %w", err)
	}
	if len(payload) == 0 || len(payload) > MaximumPayload {
		return nil, nil, fmt.Errorf("event payload length %d is outside bounds", len(payload))
	}
	header := make([]byte, HeaderSize)
	copy(header[0:4], frameMagic[:])
	binary.LittleEndian.PutUint16(header[4:6], FormatVersion)
	binary.LittleEndian.PutUint16(header[6:8], 0)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(header[12:16], crc32.ChecksumIEEE(payload))
	binary.LittleEndian.PutUint64(header[16:24], event.Sequence)
	return header, payload, nil
}

func ParseHeader(raw []byte) (Header, error) {
	if len(raw) != HeaderSize {
		return Header{}, fmt.Errorf("header length %d, expected %d", len(raw), HeaderSize)
	}
	var header Header
	copy(header.Magic[:], raw[0:4])
	header.Version = binary.LittleEndian.Uint16(raw[4:6])
	header.Flags = binary.LittleEndian.Uint16(raw[6:8])
	header.Length = binary.LittleEndian.Uint32(raw[8:12])
	header.Checksum = binary.LittleEndian.Uint32(raw[12:16])
	header.Sequence = binary.LittleEndian.Uint64(raw[16:24])
	if header.Magic != frameMagic {
		return Header{}, fmt.Errorf("invalid magic %x", header.Magic)
	}
	if header.Version != FormatVersion {
		return Header{}, fmt.Errorf("unsupported version %d", header.Version)
	}
	if header.Flags != 0 {
		return Header{}, fmt.Errorf("unsupported flags 0x%x", header.Flags)
	}
	if header.Length == 0 || header.Length > MaximumPayload {
		return Header{}, fmt.Errorf("payload length %d is outside bounds", header.Length)
	}
	if header.Sequence == 0 {
		return Header{}, errors.New("sequence is zero")
	}
	return header, nil
}

func DecodePayload(header Header, payload []byte) (model.Event, error) {
	if len(payload) != int(header.Length) {
		return model.Event{}, fmt.Errorf("payload length %d, expected %d", len(payload), header.Length)
	}
	observed := crc32.ChecksumIEEE(payload)
	if observed != header.Checksum {
		return model.Event{}, fmt.Errorf("checksum %08x, expected %08x", observed, header.Checksum)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var event model.Event
	if err := decoder.Decode(&event); err != nil {
		return model.Event{}, fmt.Errorf("decode event JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return model.Event{}, errors.New("event payload contains multiple JSON values")
		}
		return model.Event{}, fmt.Errorf("decode trailing event JSON: %w", err)
	}
	if event.Sequence != header.Sequence {
		return model.Event{}, fmt.Errorf("header sequence %d differs from payload %d", header.Sequence, event.Sequence)
	}
	if err := event.Validate(); err != nil {
		return model.Event{}, fmt.Errorf("validate event: %w", err)
	}
	return event, nil
}
