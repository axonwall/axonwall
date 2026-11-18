package engine

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
)

const parquetMagic = "PAR1"

// Parquet Thrift Physical Types
const (
	parquetTypeInt32     = 1
	parquetTypeInt64     = 2
	parquetTypeDouble    = 5
	parquetTypeByteArray = 6
)

// Parquet Repetition Types
const parquetRepRequired = 0

// Parquet ConvertedTypes
const parquetConvertedUTF8 = 0

// Parquet CompressionCodec & Encoding & PageType
const (
	parquetCodecUncompressed = 0
	parquetEncodingPlain     = 0
	parquetEncodingRLE       = 3
	parquetPageDataPage      = 0
)

// Thrift Compact Protocol wire types
const (
	tcStop   = 0
	tcI32    = 5
	tcI64    = 6
	tcDouble = 7
	tcBinary = 8
	tcList   = 9
	tcStruct = 12
)

// ThreatParquetRow defines the aligned feature row written to Apache Parquet shards
// for offline GBDT / MLP / distillation training.
type ThreatParquetRow struct {
	EpisodeID       string
	TimestampUnixMs int64
	SrcIP           string
	DstIP           string
	SrcPort         int32
	DstPort         int32
	Proto           int32
	PktCount        int64
	ByteCount       int64
	DurationMs      float64
	DnsEntropy      float64
	JA4T            string
	SNI             string
	PktSizes        []int16
	IatUs           []uint32
	LabelTier       string
}

type ThreatParquetSummary struct {
	Version    int32
	NumRows    int64
	CreatedBy  string
	ColNames   []string
	FooterSize uint32
}

type thriftCompactWriter struct {
	buf         bytes.Buffer
	lastFieldID []int16
}

func newThriftCompactWriter() *thriftCompactWriter {
	return &thriftCompactWriter{lastFieldID: []int16{0}}
}

func (w *thriftCompactWriter) pushStruct() {
	w.lastFieldID = append(w.lastFieldID, 0)
}

func (w *thriftCompactWriter) popStruct() {
	w.buf.WriteByte(tcStop)
	if len(w.lastFieldID) > 1 {
		w.lastFieldID = w.lastFieldID[:len(w.lastFieldID)-1]
	}
}

func (w *thriftCompactWriter) writeUvarint(v uint64) {
	var tmp [10]byte
	n := binary.PutUvarint(tmp[:], v)
	w.buf.Write(tmp[:n])
}

func (w *thriftCompactWriter) writeZigZag32(v int32) {
	u := uint32((v << 1) ^ (v >> 31))
	w.writeUvarint(uint64(u))
}

func (w *thriftCompactWriter) writeZigZag64(v int64) {
	u := uint64((v << 1) ^ (v >> 63))
	w.writeUvarint(u)
}

func (w *thriftCompactWriter) writeFieldBegin(fieldID int16, ctype byte) {
	topIdx := len(w.lastFieldID) - 1
	delta := fieldID - w.lastFieldID[topIdx]
	if delta > 0 && delta <= 15 {
		w.buf.WriteByte(byte(delta<<4) | ctype)
	} else {
		w.buf.WriteByte(ctype)
		w.writeZigZag32(int32(fieldID))
	}
	w.lastFieldID[topIdx] = fieldID
}

func (w *thriftCompactWriter) writeFieldI32(fieldID int16, v int32) {
	w.writeFieldBegin(fieldID, tcI32)
	w.writeZigZag32(v)
}

func (w *thriftCompactWriter) writeFieldI64(fieldID int16, v int64) {
	w.writeFieldBegin(fieldID, tcI64)
	w.writeZigZag64(v)
}

func (w *thriftCompactWriter) writeFieldString(fieldID int16, s string) {
	w.writeFieldBegin(fieldID, tcBinary)
	w.writeUvarint(uint64(len(s)))
	w.buf.WriteString(s)
}

func (w *thriftCompactWriter) writeListBegin(elemType byte, count int) {
	if count < 15 {
		w.buf.WriteByte(byte(count<<4) | elemType)
	} else {
		w.buf.WriteByte(0xF0 | elemType)
		w.writeUvarint(uint64(count))
	}
}

func writeParquetSchemaElement(w *thriftCompactWriter, name string, physType *int32, repType *int32, numChildren *int32, convertedUTF8 bool) {
	w.pushStruct()
	if physType != nil {
		w.writeFieldI32(1, *physType)
	}
	if repType != nil {
		w.writeFieldI32(3, *repType)
	}
	w.writeFieldString(4, name)
	if numChildren != nil {
		w.writeFieldI32(5, *numChildren)
	}
	if convertedUTF8 {
		w.writeFieldI32(6, parquetConvertedUTF8)
	}
	w.popStruct()
}

func encodePageHeader(numValues int32, uncompressedSize int32) []byte {
	w := newThriftCompactWriter()
	w.writeFieldI32(1, parquetPageDataPage)
	w.writeFieldI32(2, uncompressedSize)
	w.writeFieldI32(3, uncompressedSize)

	// Field 5: DataPageHeader
	w.writeFieldBegin(5, tcStruct)
	w.pushStruct()
	w.writeFieldI32(1, numValues)
	w.writeFieldI32(2, parquetEncodingPlain)
	w.writeFieldI32(3, parquetEncodingRLE)
	w.writeFieldI32(4, parquetEncodingRLE)
	w.popStruct()

	w.buf.WriteByte(tcStop)
	return w.buf.Bytes()
}

type parquetColumnSpec struct {
	name          string
	physType      int32
	convertedUTF8 bool
	encode        func(rows []ThreatParquetRow) []byte
}

func encodePlainStrings(vals []string) []byte {
	var buf bytes.Buffer
	var lenBuf [4]byte
	for _, s := range vals {
		binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(s)))
		buf.Write(lenBuf[:])
		buf.WriteString(s)
	}
	return buf.Bytes()
}

func encodePlainI32(vals []int32) []byte {
	buf := make([]byte, len(vals)*4)
	for i, v := range vals {
		binary.LittleEndian.PutUint32(buf[i*4:], uint32(v))
	}
	return buf
}

func encodePlainI64(vals []int64) []byte {
	buf := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(buf[i*8:], uint64(v))
	}
	return buf
}

func encodePlainFloat64(vals []float64) []byte {
	buf := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(buf[i*8:], math.Float64bits(v))
	}
	return buf
}

var threatParquetSchemaColumns = []parquetColumnSpec{
	{
		name: "episode_id", physType: parquetTypeByteArray, convertedUTF8: true,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]string, len(rows))
			for i, r := range rows {
				v[i] = r.EpisodeID
			}
			return encodePlainStrings(v)
		},
	},
	{
		name: "timestamp_unix_ms", physType: parquetTypeInt64,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]int64, len(rows))
			for i, r := range rows {
				v[i] = r.TimestampUnixMs
			}
			return encodePlainI64(v)
		},
	},
	{
		name: "src_ip", physType: parquetTypeByteArray, convertedUTF8: true,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]string, len(rows))
			for i, r := range rows {
				v[i] = r.SrcIP
			}
			return encodePlainStrings(v)
		},
	},
	{
		name: "dst_ip", physType: parquetTypeByteArray, convertedUTF8: true,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]string, len(rows))
			for i, r := range rows {
				v[i] = r.DstIP
			}
			return encodePlainStrings(v)
		},
	},
	{
		name: "src_port", physType: parquetTypeInt32,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]int32, len(rows))
			for i, r := range rows {
				v[i] = r.SrcPort
			}
			return encodePlainI32(v)
		},
	},
	{
		name: "dst_port", physType: parquetTypeInt32,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]int32, len(rows))
			for i, r := range rows {
				v[i] = r.DstPort
			}
			return encodePlainI32(v)
		},
	},
	{
		name: "proto", physType: parquetTypeInt32,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]int32, len(rows))
			for i, r := range rows {
				v[i] = r.Proto
			}
			return encodePlainI32(v)
		},
	},
	{
		name: "pkt_count", physType: parquetTypeInt64,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]int64, len(rows))
			for i, r := range rows {
				v[i] = r.PktCount
			}
			return encodePlainI64(v)
		},
	},
	{
		name: "byte_count", physType: parquetTypeInt64,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]int64, len(rows))
			for i, r := range rows {
				v[i] = r.ByteCount
			}
			return encodePlainI64(v)
		},
	},
	{
		name: "duration_ms", physType: parquetTypeDouble,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]float64, len(rows))
			for i, r := range rows {
				v[i] = r.DurationMs
			}
			return encodePlainFloat64(v)
		},
	},
	{
		name: "dns_entropy", physType: parquetTypeDouble,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]float64, len(rows))
			for i, r := range rows {
				v[i] = r.DnsEntropy
			}
			return encodePlainFloat64(v)
		},
	},
	{
		name: "ja4t", physType: parquetTypeByteArray, convertedUTF8: true,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]string, len(rows))
			for i, r := range rows {
				v[i] = r.JA4T
			}
			return encodePlainStrings(v)
		},
	},
	{
		name: "sni", physType: parquetTypeByteArray, convertedUTF8: true,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]string, len(rows))
			for i, r := range rows {
				v[i] = r.SNI
			}
			return encodePlainStrings(v)
		},
	},
	{
		name: "pkt_sizes_json", physType: parquetTypeByteArray, convertedUTF8: true,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]string, len(rows))
			for i, r := range rows {
				b, _ := json.Marshal(r.PktSizes)
				v[i] = string(b)
			}
			return encodePlainStrings(v)
		},
	},
	{
		name: "iat_us_json", physType: parquetTypeByteArray, convertedUTF8: true,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]string, len(rows))
			for i, r := range rows {
				b, _ := json.Marshal(r.IatUs)
				v[i] = string(b)
			}
			return encodePlainStrings(v)
		},
	},
	{
		name: "label_tier", physType: parquetTypeByteArray, convertedUTF8: true,
		encode: func(rows []ThreatParquetRow) []byte {
			v := make([]string, len(rows))
			for i, r := range rows {
				v[i] = r.LabelTier
			}
			return encodePlainStrings(v)
		},
	},
}

// WriteThreatFeatureParquet writes rows in standard Apache Parquet 1.0 binary format
// (PAR1 header, PLAIN-encoded columns, Thrift Compact FileMetaData, PAR1 trailer).
func WriteThreatFeatureParquet(w io.Writer, rows []ThreatParquetRow) error {
	if _, err := io.WriteString(w, parquetMagic); err != nil {
		return err
	}
	offset := int64(len(parquetMagic))

	type writtenChunkMeta struct {
		spec           parquetColumnSpec
		dataPageOffset int64
		totalSize      int64
	}
	var chunks []writtenChunkMeta
	var rowGroupTotalBytes int64

	if len(rows) > 0 {
		numVals := int32(len(rows))
		for _, col := range threatParquetSchemaColumns {
			rawPayload := col.encode(rows)
			hdr := encodePageHeader(numVals, int32(len(rawPayload)))
			chunkOffset := offset
			if _, err := w.Write(hdr); err != nil {
				return err
			}
			if _, err := w.Write(rawPayload); err != nil {
				return err
			}
			total := int64(len(hdr) + len(rawPayload))
			offset += total
			rowGroupTotalBytes += total
			chunks = append(chunks, writtenChunkMeta{
				spec:           col,
				dataPageOffset: chunkOffset,
				totalSize:      total,
			})
		}
	}

	// Encode Thrift Compact FileMetaData
	meta := newThriftCompactWriter()
	meta.writeFieldI32(1, 1) // version = 1

	// Field 2: schema (root + 16 children)
	meta.writeFieldBegin(2, tcList)
	meta.writeListBegin(tcStruct, 1+len(threatParquetSchemaColumns))
	numChildren := int32(len(threatParquetSchemaColumns))
	writeParquetSchemaElement(meta, "axonwall_threat_episode", nil, nil, &numChildren, false)
	repReq := int32(parquetRepRequired)
	for _, col := range threatParquetSchemaColumns {
		pt := col.physType
		writeParquetSchemaElement(meta, col.name, &pt, &repReq, nil, col.convertedUTF8)
	}

	// Field 3: num_rows
	meta.writeFieldI64(3, int64(len(rows)))

	// Field 4: row_groups
	meta.writeFieldBegin(4, tcList)
	if len(rows) == 0 {
		meta.writeListBegin(tcStruct, 0)
	} else {
		meta.writeListBegin(tcStruct, 1)
		meta.pushStruct()
		meta.writeFieldBegin(1, tcList)
		meta.writeListBegin(tcStruct, len(chunks))
		for _, ch := range chunks {
			meta.pushStruct()
			meta.writeFieldI64(2, ch.dataPageOffset)
			meta.writeFieldBegin(3, tcStruct)
			meta.pushStruct()
			meta.writeFieldI32(1, ch.spec.physType)

			meta.writeFieldBegin(2, tcList)
			meta.writeListBegin(tcI32, 2)
			meta.writeZigZag32(parquetEncodingPlain)
			meta.writeZigZag32(parquetEncodingRLE)

			meta.writeFieldBegin(3, tcList)
			meta.writeListBegin(tcBinary, 1)
			meta.writeUvarint(uint64(len(ch.spec.name)))
			meta.buf.WriteString(ch.spec.name)

			meta.writeFieldI32(4, parquetCodecUncompressed)
			meta.writeFieldI64(5, int64(len(rows)))
			meta.writeFieldI64(6, ch.totalSize)
			meta.writeFieldI64(7, ch.totalSize)
			meta.writeFieldI64(9, ch.dataPageOffset)
			meta.popStruct()
			meta.popStruct()
		}
		meta.writeFieldI64(2, rowGroupTotalBytes)
		meta.writeFieldI64(3, int64(len(rows)))
		meta.popStruct()
	}

	// Field 6: created_by
	meta.writeFieldString(6, "axonwall-ebpf-threat-harvester/1.0")
	meta.buf.WriteByte(tcStop)

	footerBytes := meta.buf.Bytes()
	if _, err := w.Write(footerBytes); err != nil {
		return err
	}
	var footerLenLE [4]byte
	binary.LittleEndian.PutUint32(footerLenLE[:], uint32(len(footerBytes)))
	if _, err := w.Write(footerLenLE[:]); err != nil {
		return err
	}
	_, err := io.WriteString(w, parquetMagic)
	return err
}

// ReadThreatParquetMetadata verifies PAR1 framing and decodes core FileMetaData
// fields (version, num_rows, schema column names, created_by) without external deps.
func ReadThreatParquetMetadata(data []byte) (*ThreatParquetSummary, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("parquet buffer too small: %d bytes", len(data))
	}
	if string(data[:4]) != parquetMagic || string(data[len(data)-4:]) != parquetMagic {
		return nil, fmt.Errorf("invalid PAR1 magic bytes")
	}
	footerSize := binary.LittleEndian.Uint32(data[len(data)-8 : len(data)-4])
	if int(footerSize)+12 > len(data) {
		return nil, fmt.Errorf("invalid parquet footer length: %d", footerSize)
	}
	footer := data[len(data)-8-int(footerSize) : len(data)-8]

	r := &thriftCompactReader{data: footer}
	summary := &ThreatParquetSummary{FooterSize: footerSize}
	var lastField int16
	for {
		fieldID, ctype, ok := r.readFieldBegin(lastField)
		if !ok {
			return nil, fmt.Errorf("unexpected EOF parsing FileMetaData")
		}
		if ctype == tcStop {
			break
		}
		lastField = fieldID
		switch fieldID {
		case 1:
			v, _ := r.readZigZag32()
			summary.Version = v
		case 2:
			elemType, count, ok2 := r.readListBegin()
			if !ok2 {
				return nil, fmt.Errorf("malformed parquet schema list header: %v", r.err)
			}
			if elemType != tcStruct {
				return nil, fmt.Errorf("unexpected schema list elemType=%d", elemType)
			}
			if count < 0 || count > len(r.data)-r.pos {
				return nil, fmt.Errorf("parquet schema list count %d out of bounds", count)
			}
			for i := 0; i < count; i++ {
				var slast int16
				for {
					fid, ft, fok := r.readFieldBegin(slast)
					if !fok || ft == tcStop {
						break
					}
					slast = fid
					if fid == 4 && ft == tcBinary {
						name := r.readString()
						if r.err != nil {
							return nil, r.err
						}
						if name != "axonwall_threat_episode" {
							summary.ColNames = append(summary.ColNames, name)
						}
					} else {
						r.skipValue(ft)
						if r.err != nil {
							return nil, r.err
						}
					}
				}
			}
		case 3:
			summary.NumRows, _ = r.readZigZag64()
		case 6:
			summary.CreatedBy = r.readString()
		default:
			r.skipValue(ctype)
		}
		if r.err != nil {
			return nil, r.err
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	return summary, nil
}

func (r *thriftCompactReader) setErr(err error) {
	if r.err == nil {
		r.err = err
	}
}

type thriftCompactReader struct {
	data []byte
	pos  int
	err  error
}

func (r *thriftCompactReader) readByte() (byte, bool) {
	if r.err != nil || r.pos < 0 || r.pos >= len(r.data) {
		r.setErr(fmt.Errorf("unexpected EOF reading byte at offset %d", r.pos))
		return 0, false
	}
	b := r.data[r.pos]
	r.pos++
	return b, true
}

func (r *thriftCompactReader) readUvarint() (uint64, bool) {
	if r.err != nil || r.pos < 0 || r.pos >= len(r.data) {
		r.setErr(fmt.Errorf("unexpected EOF reading uvarint at offset %d", r.pos))
		return 0, false
	}
	v, n := binary.Uvarint(r.data[r.pos:])
	if n <= 0 {
		r.setErr(fmt.Errorf("invalid uvarint at offset %d", r.pos))
		return 0, false
	}
	r.pos += n
	return v, true
}

func (r *thriftCompactReader) readZigZag32() (int32, bool) {
	u, ok := r.readUvarint()
	if !ok {
		return 0, false
	}
	v := int32((u >> 1) ^ -(u & 1))
	return v, true
}

func (r *thriftCompactReader) readZigZag64() (int64, bool) {
	u, ok := r.readUvarint()
	if !ok {
		return 0, false
	}
	v := int64((u >> 1) ^ -(u & 1))
	return v, true
}

func (r *thriftCompactReader) readString() string {
	n, ok := r.readUvarint()
	if !ok {
		return ""
	}
	if r.pos < 0 || r.pos > len(r.data) || n > uint64(len(r.data)-r.pos) {
		r.setErr(fmt.Errorf("parquet string length %d out of bounds (remaining=%d)", n, len(r.data)-r.pos))
		return ""
	}
	s := string(r.data[r.pos : r.pos+int(n)])
	r.pos += int(n)
	return s
}

func (r *thriftCompactReader) readFieldBegin(lastField int16) (int16, byte, bool) {
	b, ok := r.readByte()
	if !ok {
		return 0, 0, false
	}
	if b == tcStop {
		return 0, tcStop, true
	}
	delta := int16((b >> 4) & 0x0F)
	ctype := b & 0x0F
	if delta == 0 {
		fid, ok2 := r.readZigZag32()
		return int16(fid), ctype, ok2
	}
	return lastField + delta, ctype, true
}

func (r *thriftCompactReader) readListBegin() (byte, int, bool) {
	b, ok := r.readByte()
	if !ok {
		return 0, 0, false
	}
	count := int((b >> 4) & 0x0F)
	elemType := b & 0x0F
	if count == 0x0F {
		u, ok2 := r.readUvarint()
		if !ok2 {
			return 0, 0, false
		}
		if r.pos < 0 || u > uint64(len(r.data)-r.pos) {
			r.setErr(fmt.Errorf("parquet list count %d out of bounds", u))
			return 0, 0, false
		}
		count = int(u)
	}
	return elemType, count, true
}

const maxParquetSkipDepth = 32

func (r *thriftCompactReader) skipValue(ctype byte) {
	r.skipValueDepth(ctype, 0)
}

func (r *thriftCompactReader) skipValueDepth(ctype byte, depth int) {
	if r.err != nil {
		return
	}
	if depth > maxParquetSkipDepth {
		r.setErr(fmt.Errorf("parquet metadata nesting depth exceeds %d", maxParquetSkipDepth))
		return
	}
	switch ctype {
	case 1, 2:
		return
	case 3:
		r.readByte()
	case 4, 5:
		r.readUvarint()
	case 6:
		r.readUvarint()
	case 7:
		if r.pos < 0 || len(r.data)-r.pos < 8 {
			r.setErr(fmt.Errorf("parquet double field out of bounds"))
			return
		}
		r.pos += 8
	case 8:
		n, ok := r.readUvarint()
		if !ok {
			return
		}
		if r.pos < 0 || r.pos > len(r.data) || n > uint64(len(r.data)-r.pos) {
			r.setErr(fmt.Errorf("parquet binary field length %d out of bounds", n))
			return
		}
		r.pos += int(n)
	case 9, 10:
		et, cnt, ok := r.readListBegin()
		if !ok {
			return
		}
		if cnt < 0 || cnt > len(r.data)-r.pos {
			r.setErr(fmt.Errorf("parquet list/set count %d out of bounds", cnt))
			return
		}
		for i := 0; i < cnt && r.err == nil; i++ {
			r.skipValueDepth(et, depth+1)
		}
	case 11:
		cnt, ok := r.readUvarint()
		if !ok {
			return
		}
		if cnt > 0 {
			if r.pos < 0 || cnt > uint64(len(r.data)-r.pos) {
				r.setErr(fmt.Errorf("parquet map count %d out of bounds", cnt))
				return
			}
			kt, ok2 := r.readByte()
			if !ok2 {
				return
			}
			ktype := (kt >> 4) & 0x0F
			vtype := kt & 0x0F
			for i := 0; i < int(cnt) && r.err == nil; i++ {
				r.skipValueDepth(ktype, depth+1)
				r.skipValueDepth(vtype, depth+1)
			}
		}
	case 12:
		var last int16
		for r.err == nil {
			fid, ft, ok := r.readFieldBegin(last)
			if !ok || ft == tcStop {
				break
			}
			last = fid
			r.skipValueDepth(ft, depth+1)
		}
	}
}
