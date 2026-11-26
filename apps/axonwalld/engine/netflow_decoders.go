package engine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type netflowTemplateKey struct {
	exporterIP string
	sourceID   uint32
	version    string
	templateID uint16
}

type cachedTemplate struct {
	key          netflowTemplateKey
	isOptions    bool
	scopeCount   int
	fields       []TemplateFieldSpec
	fixedLen     int
	hasVarLen    bool
	updatedAt    time.Time
	lastUsedAt   time.Time
	packetsUsing uint64
}

const (
	maxDecoderTemplates   = 4096
	maxDecoderMetaEntries = 4096
	maxDecoderIfNames     = 16384
)

type cachedNodeMeta struct {
	nodeID     string
	hostname   string
	lastSeenAt int64
}

type FlowDecoder struct {
	mu           sync.RWMutex
	templates    map[netflowTemplateKey]*cachedTemplate
	samplingRate map[string]uint32         // key: exporterIP|sourceID
	samplingSeen map[string]int64          // monotonic access/update order
	nodeMeta     map[string]cachedNodeMeta // key: exporterIP|sourceID
	ifNames      map[ifAliasKey]string     // key: (exporterIP, ifIndex)
	ifNamesSeen  map[ifAliasKey]int64      // monotonic access/update order
	metaSeq      int64
}

func NewFlowDecoder() *FlowDecoder {
	return &FlowDecoder{
		templates:    make(map[netflowTemplateKey]*cachedTemplate),
		samplingRate: make(map[string]uint32),
		samplingSeen: make(map[string]int64),
		nodeMeta:     make(map[string]cachedNodeMeta),
		ifNames:      make(map[ifAliasKey]string),
		ifNamesSeen:  make(map[ifAliasKey]int64),
	}
}

func (d *FlowDecoder) GetTemplates() []TemplateCacheEntry {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]TemplateCacheEntry, 0, len(d.templates))
	for _, t := range d.templates {
		fieldsCopy := make([]TemplateFieldSpec, len(t.fields))
		copy(fieldsCopy, t.fields)
		out = append(out, TemplateCacheEntry{
			ExporterIP:   t.key.exporterIP,
			SourceID:     t.key.sourceID,
			Version:      t.key.version,
			TemplateID:   t.key.templateID,
			IsOptions:    t.isOptions,
			ScopeCount:   t.scopeCount,
			FieldCount:   len(t.fields),
			TotalBytes:   t.fixedLen,
			UpdatedAt:    t.updatedAt.UTC().Format(time.RFC3339),
			LastUsedAt:   t.lastUsedAt.UTC().Format(time.RFC3339),
			PacketsUsing: t.packetsUsing,
			Fields:       fieldsCopy,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ExporterIP != out[j].ExporterIP {
			return out[i].ExporterIP < out[j].ExporterIP
		}
		return out[i].TemplateID < out[j].TemplateID
	})
	return out
}

func (d *FlowDecoder) GetExporterSampling(exporterIP string) uint32 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	prefix := exporterIP + "|"
	for k, v := range d.samplingRate {
		if strings.HasPrefix(k, prefix) && v > 0 {
			return v
		}
	}
	return 1
}

// DecodePacket detects NetFlow v5, NetFlow v9, IPFIX (v10), or sFlow v5 and returns normalized FlowRecords.
func (d *FlowDecoder) DecodePacket(exporterIP string, raw []byte, recvTime time.Time) (string, []FlowRecord, []ExporterInterfaceCounter, error) {
	if len(raw) < 4 {
		return "", nil, nil, errors.New("flow datagram shorter than 4 bytes")
	}
	ver16 := binary.BigEndian.Uint16(raw[0:2])
	ver32 := binary.BigEndian.Uint32(raw[0:4])

	switch {
	case ver32 == 5:
		flows, counters, err := d.decodeSFlowV5(exporterIP, raw, recvTime)
		return "sflow5", flows, counters, err
	case ver16 == 5:
		flows, err := d.decodeNetFlowV5(exporterIP, raw, recvTime)
		return "netflow5", flows, nil, err
	case ver16 == 9:
		flows, err := d.decodeNetFlowV9(exporterIP, raw, recvTime)
		return "netflow9", flows, nil, err
	case ver16 == 10:
		flows, err := d.decodeIPFIX(exporterIP, raw, recvTime)
		return "ipfix", flows, nil, err
	default:
		return "", nil, nil, fmt.Errorf("unrecognized flow header version (u16=%d, u32=%d)", ver16, ver32)
	}
}

func (d *FlowDecoder) decodeNetFlowV5(exporterIP string, raw []byte, recvTime time.Time) ([]FlowRecord, error) {
	const hdrLen = 24
	const recLen = 48
	if len(raw) < hdrLen {
		return nil, errors.New("truncated netflow v5 header")
	}
	count := int(binary.BigEndian.Uint16(raw[2:4]))
	sysUptimeMs := binary.BigEndian.Uint32(raw[4:8])
	unixSecs := binary.BigEndian.Uint32(raw[8:12])
	unixNsecs := binary.BigEndian.Uint32(raw[12:16])
	samplingField := binary.BigEndian.Uint16(raw[22:24])
	samplingRate := uint32(samplingField & 0x3FFF)
	if samplingRate == 0 {
		samplingRate = 1
	}

	pktTime := recvTime
	if unixSecs > 0 {
		pktTime = time.Unix(int64(unixSecs), int64(unixNsecs))
	}

	if count == 0 || len(raw) < hdrLen+count*recLen {
		maxPossible := (len(raw) - hdrLen) / recLen
		if maxPossible < count {
			count = maxPossible
		}
	}
	flows := make([]FlowRecord, 0, count)
	for i := 0; i < count; i++ {
		rec := raw[hdrLen+i*recLen : hdrLen+(i+1)*recLen]
		srcIP := net.IP(rec[0:4]).String()
		dstIP := net.IP(rec[4:8]).String()
		inIf := uint32(binary.BigEndian.Uint16(rec[12:14]))
		outIf := uint32(binary.BigEndian.Uint16(rec[14:16]))
		dPkts := uint64(binary.BigEndian.Uint32(rec[16:20])) * uint64(samplingRate)
		dOctets := uint64(binary.BigEndian.Uint32(rec[20:24])) * uint64(samplingRate)
		firstUp := binary.BigEndian.Uint32(rec[24:28])
		lastUp := binary.BigEndian.Uint32(rec[28:32])
		srcPort := binary.BigEndian.Uint16(rec[32:34])
		dstPort := binary.BigEndian.Uint16(rec[34:36])
		tcpFlags := rec[37]
		proto := rec[38]
		tos := rec[39]
		srcAS := uint32(binary.BigEndian.Uint16(rec[40:42]))
		dstAS := uint32(binary.BigEndian.Uint16(rec[42:44]))

		endTime := pktTime
		startTime := pktTime
		if sysUptimeMs >= lastUp && lastUp >= firstUp {
			endTime = pktTime.Add(-time.Duration(sysUptimeMs-lastUp) * time.Millisecond)
			startTime = pktTime.Add(-time.Duration(sysUptimeMs-firstUp) * time.Millisecond)
		}
		durSec := endTime.Sub(startTime).Seconds()
		if durSec < 1 {
			durSec = 1
		}

		flows = append(flows, FlowRecord{
			ID:           fmt.Sprintf("nf5-%d-%d-%s-%s-%d", endTime.UnixNano(), i, srcIP, dstIP, dstPort),
			TimestampMs:  endTime.UnixMilli(),
			Timestamp:    endTime.UTC().Format(time.RFC3339Nano),
			FlowStartMs:  startTime.UnixMilli(),
			Version:      "netflow5",
			ExporterIP:   exporterIP,
			SrcIP:        srcIP,
			DstIP:        dstIP,
			SrcPort:      srcPort,
			DstPort:      dstPort,
			Protocol:     proto,
			ProtocolName: netflowProtocolName(proto),
			SrcAsn:       srcAS,
			DstAsn:       dstAS,
			InIfIndex:    inIf,
			OutIfIndex:   outIf,
			Bytes:        dOctets,
			Packets:      dPkts,
			Bps:          float64(dOctets*8) / durSec,
			Pps:          float64(dPkts) / durSec,
			TCPFlags:     tcpFlags,
			TCPFlagsStr:  formatTCPFlags(tcpFlags),
			ToS:          tos,
			DSCP:         tos >> 2,
			SamplingRate: samplingRate,
		})
	}
	return flows, nil
}

func (d *FlowDecoder) decodeNetFlowV9(exporterIP string, raw []byte, recvTime time.Time) ([]FlowRecord, error) {
	const hdrLen = 20
	if len(raw) < hdrLen {
		return nil, errors.New("truncated netflow v9 header")
	}
	count := int(binary.BigEndian.Uint16(raw[2:4]))
	sysUptimeMs := binary.BigEndian.Uint32(raw[4:8])
	unixSecs := binary.BigEndian.Uint32(raw[8:12])
	sourceID := binary.BigEndian.Uint32(raw[16:20])
	baseTime := recvTime
	if unixSecs > 0 {
		baseTime = time.Unix(int64(unixSecs), 0)
	}

	var flows []FlowRecord
	off := hdrLen
	parsedSets := 0
	for off+4 <= len(raw) && (count == 0 || parsedSets < count) {
		fsID := binary.BigEndian.Uint16(raw[off : off+2])
		fsLen := int(binary.BigEndian.Uint16(raw[off+2 : off+4]))
		if fsLen < 4 || off+fsLen > len(raw) {
			break
		}
		body := raw[off+4 : off+fsLen]
		off += fsLen
		parsedSets++

		switch {
		case fsID == 0:
			d.parseV9Templates(exporterIP, sourceID, body, recvTime)
		case fsID == 1:
			d.parseV9OptionsTemplate(exporterIP, sourceID, body, recvTime)
		case fsID >= 256:
			key := netflowTemplateKey{exporterIP: exporterIP, sourceID: sourceID, version: "netflow9", templateID: fsID}
			tmpl := d.lookupTemplate(key)
			if tmpl == nil || tmpl.fixedLen <= 0 {
				continue
			}
			if tmpl.isOptions {
				d.parseOptionsData(exporterIP, sourceID, tmpl, body)
				continue
			}
			for recOff := 0; recOff+tmpl.fixedLen <= len(body); recOff += tmpl.fixedLen {
				rec := decodeTemplateRecord(tmpl, body[recOff:recOff+tmpl.fixedLen], exporterIP, sourceID, "netflow9", baseTime, sysUptimeMs, d.GetExporterSampling(exporterIP))
				flows = append(flows, rec)
			}
		}
	}
	return flows, nil
}

func (d *FlowDecoder) parseV9Templates(exporterIP string, sourceID uint32, body []byte, now time.Time) {
	off := 0
	for off+4 <= len(body) {
		tid := binary.BigEndian.Uint16(body[off : off+2])
		fCount := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if fCount == 0 || off+fCount*4 > len(body) {
			break
		}
		fields := make([]TemplateFieldSpec, 0, fCount)
		totalLen := 0
		for i := 0; i < fCount; i++ {
			ft := binary.BigEndian.Uint16(body[off : off+2])
			fl := binary.BigEndian.Uint16(body[off+2 : off+4])
			off += 4
			fields = append(fields, TemplateFieldSpec{
				FieldType: ft,
				FieldName: ieName(0, ft),
				Length:    fl,
			})
			totalLen += int(fl)
		}
		d.storeTemplate(&cachedTemplate{
			key:        netflowTemplateKey{exporterIP: exporterIP, sourceID: sourceID, version: "netflow9", templateID: tid},
			fields:     fields,
			fixedLen:   totalLen,
			updatedAt:  now,
			lastUsedAt: now,
		})
	}
}

func (d *FlowDecoder) parseV9OptionsTemplate(exporterIP string, sourceID uint32, body []byte, now time.Time) {
	if len(body) < 6 {
		return
	}
	tid := binary.BigEndian.Uint16(body[0:2])
	optScopeLen := int(binary.BigEndian.Uint16(body[2:4]))
	optLen := int(binary.BigEndian.Uint16(body[4:6]))
	off := 6
	if off+optScopeLen+optLen > len(body) {
		return
	}
	fields := make([]TemplateFieldSpec, 0, (optScopeLen+optLen)/4)
	totalLen := 0
	scopeCount := 0
	for i := 0; i < optScopeLen/4; i++ {
		ft := binary.BigEndian.Uint16(body[off : off+2])
		fl := binary.BigEndian.Uint16(body[off+2 : off+4])
		off += 4
		fields = append(fields, TemplateFieldSpec{FieldType: ft, FieldName: ieName(0, ft), Length: fl, IsScope: true})
		totalLen += int(fl)
		scopeCount++
	}
	for i := 0; i < optLen/4; i++ {
		ft := binary.BigEndian.Uint16(body[off : off+2])
		fl := binary.BigEndian.Uint16(body[off+2 : off+4])
		off += 4
		fields = append(fields, TemplateFieldSpec{FieldType: ft, FieldName: ieName(0, ft), Length: fl})
		totalLen += int(fl)
	}
	d.storeTemplate(&cachedTemplate{
		key:        netflowTemplateKey{exporterIP: exporterIP, sourceID: sourceID, version: "netflow9", templateID: tid},
		isOptions:  true,
		scopeCount: scopeCount,
		fields:     fields,
		fixedLen:   totalLen,
		updatedAt:  now,
		lastUsedAt: now,
	})
}

func allZeroBytes(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func (d *FlowDecoder) stampDecodedMetadata(exporterIP string, domainID uint32, rec *FlowRecord) {
	d.mu.RLock()
	nm := d.nodeMeta[fmt.Sprintf("%s|%d", exporterIP, domainID)]
	inName := ""
	outName := ""
	if rec.InIfIndex > 0 {
		inName = d.ifNames[ifAliasKey{exporterIP: exporterIP, ifIndex: rec.InIfIndex}]
	}
	if rec.OutIfIndex > 0 {
		outName = d.ifNames[ifAliasKey{exporterIP: exporterIP, ifIndex: rec.OutIfIndex}]
	}
	d.mu.RUnlock()
	if rec.HostID == "" && nm.nodeID != "" {
		rec.HostID = nm.nodeID
	}
	if rec.HostName == "" && nm.hostname != "" {
		rec.HostName = nm.hostname
	}
	if rec.InIfName == "" && inName != "" {
		rec.InIfName = inName
	}
	if rec.OutIfName == "" && outName != "" {
		rec.OutIfName = outName
	}
}

func evictOldestSeen[K comparable](vals any, seen map[K]int64) (K, bool) {
	var oldestKey K
	var oldestSeq int64
	found := false
	for k, seq := range seen {
		if !found || seq < oldestSeq {
			oldestKey = k
			oldestSeq = seq
			found = true
		}
	}
	return oldestKey, found
}

func (d *FlowDecoder) touchMetaMapsLocked() {
	if d.templates == nil {
		d.templates = make(map[netflowTemplateKey]*cachedTemplate)
	}
	if d.samplingRate == nil {
		d.samplingRate = make(map[string]uint32)
	}
	if d.samplingSeen == nil {
		d.samplingSeen = make(map[string]int64)
	}
	if d.nodeMeta == nil {
		d.nodeMeta = make(map[string]cachedNodeMeta)
	}
	if d.ifNames == nil {
		d.ifNames = make(map[ifAliasKey]string)
	}
	if d.ifNamesSeen == nil {
		d.ifNamesSeen = make(map[ifAliasKey]int64)
	}
}

func (d *FlowDecoder) applyOptionsRecord(exporterIP string, domainID uint32, rec FlowRecord) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.touchMetaMapsLocked()
	d.metaSeq++
	seq := d.metaSeq
	expKey := fmt.Sprintf("%s|%d", exporterIP, domainID)
	if rec.SamplingRate > 1 {
		if _, exists := d.samplingRate[expKey]; !exists && len(d.samplingRate) >= maxDecoderMetaEntries {
			if k, ok := evictOldestSeen(d.samplingRate, d.samplingSeen); ok {
				delete(d.samplingRate, k)
				delete(d.samplingSeen, k)
			}
		}
		d.samplingRate[expKey] = rec.SamplingRate
		d.samplingSeen[expKey] = seq
	}
	if rec.HostID != "" || rec.HostName != "" {
		cur, exists := d.nodeMeta[expKey]
		if !exists && len(d.nodeMeta) >= maxDecoderMetaEntries {
			var oldestKey string
			var oldestSeq int64
			first := true
			for k, nm := range d.nodeMeta {
				if first || nm.lastSeenAt < oldestSeq {
					oldestKey = k
					oldestSeq = nm.lastSeenAt
					first = false
				}
			}
			if !first {
				delete(d.nodeMeta, oldestKey)
			}
		}
		if rec.HostID != "" {
			cur.nodeID = rec.HostID
		}
		if rec.HostName != "" {
			cur.hostname = rec.HostName
		}
		cur.lastSeenAt = seq
		d.nodeMeta[expKey] = cur
	}
	if rec.InIfIndex > 0 && rec.InIfName != "" {
		k := ifAliasKey{exporterIP: exporterIP, ifIndex: rec.InIfIndex}
		if _, exists := d.ifNames[k]; !exists && len(d.ifNames) >= maxDecoderIfNames {
			if oldKey, ok := evictOldestSeen(d.ifNames, d.ifNamesSeen); ok {
				delete(d.ifNames, oldKey)
				delete(d.ifNamesSeen, oldKey)
			}
		}
		d.ifNames[k] = rec.InIfName
		d.ifNamesSeen[k] = seq
	}
}
func (d *FlowDecoder) decodeIPFIX(exporterIP string, raw []byte, recvTime time.Time) ([]FlowRecord, error) {
	const hdrLen = 16
	if len(raw) < hdrLen {
		return nil, errors.New("truncated IPFIX header")
	}
	msgLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if msgLen > len(raw) || msgLen < hdrLen {
		msgLen = len(raw)
	}
	exportSecs := binary.BigEndian.Uint32(raw[4:8])
	domainID := binary.BigEndian.Uint32(raw[12:16])
	baseTime := recvTime
	if exportSecs > 0 {
		baseTime = time.Unix(int64(exportSecs), 0)
	}

	var flows []FlowRecord
	off := hdrLen
	for off+4 <= msgLen {
		setID := binary.BigEndian.Uint16(raw[off : off+2])
		setLen := int(binary.BigEndian.Uint16(raw[off+2 : off+4]))
		if setLen < 4 || off+setLen > msgLen {
			break
		}
		body := raw[off+4 : off+setLen]
		off += setLen

		switch {
		case setID == 2:
			d.parseIPFIXTemplates(exporterIP, domainID, body, false, recvTime)
		case setID == 3:
			d.parseIPFIXTemplates(exporterIP, domainID, body, true, recvTime)
		case setID >= 256:
			key := netflowTemplateKey{exporterIP: exporterIP, sourceID: domainID, version: "ipfix", templateID: setID}
			tmpl := d.lookupTemplate(key)
			if tmpl == nil || len(tmpl.fields) == 0 {
				continue
			}
			recOff := 0
			for recOff < len(body) {
				if !tmpl.hasVarLen && tmpl.fixedLen > 0 && len(body)-recOff < tmpl.fixedLen {
					break // IPFIX Set padding bytes
				}
				if tmpl.hasVarLen && len(body)-recOff <= 3 && allZeroBytes(body[recOff:]) {
					break // RFC 7011 trailing zero padding on varlen set
				}
				rec, nextOff, ok := decodeVariableOrFixedRecord(tmpl, body, recOff, exporterIP, domainID, "ipfix", baseTime, 0, d.GetExporterSampling(exporterIP))
				if !ok || nextOff <= recOff {
					break
				}
				recOff = nextOff
				if tmpl.isOptions {
					d.applyOptionsRecord(exporterIP, domainID, rec)
					continue
				}
				d.stampDecodedMetadata(exporterIP, domainID, &rec)
				flows = append(flows, rec)
			}
		}
	}
	return flows, nil
}

func (d *FlowDecoder) withdrawIPFIXTemplates(exporterIP string, domainID uint32, tid uint16) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.templates) == 0 {
		return
	}
	// RFC 7011 §8.1: template ID 2/3 withdraws all Data/Options templates for the Observation Domain;
	// specific IDs >= 256 withdraw that single template.
	if tid == 2 || tid == 3 {
		wantOptions := tid == 3
		for k, tmpl := range d.templates {
			if k.exporterIP == exporterIP && k.sourceID == domainID && k.version == "ipfix" && tmpl.isOptions == wantOptions {
				delete(d.templates, k)
			}
		}
		return
	}
	delete(d.templates, netflowTemplateKey{
		exporterIP: exporterIP,
		sourceID:   domainID,
		version:    "ipfix",
		templateID: tid,
	})
}

func (d *FlowDecoder) parseIPFIXTemplates(exporterIP string, domainID uint32, body []byte, isOptions bool, now time.Time) {
	off := 0
	for off+4 <= len(body) {
		tid := binary.BigEndian.Uint16(body[off : off+2])
		fCount := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if fCount == 0 {
			d.withdrawIPFIXTemplates(exporterIP, domainID, tid)
			continue
		}
		scopeCount := 0
		if isOptions {
			if off+2 > len(body) {
				break
			}
			scopeCount = int(binary.BigEndian.Uint16(body[off : off+2]))
			off += 2
			if scopeCount > fCount {
				break
			}
		}
		remaining := len(body) - off
		if fCount*4 > remaining {
			break
		}
		fields := make([]TemplateFieldSpec, 0, fCount)
		fixedLen := 0
		hasVarLen := false
		partial := false
		for i := 0; i < fCount; i++ {
			if off+4 > len(body) {
				partial = true
				break
			}
			rawIE := binary.BigEndian.Uint16(body[off : off+2])
			fl := binary.BigEndian.Uint16(body[off+2 : off+4])
			off += 4
			var entID uint32
			ft := rawIE
			if rawIE&0x8000 != 0 {
				ft = rawIE & 0x7FFF
				if off+4 > len(body) {
					partial = true
					break
				}
				entID = binary.BigEndian.Uint32(body[off : off+4])
				off += 4
			}
			if fl == 0xFFFF {
				hasVarLen = true
			} else {
				fixedLen += int(fl)
			}
			fields = append(fields, TemplateFieldSpec{
				EnterpriseID: entID,
				FieldType:    ft,
				FieldName:    ieName(entID, ft),
				Length:       fl,
				IsScope:      isOptions && i < scopeCount,
			})
		}
		if partial || len(fields) != fCount {
			break
		}
		d.storeTemplate(&cachedTemplate{
			key:        netflowTemplateKey{exporterIP: exporterIP, sourceID: domainID, version: "ipfix", templateID: tid},
			isOptions:  isOptions,
			scopeCount: scopeCount,
			fields:     fields,
			fixedLen:   fixedLen,
			hasVarLen:  hasVarLen,
			updatedAt:  now,
			lastUsedAt: now,
		})
	}
}

func (d *FlowDecoder) parseOptionsData(exporterIP string, sourceID uint32, tmpl *cachedTemplate, body []byte) {
	if len(body) < tmpl.fixedLen {
		return
	}
	rec := decodeTemplateRecord(tmpl, body[:tmpl.fixedLen], exporterIP, sourceID, tmpl.key.version, time.Now(), 0, 1)
	d.applyOptionsRecord(exporterIP, sourceID, rec)
}

func (d *FlowDecoder) storeTemplate(t *cachedTemplate) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.touchMetaMapsLocked()
	if prev, ok := d.templates[t.key]; ok {
		t.packetsUsing = prev.packetsUsing
	} else if len(d.templates) >= maxDecoderTemplates {
		var oldestKey netflowTemplateKey
		var oldestTime time.Time
		first := true
		for k, cur := range d.templates {
			ts := cur.lastUsedAt
			if ts.IsZero() {
				ts = cur.updatedAt
			}
			if first || ts.Before(oldestTime) {
				oldestKey = k
				oldestTime = ts
				first = false
			}
		}
		if !first {
			delete(d.templates, oldestKey)
		}
	}
	d.templates[t.key] = t
}

func (d *FlowDecoder) lookupTemplate(k netflowTemplateKey) *cachedTemplate {
	d.mu.Lock()
	defer d.mu.Unlock()
	t := d.templates[k]
	if t != nil {
		t.lastUsedAt = time.Now()
		t.packetsUsing++
	}
	return t
}

func decodeVariableOrFixedRecord(
	tmpl *cachedTemplate,
	body []byte,
	startOff int,
	exporterIP string,
	sourceID uint32,
	version string,
	baseTime time.Time,
	sysUptimeMs uint32,
	defaultSampling uint32,
) (FlowRecord, int, bool) {
	if !tmpl.hasVarLen {
		if startOff+tmpl.fixedLen > len(body) {
			return FlowRecord{}, startOff, false
		}
		return decodeTemplateRecord(tmpl, body[startOff:startOff+tmpl.fixedLen], exporterIP, sourceID, version, baseTime, sysUptimeMs, defaultSampling), startOff + tmpl.fixedLen, true
	}

	off := startOff
	vals := make([][]byte, len(tmpl.fields))
	for i, f := range tmpl.fields {
		var valLen int
		if f.Length == 0xFFFF {
			if off+1 > len(body) {
				return FlowRecord{}, startOff, false
			}
			l1 := int(body[off])
			off++
			if l1 == 255 {
				if off+2 > len(body) {
					return FlowRecord{}, startOff, false
				}
				valLen = int(binary.BigEndian.Uint16(body[off : off+2]))
				off += 2
			} else {
				valLen = l1
			}
		} else {
			valLen = int(f.Length)
		}
		if off+valLen > len(body) {
			return FlowRecord{}, startOff, false
		}
		vals[i] = body[off : off+valLen]
		off += valLen
	}
	rec := applyFieldSlices(tmpl.fields, vals, exporterIP, sourceID, version, baseTime, sysUptimeMs, defaultSampling)
	return rec, off, true
}

func decodeTemplateRecord(
	tmpl *cachedTemplate,
	rec []byte,
	exporterIP string,
	sourceID uint32,
	version string,
	baseTime time.Time,
	sysUptimeMs uint32,
	defaultSampling uint32,
) FlowRecord {
	vals := make([][]byte, len(tmpl.fields))
	off := 0
	for i, f := range tmpl.fields {
		l := int(f.Length)
		if off+l > len(rec) {
			break
		}
		vals[i] = rec[off : off+l]
		off += l
	}
	return applyFieldSlices(tmpl.fields, vals, exporterIP, sourceID, version, baseTime, sysUptimeMs, defaultSampling)
}

func applyFieldSlices(
	fields []TemplateFieldSpec,
	vals [][]byte,
	exporterIP string,
	sourceID uint32,
	version string,
	baseTime time.Time,
	sysUptimeMs uint32,
	defaultSampling uint32,
) FlowRecord {
	out := FlowRecord{
		Version:      version,
		ExporterIP:   exporterIP,
		SourceID:     sourceID,
		TimestampMs:  baseTime.UnixMilli(),
		Timestamp:    baseTime.UTC().Format(time.RFC3339Nano),
		FlowStartMs:  baseTime.UnixMilli(),
		SamplingRate: defaultSampling,
	}
	var startUp, endUp uint32
	var startMs, endMs int64

	for i, f := range fields {
		v := vals[i]
		if len(v) == 0 {
			continue
		}
		if f.EnterpriseID != 0 {
			switch f.FieldType {
			case 1:
				if len(v) > 0 {
					out.K3sNamespace = strings.TrimSpace(string(v))
				}
			case 2:
				if len(v) > 0 {
					out.K3sWorkload = strings.TrimSpace(string(v))
				}
			case 3:
				if us := decodeUint(v); us > 0 {
					out.RttMs = float64(us) / 1000.0
				}
			case 4:
				out.Retransmits = uint32(decodeUint(v))
			case 5:
				out.HostID = strings.TrimRight(strings.TrimSpace(string(v)), "\x00")
			case 6:
				out.HostName = strings.TrimRight(strings.TrimSpace(string(v)), "\x00")
			}
			continue
		}
		switch f.FieldType {
		case 1: // octetDeltaCount
			out.Bytes += decodeUint(v)
		case 2: // packetDeltaCount
			out.Packets += decodeUint(v)
		case 4: // protocolIdentifier
			out.Protocol = uint8(decodeUint(v))
		case 5: // ipClassOfService
			out.ToS = uint8(decodeUint(v))
			out.DSCP = out.ToS >> 2
		case 6: // tcpControlBits
			out.TCPFlags = uint8(decodeUint(v))
		case 7: // sourceTransportPort
			out.SrcPort = uint16(decodeUint(v))
		case 8: // sourceIPv4Address
			if len(v) >= 4 {
				out.SrcIP = net.IP(v[:4]).String()
			}
		case 10: // ingressInterface
			out.InIfIndex = uint32(decodeUint(v))
		case 11: // destinationTransportPort
			out.DstPort = uint16(decodeUint(v))
		case 12: // destinationIPv4Address
			if len(v) >= 4 {
				out.DstIP = net.IP(v[:4]).String()
			}
		case 14: // egressInterface
			out.OutIfIndex = uint32(decodeUint(v))
		case 16: // bgpSourceAsNumber
			out.SrcAsn = uint32(decodeUint(v))
		case 17: // bgpDestinationAsNumber
			out.DstAsn = uint32(decodeUint(v))
		case 21: // flowEndSysUpTime
			endUp = uint32(decodeUint(v))
		case 22: // flowStartSysUpTime
			startUp = uint32(decodeUint(v))
		case 27: // sourceIPv6Address
			if len(v) == 16 {
				out.SrcIP = net.IP(v).String()
			}
		case 28: // destinationIPv6Address
			if len(v) == 16 {
				out.DstIP = net.IP(v).String()
			}
		case 34, 48, 50: // samplingInterval / flowSamplerRandomInterval
			if s := uint32(decodeUint(v)); s > 0 {
				out.SamplingRate = s
			}
		case 56: // sourceMacAddress
			if len(v) == 6 {
				out.SrcMac = net.HardwareAddr(v).String()
			}
		case 57, 80: // postDestinationMacAddress / destinationMacAddress
			if len(v) == 6 {
				out.DstMac = net.HardwareAddr(v).String()
			}
		case 58, 243: // vlanId / dot1qVlanId
			out.VlanID = uint16(decodeUint(v))
		case 82: // interfaceName
			out.InIfName = strings.TrimRight(strings.TrimSpace(string(v)), "\x00")
		case 83: // interfaceDescription
			if out.InIfName == "" {
				out.InIfName = strings.TrimRight(strings.TrimSpace(string(v)), "\x00")
			}
		case 149: // observationDomainId
			if did := uint32(decodeUint(v)); did > 0 {
				out.SourceID = did
			}
		case 85: // octetTotalCount (fallback if delta missing)
			if out.Bytes == 0 {
				out.Bytes = decodeUint(v)
			}
		case 86: // packetTotalCount
			if out.Packets == 0 {
				out.Packets = decodeUint(v)
			}
		case 96: // applicationName
			out.AppName = strings.TrimRight(string(v), "\x00 ")
		case 150: // flowStartSeconds
			startMs = int64(decodeUint(v)) * 1000
		case 151: // flowEndSeconds
			endMs = int64(decodeUint(v)) * 1000
		case 152: // flowStartMilliseconds
			startMs = int64(decodeUint(v))
		case 153: // flowEndMilliseconds
			endMs = int64(decodeUint(v))
		case 225: // postNATSourceIPv4Address
			if len(v) >= 4 {
				if ip := net.IP(v[:4]); !ip.IsUnspecified() {
					out.PostNatSrcIP = ip.String()
				}
			}
		case 226: // postNATDestinationIPv4Address
			if len(v) >= 4 {
				if ip := net.IP(v[:4]); !ip.IsUnspecified() {
					out.PostNatDstIP = ip.String()
				}
			}
		case 227: // postNAPTSourceTransportPort
			out.PostNatSrcPort = uint16(decodeUint(v))
		case 228: // postNAPTDestinationTransportPort
			out.PostNatDstPort = uint16(decodeUint(v))
		case 281: // postNATSourceIPv6Address
			if len(v) == 16 {
				if ip := net.IP(v); !ip.IsUnspecified() {
					out.PostNatSrcIP = ip.String()
				}
			}
		case 282: // postNATDestinationIPv6Address
			if len(v) == 16 {
				if ip := net.IP(v); !ip.IsUnspecified() {
					out.PostNatDstIP = ip.String()
				}
			}
		case 233: // firewallEvent
			out.FirewallEvent = uint8(decodeUint(v))
		}
	}

	if out.SamplingRate > 1 {
		out.Bytes *= uint64(out.SamplingRate)
		out.Packets *= uint64(out.SamplingRate)
	}
	if startMs > 0 && endMs > 0 {
		out.FlowStartMs = startMs
		out.TimestampMs = endMs
		out.Timestamp = time.UnixMilli(endMs).UTC().Format(time.RFC3339Nano)
	} else if sysUptimeMs > 0 && endUp >= startUp && sysUptimeMs >= endUp {
		endT := baseTime.Add(-time.Duration(sysUptimeMs-endUp) * time.Millisecond)
		startT := baseTime.Add(-time.Duration(sysUptimeMs-startUp) * time.Millisecond)
		out.FlowStartMs = startT.UnixMilli()
		out.TimestampMs = endT.UnixMilli()
		out.Timestamp = endT.UTC().Format(time.RFC3339Nano)
	}

	durSec := float64(out.TimestampMs-out.FlowStartMs) / 1000.0
	if durSec < 1 {
		durSec = 1
	}
	out.Bps = float64(out.Bytes*8) / durSec
	out.Pps = float64(out.Packets) / durSec
	out.ProtocolName = netflowProtocolName(out.Protocol)
	out.TCPFlagsStr = formatTCPFlags(out.TCPFlags)
	out.ID = fmt.Sprintf("%s-%d-%s-%d-%s-%d", version, out.TimestampMs, out.SrcIP, out.SrcPort, out.DstIP, out.DstPort)
	return out
}

func (d *FlowDecoder) decodeSFlowV5(exporterIP string, raw []byte, recvTime time.Time) ([]FlowRecord, []ExporterInterfaceCounter, error) {
	if len(raw) < 28 {
		return nil, nil, errors.New("truncated sflow v5 header")
	}
	addrType := binary.BigEndian.Uint32(raw[4:8])
	off := 8
	agentIP := exporterIP
	if addrType == 1 && off+4 <= len(raw) {
		agentIP = net.IP(raw[off : off+4]).String()
		off += 4
	} else if addrType == 2 && off+16 <= len(raw) {
		agentIP = net.IP(raw[off : off+16]).String()
		off += 16
	} else {
		return nil, nil, errors.New("invalid sflow v5 agent address type")
	}
	if off+16 > len(raw) {
		return nil, nil, errors.New("truncated sflow v5 subheader")
	}
	off += 12 // subAgentID + seq + uptime
	numSamples := int(binary.BigEndian.Uint32(raw[off : off+4]))
	off += 4

	var flows []FlowRecord
	var counters []ExporterInterfaceCounter
	for s := 0; s < numSamples && off+8 <= len(raw); s++ {
		sampleFormat := binary.BigEndian.Uint32(raw[off : off+4])
		sampleLen := int(binary.BigEndian.Uint32(raw[off+4 : off+8]))
		off += 8
		if sampleLen < 0 || off+sampleLen > len(raw) {
			break
		}
		sBody := raw[off : off+sampleLen]
		off += sampleLen

		switch sampleFormat {
		case 1, 3: // Flow Sample (1) or Expanded Flow Sample (3)
			minHdr := 32
			if sampleFormat == 3 {
				minHdr = 44
			}
			if len(sBody) < minHdr {
				continue
			}
			samplingRate := binary.BigEndian.Uint32(sBody[8:12])
			if samplingRate == 0 {
				samplingRate = 1
			}
			var inIf, outIf uint32
			var numRecs int
			rOff := 0
			if sampleFormat == 1 {
				inIf = binary.BigEndian.Uint32(sBody[20:24]) & 0x3FFFFFFF
				outIf = binary.BigEndian.Uint32(sBody[24:28]) & 0x3FFFFFFF
				numRecs = int(binary.BigEndian.Uint32(sBody[28:32]))
				rOff = 32
			} else {
				inIf = binary.BigEndian.Uint32(sBody[24:28])
				outIf = binary.BigEndian.Uint32(sBody[32:36])
				numRecs = int(binary.BigEndian.Uint32(sBody[40:44]))
				rOff = 44
			}
			for r := 0; r < numRecs && rOff+8 <= len(sBody); r++ {
				recFmt := binary.BigEndian.Uint32(sBody[rOff : rOff+4])
				recLen := int(binary.BigEndian.Uint32(sBody[rOff+4 : rOff+8]))
				rOff += 8
				if recLen < 0 || rOff+recLen > len(sBody) {
					break
				}
				recBody := sBody[rOff : rOff+recLen]
				rOff += recLen
				if recFmt == 1 && len(recBody) >= 16 {
					// Raw Packet Header
					hdrProto := binary.BigEndian.Uint32(recBody[0:4])
					frameLen := uint64(binary.BigEndian.Uint32(recBody[4:8]))
					pktLen := int(binary.BigEndian.Uint32(recBody[12:16]))
					if hdrProto == 1 && 16+pktLen <= len(recBody) {
						if parsed, ok := parseEthernetFrameHeader(recBody[16:16+pktLen], frameLen, samplingRate, agentIP, inIf, outIf, recvTime); ok {
							flows = append(flows, parsed)
						}
					}
				}
			}

		case 2, 4: // Counter Sample (2) or Expanded Counter Sample (4)
			hdrBytes := 12
			if sampleFormat == 4 {
				hdrBytes = 16
			}
			if len(sBody) < hdrBytes {
				continue
			}
			numRecs := int(binary.BigEndian.Uint32(sBody[hdrBytes-4 : hdrBytes]))
			rOff := hdrBytes
			for r := 0; r < numRecs && rOff+8 <= len(sBody); r++ {
				recFmt := binary.BigEndian.Uint32(sBody[rOff : rOff+4])
				recLen := int(binary.BigEndian.Uint32(sBody[rOff+4 : rOff+8]))
				rOff += 8
				if recLen < 0 || rOff+recLen > len(sBody) {
					break
				}
				recBody := sBody[rOff : rOff+recLen]
				rOff += recLen
				if recFmt == 1 && len(recBody) >= 88 {
					ifIdx := binary.BigEndian.Uint32(recBody[0:4])
					inOct := binary.BigEndian.Uint64(recBody[28:36])
					inErr := binary.BigEndian.Uint32(recBody[48:52])
					outOct := binary.BigEndian.Uint64(recBody[56:64])
					outErr := binary.BigEndian.Uint32(recBody[76:80])
					counters = append(counters, ExporterInterfaceCounter{
						ExporterIP: agentIP,
						IfIndex:    ifIdx,
						InOctets:   inOct,
						OutOctets:  outOct,
						InErrors:   inErr,
						OutErrors:  outErr,
						UpdatedAt:  recvTime.UTC().Format(time.RFC3339),
					})
				}
			}
		}
	}
	return flows, counters, nil
}

func parseEthernetFrameHeader(
	pkt []byte,
	wireFrameLen uint64,
	samplingRate uint32,
	exporterIP string,
	inIf, outIf uint32,
	recvTime time.Time,
) (FlowRecord, bool) {
	if len(pkt) < 14 {
		return FlowRecord{}, false
	}
	dstMac := net.HardwareAddr(pkt[0:6]).String()
	srcMac := net.HardwareAddr(pkt[6:12]).String()
	ethType := binary.BigEndian.Uint16(pkt[12:14])
	off := 14
	var vlanID uint16
	for (ethType == 0x8100 || ethType == 0x88A8) && off+4 <= len(pkt) {
		vlanID = binary.BigEndian.Uint16(pkt[off:off+2]) & 0x0FFF
		ethType = binary.BigEndian.Uint16(pkt[off+2 : off+4])
		off += 4
	}

	var srcIP, dstIP string
	var proto, tos uint8
	if ethType == 0x0800 && off+20 <= len(pkt) {
		ihl := int(pkt[off]&0x0F) * 4
		if ihl < 20 || off+ihl > len(pkt) {
			return FlowRecord{}, false
		}
		tos = pkt[off+1]
		proto = pkt[off+9]
		srcIP = net.IP(pkt[off+12 : off+16]).String()
		dstIP = net.IP(pkt[off+16 : off+20]).String()
		off += ihl
	} else if ethType == 0x86DD && off+40 <= len(pkt) {
		proto = pkt[off+6]
		srcIP = net.IP(pkt[off+8 : off+24]).String()
		dstIP = net.IP(pkt[off+24 : off+40]).String()
		off += 40
	} else {
		return FlowRecord{}, false
	}

	var srcPort, dstPort uint16
	var tcpFlags uint8
	if proto == 6 && off+14 <= len(pkt) {
		srcPort = binary.BigEndian.Uint16(pkt[off : off+2])
		dstPort = binary.BigEndian.Uint16(pkt[off+2 : off+4])
		tcpFlags = pkt[off+13]
	} else if proto == 17 && off+4 <= len(pkt) {
		srcPort = binary.BigEndian.Uint16(pkt[off : off+2])
		dstPort = binary.BigEndian.Uint16(pkt[off+2 : off+4])
	}

	scaledBytes := wireFrameLen * uint64(samplingRate)
	if scaledBytes == 0 {
		scaledBytes = uint64(len(pkt)) * uint64(samplingRate)
	}
	scaledPkts := uint64(samplingRate)

	return FlowRecord{
		ID:           fmt.Sprintf("sf5-%d-%s-%d-%s-%d", recvTime.UnixNano(), srcIP, srcPort, dstIP, dstPort),
		TimestampMs:  recvTime.UnixMilli(),
		Timestamp:    recvTime.UTC().Format(time.RFC3339Nano),
		FlowStartMs:  recvTime.Add(-time.Second).UnixMilli(),
		Version:      "sflow5",
		ExporterIP:   exporterIP,
		SrcIP:        srcIP,
		DstIP:        dstIP,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		Protocol:     proto,
		ProtocolName: netflowProtocolName(proto),
		InIfIndex:    inIf,
		OutIfIndex:   outIf,
		VlanID:       vlanID,
		Bytes:        scaledBytes,
		Packets:      scaledPkts,
		Bps:          float64(scaledBytes * 8),
		Pps:          float64(scaledPkts),
		TCPFlags:     tcpFlags,
		TCPFlagsStr:  formatTCPFlags(tcpFlags),
		ToS:          tos,
		DSCP:         tos >> 2,
		SrcMac:       srcMac,
		DstMac:       dstMac,
		SamplingRate: samplingRate,
	}, true
}

// EncodeIPFIXPacket builds a standards-compliant dual-stack RFC 7011 IPFIX datagram
// (Template 256 for IPv4 + NAT IEs 225–228 + PEN 62999 NPM IEs; Template 257 for IPv6).
func EncodeIPFIXPacket(domainID uint32, seq uint32, includeTemplates bool, flows []FlowRecord) []byte {
	const v4TmplID uint16 = 256
	const v6TmplID uint16 = 257
	const axonwallPEN uint32 = 62999

	var v4Flows, v6Flows []FlowRecord
	for _, f := range flows {
		sIP := net.ParseIP(f.SrcIP)
		dIP := net.ParseIP(f.DstIP)
		if sIP == nil || dIP == nil {
			continue
		}
		if sIP.To4() != nil && dIP.To4() != nil {
			v4Flows = append(v4Flows, f)
		} else {
			v6Flows = append(v6Flows, f)
		}
	}

	buf := make([]byte, 16, 1500)
	binary.BigEndian.PutUint16(buf[0:2], 10)
	binary.BigEndian.PutUint32(buf[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(buf[8:12], seq)
	binary.BigEndian.PutUint32(buf[12:16], domainID)

	appendFieldSpec := func(dst *[]byte, ie uint16, length uint16, ent uint32) {
		var tmp [8]byte
		if ent != 0 {
			binary.BigEndian.PutUint16(tmp[0:2], ie|0x8000)
			binary.BigEndian.PutUint16(tmp[2:4], length)
			binary.BigEndian.PutUint32(tmp[4:8], ent)
			*dst = append(*dst, tmp[:8]...)
		} else {
			binary.BigEndian.PutUint16(tmp[0:2], ie)
			binary.BigEndian.PutUint16(tmp[2:4], length)
			*dst = append(*dst, tmp[:4]...)
		}
	}

	if includeTemplates {
		// Build IPFIX Template Set containing Template 256 (IPv4) + Template 257 (IPv6)
		var tBody []byte
		if len(v4Flows) > 0 || len(v6Flows) == 0 {
			var hdr [4]byte
			binary.BigEndian.PutUint16(hdr[0:2], v4TmplID)
			binary.BigEndian.PutUint16(hdr[2:4], 18) // 16 std + 2 ent
			tBody = append(tBody, hdr[:]...)
			spec4 := [][2]uint16{
				{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {6, 1},
				{10, 4}, {14, 4}, {58, 2}, {1, 8}, {2, 8}, {152, 8},
				{225, 4}, {226, 4}, {227, 2}, {228, 2},
			}
			for _, kv := range spec4 {
				appendFieldSpec(&tBody, kv[0], kv[1], 0)
			}
			appendFieldSpec(&tBody, 3, 4, axonwallPEN) // RTT us
			appendFieldSpec(&tBody, 4, 4, axonwallPEN) // retransmits
		}
		if len(v6Flows) > 0 || len(v4Flows) == 0 {
			var hdr [4]byte
			binary.BigEndian.PutUint16(hdr[0:2], v6TmplID)
			binary.BigEndian.PutUint16(hdr[2:4], 14) // 12 std + 2 ent
			tBody = append(tBody, hdr[:]...)
			spec6 := [][2]uint16{
				{27, 16}, {28, 16}, {7, 2}, {11, 2}, {4, 1}, {6, 1},
				{10, 4}, {14, 4}, {58, 2}, {1, 8}, {2, 8}, {152, 8},
			}
			for _, kv := range spec6 {
				appendFieldSpec(&tBody, kv[0], kv[1], 0)
			}
			appendFieldSpec(&tBody, 3, 4, axonwallPEN)
			appendFieldSpec(&tBody, 4, 4, axonwallPEN)
		}
		if pad := (4 - (len(tBody) % 4)) % 4; pad > 0 {
			tBody = append(tBody, make([]byte, pad)...)
		}
		var setHdr [4]byte
		binary.BigEndian.PutUint16(setHdr[0:2], 2) // Template Set ID = 2
		binary.BigEndian.PutUint16(setHdr[2:4], uint16(4+len(tBody)))
		buf = append(buf, setHdr[:]...)
		buf = append(buf, tBody...)
	}

	if len(v4Flows) > 0 {
		const recLen = 4 + 4 + 2 + 2 + 1 + 1 + 4 + 4 + 2 + 8 + 8 + 8 + 4 + 4 + 2 + 2 + 4 + 4 // 68 bytes
		dSet := make([]byte, 4+len(v4Flows)*recLen)
		binary.BigEndian.PutUint16(dSet[0:2], v4TmplID)
		binary.BigEndian.PutUint16(dSet[2:4], uint16(len(dSet)))
		for i, f := range v4Flows {
			r := dSet[4+i*recLen : 4+(i+1)*recLen]
			copy(r[0:4], net.ParseIP(f.SrcIP).To4())
			copy(r[4:8], net.ParseIP(f.DstIP).To4())
			binary.BigEndian.PutUint16(r[8:10], f.SrcPort)
			binary.BigEndian.PutUint16(r[10:12], f.DstPort)
			r[12] = f.Protocol
			r[13] = f.TCPFlags
			binary.BigEndian.PutUint32(r[14:18], f.InIfIndex)
			binary.BigEndian.PutUint32(r[18:22], f.OutIfIndex)
			binary.BigEndian.PutUint16(r[22:24], f.VlanID)
			binary.BigEndian.PutUint64(r[24:32], f.Bytes)
			binary.BigEndian.PutUint64(r[32:40], f.Packets)
			startMs := f.FlowStartMs
			if startMs <= 0 {
				startMs = time.Now().Add(-time.Second).UnixMilli()
			}
			binary.BigEndian.PutUint64(r[40:48], uint64(startMs))
			if pns := net.ParseIP(f.PostNatSrcIP).To4(); pns != nil {
				copy(r[48:52], pns)
			}
			if pnd := net.ParseIP(f.PostNatDstIP).To4(); pnd != nil {
				copy(r[52:56], pnd)
			}
			binary.BigEndian.PutUint16(r[56:58], f.PostNatSrcPort)
			binary.BigEndian.PutUint16(r[58:60], f.PostNatDstPort)
			binary.BigEndian.PutUint32(r[60:64], uint32(f.RttMs*1000))
			binary.BigEndian.PutUint32(r[64:68], f.Retransmits)
		}
		buf = append(buf, dSet...)
	}

	if len(v6Flows) > 0 {
		const recLen = 16 + 16 + 2 + 2 + 1 + 1 + 4 + 4 + 2 + 8 + 8 + 8 + 4 + 4 // 80 bytes
		dSet := make([]byte, 4+len(v6Flows)*recLen)
		binary.BigEndian.PutUint16(dSet[0:2], v6TmplID)
		binary.BigEndian.PutUint16(dSet[2:4], uint16(len(dSet)))
		for i, f := range v6Flows {
			r := dSet[4+i*recLen : 4+(i+1)*recLen]
			copy(r[0:16], net.ParseIP(f.SrcIP).To16())
			copy(r[16:32], net.ParseIP(f.DstIP).To16())
			binary.BigEndian.PutUint16(r[32:34], f.SrcPort)
			binary.BigEndian.PutUint16(r[34:36], f.DstPort)
			r[36] = f.Protocol
			r[37] = f.TCPFlags
			binary.BigEndian.PutUint32(r[38:42], f.InIfIndex)
			binary.BigEndian.PutUint32(r[42:46], f.OutIfIndex)
			binary.BigEndian.PutUint16(r[46:48], f.VlanID)
			binary.BigEndian.PutUint64(r[48:56], f.Bytes)
			binary.BigEndian.PutUint64(r[56:64], f.Packets)
			startMs := f.FlowStartMs
			if startMs <= 0 {
				startMs = time.Now().Add(-time.Second).UnixMilli()
			}
			binary.BigEndian.PutUint64(r[64:72], uint64(startMs))
			binary.BigEndian.PutUint32(r[72:76], uint32(f.RttMs*1000))
			binary.BigEndian.PutUint32(r[76:80], f.Retransmits)
		}
		buf = append(buf, dSet...)
	}

	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	return buf
}

func appendIPFIXVarString(dst *[]byte, s string) {
	if len(s) > 250 {
		s = s[:250]
	}
	*dst = append(*dst, byte(len(s)))
	*dst = append(*dst, s...)
}

// EncodeIPFIXOptionsPacket emits RFC 7011 Options Templates 258 (node_id + hostname)
// and 259 (ifIndex -> ifName/description) plus corresponding Data Sets.
func EncodeIPFIXOptionsPacket(domainID uint32, seq uint32, nodeID, hostname string, ifaces []NetFlowRemoteIface) []byte {
	const nodeOptTmplID uint16 = 258
	const ifaceOptTmplID uint16 = 259
	const axonwallPEN uint32 = 62999

	buf := make([]byte, 16, 1500)
	binary.BigEndian.PutUint16(buf[0:2], 10)
	binary.BigEndian.PutUint32(buf[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(buf[8:12], seq)
	binary.BigEndian.PutUint32(buf[12:16], domainID)

	appendFieldSpec := func(dst *[]byte, ie uint16, length uint16, ent uint32) {
		var tmp [8]byte
		if ent != 0 {
			binary.BigEndian.PutUint16(tmp[0:2], ie|0x8000)
			binary.BigEndian.PutUint16(tmp[2:4], length)
			binary.BigEndian.PutUint32(tmp[4:8], ent)
			*dst = append(*dst, tmp[:8]...)
		} else {
			binary.BigEndian.PutUint16(tmp[0:2], ie)
			binary.BigEndian.PutUint16(tmp[2:4], length)
			*dst = append(*dst, tmp[:4]...)
		}
	}

	// Build Set ID 3: Options Templates 258 + 259
	var optTmplBody []byte
	{
		var hdr [6]byte
		binary.BigEndian.PutUint16(hdr[0:2], nodeOptTmplID)
		binary.BigEndian.PutUint16(hdr[2:4], 3) // fieldCount
		binary.BigEndian.PutUint16(hdr[4:6], 1) // scopeFieldCount
		optTmplBody = append(optTmplBody, hdr[:]...)
		appendFieldSpec(&optTmplBody, 149, 4, 0)          // observationDomainId (scope)
		appendFieldSpec(&optTmplBody, 5, 0xFFFF, axonwallPEN) // axonwallNodeId
		appendFieldSpec(&optTmplBody, 6, 0xFFFF, axonwallPEN) // axonwallNodeHostname
	}
	if len(ifaces) > 0 {
		var hdr [6]byte
		binary.BigEndian.PutUint16(hdr[0:2], ifaceOptTmplID)
		binary.BigEndian.PutUint16(hdr[2:4], 3) // fieldCount
		binary.BigEndian.PutUint16(hdr[4:6], 1) // scopeFieldCount
		optTmplBody = append(optTmplBody, hdr[:]...)
		appendFieldSpec(&optTmplBody, 10, 4, 0)      // ingressInterface (scope)
		appendFieldSpec(&optTmplBody, 82, 0xFFFF, 0) // interfaceName
		appendFieldSpec(&optTmplBody, 83, 0xFFFF, 0) // interfaceDescription
	}
	if pad := (4 - (len(optTmplBody) % 4)) % 4; pad > 0 {
		optTmplBody = append(optTmplBody, make([]byte, pad)...)
	}
	var optSetHdr [4]byte
	binary.BigEndian.PutUint16(optSetHdr[0:2], 3) // Options Template Set ID = 3
	binary.BigEndian.PutUint16(optSetHdr[2:4], uint16(4+len(optTmplBody)))
	buf = append(buf, optSetHdr[:]...)
	buf = append(buf, optTmplBody...)

	// Data Set 258 (node identity)
	if nodeID != "" || hostname != "" {
		var dBody []byte
		var dom [4]byte
		binary.BigEndian.PutUint32(dom[0:4], domainID)
		dBody = append(dBody, dom[:]...)
		appendIPFIXVarString(&dBody, nodeID)
		appendIPFIXVarString(&dBody, hostname)
		if pad := (4 - (len(dBody) % 4)) % 4; pad > 0 {
			dBody = append(dBody, make([]byte, pad)...)
		}
		var dHdr [4]byte
		binary.BigEndian.PutUint16(dHdr[0:2], nodeOptTmplID)
		binary.BigEndian.PutUint16(dHdr[2:4], uint16(4+len(dBody)))
		buf = append(buf, dHdr[:]...)
		buf = append(buf, dBody...)
	}

	// Data Set 259 (interface table, capped safely to fit MTU)
	if len(ifaces) > 0 {
		var dBody []byte
		for _, ifc := range ifaces {
			if ifc.IfIndex == 0 || ifc.Name == "" {
				continue
			}
			if len(buf)+4+len(dBody)+8+len(ifc.Name)+len(ifc.Description) > 1400 {
				break
			}
			var idxBuf [4]byte
			binary.BigEndian.PutUint32(idxBuf[0:4], ifc.IfIndex)
			dBody = append(dBody, idxBuf[:]...)
			appendIPFIXVarString(&dBody, ifc.Name)
			appendIPFIXVarString(&dBody, ifc.Description)
		}
		if len(dBody) > 0 {
			if pad := (4 - (len(dBody) % 4)) % 4; pad > 0 {
				dBody = append(dBody, make([]byte, pad)...)
			}
			var dHdr [4]byte
			binary.BigEndian.PutUint16(dHdr[0:2], ifaceOptTmplID)
			binary.BigEndian.PutUint16(dHdr[2:4], uint16(4+len(dBody)))
			buf = append(buf, dHdr[:]...)
			buf = append(buf, dBody...)
		}
	}

	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	return buf
}

// EncodeNetFlowV9Packet builds a valid RFC 3954 NetFlow v9 datagram for target exporters requiring v9.
func EncodeNetFlowV9Packet(sourceID uint32, seq uint32, includeTemplates bool, flows []FlowRecord) []byte {
	const tmplID uint16 = 257
	buf := make([]byte, 20, 1500)
	binary.BigEndian.PutUint16(buf[0:2], 9)
	flowSetCount := uint16(0)
	now := time.Now()
	binary.BigEndian.PutUint32(buf[4:8], 60000)
	binary.BigEndian.PutUint32(buf[8:12], uint32(now.Unix()))
	binary.BigEndian.PutUint32(buf[12:16], seq)
	binary.BigEndian.PutUint32(buf[16:20], sourceID)

	var v4Flows []FlowRecord
	for _, f := range flows {
		if net.ParseIP(f.SrcIP).To4() != nil && net.ParseIP(f.DstIP).To4() != nil {
			v4Flows = append(v4Flows, f)
		}
	}

	if includeTemplates {
		flowSetCount++
		tSet := make([]byte, 4+4+10*4)
		binary.BigEndian.PutUint16(tSet[0:2], 0)
		binary.BigEndian.PutUint16(tSet[2:4], uint16(len(tSet)))
		binary.BigEndian.PutUint16(tSet[4:6], tmplID)
		binary.BigEndian.PutUint16(tSet[6:8], 10)
		spec := [][2]uint16{
			{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1},
			{6, 1}, {10, 4}, {14, 4}, {1, 8}, {2, 8},
		}
		for i, kv := range spec {
			binary.BigEndian.PutUint16(tSet[8+i*4:10+i*4], kv[0])
			binary.BigEndian.PutUint16(tSet[10+i*4:12+i*4], kv[1])
		}
		buf = append(buf, tSet...)
	}

	if len(v4Flows) > 0 {
		flowSetCount++
		const recLen = 38
		rawDataLen := len(v4Flows) * recLen
		pad := (4 - (rawDataLen % 4)) % 4
		dSet := make([]byte, 4+rawDataLen+pad)
		binary.BigEndian.PutUint16(dSet[0:2], tmplID)
		binary.BigEndian.PutUint16(dSet[2:4], uint16(len(dSet)))
		for i, f := range v4Flows {
			r := dSet[4+i*recLen : 4+(i+1)*recLen]
			copy(r[0:4], net.ParseIP(f.SrcIP).To4())
			copy(r[4:8], net.ParseIP(f.DstIP).To4())
			binary.BigEndian.PutUint16(r[8:10], f.SrcPort)
			binary.BigEndian.PutUint16(r[10:12], f.DstPort)
			r[12] = f.Protocol
			r[13] = f.TCPFlags
			binary.BigEndian.PutUint32(r[14:18], f.InIfIndex)
			binary.BigEndian.PutUint32(r[18:22], f.OutIfIndex)
			binary.BigEndian.PutUint64(r[22:30], f.Bytes)
			binary.BigEndian.PutUint64(r[30:38], f.Packets)
		}
		buf = append(buf, dSet...)
	}
	binary.BigEndian.PutUint16(buf[2:4], flowSetCount)
	return buf
}

func decodeUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = (v << 8) | uint64(x)
	}
	return v
}

func netflowProtocolName(p uint8) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	case 132:
		return "SCTP"
	default:
		return fmt.Sprintf("IP-%d", p)
	}
}

func formatTCPFlags(flags uint8) string {
	if flags == 0 {
		return ""
	}
	var parts []string
	if flags&0x01 != 0 {
		parts = append(parts, "FIN")
	}
	if flags&0x02 != 0 {
		parts = append(parts, "SYN")
	}
	if flags&0x04 != 0 {
		parts = append(parts, "RST")
	}
	if flags&0x08 != 0 {
		parts = append(parts, "PSH")
	}
	if flags&0x10 != 0 {
		parts = append(parts, "ACK")
	}
	if flags&0x20 != 0 {
		parts = append(parts, "URG")
	}
	return strings.Join(parts, "|")
}

func ieName(entID uint32, ft uint16) string {
	if entID != 0 {
		switch ft {
		case 1:
			return "axonwallK3sNamespace"
		case 2:
			return "axonwallK3sWorkload"
		case 3:
			return "axonwallTcpRttMicros"
		case 4:
			return "axonwallTcpRetransmits"
		case 5:
			return "axonwallNodeId"
		case 6:
			return "axonwallNodeHostname"
		default:
			return fmt.Sprintf("ent(%d).%d", entID, ft)
		}
	}
	names := map[uint16]string{
		1:   "octetDeltaCount",
		2:   "packetDeltaCount",
		4:   "protocolIdentifier",
		5:   "ipClassOfService",
		6:   "tcpControlBits",
		7:   "sourceTransportPort",
		8:   "sourceIPv4Address",
		10:  "ingressInterface",
		11:  "destinationTransportPort",
		12:  "destinationIPv4Address",
		14:  "egressInterface",
		16:  "bgpSourceAsNumber",
		17:  "bgpDestinationAsNumber",
		21:  "flowEndSysUpTime",
		22:  "flowStartSysUpTime",
		27:  "sourceIPv6Address",
		28:  "destinationIPv6Address",
		34:  "samplingInterval",
		48:  "flowSamplerID",
		50:  "flowSamplerRandomInterval",
		56:  "sourceMacAddress",
		57:  "postDestinationMacAddress",
		58:  "vlanId",
		80:  "destinationMacAddress",
		85:  "octetTotalCount",
		86:  "packetTotalCount",
		96:  "applicationName",
		150: "flowStartSeconds",
		151: "flowEndSeconds",
		152: "flowStartMilliseconds",
		153: "flowEndMilliseconds",
		225: "postNATSourceIPv4Address",
		226: "postNATDestinationIPv4Address",
		227: "postNAPTSourceTransportPort",
		228: "postNAPTDestinationTransportPort",
		233: "firewallEvent",
		243: "dot1qVlanId",
		281: "postNATSourceIPv6Address",
		282: "postNATDestinationIPv6Address",
	}
	if n, ok := names[ft]; ok {
		return n
	}
	return fmt.Sprintf("ie_%d", ft)
}
