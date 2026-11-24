package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// QueryFlows executes a local query and, when Scope == "fleet", fans out concurrently
// across enabled Topology peer Axonwall hosts and merges all analytics deterministically.
func (m *NetFlowManager) QueryFlows(req FlowQueryRequest) FlowQueryResponse {
	localResp := m.store.Query(req)

	m.mu.RLock()
	bundle := m.bundle
	tm := m.topology
	m.mu.RUnlock()

	localHostID := "local"
	localHostName := "Local Axonwall"
	if bundle != nil && bundle.LocalHostname != "" {
		localHostID = bundle.LocalHostname
		localHostName = bundle.LocalHostname
	}

	for i := range localResp.Flows {
		if localResp.Flows[i].HostID == "" {
			localResp.Flows[i].HostID = localHostID
			localResp.Flows[i].HostName = localHostName
		}
	}

	if !strings.EqualFold(req.Scope, "fleet") || tm == nil {
		return localResp
	}

	peers, peerTokens := tm.ListEnabledPeersWithTokens()
	if len(peers) == 0 {
		localResp.Engine = "federated"
		return localResp
	}

	allowedPeerSet := make(map[string]bool)
	for _, pid := range req.PeerIDs {
		if strings.TrimSpace(pid) != "" {
			allowedPeerSet[strings.TrimSpace(pid)] = true
		}
	}

	// Force sub-queries to Scope="local" to prevent recursive broadcast amplification.
	subReq := req
	subReq.Scope = "local"
	subReq.PeerIDs = nil
	bodyBytes, err := json.Marshal(subReq)
	if err != nil {
		return localResp
	}

	type peerResult struct {
		peer  TopologyPeerHostPayload
		resp  FlowQueryResponse
		err   string
		valid bool
	}

	var targetPeers []TopologyPeerHostPayload
	for _, p := range peers {
		if len(allowedPeerSet) > 0 && !allowedPeerSet[p.ID] {
			continue
		}
		targetPeers = append(targetPeers, p)
	}
	if len(targetPeers) == 0 {
		localResp.Engine = "federated"
		return localResp
	}

	results := make([]peerResult, len(targetPeers))
	var wg sync.WaitGroup
	for i, peer := range targetPeers {
		wg.Add(1)
		go func(idx int, p TopologyPeerHostPayload) {
			defer wg.Done()
			res := peerResult{peer: p}
			validURL, urlErr := validatePluginHTTPURL(p.APIURL, "peer "+p.Name)
			if urlErr != nil {
				res.err = urlErr.Error()
				results[idx] = res
				return
			}
			client, cliErr := tm.BuildPeerHTTPClient(p)
			if cliErr != nil {
				res.err = cliErr.Error()
				results[idx] = res
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
			defer cancel()

			httpReq, rerr := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(validURL, "/")+"/api/v1/netflow/query", bytes.NewReader(bodyBytes))
			if rerr != nil {
				res.err = rerr.Error()
				results[idx] = res
				return
			}
			httpReq.Header.Set("Content-Type", "application/json")
			if tok := peerTokens[p.ID]; tok != "" {
				httpReq.Header.Set("Authorization", "Bearer "+tok)
			}

			httpResp, derr := client.Do(httpReq)
			if derr != nil {
				res.err = derr.Error()
				results[idx] = res
				return
			}
			defer httpResp.Body.Close()
			raw, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4<<20))
			if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
				res.err = fmt.Sprintf("HTTP %d from %s", httpResp.StatusCode, p.Name)
				results[idx] = res
				return
			}

			var env struct {
				Status string            `json:"status"`
				Data   FlowQueryResponse `json:"data"`
			}
			if json.Unmarshal(raw, &env) == nil && (env.Data.Timestamp != "" || env.Status == "ok") {
				res.resp = env.Data
				res.valid = true
			} else {
				var direct FlowQueryResponse
				if json.Unmarshal(raw, &direct) == nil && direct.Timestamp != "" {
					res.resp = direct
					res.valid = true
				} else {
					res.err = "unexpected peer NetFlow response shape"
				}
			}
			for j := range res.resp.Flows {
				res.resp.Flows[j].HostID = p.ID
				res.resp.Flows[j].HostName = p.Name
			}
			results[idx] = res
		}(i, peer)
	}
	wg.Wait()

	mergedFlows := make([]FlowRecord, 0, len(localResp.Flows)+512)
	mergedFlows = append(mergedFlows, localResp.Flows...)

	var peerErrors []FleetPeerError
	for _, r := range results {
		if r.err != "" {
			peerErrors = append(peerErrors, FleetPeerError{
				PeerID:   r.peer.ID,
				PeerName: r.peer.Name,
				Error:    r.err,
			})
			continue
		}
		if r.valid {
			mergedFlows = append(mergedFlows, r.resp.Flows...)
		}
	}

	nowMs := time.Now().UnixMilli()
	endMs := req.EndMs
	if endMs <= 0 {
		endMs = nowMs
	}
	startMs := req.StartMs
	if startMs <= 0 {
		mins := req.RangeMinutes
		if mins <= 0 {
			mins = 60
		}
		startMs = endMs - int64(mins)*60*1000
	}

	merged := buildFlowQueryResponse(mergedFlows, startMs, endMs, req)
	merged.Engine = "federated"
	merged.PeerErrors = peerErrors
	if merged.TotalMatchedFlows < localResp.TotalMatchedFlows {
		merged.TotalMatchedFlows = localResp.TotalMatchedFlows
	}
	sort.Slice(merged.PeerErrors, func(i, j int) bool { return merged.PeerErrors[i].PeerName < merged.PeerErrors[j].PeerName })
	return merged
}
