package httpclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	loggingv2 "cloud.google.com/go/logging/apiv2"
	"github.com/googleapis/gax-go/v2"
	"github.com/tinylib/msgp/msgp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	loggingpb "google.golang.org/genproto/googleapis/logging/v2"
)

const url = "https://logging.googleapis.com/v2/entries:write"

type Client struct {
	client    *http.Client
	userAgent string
}

func NewClient(ctx context.Context, userAgent string, credentialFile string) (*Client, error) {
	creds, err := getCreds(ctx, credentialFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	return &Client{
		client:    oauth2.NewClient(oauth2.NoContext, creds.TokenSource),
		userAgent: userAgent,
	}, nil
}

func (c *Client) WriteLogEntries(ctx context.Context, loggingReq *loggingpb.WriteLogEntriesRequest, opts ...gax.CallOption) (*loggingpb.WriteLogEntriesResponse, error) {

	payload := toMsgPackPayload(loggingReq)

	data, err := payload.MarshalMsg(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var buff bytes.Buffer
	msgp.UnmarshalAsJSON(&buff, data)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buff.Bytes()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("User-Agent", c.userAgent)
	req.Header.Add("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		respData, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read error response body: %w", err)
		}

		return nil, fmt.Errorf("request returned %d response code with body '%s'", resp.StatusCode, string(respData))
	}

	return &loggingpb.WriteLogEntriesResponse{}, nil
}

func (c *Client) Close() error {
	return nil
}

func getCreds(ctx context.Context, credentialFile string) (*google.Credentials, error) {
	if credentialFile != "" {
		data, err := os.ReadFile(credentialFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read credential file: %w", err)
		}
		return google.CredentialsFromJSON(ctx, data, loggingv2.DefaultAuthScopes()...)
	}

	return google.FindDefaultCredentials(ctx, loggingv2.DefaultAuthScopes()...)
}

func toMsgPackPayload(loggingReq *loggingpb.WriteLogEntriesRequest) *MsgPackPayload {
	entries := loggingReq.GetEntries()
	payload := &MsgPackPayload{
		Entries:        make([]*MsgPackEntry, len(entries)),
		PartialSuccess: loggingReq.GetPartialSuccess(),
	}

	for i, e := range entries {
		entry := &MsgPackEntry{
			LogName: e.GetLogName(),
			Resource: &MonitoredResource{
				Type:   e.GetResource().GetType(),
				Labels: e.GetResource().GetLabels(),
			},
			TestPayload: e.GetTextPayload(),
			Timestamp: &Timestamp{
				Seconds: e.GetTimestamp().GetSeconds(),
				Nanos:   e.GetTimestamp().GetNanos(),
			},
			Severity: int32(e.GetSeverity().Number()),
		}

		payload.Entries[i] = entry
	}

	return payload
}
