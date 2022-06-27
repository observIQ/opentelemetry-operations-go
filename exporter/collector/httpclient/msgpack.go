package httpclient

//go:generate msgp

type MsgPackPayload struct {
	Entries        []*MsgPackEntry `msg:"entries"`
	PartialSuccess bool            `msg:"partialSuccess"`
}

type MsgPackEntry struct {
	LogName     string             `msg:"logName"`
	Resource    *MonitoredResource `msg:"resource"`
	TestPayload string             `msg:"textPayload"`
	Timestamp   *Timestamp         `msg:"timestamp"`
	Severity    int32              `msg:"severity"`
}

type MonitoredResource struct {
	Type   string            `msg:"type"`
	Labels map[string]string `msg:"labels"`
}

type Timestamp struct {
	Seconds int64 `msg:"seconds"`
	Nanos   int32 `msg:"nanos"`
}
