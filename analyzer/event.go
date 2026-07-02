// 出力結果を入れておく
package analyzer

type Event struct {
	Type                 string   `json:"type"` // 検出したイベントの名前・種類
	SrcIP                string   `json:"src_ip,omitempty"`
	DstIP                string   `json:"dst_ip,omitempty"`
	SrcPort              string   `json:"src_port,omitempty"`
	DstPort              string   `json:"dst_port,omitempty"`
	Protocol             string   `json:"protocol,omitempty"`
	TCPFlags             string   `json:"tcp_flags,omitempty"`
	Layers               []string `json:"layers,omitempty"`    // どのレイヤーを取ることができたか
	Direction            string   `json:"direction,omitempty"` // 内→外の通信か、外→内の通信か
	LocalIP              string   `json:"local_ip,omitempty"`
	RemoteIP             string   `json:"remote_ip,omitempty"`
	LocalPort            string   `json:"local_port,omitempty"` // localIPに対応するポート
	RemotePort           string   `json:"remote_port,omitempty"`
	Service              string   `json:"service,omitempty"` // ポートのサービス(http, telnetとか)
	HTTPMethod           string   `json:"http_method,omitempty"`
	HTTPPath             string   `json:"http_path,omitempty"`
	HTTPHost             string   `json:"http_host,omitempty"`
	HTTPUserAgent        string   `json:"http_user_agent,omitempty"`
	HTTPSensitiveHeaders []string `json:"http_sensitive_headers,omitempty"`
	Risk                 []string `json:"risk,omitempty"`
	DNSQuery             string   `json:"dns_query,omitempty"` // DNS response: true, DNS query: false
	DNSQueryType         string   `json:"dns_query_type,omitempty"`
	DNSIsResponse        bool     `json:"dns_is_response"`       // DNSには何を調べたいかのタイプがある（詳しくはmemo.mdに）
	DNSAnswers           []string `json:"dns_answers,omitempty"` // DNSから返答があったIPアドレス
	Message              string   `json:"message,omitempty"`
	Error                string   `json:"error,omitempty"` // errorが出たら出力
}

// json:"XXX　は、構造体タグと呼ばれるもの。　GOの構造体をJSONに変換するときにJSONではXXXという名前で出してねという設定
// Type string `json:"type"`は
// { "type": "package_observed" }
// になる　みたいな感じ。
