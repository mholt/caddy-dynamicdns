// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dynamicdns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ZTEFirewall{})
}

// ZTEFirewall keeps an IPv6 port-open rule on a ZTE home gateway in sync
// with the host's current global unicast address. Rules are bound to a
// full /128, so ISP prefix changes require rewriting the rule.
//
// Invoked by dynamic_dns on the same trigger as DNS updates (public IP
// change). Compatible with the vuejsonData admin API
// (security_firewall_ipv6_data), including login preempt and logout.
//
// Caddyfile:
//
//	ip_updater zte_firewall {
//	    router   <url>           // required
//	    password <secret>        // required; {env.*} / {file.*} OK
//	    name     <rule-name>     // required; same name updates in place
//	    port     <1-65535>       // required
//	    username <user>          // optional, default "admin"
//	    protocol TCP|UDP|BOTH    // optional, default "BOTH"
//	}
type ZTEFirewall struct {
	// Base URL of the router admin UI (required). Example: http://192.168.1.1
	Router string `json:"router,omitempty"`

	// Admin username. Default: "admin".
	Username string `json:"username,omitempty"`

	// Admin password (required). Prefer {env.*} / {file.*} placeholders.
	Password string `json:"password,omitempty"`

	// Firewall rule name to create or update (required).
	// Use the same name as an existing rule to update it in place.
	Name string `json:"name,omitempty"`

	// TCP/UDP port to open (required). Written as MinPort = MaxPort.
	Port int `json:"port,omitempty"`

	// Protocol: TCP, UDP, or BOTH. Default: "BOTH".
	Protocol string `json:"protocol,omitempty"`

	logger *zap.Logger

	mu          sync.Mutex
	lastApplied netip.Addr // zero if never applied this process
}

// CaddyModule returns the Caddy module information.
func (ZTEFirewall) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.ip_updaters.zte_firewall",
		New: func() caddy.Module { return new(ZTEFirewall) },
	}
}

// Provision sets up the module. Required fields must come from config
// (Caddyfile / JSON); only username and protocol have soft defaults.
func (z *ZTEFirewall) Provision(ctx caddy.Context) error {
	z.logger = ctx.Logger(z)

	// Expand standard Caddy placeholders ({env.*}, {file.*}, …).
	repl := caddy.NewReplacer()
	if r, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok && r != nil {
		repl = r
	}
	z.Router = strings.TrimSpace(repl.ReplaceAll(z.Router, ""))
	z.Username = strings.TrimSpace(repl.ReplaceAll(z.Username, ""))
	z.Password = repl.ReplaceAll(z.Password, "")
	z.Name = strings.TrimSpace(repl.ReplaceAll(z.Name, ""))
	z.Protocol = strings.TrimSpace(repl.ReplaceAll(z.Protocol, ""))

	if z.Router == "" {
		return fmt.Errorf("zte_firewall: router is required (set via Caddyfile/JSON)")
	}
	z.Router = strings.TrimRight(z.Router, "/")
	if z.Password == "" {
		return fmt.Errorf("zte_firewall: password is required (set via Caddyfile/JSON)")
	}
	if z.Name == "" {
		return fmt.Errorf("zte_firewall: name is required (firewall rule name)")
	}
	if z.Port == 0 {
		return fmt.Errorf("zte_firewall: port is required")
	}
	if z.Port < 1 || z.Port > 65535 {
		return fmt.Errorf("zte_firewall: port out of range")
	}
	if z.Username == "" {
		z.Username = "admin"
	}
	if z.Protocol == "" {
		z.Protocol = "BOTH"
	}
	switch z.Protocol {
	case "TCP", "UDP", "BOTH":
	default:
		return fmt.Errorf("zte_firewall: protocol must be TCP, UDP, or BOTH")
	}
	return nil
}

// UnmarshalCaddyfile parses the zte_firewall block (see type docs).
func (z *ZTEFirewall) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// consume module name
	if !d.Next() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "router":
			if !d.AllArgs(&z.Router) {
				return d.ArgErr()
			}
		case "username":
			if !d.AllArgs(&z.Username) {
				return d.ArgErr()
			}
		case "password":
			if !d.AllArgs(&z.Password) {
				return d.ArgErr()
			}
		case "name":
			if !d.AllArgs(&z.Name) {
				return d.ArgErr()
			}
		case "port":
			var p string
			if !d.AllArgs(&p) {
				return d.ArgErr()
			}
			var port int
			if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
				return d.Errf("invalid port: %s", p)
			}
			z.Port = port
		case "protocol":
			if !d.AllArgs(&z.Protocol) {
				return d.ArgErr()
			}
		default:
			return d.Errf("unknown subdirective: %s", d.Val())
		}
	}
	return nil
}

// UpdateIPs implements IPUpdater for the first IPv6 address in ips.
func (z *ZTEFirewall) UpdateIPs(ctx context.Context, ips []netip.Addr) error {
	log := z.logger
	if log == nil {
		log = zap.NewNop()
	}

	v6, ok := firstIPv6(ips)
	if !ok {
		log.Debug("no IPv6 address to apply; skipping zte_firewall")
		return nil
	}

	z.mu.Lock()
	defer z.mu.Unlock()

	if z.lastApplied.IsValid() && z.lastApplied.Compare(v6) == 0 {
		log.Debug("firewall already at current IPv6",
			zap.String("ip", v6.String()),
			zap.String("rule", z.Name))
		return nil
	}

	if err := z.reconcile(ctx, v6); err != nil {
		return err
	}
	z.lastApplied = v6
	return nil
}

func firstIPv6(ips []netip.Addr) (netip.Addr, bool) {
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is6() {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func (z *ZTEFirewall) reconcile(ctx context.Context, ip netip.Addr) error {
	log := z.logger
	if log == nil {
		log = zap.NewNop()
	}

	client, err := newZTEClient(z.Router)
	if err != nil {
		return err
	}
	if err := client.login(ctx, z.Username, z.Password); err != nil {
		return fmt.Errorf("zte login: %w", err)
	}
	defer func() {
		if err := client.logout(ctx); err != nil {
			log.Debug("zte logout failed", zap.Error(err))
		}
	}()

	rules, err := client.listIPv6Firewall(ctx)
	if err != nil {
		return fmt.Errorf("zte list firewall: %w", err)
	}

	portStr := fmt.Sprintf("%d", z.Port)
	var existing *zteFWRule
	for i := range rules {
		if rules[i].Name == z.Name {
			existing = &rules[i]
			break
		}
	}

	if existing != nil &&
		existing.Prefix == ip.String() &&
		existing.PrefixLen == "128" &&
		existing.MinPort == portStr &&
		existing.MaxPort == portStr &&
		existing.Protocol == z.Protocol &&
		existing.Enable == "1" {
		log.Debug("router rule already correct",
			zap.String("rule", z.Name),
			zap.String("ip", ip.String()))
		return nil
	}

	rule := zteFWRule{
		Name:      z.Name,
		Prefix:    ip.String(),
		PrefixLen: "128",
		MinPort:   portStr,
		MaxPort:   portStr,
		Protocol:  z.Protocol,
		Enable:    "1",
		InstID:    "-1",
	}
	if existing != nil {
		rule.InstID = existing.InstID
		log.Info("updating zte ipv6 firewall rule",
			zap.String("rule", z.Name),
			zap.String("old_ip", existing.Prefix),
			zap.String("new_ip", ip.String()),
			zap.String("inst", rule.InstID))
	} else {
		log.Info("creating zte ipv6 firewall rule",
			zap.String("rule", z.Name),
			zap.String("ip", ip.String()),
			zap.Int("port", z.Port))
	}

	if err := client.applyIPv6Firewall(ctx, rule); err != nil {
		return fmt.Errorf("zte apply firewall: %w", err)
	}
	return nil
}

// --- low-level ZTE web API client --------------------------------------

type zteClient struct {
	base   string
	http   *http.Client
	token  string
}

type zteFWRule struct {
	Name      string
	Prefix    string
	PrefixLen string
	MinPort   string
	MaxPort   string
	Protocol  string
	Enable    string
	InstID    string
}

func newZTEClient(base string) (*zteClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &zteClient{
		base: base,
		http: &http.Client{
			Timeout: 15 * time.Second,
			Jar:     jar,
		},
	}, nil
}

func (c *zteClient) login(ctx context.Context, user, pass string) error {
	// Establish SID cookie.
	if _, err := c.do(ctx, http.MethodGet, "/", nil); err != nil {
		return err
	}

	raw, err := c.do(ctx, http.MethodGet, "/?_type=loginsceneData&_tag=login_token_json", nil)
	if err != nil {
		return err
	}
	var tok struct {
		SessionToken string `json:"_sessionToken"`
		LoginToken   any    `json:"logintoken"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return fmt.Errorf("parse login token: %w", err)
	}
	c.token = tok.SessionToken
	loginToken := fmt.Sprint(tok.LoginToken)

	sum := sha256.Sum256([]byte(pass + loginToken))
	pwHash := hex.EncodeToString(sum[:])

	form := url.Values{
		"Username":       {user},
		"Password":       {pwHash},
		"action":         {"login"},
		"Frm_Logintoken": {""},
		"captchaCode":    {""},
		"_sessionTOKEN":  {c.token},
	}
	raw, err = c.do(ctx, http.MethodPost, "/?_type=loginData&_tag=login_entry", form)
	if err != nil {
		return err
	}

	// Login flow mirrors the stock admin SPA: password POST, then userif;
	// LOGIN_PREEMPT_ID triggers login_preempt (no second password POST).
	entry, entryErr := parseLoginEntry(raw)
	if entry.SessToken != "" {
		c.token = entry.SessToken
	}
	if entryErr != nil && !entry.SessionCandidate {
		return entryErr
	}

	userif, err := c.do(ctx, http.MethodGet, "/?_type=hiddenData&_tag=vue_userif_data", nil)
	if err != nil {
		if entry.OK {
			return nil
		}
		return fmt.Errorf("get userif: %w", err)
	}

	if strings.Contains(string(userif), "<LOGIN_PREEMPT_ID") {
		sessid := extractPreemptSessid(userif)
		if sessid == "" {
			sessid = extractPreemptSessid(raw)
		}
		if sessid == "" {
			return fmt.Errorf("LOGIN_PREEMPT_ID present but preempt_sessid missing (userif=%s)", truncate(userif, 400))
		}
		if err := c.preempt(ctx, sessid); err != nil {
			return fmt.Errorf("preempt: %w", err)
		}
		return nil
	}

	if entry.OK || entry.SessionCandidate {
		return nil
	}
	if entryErr != nil {
		return entryErr
	}
	return fmt.Errorf("login failed: unexpected response %s", truncate(raw, 200))
}

type loginEntryResult struct {
	OK               bool // clean success (need_refresh, empty err type)
	SessionCandidate bool // has sess_token; usable after userif check
	SessToken        string
}

func parseLoginEntry(raw []byte) (loginEntryResult, error) {
	var loginResp struct {
		SessToken        string `json:"sess_token"`
		LoginErrType     string `json:"loginErrType"`
		LoginNeedRefresh bool   `json:"login_need_refresh"`
		LoginErrMsg      string `json:"loginErrMsg"`
		PreemptSessid    string `json:"preempt_sessid"`
	}
	if err := json.Unmarshal(raw, &loginResp); err != nil {
		if strings.Contains(string(raw), "LOGIN_PREEMPT") {
			return loginEntryResult{SessionCandidate: true}, nil
		}
		return loginEntryResult{}, fmt.Errorf("parse login response: %w (body=%s)", err, truncate(raw, 200))
	}
	out := loginEntryResult{SessToken: loginResp.SessToken}

	// SPA treats login_need_refresh as password OK (may still set e_exceed).
	if loginResp.LoginNeedRefresh && loginResp.SessToken != "" {
		out.OK = loginResp.LoginErrType == "" || loginResp.LoginErrType == "e_exceed_max_user_preempt"
		out.SessionCandidate = true
		return out, nil
	}
	if loginResp.LoginErrType == "" && loginResp.SessToken != "" && loginResp.LoginErrMsg == "" {
		out.OK = true
		out.SessionCandidate = true
		return out, nil
	}
	if loginResp.LoginErrType != "" && loginResp.LoginErrType != "e_exceed_max_user_preempt" {
		return out, fmt.Errorf("login rejected: %s", loginResp.LoginErrType)
	}
	if loginResp.LoginErrMsg != "" {
		return out, fmt.Errorf("login rejected: %s", loginResp.LoginErrMsg)
	}
	if loginResp.LoginErrType == "e_exceed_max_user_preempt" && loginResp.SessToken != "" {
		out.SessionCandidate = true
		return out, nil
	}
	return out, fmt.Errorf("login rejected: unexpected response %s", truncate(raw, 160))
}

var (
	preemptSessidJSON = regexp.MustCompile(`(?i)"preempt_sessid"\s*:\s*"([^"]+)"`)
	preemptSessidXML  = regexp.MustCompile(`(?i)name="preempt_sessid"\s+value=?"?([^"\s/>]+)`)
	preemptSessidTag  = regexp.MustCompile(`(?i)<preempt_sessid>([^<]+)</preempt_sessid>`)
	preemptSessidPara = regexp.MustCompile(`(?is)<ParaName>\s*preempt_sessid\s*</ParaName>\s*<ParaValue>([^<]*)</ParaValue>`)
	preemptSessidInst = regexp.MustCompile(`(?is)<(?:InstName|Name)>\s*preempt_sessid\s*</(?:InstName|Name)>\s*<(?:InstValue|Value)>([^<]*)</(?:InstValue|Value)>`)
)

func extractPreemptSessid(raw []byte) string {
	s := string(raw)
	section := s
	if i := strings.Index(s, "<LOGIN_PREEMPT_ID"); i >= 0 {
		section = s[i:]
		if j := strings.Index(section, "</LOGIN_PREEMPT_ID>"); j >= 0 {
			section = section[:j+len("</LOGIN_PREEMPT_ID>")]
		}
	}
	for _, re := range []*regexp.Regexp{preemptSessidPara, preemptSessidTag, preemptSessidInst, preemptSessidJSON, preemptSessidXML} {
		if m := re.FindStringSubmatch(section); len(m) == 2 {
			if v := strings.TrimSpace(m[1]); v != "" {
				return v
			}
		}
	}
	for _, re := range []*regexp.Regexp{preemptSessidPara, preemptSessidTag, preemptSessidJSON} {
		if m := re.FindStringSubmatch(s); len(m) == 2 {
			if v := strings.TrimSpace(m[1]); v != "" {
				return v
			}
		}
	}
	return ""
}

// preempt force-logs out another admin session (stock UI confirm dialog).
func (c *zteClient) preempt(ctx context.Context, sessid string) error {
	form := url.Values{
		"action":         {"preempt"},
		"preempt_sessid": {sessid},
		"_sessionTOKEN":  {c.token},
	}
	_, _ = c.do(ctx, http.MethodPost, "/", form)
	raw, err := c.do(ctx, http.MethodPost, "/?_type=loginData&_tag=login_preempt", form)
	if err != nil {
		return err
	}
	var resp struct {
		LoginErrType     string `json:"loginErrType"`
		LoginNeedRefresh bool   `json:"login_need_refresh"`
		SessToken        string `json:"sess_token"`
		LoginErrMsg      string `json:"loginErrMsg"`
	}
	_ = json.Unmarshal(raw, &resp)
	if resp.SessToken != "" {
		c.token = resp.SessToken
	}
	if resp.LoginErrType != "" {
		return fmt.Errorf("preempt rejected: %s (body=%s)", resp.LoginErrType, truncate(raw, 200))
	}
	if resp.LoginErrMsg != "" {
		return fmt.Errorf("preempt rejected: %s", resp.LoginErrMsg)
	}
	return nil
}

func (c *zteClient) logout(ctx context.Context) error {
	form := url.Values{
		"action":        {"logout"},
		"_sessionTOKEN": {c.token},
	}
	_, err := c.do(ctx, http.MethodPost, "/?_type=loginData&_tag=logout_entry", form)
	return err
}

func (c *zteClient) listIPv6Firewall(ctx context.Context) ([]zteFWRule, error) {
	raw, err := c.do(ctx, http.MethodGet, "/?_type=vuejsonData&_tag=security_firewall_ipv6_data", nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		SessionToken string `json:"_sessionToken"`
		Data         struct {
			Rules []struct {
				Name      string `json:"Name"`
				MinPort   string `json:"MinPort"`
				MaxPort   string `json:"MaxPort"`
				Protocol  string `json:"Protocol"`
				InstID    string `json:"_InstID"`
				Enable    string `json:"Enable"`
				PrefixLen string `json:"PrefixLen"`
				Prefix    string `json:"Prefix"`
			} `json:"OBJ_FWSC_IPV6_ID"`
			ErrorStr string `json:"IF_ERRORSTR"`
		} `json:"data"`
		Code string `json:"code"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse firewall list: %w", err)
	}
	if resp.SessionToken != "" {
		c.token = resp.SessionToken
	}
	out := make([]zteFWRule, 0, len(resp.Data.Rules))
	for _, r := range resp.Data.Rules {
		out = append(out, zteFWRule{
			Name:      r.Name,
			Prefix:    r.Prefix,
			PrefixLen: r.PrefixLen,
			MinPort:   r.MinPort,
			MaxPort:   r.MaxPort,
			Protocol:  r.Protocol,
			Enable:    r.Enable,
			InstID:    r.InstID,
		})
	}
	return out, nil
}

func (c *zteClient) applyIPv6Firewall(ctx context.Context, rule zteFWRule) error {
	form := url.Values{
		"IF_ACTION":     {"Apply"},
		"Enable":        {rule.Enable},
		"Protocol":      {rule.Protocol},
		"PrefixLen":     {rule.PrefixLen},
		"Name":          {rule.Name},
		"Prefix":        {rule.Prefix},
		"MinPort":       {rule.MinPort},
		"MaxPort":       {rule.MaxPort},
		"_InstID":       {rule.InstID},
		"_sessionTOKEN": {c.token},
	}
	raw, err := c.do(ctx, http.MethodPost, "/?_type=vuejsonData&_tag=security_firewall_ipv6_data", form)
	if err != nil {
		return err
	}
	var resp struct {
		SessionToken string `json:"_sessionToken"`
		ErrPara      string `json:"errPara"`
		Code         string `json:"code"`
		Data         struct {
			ErrorStr string `json:"IF_ERRORSTR"`
			IRet     string `json:"IF_IRET"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("parse apply response: %w (body=%s)", err, truncate(raw, 200))
	}
	if resp.SessionToken != "" {
		c.token = resp.SessionToken
	}
	if resp.Data.ErrorStr != "" && resp.Data.ErrorStr != "SUCC" {
		return fmt.Errorf("apply failed: IF_ERRORSTR=%s code=%s errPara=%s iret=%s",
			resp.Data.ErrorStr, resp.Code, resp.ErrPara, resp.Data.IRet)
	}
	if resp.Code != "" && resp.Code != "0" {
		return fmt.Errorf("apply failed: code=%s errPara=%s body=%s",
			resp.Code, resp.ErrPara, truncate(raw, 200))
	}
	return nil
}

func (c *zteClient) do(ctx context.Context, method, path string, form url.Values) ([]byte, error) {
	var body io.Reader
	if form != nil {
		if c.token != "" && form.Get("_sessionTOKEN") == "" {
			form.Set("_sessionTOKEN", c.token)
		}
		body = strings.NewReader(form.Encode())
	}
	u := c.base + path
	if method == http.MethodGet {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		u = u + sep + "_=" + fmt.Sprintf("%d", time.Now().UnixMilli())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "caddy-dynamicdns-zte-firewall/1.0")
	req.Header.Set("Referer", c.base+"/")
	req.Header.Set("Accept", "*/*")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", c.base)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		return raw, fmt.Errorf("HTTP %d: %s", res.StatusCode, truncate(raw, 200))
	}
	// Capture rolling _sessionToken from JSON bodies even on intermediate calls.
	var maybe struct {
		SessionToken string `json:"_sessionToken"`
	}
	if json.Unmarshal(raw, &maybe) == nil && maybe.SessionToken != "" {
		c.token = maybe.SessionToken
	}
	return raw, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// Interface guards
var (
	_ caddy.Provisioner     = (*ZTEFirewall)(nil)
	_ caddyfile.Unmarshaler = (*ZTEFirewall)(nil)
	_ IPUpdater             = (*ZTEFirewall)(nil)
)
