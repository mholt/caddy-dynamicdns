package dynamicdns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// fakeZTE pretends to be a ZTE router's login + ipv6 firewall API.
type fakeZTE struct {
	mu            sync.Mutex
	password      string
	token         int
	loginTok      int
	rules         []map[string]string
	busy          bool // another admin holds the slot
	preempted     bool
	sessions      int  // successful logins minus logouts
	exceedOnLogin bool // return e_exceed_max_user_preempt from login_entry
}

func (f *fakeZTE) nextToken() string {
	f.token++
	return fmt.Sprintf("tok-%d", f.token)
}

func (f *fakeZTE) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		q := r.URL.Query()
		typ, tag := q.Get("_type"), q.Get("_tag")

		switch {
		case typ == "loginsceneData" && tag == "login_token_json":
			f.loginTok = 424242
			_ = json.NewEncoder(w).Encode(map[string]any{
				"_sessionToken": f.nextToken(),
				"logintoken":    f.loginTok,
			})

		case typ == "loginData" && tag == "login_entry":
			body, _ := io.ReadAll(r.Body)
			vals, _ := url.ParseQuery(string(body))
			sum := sha256.Sum256([]byte(f.password + fmt.Sprint(f.loginTok)))
			want := hex.EncodeToString(sum[:])
			if vals.Get("Password") != want {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"loginErrType":       "pwdError",
					"login_need_refresh": false,
					"sess_token":         "",
				})
				return
			}
			f.sessions++
			if f.exceedOnLogin && f.busy && !f.preempted {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"login_need_refresh": false,
					"sess_token":         f.nextToken(),
					"loginErrType":       "e_exceed_max_user_preempt",
				})
				return
			}
			// Web-like: password login still returns need_refresh; preempt
			// is discovered on the subsequent userif fetch when busy.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"login_need_refresh": true,
				"sess_token":         f.nextToken(),
				"loginErrType":       "",
			})

		case typ == "hiddenData" && tag == "vue_userif_data":
			if f.busy && !f.preempted {
				_, _ = w.Write([]byte(`<ajax_response_xml_root><IF_ERRORSTR>SUCC</IF_ERRORSTR><LOGIN_PREEMPT_ID><Instance><ParaName>preempt_sessid</ParaName><ParaValue>other-session-1</ParaValue><ParaName>preempt_ip</ParaName><ParaValue>192.168.1.2</ParaValue><ParaName>preempt_mac</ParaName><ParaValue>AA:BB:CC:DD:EE:FF</ParaValue><ParaName>login_name</ParaName><ParaValue>admin</ParaValue></Instance></LOGIN_PREEMPT_ID></ajax_response_xml_root>`))
				return
			}
			_, _ = w.Write([]byte(`<ajax_response_xml_root><IF_ERRORSTR>SUCC</IF_ERRORSTR><OBJ_GLOBAL_ENV><Instance><ParaName>OpenAndSlave</ParaName><ParaValue>false</ParaValue></Instance></OBJ_GLOBAL_ENV><OBJ_USERIF_ID><Instance><ParaName>Timeout</ParaName><ParaValue>15</ParaValue></Instance></OBJ_USERIF_ID></ajax_response_xml_root>`))

		case typ == "loginData" && tag == "login_preempt":
			body, _ := io.ReadAll(r.Body)
			vals, _ := url.ParseQuery(string(body))
			if vals.Get("action") != "preempt" || vals.Get("preempt_sessid") == "" {
				http.Error(w, "bad preempt", 400)
				return
			}
			f.preempted = true
			f.busy = false
			_ = json.NewEncoder(w).Encode(map[string]any{
				"loginErrType":       "",
				"login_need_refresh": true,
				"sess_token":         f.nextToken(),
			})

		case typ == "loginData" && tag == "logout_entry":
			f.sessions--
			if f.sessions < 0 {
				f.sessions = 0
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"need_refresh": false})

		case typ == "vuejsonData" && tag == "security_firewall_ipv6_data" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"_sessionToken": f.nextToken(),
				"errPara":       "SUCC",
				"code":          "0",
				"data": map[string]any{
					"OBJ_FWSC_IPV6_ID": f.rules,
					"IF_ERRORSTR":      "SUCC",
				},
			})

		case typ == "vuejsonData" && tag == "security_firewall_ipv6_data" && r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			vals, _ := url.ParseQuery(string(body))
			if vals.Get("IF_ACTION") != "Apply" {
				http.Error(w, "bad action", 400)
				return
			}
			inst := vals.Get("_InstID")
			rule := map[string]string{
				"Name":      vals.Get("Name"),
				"Prefix":    vals.Get("Prefix"),
				"PrefixLen": vals.Get("PrefixLen"),
				"MinPort":   vals.Get("MinPort"),
				"MaxPort":   vals.Get("MaxPort"),
				"Protocol":  vals.Get("Protocol"),
				"Enable":    vals.Get("Enable"),
				"_InstID":   inst,
			}
			if inst == "-1" {
				rule["_InstID"] = fmt.Sprintf("DEV.FWLEVELSC%d", len(f.rules)+1)
				f.rules = append(f.rules, rule)
			} else {
				found := false
				for i, existing := range f.rules {
					if existing["_InstID"] == inst {
						f.rules[i] = rule
						found = true
						break
					}
				}
				if !found {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"_sessionToken": f.nextToken(),
						"code":          "-1",
						"data":          map[string]any{"IF_ERRORSTR": "FAIL"},
					})
					return
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"_sessionToken": f.nextToken(),
				"errPara":       "SUCC",
				"code":          "0",
				"data":          map[string]any{"IF_ERRORSTR": "SUCC", "IF_IRET": "0"},
			})

		case r.URL.Path == "/" && r.Method == http.MethodGet && typ == "" && tag == "":
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "testsid"})
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<html></html>"))

		default:
			http.NotFound(w, r)
		}
	})
}

func TestZTEFirewallCreateAndUpdate(t *testing.T) {
	fake := &fakeZTE{password: "secret"}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	z := &ZTEFirewall{
		Router:   strings.TrimRight(srv.URL, "/"),
		Username: "admin",
		Password: "secret",
		Name:     "caddy",
		Port:     443,
		Protocol: "BOTH",
	}

	ip1 := netip.MustParseAddr("2001:db8::1")
	if err := z.UpdateIPs(context.Background(), []netip.Addr{ip1}); err != nil {
		t.Fatalf("create: %v", err)
	}

	fake.mu.Lock()
	if len(fake.rules) != 1 {
		t.Fatalf("want 1 rule, got %#v", fake.rules)
	}
	if fake.rules[0]["Prefix"] != ip1.String() {
		t.Fatalf("prefix=%s", fake.rules[0]["Prefix"])
	}
	if fake.rules[0]["PrefixLen"] != "128" || fake.rules[0]["MinPort"] != "443" {
		t.Fatalf("rule=%#v", fake.rules[0])
	}
	inst := fake.rules[0]["_InstID"]
	fake.mu.Unlock()

	// Second call with same IP should be a no-op (cached).
	if err := z.UpdateIPs(context.Background(), []netip.Addr{ip1}); err != nil {
		t.Fatalf("noop: %v", err)
	}
	fake.mu.Lock()
	if len(fake.rules) != 1 {
		t.Fatalf("noop created extra rule: %#v", fake.rules)
	}
	fake.mu.Unlock()

	// Prefix change should update in place.
	ip2 := netip.MustParseAddr("2001:db8::2")
	if err := z.UpdateIPs(context.Background(), []netip.Addr{ip2}); err != nil {
		t.Fatalf("update: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.rules) != 1 {
		t.Fatalf("want still 1 rule, got %#v", fake.rules)
	}
	if fake.rules[0]["_InstID"] != inst {
		t.Fatalf("inst changed: %s -> %s", inst, fake.rules[0]["_InstID"])
	}
	if fake.rules[0]["Prefix"] != ip2.String() {
		t.Fatalf("updated prefix=%s", fake.rules[0]["Prefix"])
	}
}

func TestZTEFirewallPreemptAndLogout(t *testing.T) {
	fake := &fakeZTE{password: "secret", busy: true}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	z := &ZTEFirewall{
		Router:   strings.TrimRight(srv.URL, "/"),
		Username: "admin",
		Password: "secret",
		Name:     "caddy",
		Port:     443,
		Protocol: "BOTH",
	}
	ip := netip.MustParseAddr("2001:db8::10")
	if err := z.UpdateIPs(context.Background(), []netip.Addr{ip}); err != nil {
		t.Fatalf("preempt path: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !fake.preempted {
		t.Fatal("expected login_preempt to be called")
	}
	if fake.sessions != 0 {
		t.Fatalf("expected logout to release session, sessions=%d", fake.sessions)
	}
	if len(fake.rules) != 1 || fake.rules[0]["Prefix"] != ip.String() {
		t.Fatalf("rules=%#v", fake.rules)
	}
}

func TestExtractPreemptSessidParaName(t *testing.T) {
	raw := []byte(`<LOGIN_PREEMPT_ID><Instance><ParaName>preempt_ip</ParaName><ParaValue>1.2.3.4</ParaValue><ParaName>preempt_sessid</ParaName><ParaValue>sess-abc-999</ParaValue></Instance></LOGIN_PREEMPT_ID>`)
	if g := extractPreemptSessid(raw); g != "sess-abc-999" {
		t.Fatalf("got %q", g)
	}
}

func TestZTEFirewallExceedErrThenUserifPreempt(t *testing.T) {
	// Some firmwares return e_exceed on login_entry itself; sessid still comes from userif.
	fake := &fakeZTE{password: "secret", busy: true, exceedOnLogin: true}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	z := &ZTEFirewall{
		Router:   strings.TrimRight(srv.URL, "/"),
		Username: "admin",
		Password: "secret",
		Name:     "probe",
		Port:     443,
		Protocol: "BOTH",
	}
	ip := netip.MustParseAddr("2001:db8::11")
	if err := z.UpdateIPs(context.Background(), []netip.Addr{ip}); err != nil {
		t.Fatalf("exceed+userif preempt: %v", err)
	}
	if !fake.preempted {
		t.Fatal("expected preempt")
	}
}

func TestZTEFirewallSkipsIPv4Only(t *testing.T) {
	z := &ZTEFirewall{
		Router:   "http://127.0.0.1:1", // must not be contacted
		Password: "x",
		Name:     "caddy",
		Port:     443,
		Protocol: "BOTH",
	}
	z.Router = strings.TrimRight(z.Router, "/")
	ip4 := netip.MustParseAddr("1.2.3.4")
	if err := z.UpdateIPs(context.Background(), []netip.Addr{ip4}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestZTEFirewallCaddyfile(t *testing.T) {
	input := `zte_firewall {
		router http://192.168.1.1
		username admin
		password test-password
		name caddy
		port 443
		protocol BOTH
	}`
	d := caddyfile.NewTestDispenser(input)
	var z ZTEFirewall
	if err := z.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}
	if z.Router != "http://192.168.1.1" || z.Name != "caddy" || z.Port != 443 || z.Password != "test-password" {
		t.Fatalf("parsed=%#v", z)
	}
}

func TestZTEFirewallProvisionRequiresConfig(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	z := &ZTEFirewall{}
	if err := z.Provision(ctx); err == nil {
		t.Fatal("expected error for empty config")
	}

	// Missing password
	z = &ZTEFirewall{Router: "http://192.168.1.1", Name: "r", Port: 443}
	if err := z.Provision(ctx); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("want password error, got %v", err)
	}

	// Missing name
	z = &ZTEFirewall{Router: "http://192.168.1.1", Password: "x", Port: 443}
	if err := z.Provision(ctx); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("want name error, got %v", err)
	}

	// Missing port
	z = &ZTEFirewall{Router: "http://192.168.1.1", Password: "x", Name: "r"}
	if err := z.Provision(ctx); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("want port error, got %v", err)
	}

	// Complete config: soft defaults fill username + protocol.
	z = &ZTEFirewall{
		Router:   "http://192.168.1.1/",
		Password: "x",
		Name:     "caddy",
		Port:     443,
	}
	if err := z.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if z.Router != "http://192.168.1.1" {
		t.Fatalf("router not trimmed: %s", z.Router)
	}
	if z.Username != "admin" || z.Protocol != "BOTH" {
		t.Fatalf("defaults not applied: user=%s proto=%s", z.Username, z.Protocol)
	}
}
