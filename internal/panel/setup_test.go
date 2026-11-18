package panel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/livecfg"
)

// 初始化向导（setup.go）行为矩阵：
//   - 出厂形态（api_key=test_key 且面板密码未设）→ status=true，向导可设面板密码；
//   - 面板密码已设 / api_key 已自定义 / 空（显式关鉴权）→ status=false；
//   - 输入校验：空 / 短于 6 字符 → 400 不落盘；
//   - 初始化完成后 setup/key 永久 403。
func TestSetupStatusMatrix(t *testing.T) {
	cases := []struct {
		name     string
		apiKey   string
		panelPw  string
		required bool
	}{
		{"factory", "test_key", "", true}, // 出厂形态 → 待初始化
		{"customized key", "lylywayr", "", false},
		{"panel pw set", "test_key", "pw123456", false},
		{"no auth", "", "", false}, // 显式关闭鉴权：不是待初始化状态
	}
	for _, c := range cases {
		p := New(Config{Version: "t", APIKey: c.apiKey, PanelPassword: c.panelPw})
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/api/setup/status", nil))
		if rec.Code != 200 {
			t.Fatalf("%s: status code=%d", c.name, rec.Code)
		}
		want := "false"
		if c.required {
			want = "true"
		}
		if !strings.Contains(rec.Body.String(), `"setup_required":`+want) {
			t.Errorf("%s: setup_required body=%s want %s", c.name, rec.Body.String(), want)
		}
	}
}

func TestSetupKeyFlow(t *testing.T) {
	var savedRaw []string
	p := New(Config{Version: "t", APIKey: "test_key",
		SaveConfig: func(raw []byte) ([]string, error) {
			savedRaw = append(savedRaw, string(raw))
			return nil, nil
		}})

	// 合法密码：200、SaveConfig 收到仅含 panel.password 的深 merge 片段。
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("POST", "/panel/api/setup/key", strings.NewReader(`{"password":"my-panel-pw"}`)))
	if rec.Code != 200 {
		t.Fatalf("setup/key code=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(savedRaw) != 1 {
		t.Fatalf("SaveConfig calls=%d", len(savedRaw))
	}
	if !strings.Contains(savedRaw[0], `"panel"`) || !strings.Contains(savedRaw[0], `"password"`) || !strings.Contains(savedRaw[0], "my-panel-pw") {
		t.Fatalf("SaveConfig raw=%s want panel.password deep-merge fragment", savedRaw[0])
	}

	// 校验分支：短密码 / 空密码 → 400 且不落盘。
	for _, bad := range []string{`{"password":"abc"}`, `{"password":""}`} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest("POST", "/panel/api/setup/key", strings.NewReader(bad)))
		if rec.Code != 400 {
			t.Errorf("bad body %s: code=%d want 400", bad, rec.Code)
		}
	}
	if len(savedRaw) != 1 {
		t.Fatalf("invalid input must not reach SaveConfig, calls=%d", len(savedRaw))
	}
}

// 已初始化（面板密码已设或 api_key 已自定义）后 setup/key 必须永久 403——
// 这是向导不构成鉴权旁路的关键性质。
func TestSetupKeyClosedAfterInit(t *testing.T) {
	for _, c := range []struct {
		name    string
		apiKey  string
		panelPw string
	}{
		{"panel pw set", "test_key", "my-password"},
		{"customized key", "custom-key", ""},
	} {
		p := New(Config{Version: "t", APIKey: c.apiKey, PanelPassword: c.panelPw,
			SaveConfig: func(raw []byte) ([]string, error) { return nil, nil }})
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest("POST", "/panel/api/setup/key", strings.NewReader(`{"password":"attacker-pw"}`)))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: code=%d want 403 (setup must be closed)", c.name, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "attacker-pw") {
			t.Errorf("%s: must not echo submitted password: %s", c.name, rec.Body.String())
		}
	}
}

// 面板密码与网关 api_key 分离（panelKey）：密码设置后面板只认密码、api_key
// 不再能进面板；未设置时沿用 api_key（存量部署行为不变）。Live 热切换同测。
// 探针端点用 /panel/api/config（LoadConfig nil 时 501）：鉴权通过与否可区分，
// 且不需要 Pool 等重依赖——401=鉴权失败，501=鉴权已通过。
func TestPanelAuthSeparation(t *testing.T) {
	// 未设面板密码：api_key 可进（存量兼容形态）。
	p := New(Config{Version: "t", APIKey: "gateway-key"})
	over := httptest.NewRequest("GET", "/panel/api/config", nil)
	over.Header.Set("Authorization", "Bearer gateway-key")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, over)
	if rec.Code == 401 {
		t.Fatalf("no panel password: api_key must still work (compat), code=%d", rec.Code)
	}

	// 设置面板密码（Live）：api_key 拒绝、面板密码放行。
	live := livecfg.New(livecfg.Snapshot{APIKey: "gateway-key", PanelPassword: "panel-pw"})
	p2 := New(Config{Version: "t", APIKey: "gateway-key", Live: live})
	over2 := httptest.NewRequest("GET", "/panel/api/config", nil)
	over2.Header.Set("Authorization", "Bearer gateway-key")
	rec2 := httptest.NewRecorder()
	p2.ServeHTTP(rec2, over2)
	if rec2.Code != 401 {
		t.Fatalf("api_key must be rejected for panel auth when password set: code=%d", rec2.Code)
	}
	over3 := httptest.NewRequest("GET", "/panel/api/config", nil)
	over3.Header.Set("Authorization", "Bearer panel-pw")
	rec3 := httptest.NewRecorder()
	p2.ServeHTTP(rec3, over3)
	if rec3.Code == 401 {
		t.Fatalf("panel password must authenticate: code=%d body=%s", rec3.Code, rec3.Body.String())
	}

	// 静态字段路径（Live 为 nil 的裸用/测试形态）。
	p3 := New(Config{Version: "t", APIKey: "gateway-key", PanelPassword: "static-pw"})
	over4 := httptest.NewRequest("GET", "/panel/api/config", nil)
	over4.Header.Set("Authorization", "Bearer static-pw")
	rec4 := httptest.NewRecorder()
	p3.ServeHTTP(rec4, over4)
	if rec4.Code == 401 {
		t.Fatalf("static panel password must authenticate: code=%d", rec4.Code)
	}
}
