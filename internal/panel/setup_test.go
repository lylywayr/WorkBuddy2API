package panel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 初始化向导（setup.go）行为矩阵：
//   - 出厂默认密钥（test_key）→ status=true，setup/key 可用且写盘走 SaveConfig；
//   - 自定义密钥 / 空（显式关鉴权）→ status=false，setup/key 永久 403；
//   - 输入校验：空 / 短于 6 字符 / 与出厂默认相同 → 400 不落盘。
func TestSetupStatusMatrix(t *testing.T) {
	cases := []struct {
		key      string
		required bool
	}{
		{"test_key", true},  // 出厂默认 → 待初始化
		{"lylywayr", false}, // 已自定义
		{"", false},         // 显式关闭鉴权：不是待初始化状态
	}
	for _, c := range cases {
		p := New(Config{Version: "t", APIKey: c.key})
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/api/setup/status", nil))
		if rec.Code != 200 {
			t.Fatalf("key=%q status code=%d", c.key, rec.Code)
		}
		want := "false"
		if c.required {
			want = "true"
		}
		if !strings.Contains(rec.Body.String(), `"setup_required":`+want) {
			t.Errorf("key=%q setup_required body=%s want %s", c.key, rec.Body.String(), want)
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

	// 合法新密钥：200、SaveConfig 收到仅含 api_key 的 merge 片段。
	body := `{"api_key":"my-own-key"}`
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("POST", "/panel/api/setup/key", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("setup/key code=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(savedRaw) != 1 || !strings.Contains(savedRaw[0], `"my-own-key"`) {
		t.Fatalf("SaveConfig calls=%v raw=%v", savedRaw, savedRaw)
	}

	// 校验分支：短密钥 / 空密钥 / 等于出厂默认 → 400 且不落盘。
	for _, bad := range []string{`{"api_key":"abc"}`, `{"api_key":""}`, `{"api_key":"test_key"}`} {
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

// 已初始化（非出厂默认密钥）后 setup/key 必须永久 403——这是向导不构成
// 鉴权旁路的关键性质。
func TestSetupKeyClosedAfterInit(t *testing.T) {
	p := New(Config{Version: "t", APIKey: "custom-key",
		SaveConfig: func(raw []byte) ([]string, error) { return nil, nil }})
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("POST", "/panel/api/setup/key", strings.NewReader(`{"api_key":"attacker"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403 (setup must be closed)", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "attacker") {
		t.Errorf("must not echo submitted key: %s", rec.Body.String())
	}
}
