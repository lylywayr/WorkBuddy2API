package panel

// setup.go 面板首次初始化向导：「首次进入由用户自定义访问密钥」。
//
// 背景：密钥门的提示是「请输入 config.json 中的密钥」——对不看配置文件的
// 用户等于没说（他既不知道值在哪、也改不动它）。新部署的出厂默认密钥
// （config.example.json 的 api_key="test_key"）必须被替换成用户自己的密钥
// 才算完成初始化，于是把这一步做成向导：
//
//   - GET  /panel/api/setup/status  无鉴权，返回 {setup_required}：
//     当前密钥仍为出厂默认值时为 true（前端据此把密钥门切换为
//     「设置新密钥」形态）。暴露面仅「是否待初始化」，与路由器首启
//     向导同级；密钥一旦自定义（含空 = 主动关鉴权）即永久 false。
//   - POST /panel/api/setup/key     仅初始化窗口期可用：body
//     {"api_key":"..."}，写盘复用 SaveConfig 闭包（merge 旧配置 →
//     同一套校验 → 原子落盘 → live 热生效，网关侧鉴权同步换新值）。
//     初始化完成后本端点永远 403——杜绝「事后改 key 接管面板」。
//
// 已自定义过密钥的存量部署（如 NAS 上 lylywayr）不受影响：status 恒
// false，向导从不出现；改密钥走既有路径（面板「配置」页 api_key 字段，
// 热生效）。空密钥（显式关闭鉴权）同样不触发向导——那是用户的主动
// 选择，不是待初始化状态。
import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

// factoryDefaultAPIKey 出厂默认密钥（config.example.json 的 api_key 值）。
// 仅作为「未初始化」的哨兵值使用；setup 之后任何值（含再次改回本值，
// 会 setupKey 显式拒绝）都不再触发向导。
const factoryDefaultAPIKey = "test_key"

// setupStatus 初始化状态探测（无鉴权）：密钥仍为出厂默认时 setup_required=true。
func (p *Panel) setupStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"setup_required": p.apiKey() == factoryDefaultAPIKey,
	})
}

// setupKey 初始化设置新密钥（仅出厂默认密钥窗口期可用，此后永久 403）。
func (p *Panel) setupKey(w http.ResponseWriter, r *http.Request) {
	if p.apiKey() != factoryDefaultAPIKey {
		// 已初始化（或鉴权已显式关闭）：向导通道关闭。不用 401——那会让
		// 前端误走「密钥不正确」重试分支；403 + 明确语义让前端直接回落登录态。
		writeErr(w, http.StatusForbidden, "setup already completed")
		return
	}
	if p.cfg.SaveConfig == nil {
		writeErr(w, http.StatusNotImplemented, "config api not available")
		return
	}
	var body struct {
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	k := strings.TrimSpace(body.APIKey)
	switch {
	case k == "":
		writeErr(w, http.StatusBadRequest, "api_key required")
		return
	case len([]rune(k)) < 6:
		writeErr(w, http.StatusBadRequest, "密钥至少需要 6 个字符")
		return
	case k == factoryDefaultAPIKey:
		writeErr(w, http.StatusBadRequest, "新密钥不能与出厂默认值相同")
		return
	}
	// SaveConfig 是 merge 语义（main.go saveConfig：旧配置为底、incoming
	// 覆盖同名键），只提交 api_key 即完成替换，其余配置原样保留。
	if _, err := p.cfg.SaveConfig([]byte(`{"api_key":` + jsonQuote(k) + `}`)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("panel: 初始化向导完成，访问密钥已由用户自定义（长度 %d，热生效）", len([]rune(k)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// jsonQuote JSON 字符串转义（json.Marshal 单值的快捷方式）。
func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
