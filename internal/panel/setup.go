package panel

// setup.go 面板首次初始化向导：「首次进入由用户自定义面板登录密码」。
//
// 背景：密钥门的提示是「请输入 config.json 中的密钥」——对不看配置文件的
// 用户等于没说（他既不知道值在哪、也改不动它）。新部署的出厂形态是
// api_key=test_key 且未设面板密码，把「设一个自己的面板密码」做成向导：
//
//   - GET  /panel/api/setup/status  无鉴权，返回 {setup_required}：
//     面板密码未设置且 api_key 仍为出厂默认值（config.example.json 的
//     "test_key"）时为 true。设置密码（或 api_key 已自定义/显式关鉴权）
//     即永久 false。暴露面仅「是否待初始化」，与路由器首启向导同级。
//   - POST /panel/api/setup/key     仅初始化窗口期可用：body
//     {"password":"..."}，写盘复用 SaveConfig 闭包（深 merge 旧配置 →
//     同一套校验 → 原子落盘 → live 热生效）。此后本端点永远 403——
//     杜绝「事后改密码接管面板」。
//
// 密钥体系（与 api_key 分离，用户 2026-11-18 设计）：
//   - 面板密码（panel.password）：人用，管面板后台；
//   - API key（api_key）：客户端机器用，管网关 /v1 接入，在面板「接入指南」
//     里自定义或随机生成（前端实现，走既有 saveConfig）。
// 向导只设面板密码；API key 的更换是登录后在接入指南里的事。
//
// 存量部署（api_key 已自定义、面板密码未设）不受影响：status 恒 false，
// 向导从不出现，面板继续认 api_key（panelKey 回落）。
import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

// factoryDefaultAPIKey 出厂默认密钥（config.example.json 的 api_key 值）。
// 仅作为「未初始化」的哨兵值使用之一。
const factoryDefaultAPIKey = "test_key"

// panelPassword 当前面板密码（Live 优先，回落静态字段；空 = 未设置）。
func (p *Panel) panelPassword() string {
	if p.cfg.Live != nil {
		return p.cfg.Live.Load().PanelPassword
	}
	return p.cfg.PanelPassword
}

// setupStatus 初始化状态探测（无鉴权）：面板密码未设 + api_key 仍为出厂
// 默认时 setup_required=true。
func (p *Panel) setupStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"setup_required": p.panelPassword() == "" && p.apiKey() == factoryDefaultAPIKey,
	})
}

// setupKey 初始化设置面板登录密码（仅出厂默认窗口期可用，此后永久 403）。
func (p *Panel) setupKey(w http.ResponseWriter, r *http.Request) {
	if p.panelPassword() != "" || p.apiKey() != factoryDefaultAPIKey {
		// 已初始化（或 api_key 已自定义）：向导通道关闭。不用 401——那会让
		// 前端误走「密钥不正确」重试分支；403 + 明确语义让前端直接回落登录态。
		writeErr(w, http.StatusForbidden, "setup already completed")
		return
	}
	if p.cfg.SaveConfig == nil {
		writeErr(w, http.StatusNotImplemented, "config api not available")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	pw := strings.TrimSpace(body.Password)
	switch {
	case pw == "":
		writeErr(w, http.StatusBadRequest, "password required")
		return
	case len([]rune(pw)) < 6:
		writeErr(w, http.StatusBadRequest, "面板密码至少需要 6 个字符")
		return
	}
	// SaveConfig 是深 merge 语义（main.go mergeConfigMaps：嵌套对象递归合并），
	// 只提交 panel.password 即完成设置，panel.package_detail_limit 等原样保留。
	frag, err := json.Marshal(map[string]any{"panel": map[string]any{"password": pw}})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := p.cfg.SaveConfig(frag); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("panel: 初始化向导完成，面板登录密码已由用户自定义（长度 %d，热生效）", len([]rune(pw)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
