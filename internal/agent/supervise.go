package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Supervise — сервер-локальное самолечение xray (инцидент 9.10: контейнер
// на CR вис зомбём с 30.09 — «running», порт слушает, сервис мёртв — и никто
// не заметил). Крутится root-юмнитом рядом со статс-агентом: грепаем
// gRPC-API xray (127.0.0.1:10085); два промаха подряд → рестарт контейнера
// через vpn-helper activate <current>. Облачных зависимостей нет.

const SuperviseStateFile = "/var/lib/vpn-agent/supervise.json"

// HealthChecker — минимальный контракт: жив ли xray-API.
type HealthChecker interface {
	Alive(ctx context.Context) error
}

// HelperDriver — управление релизами xray на хосте (vpn-helper).
type HelperDriver interface {
	Status() (current string, containerRunning bool, err error)
	Activate(id string) error
}

// SuperviseResult — для журнала юнита.
type SuperviseResult struct {
	Healthy   bool
	Fails     int
	Restarted bool
	Note      string
}

type superviseState struct {
	Fails int `json:"fails"`
}

func loadSuperviseState(path string) superviseState {
	b, err := os.ReadFile(path)
	if err != nil {
		return superviseState{}
	}
	var s superviseState
	_ = json.Unmarshal(b, &s)
	return s
}

func saveSuperviseState(path string, s superviseState) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// SuperviseOnce — один проход проверки (вызывается таймером каждые 5 мин).
// maxFails — сколько промахов подряд до рестарта (2 = мёртв ≥5 минут).
func SuperviseOnce(ctx context.Context, health HealthChecker, helper HelperDriver, statePath string, maxFails int) SuperviseResult {
	res := SuperviseResult{}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	state := loadSuperviseState(statePath)

	err := health.Alive(ctx)
	res.Healthy = err == nil
	if res.Healthy {
		if state.Fails > 0 {
			res.Note = fmt.Sprintf("recovered after %d fails", state.Fails)
		}
		state.Fails = 0
		_ = saveSuperviseState(statePath, state)
		res.Fails = 0
		return res
	}

	state.Fails++
	res.Fails = state.Fails
	if state.Fails < maxFails {
		_ = saveSuperviseState(statePath, state)
		res.Note = fmt.Sprintf("unhealthy (%v), strike %d/%d", err, state.Fails, maxFails)
		return res
	}

	// Порог пройден: рестарт текущего релиза.
	current, running, err := helper.Status()
	if err != nil {
		res.Note = fmt.Sprintf("unhealthy, helper status failed: %v", err)
		_ = saveSuperviseState(statePath, state)
		return res
	}
	if !running {
		res.Note = "container not running"
	}
	if current == "" {
		res.Note += ", no current release"
		_ = saveSuperviseState(statePath, state)
		return res
	}
	if err := helper.Activate(current); err != nil {
		res.Note = fmt.Sprintf("restart %s failed: %v", current, err)
		_ = saveSuperviseState(statePath, state)
		return res
	}
	res.Restarted = true
	res.Note = fmt.Sprintf("restarted release %s after %d fails (%s)", current, state.Fails, firstLine(err))
	// Счётчик не сбрасываем: если xray мёртв всерьёз, следующий проход
	// добьётся повторного рестарта сразу (rate-limit по факту — таймер).
	return res
}

func firstLine(err error) string {
	if err == nil {
		return "alive-check failed"
	}
	s := strings.TrimSpace(err.Error())
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// ParseHelperStatus разбирает вывод `vpn-helper status`:
// current=<id> / previous=<id> / container=running|… / listen=…
func ParseHelperStatus(out string) (current string, running bool) {
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "current="):
			current = strings.TrimSpace(strings.TrimPrefix(line, "current="))
		case strings.HasPrefix(line, "container="):
			running = strings.TrimSpace(strings.TrimPrefix(line, "container=")) == "running"
		}
	}
	return current, running
}
