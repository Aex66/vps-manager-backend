package cmdqueue

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	hashPrefix      = "command:"
	pendPrefix      = "commands:pending:"
	procPrefix      = "commands:processing:"
	defaultStale    = 30 * time.Minute // processing-timeout → retry or fail (override with COMMAND_STALE_SEC)
	maxAttempts     = 3
	failedRecordTTL = 24 * time.Hour // hash retention after terminal failure (not retried)
)

var ErrNotFound = errors.New("command not in processing queue")

// Store is a Redis-backed reliable command queue per VPS (queueKey).
type Store struct {
	rdb   *redis.Client
	stale time.Duration
}

func New(redisAddr string) (*Store, error) {
	redisAddr = strings.TrimSpace(redisAddr)
	if redisAddr == "" {
		return nil, errors.New("empty redis address")
	}
	opt, err := redis.ParseURL(redisAddr)
	if err != nil {
		// Bare host:port
		opt = &redis.Options{Addr: redisAddr}
	}
	c := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		_ = c.Close()
		return nil, err
	}
	return &Store{rdb: c, stale: defaultStale}, nil
}

func (s *Store) Close() error {
	if s == nil || s.rdb == nil {
		return nil
	}
	return s.rdb.Close()
}

func pendingKey(queueKey string) string {
	return pendPrefix + queueKey
}

func processingKey(queueKey string) string {
	return procPrefix + queueKey
}

func commandHash(id string) string {
	return hashPrefix + id
}

// HasQueuedOrProcessingOfCmd reports whether an entry with the same cmd string exists on pending or processing lists.
func (s *Store) HasQueuedOrProcessingOfCmd(ctx context.Context, queueKey, cmd string) (bool, error) {
	if s == nil || s.rdb == nil {
		return false, errors.New("nil store")
	}
	queueKey = strings.TrimSpace(queueKey)
	cmd = strings.TrimSpace(cmd)
	if queueKey == "" || cmd == "" {
		return false, errors.New("queue key and cmd required")
	}
	pk := pendingKey(queueKey)
	prk := processingKey(queueKey)
	pendIDs, err := s.rdb.LRange(ctx, pk, 0, -1).Result()
	if err != nil {
		return false, err
	}
	procIDs, err := s.rdb.LRange(ctx, prk, 0, -1).Result()
	if err != nil {
		return false, err
	}
	seen := make(map[string]struct{}, len(pendIDs)+len(procIDs))
	for _, id := range append(append([]string{}, pendIDs...), procIDs...) {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		h := commandHash(id)
		c, err := s.rdb.HGet(ctx, h, "cmd").Result()
		if err == redis.Nil {
			continue
		}
		if err != nil {
			return false, err
		}
		if strings.TrimSpace(c) == cmd {
			return true, nil
		}
	}
	return false, nil
}

// Enqueue stores the command and pushes its id onto the pending list (LPUSH: newest at head; consume oldest with RPOPLPUSH — atomic like BRPOPLPUSH with zero timeout).
func (s *Store) Enqueue(ctx context.Context, queueKey, cmd string, payload map[string]any) (id string, err error) {
	queueKey = strings.TrimSpace(queueKey)
	cmd = strings.TrimSpace(cmd)
	if queueKey == "" || cmd == "" {
		return "", errors.New("queue key and cmd required")
	}
	var rb [16]byte
	if _, e := rand.Read(rb[:]); e != nil {
		return "", e
	}
	id = hex.EncodeToString(rb[:])
	pl, _ := json.Marshal(payload)
	h := commandHash(id)
	pipe := s.rdb.Pipeline()
	pipe.HSet(ctx, h, map[string]any{
		"vps_id":     queueKey,
		"cmd":        cmd,
		"status":     "pending",
		"attempts":   0,
		"created_at": time.Now().Unix(),
		"payload":    string(pl),
	})
	pipe.Expire(ctx, h, 7*24*time.Hour)
	pipe.LPush(ctx, pendingKey(queueKey), id)
	_, err = pipe.Exec(ctx)
	if err != nil {
		return "", err
	}
	return id, nil
}

// recoverStale moves timed-out processing entries back to pending or marks failed.
func (s *Store) recoverStale(ctx context.Context, queueKey string) error {
	pk := pendingKey(queueKey)
	prk := processingKey(queueKey)
	now := time.Now().Unix()
	staleSec := int64(s.stale.Seconds())
	maxA := int64(maxAttempts)

	ids, err := s.rdb.LRange(ctx, prk, 0, -1).Result()
	if err != nil || len(ids) == 0 {
		return err
	}

	for _, cid := range ids {
		h := commandHash(cid)
		m, err := s.rdb.HGetAll(ctx, h).Result()
		if err != nil || len(m) == 0 {
			continue
		}
		started, _ := strconv.ParseInt(m["started_at"], 10, 64)
		attempts, _ := strconv.ParseInt(m["attempts"], 10, 64)
		st := m["status"]
		if st != "processing" || started == 0 {
			continue
		}
		if now-started < staleSec {
			continue
		}
		if attempts >= maxA {
			pipe := s.rdb.Pipeline()
			pipe.LRem(ctx, prk, 1, cid)
			pipe.HSet(ctx, h, "status", "failed", "failed_at", now)
			pipe.Expire(ctx, h, failedRecordTTL)
			_, _ = pipe.Exec(ctx)
			continue
		}
		pipe := s.rdb.Pipeline()
		pipe.LRem(ctx, prk, 1, cid)
		pipe.RPush(ctx, pk, cid)
		pipe.HSet(ctx, h, "status", "pending", "started_at", 0)
		_, _ = pipe.Exec(ctx)
	}
	return nil
}

// ClaimResult is returned when a command is claimed successfully.
type ClaimResult struct {
	ID       string         `json:"id"`
	Cmd      string         `json:"cmd"`
	Attempts int            `json:"attempts"`
	Extras   map[string]any `json:"-"` // merged into agent message (e.g. cmd_secret)
}

// Claim moves one command pending → processing atomically (RPOPLPUSH) and updates metadata.
func (s *Store) Claim(ctx context.Context, queueKey string) (*ClaimResult, error) {
	queueKey = strings.TrimSpace(queueKey)
	if queueKey == "" {
		return nil, errors.New("queue key required")
	}
	if err := s.recoverStale(ctx, queueKey); err != nil {
		return nil, err
	}
	pk := pendingKey(queueKey)
	prk := processingKey(queueKey)

	id, err := s.rdb.RPopLPush(ctx, pk, prk).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	h := commandHash(id)
	now := time.Now().Unix()
	attempts, err := s.rdb.HIncrBy(ctx, h, "attempts", 1).Result()
	if err != nil {
		// Best-effort rollback: push back to pending tail = RPUSH? list is LPUSH pending — tail is oldest consumed with RPOP from right of pending... We moved with RPopLPush from pending right to processing left. Rollback: LREM processing + RPUSH pending?
		_, _ = s.rdb.LRem(ctx, prk, 1, id).Result()
		_, _ = s.rdb.RPush(ctx, pk, id).Result()
		return nil, err
	}
	if attempts > maxAttempts { // allow 1..maxAttempts claims
		pipe := s.rdb.Pipeline()
		pipe.LRem(ctx, prk, 1, id)
		pipe.HSet(ctx, h, "status", "failed", "failed_at", now)
		pipe.Expire(ctx, h, failedRecordTTL)
		_, _ = pipe.Exec(ctx)
		return nil, nil
	}
	_, err = s.rdb.HSet(ctx, h, map[string]any{
		"status":     "processing",
		"started_at": now,
	}).Result()
	if err != nil {
		return nil, err
	}

	cmd, _ := s.rdb.HGet(ctx, h, "cmd").Result()
	plStr, _ := s.rdb.HGet(ctx, h, "payload").Result()
	extras := map[string]any{}
	if plStr != "" {
		_ = json.Unmarshal([]byte(plStr), &extras)
	}
	return &ClaimResult{
		ID:       id,
		Cmd:      cmd,
		Attempts: int(attempts),
		Extras:   extras,
	}, nil
}

// Ack removes the command from the processing list and deletes the hash.
func (s *Store) Ack(ctx context.Context, queueKey, commandID string) error {
	queueKey = strings.TrimSpace(queueKey)
	commandID = strings.TrimSpace(commandID)
	if queueKey == "" || commandID == "" {
		return errors.New("queue key and command id required")
	}
	prk := processingKey(queueKey)
	h := commandHash(commandID)
	// Verify hash belongs to this queue
	vps, err := s.rdb.HGet(ctx, h, "vps_id").Result()
	if err == redis.Nil || strings.TrimSpace(vps) != queueKey {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	n, err := s.rdb.LRem(ctx, prk, 1, commandID).Result()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	_, _ = s.rdb.Del(ctx, h).Result()
	return nil
}

// StaleDuration returns configured processing timeout.
func (s *Store) StaleDuration() time.Duration {
	if s == nil {
		return defaultStale
	}
	return s.stale
}

// ParseStaleEnv overrides stale timeout via "COMMAND_STALE_SEC" number (optional helper for main).
func ParseStaleSec(getenv func(string) string) time.Duration {
	v := strings.TrimSpace(getenv("COMMAND_STALE_SEC"))
	if v == "" {
		return defaultStale
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 10 {
		return defaultStale
	}
	return time.Duration(n) * time.Second
}

// ApplyStale sets recovery timeout (call once after New if needed).
func (s *Store) ApplyStale(d time.Duration) {
	if s == nil || d < 10*time.Second {
		return
	}
	s.stale = d
}

// FormatQueueKeyForLog avoids huge log lines.
func FormatQueueKeyForLog(k string) string {
	k = strings.TrimSpace(k)
	if len(k) <= 20 {
		return k
	}
	return k[:12] + "…"
}
