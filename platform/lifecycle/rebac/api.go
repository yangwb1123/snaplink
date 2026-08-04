package rebac

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/yangwb1123/snaplink/shared/core"
)

// APIHandler holds the product-level FGA tuple management handlers.

// TupleDeps is what the FGA tuple API handlers need from the host server.
type TupleDeps interface {
	RebacEngine() *Engine
	RebacStore() RelationTupleStore
	ErrorBody(code string) map[string]any
	ErrorBodyDesc(code, desc string) map[string]any
}

// tupleRequest is the JSON body for Write/Delete tuple operations.
type tupleRequest struct {
	Object   string `json:"object"`
	Relation string `json:"relation"`
	Subject  string `json:"subject"`
}

// HandleWriteTuple serves POST /api/v1/authz/tuples — writes relationship
// tuples. Accepts a single tuple or {"tuples": [...]}.
func HandleWriteTuple(d TupleDeps, ctx core.HandlerContext) {
	store := d.RebacStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	var single tupleRequest
	var bulk struct {
		Tuples []tupleRequest `json:"tuples"`
	}
	if json.Unmarshal(body, &bulk) == nil && len(bulk.Tuples) > 0 {
		for _, t := range bulk.Tuples {
			if err := store.Write(ctx.Request().Context(), Tuple{
				Object: t.Object, Relation: t.Relation, Subject: t.Subject,
			}); err != nil {
				ctx.JSON(http.StatusBadRequest, d.ErrorBodyDesc(core.ErrInvalidRequest, err.Error()))
				return
			}
		}
		ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK, "written": len(bulk.Tuples)})
		return
	}
	if json.Unmarshal(body, &single) != nil || single.Object == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if err := store.Write(ctx.Request().Context(), Tuple{
		Object: single.Object, Relation: single.Relation, Subject: single.Subject,
	}); err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBodyDesc(core.ErrInvalidRequest, err.Error()))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK})
}

// HandleDeleteTuple serves DELETE /api/v1/authz/tuples — deletes a tuple.
func HandleDeleteTuple(d TupleDeps, ctx core.HandlerContext) {
	store := d.RebacStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	var req tupleRequest
	if json.Unmarshal(body, &req) != nil || req.Object == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if err := store.Delete(ctx.Request().Context(), Tuple{
		Object: req.Object, Relation: req.Relation, Subject: req.Subject,
	}); err != nil {
		ctx.JSON(http.StatusInternalServerError, d.ErrorBodyDesc(core.ErrInternal, err.Error()))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK})
}

// HandleReadTuples serves GET /api/v1/authz/tuples — reads tuples matching
// query parameters (?object=&relation=&subject=).
func HandleReadTuples(d TupleDeps, ctx core.HandlerContext) {
	store := d.RebacStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	filter := TupleFilter{
		Object:   ctx.Query("object"),
		Relation: ctx.Query("relation"),
		Subject:  ctx.Query("subject"),
	}
	tuples, err := store.Read(ctx.Request().Context(), filter)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, d.ErrorBodyDesc(core.ErrInternal, err.Error()))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"tuples": tuples})
}

// HandleCheckAccess serves GET /api/v1/authz/check — checks whether subject
// has relation on object. Product-grade, not admin-debug.
func HandleCheckAccess(d TupleDeps, ctx core.HandlerContext) {
	eng := d.RebacEngine()
	if eng == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	object := ctx.Query("object")
	relation := ctx.Query("relation")
	subject := ctx.Query("subject")
	if object == "" || relation == "" || subject == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	allowed, err := eng.Check(ctx.Request().Context(), object, relation, subject)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, d.ErrorBodyDesc(core.ErrInternal, err.Error()))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"allowed": allowed, "object": object,
		"relation": relation, "subject": subject,
	})
}

// batchTupleRequest is the request body for HandleBatchWriteTuples.
type batchTupleRequest struct {
	IdempotencyKey string  `json:"idempotency_key,omitempty"`
	Writes         []Tuple `json:"writes,omitempty"`
	Deletes        []Tuple `json:"deletes,omitempty"`
}

type batchTupleResult struct {
	IdempotencyKey string `json:"idempotency_key"`
	Operation      string `json:"operation"`
	Status         string `json:"status"`
	Tuple          Tuple  `json:"tuple"`
	Error          string `json:"error,omitempty"`
}

// HandleBatchWriteTuples serves POST /authz/tuples/batch — executes a
// batch of writes and deletes atomically (all-or-nothing via the store's
// own semantics; the MemoryStore processes them sequentially without an
// explicit transaction, while a future SQLite/Postgres backend would wrap
// them in a BEGIN/COMMIT). Modeled after Zanzibar's WriteTuples RPC.
func HandleBatchWriteTuples(d TupleDeps, ctx core.HandlerContext) {
	store := d.RebacStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	raw, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBodyDesc(core.ErrInvalidRequest, "cannot read body"))
		return
	}
	var req batchTupleRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBodyDesc(core.ErrInvalidRequest, "invalid JSON"))
		return
	}
	key := req.IdempotencyKey
	if headerKey := ctx.Request().Header.Get(core.HeaderIdempotencyKey); headerKey != "" {
		key = headerKey
	}
	if key == "" {
		sum := sha256.Sum256(raw)
		key = fmt.Sprintf("rebac-batch:%x", sum[:12])
	}
	results := tupleBatchResults(key, req.Writes, req.Deletes, "applied", "")
	if err := store.ApplyBatch(ctx.Request().Context(), req.Writes, req.Deletes); err != nil {
		results = tupleBatchResults(key, req.Writes, req.Deletes, "not_applied", err.Error())
		ctx.JSON(http.StatusBadRequest, map[string]any{
			core.KeyError: "invalid_batch", "idempotency_key": key, "items": results,
		})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"status": "ok", "idempotency_key": key, "items": results,
		"written": len(req.Writes), "deleted": len(req.Deletes),
	})
}

func tupleBatchResults(key string, writes, deletes []Tuple, status, message string) []batchTupleResult {
	out := make([]batchTupleResult, 0, len(writes)+len(deletes))
	appendResults := func(operation string, tuples []Tuple) {
		for i, tuple := range tuples {
			out = append(out, batchTupleResult{
				IdempotencyKey: fmt.Sprintf("%s:%s:%d", key, operation, i),
				Operation:      operation, Status: status, Tuple: tuple, Error: message,
			})
		}
	}
	appendResults("write", writes)
	appendResults("delete", deletes)
	return out
}

// HandleReverseExpand serves GET /authz/graph — given a subject,
// returns every (object, relation) pair the subject has been granted.
// This is the "what can this user access?" reverse query.
func HandleReverseExpand(d TupleDeps, ctx core.HandlerContext) {
	store := d.RebacStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	subject := ctx.Query("subject")
	if subject == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	tuples, err := store.Read(ctx.Request().Context(), TupleFilter{Subject: subject})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, d.ErrorBodyDesc(core.ErrInternal, err.Error()))
		return
	}
	type edge struct {
		Object   string `json:"object"`
		Relation string `json:"relation"`
	}
	edges := make([]edge, 0, len(tuples))
	for _, t := range tuples {
		edges = append(edges, edge{Object: t.Object, Relation: t.Relation})
	}
	ctx.JSON(http.StatusOK, map[string]any{"subject": subject, "edges": edges})
}
