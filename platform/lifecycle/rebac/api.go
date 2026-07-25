package rebac

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/snaplink/sso/shared/core"
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
