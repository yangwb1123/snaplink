package sso

import "net/http"

// handleAdminBackup triggers an online backup of each registered
// SQLite backup source via VACUUM INTO and returns a result summary.
func (s *Server) handleAdminBackup(ctx HandlerContext) {
	if len(s.backupSources) == 0 {
		ctx.JSON(http.StatusOK, map[string]any{
			KeyStatus: StatusOK,
			"sources": []string{},
		})
		return
	}
	results := make([]map[string]any, 0, len(s.backupSources))
	for _, src := range s.backupSources {
		dest := "/tmp/sso-backup-" + src.Name() + ".db"
		if err := src.BackupTo(ctx.Request().Context(), dest); err != nil {
			s.logger.Error("backup failed", "source", src.Name(), "error", err)
			results = append(results, map[string]any{
				"name":   src.Name(),
				"status": "failed",
			})
			continue
		}
		results = append(results, map[string]any{
			"name":   src.Name(),
			"status": "ok",
			"path":   dest,
		})
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus: StatusOK,
		"sources": results,
	})
}
