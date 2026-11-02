package securitystore

import (
	"context"
	"sync"
	"testing"
	"time"

	pg "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

func TestLockoutConcurrentFailureAndSuccessReset(t *testing.T) {
	db, dsn := fixture(t)
	a, err := NewAccountLockoutWithDB(db, pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAccountLockoutWithDB(openPool(t, dsn), pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	a.MaxFailures, b.MaxFailures = 64, 64
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	start := make(chan struct{})
	var arrived, done sync.WaitGroup
	arrived.Add(32)
	for i := range 32 {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			arrived.Done()
			<-start
			if i%2 == 0 {
				_, _, err := a.RegisterFailure(ctx, "shared:key")
				if err != nil {
					t.Error("failure raced with a valid success reset", err)
				}
			} else if err := b.RegisterSuccess(ctx, "shared:key"); err != nil {
				t.Error(err)
			}
		}(i)
	}
	arrived.Wait()
	close(start)
	done.Wait()
}
