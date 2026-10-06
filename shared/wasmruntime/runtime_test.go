package wasmruntime

import (
	"context"
	"testing"

	"github.com/tetratelabs/wazero"
)

var emptyModule = []byte{0, 'a', 's', 'm', 1, 0, 0, 0}

func TestConcurrentConstruction(t *testing.T) {
	// Keep this cold-start test ahead of sequential construction tests so the
	// upstream version cache has not already been populated in this process.
	const workers = 32
	start := make(chan struct{})
	results := make(chan error, workers)
	config := wazero.NewRuntimeConfig().WithCloseOnContextDone(true).WithMemoryLimitPages(256)
	for range workers {
		go func() {
			<-start
			ctx := context.Background()
			runtime := New(ctx, config)
			_, err := runtime.CompileModule(ctx, emptyModule)
			if closeErr := runtime.Close(ctx); err == nil {
				err = closeErr
			}
			results <- err
		}()
	}
	close(start)
	for range workers {
		if err := <-results; err != nil {
			t.Errorf("runtime construction and compilation: %v", err)
		}
	}
}

func TestConstructionPreservesMemoryLimit(t *testing.T) {
	// One unbounded memory declaration with a two-page initial allocation.
	module := append(append([]byte(nil), emptyModule...), 5, 3, 1, 0, 2)
	ctx := context.Background()
	for _, pages := range []uint32{1, 2} {
		runtime := New(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(pages))
		_, err := runtime.CompileModule(ctx, module)
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Fatal(closeErr)
		}
		if pages == 1 && err == nil {
			t.Fatal("runtime discarded the caller's memory limit")
		}
		if pages == 2 && err != nil {
			t.Fatalf("permitted memory rejected: %v", err)
		}
	}
}
