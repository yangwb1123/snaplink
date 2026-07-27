// Command sso-operator runs the SSOConfigDrift controller: a Kubernetes
// operator that watches SSOConfigDrift custom resources and reports
// (never applies) cross-cluster SSO config drift. See doc.go for the full
// scope and explicit non-goals.
package main

import (
	"flag"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	driftv1alpha1 "github.com/yangwb1123/snaplink/cmd/sso-operator/apiv1alpha1"
	"github.com/yangwb1123/snaplink/cmd/sso-operator/controller"
)

// scheme is package-level per the standard kubebuilder scaffold: it must be
// populated before manager.New, and every controller in this binary shares
// it.
var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(driftv1alpha1.AddToScheme(scheme))
}

func main() {
	opts := parseFlags()
	ctrl.SetLogger(zap.New(zap.UseDevMode(opts.devMode)))

	mgr, err := newManager(opts)
	if err != nil {
		exitOnError("unable to start manager", err)
	}

	if err := (&controller.Reconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		exitOnError("unable to create controller", err)
	}

	if err := registerHealthChecks(mgr); err != nil {
		exitOnError("unable to set up health check", err)
	}

	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("starting sso-operator")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		exitOnError("problem running manager", err)
	}
}

// operatorFlags holds the small set of CLI flags this binary exposes.
// Kept as a struct (rather than passing flag.* values around) so
// newManager takes one argument instead of four.
type operatorFlags struct {
	metricsAddr          string
	probeAddr            string
	enableLeaderElection bool
	devMode              bool
}

func parseFlags() operatorFlags {
	var f operatorFlags
	flag.StringVar(&f.metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&f.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&f.enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&f.devMode, "dev", false, "Enable development-mode (human-readable) logging.")
	flag.Parse()
	return f
}

// newManager builds the controller-runtime Manager. Split out of main so
// main itself stays a short, linear "wire it up, run it" body.
func newManager(f operatorFlags) (ctrl.Manager, error) {
	return ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions(f.metricsAddr),
		HealthProbeBindAddress: f.probeAddr,
		LeaderElection:         f.enableLeaderElection,
		LeaderElectionID:       "sso-operator-leader.snaplink.io",
	})
}

func metricsServerOptions(addr string) metricsserver.Options {
	return metricsserver.Options{BindAddress: addr}
}

func registerHealthChecks(mgr ctrl.Manager) error {
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	return mgr.AddReadyzCheck("readyz", healthz.Ping)
}

func exitOnError(msg string, err error) {
	ctrl.Log.Error(err, msg)
	os.Exit(1)
}
